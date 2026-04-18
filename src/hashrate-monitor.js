'use strict';
/**
 * hashrate-monitor.js — Hashrate Concentration Guard
 *
 * Computes pool/network hashrate ratio from INDEPENDENT sources so a
 * malicious pool cannot hide concentration by refusing to report stats.
 *
 * Data sources (checked in order, highest trust wins):
 *   1. localHashrate callback — proxy/miner measures own share rate locally
 *   2. poolStatsUrl           — third-party source (miningpoolstats, etc.)
 *      must return { poolHashrate: H/s } or { hashrate: H/s }
 *   3. poolHealthUrl          — pool's own /pool/health (least trusted)
 *
 * Network hashrate is ALWAYS fetched from independent public Monero nodes —
 * never from the pool being monitored. Six sources queried in parallel;
 * first valid answer wins.
 *
 * Events:
 *   'warn'       { hashratePct, threshold, source }   pool > 85% of threshold
 *   'crit'       { hashratePct, threshold, source }   pool >= threshold, grace starts
 *   'grace-tick' { secsLeft }                         countdown each second
 *   'evacuate'   { reason, fallback }                 grace elapsed — switch NOW
 *   'safe'       { hashratePct }                      dropped back below warn
 *   'fork'       { }                                  fork/reorg detected — immediate evacuate
 *
 * @license LGPL-2.1
 */

const https = require('https');
const http  = require('http');
const { EventEmitter } = require('events');

const WARN_RATIO    = 0.85;
const POLL_DEFAULT  = 30_000;
const GRACE_DEFAULT = 60_000;

const DEFAULT_NETWORK_URLS = [
  'https://xmrchain.net/api/networkinfo',
  'https://community.xmr.to/api/v1/networkinfo',
  'https://moneroblocks.info/api/get_stats',
  'https://localmonero.co/blocks/api/get_stats',
  'https://p2pool.io/api/pool_info',
  'https://mini.p2pool.io/api/pool_info',
];

class HashrateMonitor extends EventEmitter {
  /**
   * @param {object}   opts
   * @param {Function} [opts.localHashrate]   () => number  H/s measured locally
   * @param {string}   [opts.poolStatsUrl]    independent third-party stats URL
   * @param {string}   [opts.poolHealthUrl]   pool's own /pool/health (untrusted fallback)
   * @param {string[]} [opts.networkDiffUrls] override default network API list
   * @param {number}   [opts.threshold]       fraction 0.0–1.0 (default 0.30)
   * @param {number}   [opts.pollIntervalMs]
   * @param {number}   [opts.gracePeriodMs]
   * @param {object[]} [opts.fallbackPools]   [{host, port}, …]
   * @param {boolean}  [opts.enabled]
   */
  constructor({
    localHashrate    = null,
    poolStatsUrl     = null,
    poolHealthUrl    = null,
    networkDiffUrls  = DEFAULT_NETWORK_URLS,
    threshold        = 0.43,
    pollIntervalMs   = POLL_DEFAULT,
    gracePeriodMs    = GRACE_DEFAULT,
    fallbackPools    = [],
    enabled          = true,
  } = {}) {
    super();
    this.localHashrate   = localHashrate;
    this.poolStatsUrl    = poolStatsUrl;
    this.poolHealthUrl   = poolHealthUrl;
    this.networkDiffUrls = networkDiffUrls;
    this.threshold       = threshold;
    this.pollIntervalMs  = pollIntervalMs;
    this.gracePeriodMs   = gracePeriodMs;
    this.fallbackPools   = fallbackPools;
    this.enabled         = enabled;

    this._pollTimer        = null;
    this._graceTick        = null;
    this._inGrace          = false;
    this._fallbackIdx      = 0;
    this._lastEvacuatedAt  = 0;
    this.lastPct           = null;
    this.lastError         = null;
  }

  start() {
    if (!this.enabled) return this;
    if (!this.localHashrate && !this.poolStatsUrl && !this.poolHealthUrl) {
      console.warn('[hashrate-monitor] No pool hashrate source configured — guard disabled');
      return this;
    }
    if (this._pollTimer) clearInterval(this._pollTimer);
    // After an evacuate, skip the immediate poll to avoid re-entrancy loops
    // while the upstream condition (fork/crit) may still be active.
    const msSinceEvacuate = Date.now() - this._lastEvacuatedAt;
    if (msSinceEvacuate > this.gracePeriodMs) {
      this._poll();
    }
    this._pollTimer = setInterval(() => this._poll(), this.pollIntervalMs);
    return this;
  }

  stop() {
    clearInterval(this._pollTimer);
    this._cancelGrace();
    this._pollTimer = null;
    return this;
  }

  /** Trigger an immediate poll — used when a federation peer sends a hint. */
  pollNow() { this._poll(); }

  // ── Internal ────────────────────────────────────────────────────────────────

  async _poll() {
    // Skip poll entirely during evacuate cooldown — prevents re-trigger while
    // upstream condition (fork/crit) is still active after a restart.
    if (Date.now() - this._lastEvacuatedAt < this.gracePeriodMs) return;

    const networkHashrate = await this._fetchNetworkHashrate();
    if (!networkHashrate) { this.lastError = 'network hashrate unavailable'; return; }

    let poolHashrate = null;
    let source = 'unknown';

    if (typeof this.localHashrate === 'function') {
      const h = this.localHashrate();
      if (h > 0) { poolHashrate = h; source = 'local'; }
    }

    if (poolHashrate === null && this.poolStatsUrl) {
      const r = await this._fetchPoolStatsIndependent(this.poolStatsUrl);
      if (r !== null) { poolHashrate = r; source = 'independent'; }
    }

    if (poolHashrate === null && this.poolHealthUrl) {
      const r = await this._fetchPoolHealth(this.poolHealthUrl);
      if (r !== null) {
        const prevPct = this.lastPct;
        this.lastPct   = r.hashratePct;
        this.lastError = null;
        if (r.forkDetected) { this.emit('fork', {}); this._startEvacuate('fork'); return; }
        this._evaluate(r.hashratePct, prevPct, 'pool-self-reported');
        return;
      }
    }

    if (poolHashrate === null) { this.lastError = 'pool hashrate unavailable'; return; }

    const pct     = poolHashrate / networkHashrate;
    const prevPct = this.lastPct;
    this.lastPct   = pct;
    this.lastError = null;
    this._evaluate(pct, prevPct, source);
  }

  _evaluate(pct, prevPct, source) {
    // Drop results from polls that were in-flight during an evacuate.
    if (Date.now() - this._lastEvacuatedAt < this.gracePeriodMs) return;
    const warnLevel = this.threshold * WARN_RATIO;
    if (pct >= this.threshold) {
      this.emit('crit', { hashratePct: pct, threshold: this.threshold, source });
      if (!this._inGrace) this._startGrace(pct, source);
    } else if (pct >= warnLevel) {
      this.emit('warn', { hashratePct: pct, threshold: this.threshold, source });
      this._cancelGrace();
    } else {
      if (this._inGrace) this._cancelGrace();
      if (prevPct !== null && prevPct >= warnLevel) this.emit('safe', { hashratePct: pct });
    }
  }

  async _fetchNetworkHashrate() {
    const attempts = this.networkDiffUrls.map(async (url) => {
      const data = await _fetchJson(url, 6000);
      const diff = _extractDifficulty(data);
      if (!diff) throw new Error('no difficulty');
      return Math.floor(diff / 120);
    });
    try { return await Promise.any(attempts); } catch { return null; }
  }

  async _fetchPoolStatsIndependent(url) {
    try {
      const data = await _fetchJson(url, 8000);
      const h = data.poolHashrate ?? data.hashrate ?? data.pool_hashrate ?? null;
      return typeof h === 'number' ? h : null;
    } catch { return null; }
  }

  async _fetchPoolHealth(url) {
    try {
      const data = await _fetchJson(url, 8000);
      if (typeof data.hashratePct === 'number') return data;
      return null;
    } catch { return null; }
  }

  _startGrace(pct, source) {
    this._inGrace = true;
    let secsLeft = Math.ceil(this.gracePeriodMs / 1000);
    console.warn(`[hashrate-monitor] ${(pct*100).toFixed(1)}% [${source}] — grace ${secsLeft}s`);
    this._graceTick = setInterval(() => {
      secsLeft--;
      this.emit('grace-tick', { secsLeft });
      if (secsLeft <= 0) {
        clearInterval(this._graceTick);
        this._graceTick = null;
        this._startEvacuate('threshold');
      }
    }, 1000);
  }

  _cancelGrace() {
    if (this._graceTick) { clearInterval(this._graceTick); this._graceTick = null; }
    this._inGrace = false;
  }

  _startEvacuate(reason) {
    this._cancelGrace();
    this.stop();
    this._lastEvacuatedAt = Date.now();
    const fallback = this._nextFallback();
    console.warn(`[hashrate-monitor] EVACUATE reason=${reason} → ${fallback ? fallback.host+':'+fallback.port : 'none'}`);
    this.emit('evacuate', { reason, fallback });
  }

  _nextFallback() {
    if (!this.fallbackPools.length) return null;
    const pool = this.fallbackPools[this._fallbackIdx % this.fallbackPools.length];
    this._fallbackIdx++;
    return pool;
  }
}

function _extractDifficulty(data) {
  if (!data) return null;
  if (typeof data.difficulty === 'number'            && data.difficulty > 0)            return data.difficulty;
  if (typeof data.data?.difficulty === 'number'      && data.data.difficulty > 0)       return data.data.difficulty;
  if (typeof data.last_difficulty === 'number'       && data.last_difficulty > 0)       return data.last_difficulty;
  if (typeof data.mainchain?.difficulty === 'number' && data.mainchain.difficulty > 0)  return data.mainchain.difficulty;
  return null;
}

function _fetchJson(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { reject(new Error('Invalid JSON')); } });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.on('error', reject);
  });
}

module.exports = { HashrateMonitor, DEFAULT_NETWORK_URLS };
