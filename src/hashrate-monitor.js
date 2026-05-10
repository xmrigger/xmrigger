'use strict';
/**
 * hashrate-monitor.js — Hashrate Concentration Guard
 *
 * @version  0.1.0
 * @released 2026-04-18
 * @license  LGPL-2.1
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

// Endpoints for Monero mainnet difficulty (network hashrate = diff / 120s).
// 2026-05-09: 3 endpoints removed because dead/dropped (live audit):
//   community.xmr.to     — DNS dropped
//   p2pool.io/pool_info  — endpoint changed (404)
//   mini.p2pool.io       — host down
// Replaced with: supportxmr.com (network/stats) and p2pool.observer
// (sidechain.last_found.main_block.difficulty — needs Accept header).
// _fetchJson now sends Accept: application/json + User-Agent so JSON-only
// endpoints don't serve HTML to default Node UA. _extractDifficulty handles
// the nested observer path.
const DEFAULT_NETWORK_URLS = [
  'https://xmrchain.net/api/networkinfo',
  'https://moneroblocks.info/api/get_stats',
  'https://localmonero.co/blocks/api/get_stats',
  'https://supportxmr.com/api/network/stats',
  'https://p2pool.observer/api/pool_info',
];

class HashrateMonitor extends EventEmitter {
  /**
   * @param {object}   opts
   * @param {Function} [opts.localHashrate]   () => number  H/s measured locally
   * @param {string}   [opts.poolStatsUrl]    independent third-party stats URL
   * @param {string}   [opts.poolHealthUrl]   pool's own /pool/health (untrusted fallback)
   * @param {string[]} [opts.networkDiffUrls] override default network API list
   * @param {number}   [opts.threshold]       fraction 0.0–1.0 (default 0.43)
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
      if (prevPct === null || prevPct >= warnLevel) this.emit('safe', { hashratePct: pct });
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
      // Try common pool API response shapes (flat and nested)
      const h = data.poolHashrate
             ?? data.hashrate
             ?? data.pool_hashrate
             ?? data.pool_statistics?.hashRate
             ?? data.pool_statistics?.hashrate
             ?? data.pool_statistics?.collective?.hashRate
             ?? data.stats?.hashrate
             ?? data.network?.hashrate
             ?? data.data?.pool_hashrate
             ?? (Array.isArray(data.data) ? null : data.data?.hashrate)
             ?? null;
      if (typeof h === 'number') return h;
      // nanopool: { data: <number> }
      if (typeof data.data === 'number') return data.data;
      return null;
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
  const candidates = [
    data.difficulty,
    data.data?.difficulty,
    data.last_difficulty,
    data.mainchain?.difficulty,
    data.network_difficulty,
    data.top_block_hash_difficulty,
    // p2pool.observer/api/pool_info: Monero mainnet diff lives nested
    data.sidechain?.last_found?.main_block?.difficulty,
  ];
  for (const v of candidates) {
    const n = typeof v === 'number' ? v : (v != null ? parseInt(v, 10) : NaN);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return null;
}

// Cap on the size of an upstream JSON body. The legitimate stats endpoints
// return ~1-50 KB of JSON; 256 KB is generous. Without this cap a hostile
// or compromised endpoint can exhaust memory and block the event loop in
// JSON.parse on a single request.
const MAX_BODY_BYTES = 256 * 1024;

// Hosts/ranges to refuse following a 3xx redirect into. Without this guard
// a compromised default endpoint could redirect the fetcher into local /
// metadata services or RFC1918 / link-local destinations and exfiltrate
// state via DNS rebinding-style attacks. Keep the list aggressive.
function _isPrivateOrLoopbackHost(host) {
  if (!host) return true;
  const h = host.toLowerCase();
  if (h === 'localhost') return true;
  if (h.endsWith('.local') || h.endsWith('.internal')) return true;
  // IPv4 literal
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const a = +v4[1], b = +v4[2];
    if (a === 10) return true;                                  // 10/8
    if (a === 127) return true;                                 // loopback
    if (a === 169 && b === 254) return true;                    // link-local
    if (a === 172 && b >= 16 && b <= 31) return true;           // 172.16/12
    if (a === 192 && b === 168) return true;                    // 192.168/16
    if (a === 0) return true;                                   // 0/8
  }
  // IPv6 literal
  if (h.startsWith('[')) {
    const v6 = h.replace(/^\[|\]$/g, '');
    if (v6 === '::1' || v6 === '::') return true;
    if (v6.startsWith('fe80:') || v6.startsWith('fc') || v6.startsWith('fd')) return true;
  }
  return false;
}

function _fetchJson(url, timeoutMs = 8000, _redirects = 0) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    // Some endpoints (e.g. p2pool.observer) serve HTML to default UA and JSON only
    // when Accept is set explicitly. Provide a generic UA + Accept to be safe.
    const headers = {
      'Accept': 'application/json',
      'User-Agent': 'xmrigger-hashrate-monitor/1.0',
    };
    const req = mod.get(url, { timeout: timeoutMs, headers }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (_redirects >= 3) return reject(new Error('Too many redirects'));
        const next = new URL(res.headers.location, url);
        // SSRF / metadata-service guard: refuse redirects into private,
        // loopback, link-local, or *.local/*.internal hosts.
        if (_isPrivateOrLoopbackHost(next.hostname)) {
          return reject(new Error(`Refused redirect into non-public host: ${next.hostname}`));
        }
        return resolve(_fetchJson(next.href, timeoutMs, _redirects + 1));
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      // Bound body accumulation. Prefer a Buffer chain over `raw += c` —
      // string concat on chunked responses degrades to UTF-8 reinterpretation
      // per chunk (slow + exposes the parser to surrogate-pair edge cases).
      let total = 0;
      const chunks = [];
      res.on('data', (c) => {
        total += c.length;
        if (total > MAX_BODY_BYTES) {
          res.resume();
          req.destroy();
          return reject(new Error(`Response body exceeds ${MAX_BODY_BYTES} bytes`));
        }
        chunks.push(c);
      });
      res.on('end', () => {
        if (total > MAX_BODY_BYTES) return;     // already rejected above
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new Error('Invalid JSON')); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.on('error', reject);
  });
}

module.exports = { HashrateMonitor, DEFAULT_NETWORK_URLS };
