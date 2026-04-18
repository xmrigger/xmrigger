'use strict';
/**
 * prevhash-monitor.js — Cross-pool prevhash divergence detector
 *
 * @version  0.1.0
 * @released 2026-04-18
 * @license  LGPL-2.1
 *
 * Detects selfish mining by comparing the `prevhash` field from Stratum job
 * messages across proxy peers in a federation.
 *
 * How it works
 * ────────────
 * In Stratum v1, every mining.notify includes prevhash as params[1].
 * In Stratum v2, SetNewPrevHash carries the same value.
 *
 * A pool engaged in selfish mining must distribute jobs that reference a
 * private chain tip. That tip leaks through prevhash. When one proxy's
 * upstream pool shows a different prevhash than federation peers — and the
 * divergence persists for more than divergenceMs — a private fork is
 * almost certainly in progress.
 *
 * No protocol changes. No block building. Pure observation.
 * Each proxy monitors its own upstream and shares its prevhash with peers.
 * Each proxy decides independently whether to alert or evacuate.
 *
 * Integration
 * ───────────
 *   const mon = new PrevhashMonitor({
 *     poolId:      'pool.hashvault.pro:3333',
 *     getPrevhash: () => proxy.lastPrevhash,   // string | null
 *     pollIntervalMs: 5_000,
 *     divergenceMs:   20_000,
 *   });
 *
 *   mon.on('announce',   ({ prevhash }) => federation.broadcastPrevhash(prevhash));
 *   mon.on('divergence', ({ ownPrevhash, divergentPeers }) => { ... evacuate ... });
 *   mon.on('resolved',   ({ prevhash }) => console.log('chains in sync'));
 *
 *   // When federation receives a peer announce:
 *   federation.on('prevhash-announce', ({ from, prevhash, ts }) =>
 *     mon.onPeerAnnounce(from, prevhash, ts));
 *
 *   mon.start();
 *
 * Events
 * ──────
 *   'announce'    { prevhash }
 *       Own prevhash changed. Broadcast to federation peers.
 *
 *   'divergence'  { ownPrevhash, divergentPeers, seenMs }
 *       divergentPeers: [{ peerId, prevhash, peerAgeMs }]
 *       seenMs: how long the divergence has been observed
 *       Disagreement persisted for divergenceMs.
 *       At least one peer is on a different chain.
 *
 *   'resolved'    { prevhash }
 *       All known peers now report the same prevhash.
 *
 * @license LGPL-2.1
 */

const { EventEmitter } = require('events');

const PEER_STALE_MS = 120_000;  // ignore peers silent for > 2 min

class PrevhashMonitor extends EventEmitter {
  /**
   * @param {object}   opts
   * @param {string}   opts.poolId              Human-readable pool identifier
   * @param {Function} opts.getPrevhash         () => string|null — current upstream prevhash
   * @param {number}   [opts.pollIntervalMs=5000]
   * @param {number}   [opts.divergenceMs=20000]  Persist before emitting 'divergence'
   * @param {number}   [opts.minPeersForAlert=1]  Min fresh peers required before alerting
   *                                               (prevents a single Sybil peer from triggering)
   * @param {boolean}  [opts.enabled=true]
   */
  constructor({
    poolId            = 'unknown',
    getPrevhash,
    pollIntervalMs    = 5_000,
    divergenceMs      = 20_000,
    minPeersForAlert  = 1,
    enabled           = true,
  } = {}) {
    super();
    this.poolId           = poolId;
    this.getPrevhash      = getPrevhash;
    this.pollIntervalMs   = pollIntervalMs;
    this.divergenceMs     = divergenceMs;
    this.minPeersForAlert = minPeersForAlert;
    this.enabled          = enabled;

    this._pollTimer    = null;
    this._ownPrevhash  = null;        // current prevhash of our upstream pool
    this._peers        = new Map();   // peerId → { prevhash, ts }
    this._divergeStart = null;        // Date.now() when divergence first seen
    this._divergeEmitted = false;     // have we emitted 'divergence' for current run?
  }

  start() {
    if (!this.enabled) return this;
    if (!this.getPrevhash) {
      console.warn('[prevhash-monitor] getPrevhash not configured — disabled');
      return this;
    }
    if (this._pollTimer) clearInterval(this._pollTimer);
    this._poll();
    this._pollTimer = setInterval(() => this._poll(), this.pollIntervalMs);
    return this;
  }

  stop() {
    clearInterval(this._pollTimer);
    this._pollTimer = null;
    return this;
  }

  /**
   * Called by the federation handler when a peer broadcasts its prevhash.
   * @param {string} peerId    Peer name / identifier
   * @param {string} prevhash  Hex prevhash from the peer's upstream pool
   * @param {number} [ts]      Timestamp (defaults to now)
   */
  onPeerAnnounce(peerId, prevhash, ts = Date.now()) {
    if (!prevhash) return;
    this._peers.set(peerId, { prevhash, ts });
    this.emit('peer-updated', { peerId, prevhash, ts });
    this._checkDivergence();
  }

  // ── Internal ────────────────────────────────────────────────────────────────

  _poll() {
    const fresh = this.getPrevhash();
    if (!fresh) return;

    const changed = fresh !== this._ownPrevhash;
    this._ownPrevhash = fresh;

    if (changed) {
      this.emit('announce', { prevhash: fresh });
    }

    this._checkDivergence();
  }

  _checkDivergence() {
    if (!this._ownPrevhash) return;

    const now = Date.now();
    const freshPeers = [...this._peers.entries()]
      .filter(([, p]) => now - p.ts < PEER_STALE_MS);

    if (freshPeers.length === 0 || freshPeers.length < this.minPeersForAlert) {
      // Not enough peers to make a determination — reset divergence state.
      // Prevents a single Sybil peer from triggering alerts when minPeersForAlert > 1.
      this._divergeStart   = null;
      this._divergeEmitted = false;
      return;
    }

    const divergent = freshPeers
      .filter(([, p]) => p.prevhash !== this._ownPrevhash)
      .map(([id, p]) => ({
        peerId:     id,
        prevhash:   p.prevhash,
        peerAgeMs:  now - p.ts,   // time since last announce from this peer
      }));

    if (divergent.length === 0) {
      // All peers agree with us
      if (this._divergeStart !== null) {
        this._divergeStart   = null;
        this._divergeEmitted = false;
        this.emit('resolved', { prevhash: this._ownPrevhash });
      }
      return;
    }

    // At least one peer disagrees
    if (this._divergeStart === null) {
      this._divergeStart   = now;
      this._divergeEmitted = false;
    }

    const seenMs = now - this._divergeStart;

    if (!this._divergeEmitted && seenMs >= this.divergenceMs) {
      this._divergeEmitted = true;
      this.emit('divergence', {
        ownPrevhash:    this._ownPrevhash,
        divergentPeers: divergent,
        seenMs,
      });
    }
  }
}

module.exports = { PrevhashMonitor, PEER_STALE_MS };
