'use strict';
/**
 * prevhash-monitor.js — Cross-pool prevhash divergence detector
 *
 * @version  0.2.0
 * @released 2026-05-12
 * @license  LGPL-2.1
 *
 * Detects selfish mining by comparing the `prevhash` field from Stratum job
 * messages across proxy peers in a federation.
 *
 * Design (v0.2)
 * ─────────────
 * In Stratum v1, every mining.notify includes prevhash as params[1].
 * In Stratum v2, SetNewPrevHash carries the same value.
 *
 * A pool engaged in selfish mining must distribute jobs that reference a
 * private chain tip. That tip leaks through prevhash. The monitor decides
 * whether the *local* pool is the divergent one by computing the canonical
 * verdict via majority vote over (self + fresh peers), then checking whether
 * the local prevhash agrees with that majority.
 *
 * Three independent stabilisers prevent false positives:
 *
 *   (1) Majority vote. Verdict = prev_hash with the most votes among
 *       (self + fresh peers). A single Sybil peer cannot push the verdict
 *       against a true majority of honest observers. Ties are "indeterminate"
 *       and never raise.
 *
 *   (2) Short history (historyK). The "self-in-minority" condition must hold
 *       for K consecutive ticks before divergence is emitted. Absorbs the
 *       1–2s propagation jitter between honest pools when a new block lands.
 *
 *   (3) Persistence timer (divergenceMs). Minority must persist for at least
 *       this duration. Bounded by Monero's natural orphan window.
 *
 * Both (2) and (3) must be satisfied. The two stabilisers are orthogonal:
 * historyK is sample-count, divergenceMs is wall-clock — one without the other
 * is bypassable.
 *
 * Known limit: a Sybil set holding ≥50% of the peer roster can force the
 * verdict. Mitigation is out of scope for v0.2 — adding peer-identity
 * attestation belongs in the federation layer, not here. v0.2 keeps the door
 * open by treating `minPeersForAlert` as the floor before votes count.
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
 *     historyK:       3,
 *     majorityVote:   true,
 *   });
 *
 *   mon.on('announce',   ({ prevhash }) => federation.broadcastPrevhash(prevhash));
 *   mon.on('divergence', ({ ownPrevhash, canonical, divergentPeers }) => { ... });
 *   mon.on('resolved',   ({ prevhash }) => console.log('chains in sync'));
 *
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
 *   'divergence'  { ownPrevhash, canonical, divergentPeers, seenMs, sampleCount }
 *       canonical:     prev_hash held by majority (self + peers)
 *       divergentPeers: peers whose prev_hash != canonical (excludes self)
 *       seenMs:        how long self has been in minority
 *       sampleCount:   consecutive ticks of stable minority (>= historyK)
 *
 *   'resolved'    { prevhash }
 *       Self has rejoined the majority verdict.
 */

const { EventEmitter } = require('events');

const PEER_STALE_MS = 120_000;  // ignore peers silent for > 2 min

class PrevhashMonitor extends EventEmitter {
  /**
   * @param {object}   opts
   * @param {string}   opts.poolId              Human-readable pool identifier
   * @param {Function} opts.getPrevhash         () => string|null
   * @param {number}   [opts.pollIntervalMs=5000]
   * @param {number}   [opts.divergenceMs=20000]   Persistence floor before emit
   * @param {number}   [opts.minPeersForAlert=1]   Min fresh peers required
   * @param {number}   [opts.historyK=3]           Consecutive stable ticks
   * @param {boolean}  [opts.majorityVote=true]    Use majority vote (v0.2);
   *                                                 false = legacy v0.1 behaviour
   * @param {boolean}  [opts.enabled=true]
   */
  constructor({
    poolId            = 'unknown',
    getPrevhash,
    pollIntervalMs    = 5_000,
    divergenceMs      = 20_000,
    minPeersForAlert  = 1,
    historyK          = 3,
    majorityVote      = true,
    enabled           = true,
  } = {}) {
    super();
    this.poolId           = poolId;
    this.getPrevhash      = getPrevhash;
    this.pollIntervalMs   = pollIntervalMs;
    this.divergenceMs     = divergenceMs;
    this.minPeersForAlert = minPeersForAlert;
    this.historyK         = Math.max(1, historyK | 0);
    this.majorityVote     = majorityVote;
    this.enabled          = enabled;

    this._pollTimer    = null;
    this._ownPrevhash  = null;        // current prevhash of our upstream pool
    this._peers        = new Map();   // peerId → { prevhash, ts }
    this._divergeStart = null;        // Date.now() when divergence first seen
    this._divergeEmitted = false;
    this._stableMinorityTicks = 0;    // consecutive ticks of self-in-minority
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

  /**
   * Tally votes across (self + fresh peers).
   * @returns {{ verdict: string|null, tally: Map<string,number>, freshPeers: Array }}
   *   verdict === null when undecidable (tie, or no peers).
   */
  _tally() {
    const now = Date.now();
    // Evict stale peers in-place to keep the map bounded.
    for (const [pid, p] of this._peers) {
      if (now - p.ts >= PEER_STALE_MS) this._peers.delete(pid);
    }
    const freshPeers = [...this._peers.entries()]
      .filter(([, p]) => now - p.ts < PEER_STALE_MS);

    const tally = new Map();
    tally.set(this._ownPrevhash, 1);
    for (const [, p] of freshPeers) {
      tally.set(p.prevhash, (tally.get(p.prevhash) || 0) + 1);
    }

    // Pick the entry with the highest count; null on tie.
    let verdict = null;
    let topCount = -1;
    let tied = false;
    for (const [hash, count] of tally) {
      if (count > topCount) { verdict = hash; topCount = count; tied = false; }
      else if (count === topCount) { tied = true; }
    }
    if (tied) verdict = null;

    return { verdict, tally, freshPeers, now };
  }

  _checkDivergence() {
    if (!this._ownPrevhash) return;

    const { verdict, freshPeers, now } = this._tally();

    if (freshPeers.length === 0 || freshPeers.length < this.minPeersForAlert) {
      this._resetMinorityState();
      return;
    }

    // ── Legacy mode (v0.1): self-as-oracle ─────────────────────────────────
    if (!this.majorityVote) {
      const divergent = freshPeers
        .filter(([, p]) => p.prevhash !== this._ownPrevhash)
        .map(([id, p]) => ({ peerId: id, prevhash: p.prevhash, peerAgeMs: now - p.ts }));

      if (divergent.length === 0) {
        if (this._divergeStart !== null) {
          this._resetMinorityState();
          this.emit('resolved', { prevhash: this._ownPrevhash });
        }
        return;
      }
      this._tickMinority(now, this._ownPrevhash, divergent);
      return;
    }

    // ── Majority mode (v0.2 default) ───────────────────────────────────────
    // Undecidable verdict (tie) is treated as "indeterminate, no alarm".
    if (verdict === null) {
      this._resetMinorityState();
      return;
    }

    if (verdict === this._ownPrevhash) {
      // Self in majority — resolved
      if (this._divergeStart !== null) {
        this._resetMinorityState();
        this.emit('resolved', { prevhash: this._ownPrevhash });
      }
      return;
    }

    // Self is in MINORITY — the local pool disagrees with the canonical chain.
    // Peers on the canonical chain are NOT divergent; those off it are.
    const divergent = freshPeers
      .filter(([, p]) => p.prevhash !== verdict)
      .map(([id, p]) => ({ peerId: id, prevhash: p.prevhash, peerAgeMs: now - p.ts }));

    this._tickMinority(now, verdict, divergent);
  }

  _tickMinority(now, canonical, divergent) {
    if (this._divergeStart === null) {
      this._divergeStart = now;
      this._divergeEmitted = false;
      this._stableMinorityTicks = 0;
    }
    this._stableMinorityTicks += 1;

    const seenMs = now - this._divergeStart;
    const stableEnough = this._stableMinorityTicks >= this.historyK;
    const persistedEnough = seenMs >= this.divergenceMs;

    if (!this._divergeEmitted && stableEnough && persistedEnough) {
      this._divergeEmitted = true;
      this.emit('divergence', {
        ownPrevhash:    this._ownPrevhash,
        canonical,
        divergentPeers: divergent,
        seenMs,
        sampleCount:    this._stableMinorityTicks,
      });
    }
  }

  _resetMinorityState() {
    this._divergeStart        = null;
    this._divergeEmitted      = false;
    this._stableMinorityTicks = 0;
  }
}

module.exports = { PrevhashMonitor, PEER_STALE_MS };
