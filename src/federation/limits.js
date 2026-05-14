'use strict';
/**
 * limits.js — per-peer / per-IP rate limiting + ban list.
 *
 * @license LGPL-2.1
 *
 * SPEC-FEDERATION-v1.md §5.1, §5.2, §5.3.
 *
 * All values are hardcoded via consts.js. No env-tunable knobs.
 *
 * Three layers, distinct lifecycles:
 *
 *   - PerIpRate:  pre-handshake gate (handshake-rate cap, half-open cap).
 *                 Lives entirely in memory, no persistence.
 *   - PerPeer:    after HELLO completed; token-bucket per id_pub for frame
 *                 and byte budgets, plus strike escalation.
 *   - BanList:    cross-cutting; entries keyed by IP, TTL'd, in-memory only
 *                 by default (persistent file optional, off by default).
 *
 * Strike escalation chain:
 *
 *   N strikes within STRIKE_WINDOW_MS:
 *     N >= STRIKE_SOFT_THRESHOLD  → soft quarantine SOFT_QUARANTINE_MS
 *     N >= STRIKE_HARD_THRESHOLD  → hard quarantine HARD_QUARANTINE_MS
 *                                   + add ban for HARD_QUARANTINE_MS on IP
 *
 *   Hard quarantines per IP within 24 h:
 *     count >= HARD_HISTORY_24H_LIMIT → persistent ban PERSISTENT_BAN_MS
 *
 * Hardcoded, no profile selector, no env override.
 */

const C = require('./consts');

// ── Token bucket ────────────────────────────────────────────────────────────

class TokenBucket {
  constructor(capacity, refillPerSec) {
    this.capacity = capacity;
    this.refill   = refillPerSec;
    this.tokens   = capacity;
    this.last     = Date.now();
  }
  _refill(now) {
    const dt = (now - this.last) / 1000;
    if (dt <= 0) return;
    this.tokens = Math.min(this.capacity, this.tokens + dt * this.refill);
    this.last   = now;
  }
  take(n = 1, now = Date.now()) {
    this._refill(now);
    if (this.tokens >= n) { this.tokens -= n; return true; }
    return false;
  }
}

// ── BanList ─────────────────────────────────────────────────────────────────

class BanList {
  constructor({ now = Date.now } = {}) {
    this._now = now;
    /** ip → expiresAtMs */
    this._bans = new Map();
  }

  add(ip, ttlMs, _reason) {
    if (!ip) return;
    const exp = this._now() + ttlMs;
    const cur = this._bans.get(ip) || 0;
    if (exp > cur) this._bans.set(ip, exp);
    this._evict();
  }

  isBanned(ip) {
    if (!ip) return false;
    const exp = this._bans.get(ip);
    if (!exp) return false;
    if (exp <= this._now()) { this._bans.delete(ip); return false; }
    return true;
  }

  remove(ip) { this._bans.delete(ip); }
  size()      { return this._bans.size; }
  clear()     { this._bans.clear(); }

  _evict() {
    while (this._bans.size > C.BAN_LIST_MAX) {
      const k = this._bans.keys().next().value;
      this._bans.delete(k);
    }
  }
}

// ── PerIpRate (pre-handshake) ───────────────────────────────────────────────

class PerIpRate {
  constructor({ now = Date.now } = {}) {
    this._now = now;
    /** ip → { handshakes:number[], halfOpen:number } */
    this._state = new Map();
  }

  /** Returns true if the IP may attempt a new handshake. */
  allowHandshake(ip) {
    const now = this._now();
    const s = this._stateFor(ip);
    s.handshakes = s.handshakes.filter((t) => now - t < C.IP_HANDSHAKE_WINDOW_MS);
    if (s.handshakes.length >= C.IP_HANDSHAKE_RATE) return false;
    s.handshakes.push(now);
    return true;
  }

  /** Returns true if a new half-open slot is available. Increments. */
  acquireHalfOpen(ip) {
    const s = this._stateFor(ip);
    if (s.halfOpen >= C.IP_HALF_OPEN_CAP) return false;
    s.halfOpen += 1;
    return true;
  }

  releaseHalfOpen(ip) {
    const s = this._state.get(ip);
    if (!s) return;
    if (s.halfOpen > 0) s.halfOpen -= 1;
    if (s.halfOpen === 0 && s.handshakes.length === 0) this._state.delete(ip);
  }

  halfOpenCount(ip) { return (this._state.get(ip) || { halfOpen: 0 }).halfOpen; }

  _stateFor(ip) {
    let s = this._state.get(ip);
    if (!s) { s = { handshakes: [], halfOpen: 0 }; this._state.set(ip, s); }
    return s;
  }
}

// ── PerPeer (post-handshake) ────────────────────────────────────────────────

class PerPeerLimiter {
  /**
   * @param {object} opts
   * @param {BanList} opts.banList
   * @param {Function} [opts.now=Date.now]
   */
  constructor({ banList, now = Date.now }) {
    if (!banList) throw new Error('banList required');
    this.banList = banList;
    this._now    = now;
    /** idHex → PeerState */
    this._peers  = new Map();
    /** ip → number[] (timestamps of hard quarantines, last 24h) */
    this._hardByIp = new Map();
  }

  _peerState(idHex) {
    let s = this._peers.get(idHex);
    if (!s) {
      s = {
        bucketFrames: new TokenBucket(C.PEER_FRAME_BURST,  C.PEER_FRAME_CAP),
        bucketBytes:  new TokenBucket(C.PEER_BYTE_BURST,   C.PEER_BYTE_CAP_PER_S),
        strikes: [],         // timestamps within STRIKE_WINDOW_MS
        softUntil: 0,
        hardUntil: 0,
      };
      this._peers.set(idHex, s);
    }
    return s;
  }

  /**
   * Charge a frame against the peer's buckets and check quarantine state.
   * Returns a verdict; caller drops the frame if !allow.
   *
   * @param {string} idHex
   * @param {number} frameSize
   * @param {string} ip
   * @returns {{allow:boolean, reason?:string, escalate?:string}}
   */
  charge(idHex, frameSize, ip) {
    const now = this._now();
    const s   = this._peerState(idHex);
    this._pruneStrikes(s, now);
    this._pruneHardHistory(ip, now);

    if (s.hardUntil > now) {
      return { allow: false, reason: 'hard-quarantine', escalate: 'hard' };
    }
    if (s.softUntil > now) {
      // Insistence accrues strikes (punitive escalation path).
      return this._strike(s, ip, now, 'soft-quarantine-insist');
    }

    if (!s.bucketFrames.take(1, now)) {
      return this._strike(s, ip, now, 'frame-rate-exceeded');
    }
    if (!s.bucketBytes.take(frameSize, now)) {
      return this._strike(s, ip, now, 'byte-rate-exceeded');
    }
    return { allow: true };
  }

  /** Force a strike for a non-rate violation (parse fail, sig fail, etc). */
  strike(idHex, ip, reason) {
    const now = this._now();
    const s   = this._peerState(idHex);
    this._pruneStrikes(s, now);
    this._pruneHardHistory(ip, now);
    return this._strike(s, ip, now, reason);
  }

  _strike(s, ip, now, reason) {
    s.strikes.push(now);
    const n = s.strikes.length;

    if (n >= C.STRIKE_HARD_THRESHOLD && s.hardUntil <= now) {
      s.hardUntil = now + C.HARD_QUARANTINE_MS;
      // Track per IP for persistent-ban escalation.
      if (ip) {
        let arr = this._hardByIp.get(ip);
        if (!arr) { arr = []; this._hardByIp.set(ip, arr); }
        arr.push(now);
        if (arr.length >= C.HARD_HISTORY_24H_LIMIT) {
          this.banList.add(ip, C.PERSISTENT_BAN_MS, `repeated-hard:${reason}`);
          return { allow: false, reason, escalate: 'ban' };
        }
        this.banList.add(ip, C.HARD_QUARANTINE_MS, `hard:${reason}`);
      }
      return { allow: false, reason, escalate: 'hard' };
    }

    if (n >= C.STRIKE_SOFT_THRESHOLD && s.softUntil <= now) {
      s.softUntil = now + C.SOFT_QUARANTINE_MS;
      return { allow: false, reason, escalate: 'soft' };
    }

    return { allow: false, reason };
  }

  _pruneStrikes(s, now) {
    const cutoff = now - C.STRIKE_WINDOW_MS;
    while (s.strikes.length && s.strikes[0] < cutoff) s.strikes.shift();
  }

  _pruneHardHistory(ip, now) {
    if (!ip) return;
    const arr = this._hardByIp.get(ip);
    if (!arr) return;
    const cutoff = now - 24 * 3600_000;
    while (arr.length && arr[0] < cutoff) arr.shift();
    if (arr.length === 0) this._hardByIp.delete(ip);
  }

  forget(idHex) { this._peers.delete(idHex); }
  forgetIp(ip)  { this._hardByIp.delete(ip); }

  snapshot(idHex) {
    const s = this._peers.get(idHex);
    if (!s) return null;
    return {
      strikes:    s.strikes.length,
      softUntil:  s.softUntil,
      hardUntil:  s.hardUntil,
      tokensFrames: Math.floor(s.bucketFrames.tokens),
      tokensBytes:  Math.floor(s.bucketBytes.tokens),
    };
  }
}

module.exports = { TokenBucket, BanList, PerIpRate, PerPeerLimiter };
