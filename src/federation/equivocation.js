'use strict';
/**
 * equivocation.js — local equivocation cache.
 *
 * @license LGPL-2.1
 *
 * SPEC-FEDERATION-v1.md §5.4.
 *
 * Tracks (id_pub, block_height) → (prevhash, ts) for the EQUIVOCATION_WINDOW_MS
 * window. If a second PREVHASH frame arrives with the same key but a
 * different prevhash, the source has equivocated: bannable evidence.
 *
 * Bounded by EQUIVOCATION_CACHE_MAX entries. LRU eviction.
 *
 * D4: no evidence is forwarded. The detection produces a verdict consumed
 * locally by the caller (typically via banList.add for the source IP).
 */

const C = require('./consts');

class EquivocationCache {
  /**
   * @param {object} [opts]
   * @param {number} [opts.windowMs]
   * @param {number} [opts.maxEntries]
   * @param {Function} [opts.now]
   */
  constructor({ windowMs = C.EQUIVOCATION_WINDOW_MS,
                maxEntries = C.EQUIVOCATION_CACHE_MAX,
                now = Date.now } = {}) {
    this.windowMs   = windowMs;
    this.maxEntries = maxEntries;
    this._now       = now;
    /** key = idHex + ':' + heightStr → { prevhash:Buffer, ts:number } */
    this._cache = new Map();   // Map preserves insertion order → poor man's LRU
  }

  _key(idPubRaw, blockHeight) {
    return idPubRaw.toString('hex') + ':' + blockHeight.toString();
  }

  /**
   * Record a fresh observation. If a conflicting prevhash already exists
   * for the same (id_pub, height) within the window, returns evidence;
   * otherwise stores and returns null.
   *
   * @param {Buffer}  idPubRaw     32 B
   * @param {bigint|number} blockHeight
   * @param {Buffer}  prevhash     32 B
   * @returns {{ existing:Buffer, observed:Buffer, ts:number } | null}
   */
  observe(idPubRaw, blockHeight, prevhash) {
    const now = this._now();
    this._evictExpired(now);
    this._evictToBounds();

    const key  = this._key(idPubRaw, blockHeight);
    const prev = this._cache.get(key);

    if (prev && (now - prev.ts) < this.windowMs && !prev.prevhash.equals(prevhash)) {
      // Equivocation. Don't overwrite — keep the first observation as the
      // canonical "what the peer said first". Caller decides ban policy.
      return { existing: prev.prevhash, observed: prevhash, ts: prev.ts };
    }

    // Refresh insertion order so this entry is "most recent" in LRU sense
    this._cache.delete(key);
    this._cache.set(key, { prevhash: Buffer.from(prevhash), ts: now });
    return null;
  }

  _evictExpired(now) {
    const cutoff = now - this.windowMs;
    for (const [k, v] of this._cache) {
      if (v.ts < cutoff) this._cache.delete(k);
      else break;     // Map iteration is in insertion order; older first
    }
  }

  _evictToBounds() {
    while (this._cache.size > this.maxEntries) {
      const oldestKey = this._cache.keys().next().value;
      this._cache.delete(oldestKey);
    }
  }

  size()  { return this._cache.size; }
  clear() { this._cache.clear(); }
}

module.exports = { EquivocationCache };
