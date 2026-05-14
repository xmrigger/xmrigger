'use strict';
/**
 * Scenario 18 — BigInt edge cases in PREVHASH block_height + GUARD windowStart.
 *
 * SPEC §3.4.2 defines `block_height` as uint64 BE (0..2^64-1). SPEC §3.4.3
 * defines `window_start_ms` as uint64 BE. The serializers use
 * Buffer.writeBigUInt64BE which throws on values outside [0, 2^64-1].
 *
 * Edge cases tested:
 *   1. blockHeight = 0n  → serialize OK, parse round-trips to 0n.
 *   2. blockHeight = 2^64 - 1 (MAX_UINT64) → serialize OK, parse round-trips.
 *   3. blockHeight = -1 (negative number) → must throw (security: a
 *      negative coerced via BigInt() actually throws "RangeError: value
 *      must be >= 0n"; we verify the throw is reached and not swallowed).
 *   4. blockHeight = 2^64 (one past max) → must throw.
 *   5. EquivocationCache key with height 0n vs 0 (number) — both stringify
 *      to '0' so cache key collides. Verify this is intended.
 *   6. EquivocationCache key with height = MAX_UINT64 against MAX_UINT64-1
 *      (distinct keys, must NOT collide).
 */

const wire   = require('../../../src/federation/wire');
const eqMod  = require('../../../src/federation/equivocation');

function tryFn(fn) {
  try { return { ok: true, value: fn() }; } catch (e) { return { ok: false, error: e.message }; }
}

module.exports = {
  id: '18',
  name: 'BigInt edge cases: block_height = 0, MAX_UINT64, negative, overflow',
  spec: 'SPEC-FEDERATION-v1.md §3.4.2',
  attack_vector: 'numeric edge cases that may break serializer or equivocation key',
  expected_outcome: 'zero and max are accepted byte-exact; negative and overflow throw; cache keys do not collide',
  requires_impl: false,

  async run() {
    const ph = Buffer.alloc(32, 0xEE);
    const MAX_U64 = (1n << 64n) - 1n;

    // 1 & 2: round-trip
    const p0   = wire.serializePrevhashPayload({ poolId: 0n, prevhash: ph, blockHeight: 0n });
    const pMax = wire.serializePrevhashPayload({ poolId: 0n, prevhash: ph, blockHeight: MAX_U64 });
    const r0   = wire.parsePrevhashPayload(p0);
    const rMax = wire.parsePrevhashPayload(pMax);

    // 3: negative — Node throws RangeError
    const rNeg = tryFn(() => wire.serializePrevhashPayload({ poolId: 0n, prevhash: ph, blockHeight: -1 }));

    // 4: overflow
    const rOver = tryFn(() => wire.serializePrevhashPayload({ poolId: 0n, prevhash: ph, blockHeight: MAX_U64 + 1n }));

    // 5: cache key — 0n vs 0 (number)
    const cache = new eqMod.EquivocationCache();
    const id = Buffer.alloc(32, 0x33);
    const a = Buffer.alloc(32, 0x01);
    const b = Buffer.alloc(32, 0x02);
    cache.observe(id, 0n, a);
    const collisionResult = cache.observe(id, 0, b);    // 0 (number) toString === '0n' toString === '0'

    // 6: distinct max keys
    const cache2 = new eqMod.EquivocationCache();
    cache2.observe(id, MAX_U64,       a);
    const distinctMax = cache2.observe(id, MAX_U64 - 1n, b);

    return {
      zero_roundtrip:    r0 && r0.blockHeight === 0n,
      max_roundtrip:     rMax && rMax.blockHeight === MAX_U64,
      negative_throws:   rNeg.ok === false,
      overflow_throws:   rOver.ok === false,
      cache_key_0n_eq_0: collisionResult !== null,       // they SHOULD collide (height==height)
      cache_distinct_max_keys: distinctMax === null,     // distinct heights, no collision
    };
  },

  verify(result) {
    return result.zero_roundtrip === true &&
           result.max_roundtrip === true &&
           result.negative_throws === true &&
           result.overflow_throws === true &&
           result.cache_key_0n_eq_0 === true &&
           result.cache_distinct_max_keys === true;
  },
};
