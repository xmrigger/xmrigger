'use strict';
/**
 * wire.js — serialize / parse for the federation transport.
 *
 * @license LGPL-2.1
 *
 * One canonical encoding per logical frame, fixed 192 bytes, no library
 * involvement (no JSON, no CBOR, no protobuf). Only Buffer slice + uint
 * read primitives. See SPEC-FEDERATION-v1.md §3.
 *
 * Public surface (pure functions, no I/O, no time):
 *
 *   serializeHelloPayload({ ephPub, prevhash, nonce })            → 80 B
 *   serializePrevhashPayload({ poolId, prevhash, blockHeight })   → 80 B
 *   serializeGuardPayload({ ppm, observedPeers, windowStart })    → 80 B
 *
 *   serializeFrame({ type, timestamp, identity, payload })        → 128 B (signed region)
 *   wrapSignature(signedRegion, signature)                        → 192 B (full frame)
 *
 *   parse(canonical192)
 *     → { type, timestamp, identity, payload, signature }   on success
 *     → null                                                  on any invariant violation
 *
 *   parseHelloPayload(payload80)      → { ephPub, prevhash, nonce } | null
 *   parsePrevhashPayload(payload80)   → { poolId, prevhash, blockHeight } | null
 *   parseGuardPayload(payload80)      → { ppm, observedPeers, windowStart } | null
 *
 * Idempotency invariant (proven in test/federation-unit.js):
 *
 *   parse(serializeFrame(...) ‖ signature) === { ... } whose components
 *   re-serialize byte-exact to the input.
 *
 * Schema-confusion is impossible by construction: parse() has exactly
 * three branches keyed on the type byte at offset 1, each with a fixed
 * payload layout. There is no extension range. There is no length prefix.
 */

const C = require('./consts');

// ── Helpers ─────────────────────────────────────────────────────────────────

function _check(cond, _why) {
  // Returning null on failure is the SPEC convention. We never throw on
  // bad input — that gives the attacker a differential signal.
  return cond;
}

function _checkPayloadLen(buf) { return Buffer.isBuffer(buf) && buf.length === C.PAYLOAD_LEN; }

// ── Header serialization ────────────────────────────────────────────────────

/**
 * Build the 16-byte header. Reserved bytes are set to zero by Buffer.alloc.
 * Caller MUST pass a valid type and a numeric timestamp.
 */
function _serializeHeader(type, timestamp) {
  const h = Buffer.alloc(C.HEADER_LEN);     // already zero-filled
  h[0] = C.PROTO_V & 0xFF;
  h[1] = type & 0xFF;
  h.writeBigUInt64BE(BigInt(timestamp), 2);
  // bytes 10..15 reserved zero
  return h;
}

// ── Payload serializers (per type) ──────────────────────────────────────────

function serializeHelloPayload({ ephPub, prevhash, nonce }) {
  if (!Buffer.isBuffer(ephPub)   || ephPub.length   !== 32) throw new Error('ephPub must be 32 B');
  if (!Buffer.isBuffer(prevhash) || prevhash.length !== 32) throw new Error('prevhash must be 32 B');
  if (!Buffer.isBuffer(nonce)    || nonce.length    !== 16) throw new Error('nonce must be 16 B');
  const p = Buffer.alloc(C.PAYLOAD_LEN);
  ephPub.copy(p,   C.HELLO_OFF_EPH_PUB);
  prevhash.copy(p, C.HELLO_OFF_PREVHASH);
  nonce.copy(p,    C.HELLO_OFF_NONCE);
  return p;
}

function serializePrevhashPayload({ poolId, prevhash, blockHeight }) {
  if (typeof poolId      !== 'bigint' && typeof poolId      !== 'number') {
    throw new Error('poolId must be number or bigint (uint64 BE)');
  }
  if (!Buffer.isBuffer(prevhash) || prevhash.length !== 32) throw new Error('prevhash must be 32 B');
  if (typeof blockHeight !== 'bigint' && typeof blockHeight !== 'number') {
    throw new Error('blockHeight must be number or bigint (uint64 BE)');
  }
  const p = Buffer.alloc(C.PAYLOAD_LEN);
  p.writeBigUInt64BE(BigInt(poolId),      C.PREVHASH_OFF_POOL_ID);
  prevhash.copy(p,                         C.PREVHASH_OFF_PREVHASH);
  p.writeBigUInt64BE(BigInt(blockHeight), C.PREVHASH_OFF_HEIGHT);
  // reserved bytes 48..79 zero (Buffer.alloc)
  return p;
}

function serializeGuardPayload({ ppm, observedPeers, windowStart }) {
  if (!Number.isInteger(ppm) || ppm < 0 || ppm > 1_000_000) {
    throw new Error('ppm must be integer 0..1_000_000');
  }
  if (!Number.isInteger(observedPeers) || observedPeers < 0 || observedPeers > 255) {
    throw new Error('observedPeers must be uint8');
  }
  if (typeof windowStart !== 'bigint' && typeof windowStart !== 'number') {
    throw new Error('windowStart must be number or bigint (uint64 BE)');
  }
  const p = Buffer.alloc(C.PAYLOAD_LEN);
  p.writeUInt32BE(ppm, C.GUARD_OFF_PPM);
  p[C.GUARD_OFF_OBSERVED_PEERS] = observedPeers;
  p.writeBigUInt64BE(BigInt(windowStart), C.GUARD_OFF_WINDOW_START);
  // reserved bytes 13..79 zero
  return p;
}

// ── Frame assembly ──────────────────────────────────────────────────────────

/**
 * Assemble the SIGNED REGION (header ‖ identity ‖ payload), 128 bytes.
 * Caller signs this with Ed25519 and then calls wrapSignature().
 */
function serializeSignedRegion({ type, timestamp, identity, payload }) {
  if (![C.TYPE_HELLO, C.TYPE_PREVHASH, C.TYPE_GUARD].includes(type)) {
    throw new Error(`type must be 1, 2, or 3; got ${type}`);
  }
  if (!Buffer.isBuffer(identity) || identity.length !== C.IDENTITY_LEN) {
    throw new Error('identity must be 32 B');
  }
  if (!_checkPayloadLen(payload)) throw new Error('payload must be 80 B');

  const buf = Buffer.alloc(C.SIGNED_REGION_LEN);
  _serializeHeader(type, timestamp).copy(buf, 0);
  identity.copy(buf, C.HEADER_LEN);
  payload.copy(buf,  C.HEADER_LEN + C.IDENTITY_LEN);
  return buf;
}

/**
 * Concatenate the signed region with its 64-byte signature → 192 B canonical frame.
 */
function wrapSignature(signedRegion, signature) {
  if (!Buffer.isBuffer(signedRegion) || signedRegion.length !== C.SIGNED_REGION_LEN) {
    throw new Error('signedRegion must be 128 B');
  }
  if (!Buffer.isBuffer(signature) || signature.length !== C.SIGNATURE_LEN) {
    throw new Error('signature must be 64 B');
  }
  return Buffer.concat([signedRegion, signature], C.FRAME_LEN);
}

// ── Parse — single entry point, three type branches ─────────────────────────

/**
 * Parse a canonical 192-byte frame into its components, applying every
 * structural invariant from SPEC §3. Returns null on any violation; never
 * throws (no diagnostic feedback to upstream callers).
 *
 * The returned `payload` is a slice of the input — caller MUST NOT mutate.
 *
 * @param {Buffer} buf
 * @returns {{type: number, timestamp: number, identity: Buffer, payload: Buffer, signature: Buffer} | null}
 */
function parse(buf) {
  if (!_check(Buffer.isBuffer(buf) && buf.length === C.FRAME_LEN, 'frame-len')) return null;

  // proto_v
  if (!_check(buf[0] === C.PROTO_V, 'proto-v')) return null;

  // type ∈ {1,2,3}
  const type = buf[1];
  if (!_check(type === C.TYPE_HELLO || type === C.TYPE_PREVHASH || type === C.TYPE_GUARD, 'type')) {
    return null;
  }

  // header reserved zero (offsets 10..15)
  for (let k = 10; k < 16; k++) if (!_check(buf[k] === 0, 'header-reserved')) return null;

  // timestamp: range check is the caller's job (it depends on now())
  // Here we just decode — the decoded value is trustworthy because the
  // signature covers it.
  const timestamp = Number(buf.readBigUInt64BE(2));

  // payload-type-specific reserved-zero invariants
  if (type === C.TYPE_PREVHASH) {
    for (let k = 0; k < C.PREVHASH_RESERVED_LEN; k++) {
      if (!_check(buf[C.HEADER_LEN + C.IDENTITY_LEN + C.PREVHASH_OFF_RESERVED + k] === 0, 'prev-reserved')) {
        return null;
      }
    }
  } else if (type === C.TYPE_GUARD) {
    for (let k = 0; k < C.GUARD_RESERVED_LEN; k++) {
      if (!_check(buf[C.HEADER_LEN + C.IDENTITY_LEN + C.GUARD_OFF_RESERVED + k] === 0, 'guard-reserved')) {
        return null;
      }
    }
  }

  return {
    type,
    timestamp,
    identity:  buf.subarray(C.HEADER_LEN, C.HEADER_LEN + C.IDENTITY_LEN),
    payload:   buf.subarray(C.HEADER_LEN + C.IDENTITY_LEN, C.SIGNED_REGION_LEN),
    signature: buf.subarray(C.SIGNED_REGION_LEN, C.FRAME_LEN),
  };
}

// ── Payload parsers ─────────────────────────────────────────────────────────

function parseHelloPayload(p) {
  if (!_checkPayloadLen(p)) return null;
  return {
    ephPub:   p.subarray(C.HELLO_OFF_EPH_PUB,   C.HELLO_OFF_EPH_PUB + 32),
    prevhash: p.subarray(C.HELLO_OFF_PREVHASH,  C.HELLO_OFF_PREVHASH + 32),
    nonce:    p.subarray(C.HELLO_OFF_NONCE,     C.HELLO_OFF_NONCE + C.HELLO_NONCE_LEN),
  };
}

function parsePrevhashPayload(p) {
  if (!_checkPayloadLen(p)) return null;
  return {
    poolId:      p.readBigUInt64BE(C.PREVHASH_OFF_POOL_ID),
    prevhash:    p.subarray(C.PREVHASH_OFF_PREVHASH, C.PREVHASH_OFF_PREVHASH + 32),
    blockHeight: p.readBigUInt64BE(C.PREVHASH_OFF_HEIGHT),
  };
}

function parseGuardPayload(p) {
  if (!_checkPayloadLen(p)) return null;
  return {
    ppm:           p.readUInt32BE(C.GUARD_OFF_PPM),
    observedPeers: p[C.GUARD_OFF_OBSERVED_PEERS],
    windowStart:   p.readBigUInt64BE(C.GUARD_OFF_WINDOW_START),
  };
}

module.exports = {
  serializeHelloPayload,
  serializePrevhashPayload,
  serializeGuardPayload,
  serializeSignedRegion,
  wrapSignature,
  parse,
  parseHelloPayload,
  parsePrevhashPayload,
  parseGuardPayload,
};
