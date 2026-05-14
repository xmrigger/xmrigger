'use strict';
/**
 * consts.js — hardcoded SPEC constants. Single source of truth.
 *
 * @license LGPL-2.1
 *
 * Every value defined here corresponds to a numeric in SPEC-FEDERATION-v1.md.
 * Per §5.7 the SPEC explicitly forbids env-tunable security parameters: the
 * sole allowed env var is TNZX_FEDERATION_BOOTSTRAP, which controls only the
 * cold-start HELLO acceptance window and is implemented in identity.js.
 *
 * Anyone changing a value here is changing the protocol. Bump PROTO_V if
 * the change affects wire compatibility.
 */

module.exports = Object.freeze({
  // Protocol identity (§3.2)
  PROTO_V:                   2,

  // Frame layout (§3.1)
  FRAME_LEN:               192,
  HEADER_LEN:               16,
  IDENTITY_LEN:             32,
  PAYLOAD_LEN:              80,
  SIGNATURE_LEN:            64,
  SIGNED_REGION_LEN:       128,    // header + identity + payload

  // Frame types (§3.4)
  TYPE_HELLO:                1,
  TYPE_PREVHASH:             2,
  TYPE_GUARD:                3,

  // HELLO payload offsets (§3.4.1)
  HELLO_OFF_EPH_PUB:         0,
  HELLO_OFF_PREVHASH:       32,
  HELLO_OFF_NONCE:          64,
  HELLO_NONCE_LEN:          16,

  // PREVHASH payload offsets (§3.4.2)
  PREVHASH_OFF_POOL_ID:      0,
  PREVHASH_OFF_PREVHASH:     8,
  PREVHASH_OFF_HEIGHT:      40,
  PREVHASH_OFF_RESERVED:    48,
  PREVHASH_RESERVED_LEN:    32,

  // GUARD payload offsets (§3.4.3)
  GUARD_OFF_PPM:             0,
  GUARD_OFF_OBSERVED_PEERS:  4,
  GUARD_OFF_WINDOW_START:    5,
  GUARD_OFF_RESERVED:       13,
  GUARD_RESERVED_LEN:       67,

  // Time windows (§3.2, §4.3)
  TS_SKEW_TOLERANCE_MS:    300_000,    // ±5 min
  PEER_FRESH_MS:            30_000,    // peer ts in fresh-list for HELLO mining-bound check (§4.3)

  // AEAD (§3.6)
  AEAD_NONCE_LEN:           12,
  AEAD_TAG_LEN:             16,
  WIRE_FRAME_LEN:          220,        // 12 + 192 + 16
  WS_MAX_PAYLOAD:          256,        // §5.5
  HKDF_INFO:               'xmrigger-federation-v1',

  // Per-peer rate limits (§5.1)
  PEER_FRAME_CAP:            5,
  PEER_FRAME_BURST:         20,
  PEER_BYTE_CAP_PER_S:    5_120,       // 5 KB/s sustained
  PEER_BYTE_BURST:        20_480,      // 20 KB burst

  // Per-IP rate limits (§5.2 / D6+D7)
  IP_HANDSHAKE_RATE:         3,
  IP_HANDSHAKE_WINDOW_MS: 60_000,
  IP_HALF_OPEN_CAP:          5,
  HANDSHAKE_TIMEOUT_MS:  10_000,

  // Strike escalation (§5.3)
  STRIKE_WINDOW_MS:      60_000,
  STRIKE_SOFT_THRESHOLD:     3,
  STRIKE_HARD_THRESHOLD:     6,
  SOFT_QUARANTINE_MS:   300_000,       // 5 min
  HARD_QUARANTINE_MS: 3_600_000,       // 1 h
  HARD_HISTORY_24H_LIMIT:    3,
  PERSISTENT_BAN_MS: 30 * 24 * 3600_000,

  // Equivocation (§5.4)
  EQUIVOCATION_WINDOW_MS: 60_000,
  EQUIVOCATION_CACHE_MAX: 10_000,

  // Memory caps (§5.5)
  MAX_PEER_SESSIONS:      1000,
  BAN_LIST_MAX:         10_000,
  SEEN_NONCE_PER_PEER:    1024,
  HALF_OPEN_STATE_BYTES:  1024,
});
