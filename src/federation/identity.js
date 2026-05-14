'use strict';
/**
 * identity.js — ephemeral identity + mining-bound HELLO.
 *
 * @license LGPL-2.1
 *
 * SPEC-FEDERATION-v1.md §4.
 *
 *   - One Ed25519 keypair per process (not per peer connection). Generated
 *     at start, discarded at exit. No persistence on disk.
 *   - HELLO carries an X25519 ephemeral pubkey for this session, the
 *     prevhash the sender most recently observed from its upstream pool,
 *     and an anti-replay nonce.
 *   - HELLO is mining-bound: receiver validates that the prevhash is one
 *     it can reconcile with the chain it sees (own prevhash, or any fresh
 *     peer prevhash within PEER_FRESH_MS).
 *   - During TNZX_FEDERATION_BOOTSTRAP=1, the chain reconciliation step
 *     is bypassed (cold-start of the network). Other checks remain.
 */

const C       = require('./consts');
const crypto  = require('./crypto');
const wire    = require('./wire');

class Identity {
  constructor() {
    const ed = crypto.generateEd25519();
    this.privateKey   = ed.privateKey;
    this.publicKeyRaw = ed.publicKeyRaw;     // 32 B raw, used as `identity` in frames
    this.idHex        = this.publicKeyRaw.toString('hex');
  }
}

/**
 * Build a 192-byte HELLO frame ready to be AEAD-wrapped.
 *
 * @param {Identity} myIdentity
 * @param {Buffer}   ephPubX25519     32 B X25519 raw public key for this session
 * @param {Buffer}   recentPrevhash   32 B Monero prevhash recently seen by my pool
 * @param {number}   [timestampMs]    defaults to Date.now()
 * @returns {Buffer} 192 B canonical frame
 */
function buildHello(myIdentity, ephPubX25519, recentPrevhash, timestampMs = Date.now()) {
  const nonce = require('crypto').randomBytes(C.HELLO_NONCE_LEN);
  const payload = wire.serializeHelloPayload({
    ephPub:   ephPubX25519,
    prevhash: recentPrevhash,
    nonce,
  });
  const signedRegion = wire.serializeSignedRegion({
    type:      C.TYPE_HELLO,
    timestamp: timestampMs,
    identity:  myIdentity.publicKeyRaw,
    payload,
  });
  const sig = crypto.ed25519Sign(myIdentity.privateKey, signedRegion);
  return wire.wrapSignature(signedRegion, sig);
}

/**
 * Validate a HELLO frame received from a peer.
 *
 * Checks (in order, fail-fast, no diagnostic feedback):
 *   1. Wire parse passes (type=1, fixed size, reserved zero, etc.).
 *   2. timestamp within ±TS_SKEW_TOLERANCE_MS of `now`.
 *   3. Ed25519 signature verifies against identity.
 *   4. recentPrevhash is consistent with one of:
 *        - own current prevhash,
 *        - any fresh peer's announced prevhash (ts within PEER_FRESH_MS),
 *        - or unconditionally accepted if BOOTSTRAP env var is "1".
 *
 * @param {Buffer}   frame              192 B canonical frame
 * @param {object}   chainView          accessors to local chain knowledge
 * @param {Function} chainView.ownPrevhash    () => Buffer|null
 * @param {Function} chainView.freshPeerPrevhashes  () => Buffer[]   (32 B each)
 * @param {number}   nowMs              current time
 * @param {object}   [opts]
 * @param {boolean}  [opts.bootstrap]   override env-driven flag for tests
 * @returns {{ok:true, ephPub:Buffer, identity:Buffer, timestamp:number, nonce:Buffer} | {ok:false, reason:string}}
 */
function validateHello(frame, chainView, nowMs = Date.now(), opts = {}) {
  const parsed = wire.parse(frame);
  if (!parsed)                              return { ok: false, reason: 'wire' };
  if (parsed.type !== C.TYPE_HELLO)         return { ok: false, reason: 'type' };
  if (Math.abs(nowMs - parsed.timestamp) > C.TS_SKEW_TOLERANCE_MS) {
    return { ok: false, reason: 'ts-skew' };
  }
  // Reconstruct signed region byte-exact for verification.
  const signedRegion = frame.subarray(0, C.SIGNED_REGION_LEN);
  if (!crypto.ed25519Verify(parsed.identity, signedRegion, parsed.signature)) {
    return { ok: false, reason: 'sig' };
  }

  const helloP = wire.parseHelloPayload(parsed.payload);
  if (!helloP) return { ok: false, reason: 'payload' };

  // Mining-bound check (§4.3 step 3)
  const bootstrap = (opts.bootstrap === true) || (process.env.TNZX_FEDERATION_BOOTSTRAP === '1');
  if (!bootstrap) {
    let reconciled = false;
    const own = chainView.ownPrevhash && chainView.ownPrevhash();
    if (own && Buffer.isBuffer(own) && own.equals(helloP.prevhash)) reconciled = true;
    if (!reconciled) {
      const fresh = (chainView.freshPeerPrevhashes && chainView.freshPeerPrevhashes()) || [];
      for (const ph of fresh) {
        if (Buffer.isBuffer(ph) && ph.equals(helloP.prevhash)) { reconciled = true; break; }
      }
    }
    if (!reconciled) return { ok: false, reason: 'mining-bound' };
  }

  return {
    ok:        true,
    ephPub:    Buffer.from(helloP.ephPub),       // copy out of subarray view
    identity:  Buffer.from(parsed.identity),
    timestamp: parsed.timestamp,
    nonce:     Buffer.from(helloP.nonce),
  };
}

/**
 * Build a 192-byte PREVHASH frame.
 */
function buildPrevhash(myIdentity, poolId, prevhash, blockHeight, timestampMs = Date.now()) {
  const payload = wire.serializePrevhashPayload({ poolId, prevhash, blockHeight });
  const signedRegion = wire.serializeSignedRegion({
    type:      C.TYPE_PREVHASH,
    timestamp: timestampMs,
    identity:  myIdentity.publicKeyRaw,
    payload,
  });
  const sig = crypto.ed25519Sign(myIdentity.privateKey, signedRegion);
  return wire.wrapSignature(signedRegion, sig);
}

/**
 * Build a 192-byte GUARD frame.
 */
function buildGuard(myIdentity, ppm, observedPeers, windowStartMs, timestampMs = Date.now()) {
  const payload = wire.serializeGuardPayload({ ppm, observedPeers, windowStart: windowStartMs });
  const signedRegion = wire.serializeSignedRegion({
    type:      C.TYPE_GUARD,
    timestamp: timestampMs,
    identity:  myIdentity.publicKeyRaw,
    payload,
  });
  const sig = crypto.ed25519Sign(myIdentity.privateKey, signedRegion);
  return wire.wrapSignature(signedRegion, sig);
}

/**
 * Verify a non-HELLO (PREVHASH or GUARD) frame received from a peer.
 * Caller already established the session; this checks the frame.
 *
 * @returns {{ok:true, parsed:object} | {ok:false, reason:string}}
 */
function verifyFrame(frame, expectedIdentityRaw, nowMs = Date.now()) {
  const parsed = wire.parse(frame);
  if (!parsed) return { ok: false, reason: 'wire' };
  if (parsed.type === C.TYPE_HELLO) return { ok: false, reason: 'unexpected-hello' };
  if (Math.abs(nowMs - parsed.timestamp) > C.TS_SKEW_TOLERANCE_MS) {
    return { ok: false, reason: 'ts-skew' };
  }
  if (expectedIdentityRaw && !parsed.identity.equals(expectedIdentityRaw)) {
    return { ok: false, reason: 'identity-mismatch' };
  }
  const signedRegion = frame.subarray(0, C.SIGNED_REGION_LEN);
  if (!crypto.ed25519Verify(parsed.identity, signedRegion, parsed.signature)) {
    return { ok: false, reason: 'sig' };
  }
  return { ok: true, parsed };
}

module.exports = {
  Identity,
  buildHello,
  validateHello,
  buildPrevhash,
  buildGuard,
  verifyFrame,
};
