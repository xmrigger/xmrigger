'use strict';
/**
 * Scenario 10 — byte-mutation property test (library mode).
 *
 * Build one valid signed frame, then for each byte position 0..127 in
 * the signed region, flip the high bit and verify the signature. Every
 * mutation MUST cause verification to fail.
 *
 * This is a property test on the federation modules directly. It does
 * not need the network, so it always runs (no requires_impl gate).
 */

const C        = require('../../../src/federation/consts');
const wire     = require('../../../src/federation/wire');
const cryptoFn = require('../../../src/federation/crypto');

module.exports = {
  id: '10',
  name: 'byte mutation in signed region invalidates frame (property)',
  spec: 'SPEC-FEDERATION-v1.md §3.5',
  attack_vector: 'E22 sign/verify mutation tolerance',
  expected_outcome: 'all 128 single-byte mutations rejected by signature verify',
  requires_impl: false,

  async run() {
    const ed = cryptoFn.generateEd25519();
    const x  = cryptoFn.generateX25519();
    const helloP = wire.serializeHelloPayload({
      ephPub:   x.publicKeyRaw,
      prevhash: Buffer.alloc(32, 0xAB),
      nonce:    Buffer.alloc(16, 0xCD),
    });
    const signed = wire.serializeSignedRegion({
      type:      C.TYPE_HELLO,
      timestamp: Date.now(),
      identity:  ed.publicKeyRaw,
      payload:   helloP,
    });
    const sig = cryptoFn.ed25519Sign(ed.privateKey, signed);

    let totalRejections = 0;
    for (let i = 0; i < C.SIGNED_REGION_LEN; i++) {
      const tampered = Buffer.from(signed);
      tampered[i] = tampered[i] ^ 0x80;
      const ok = cryptoFn.ed25519Verify(ed.publicKeyRaw, tampered, sig);
      if (!ok) totalRejections += 1;
    }
    return { totalRejections, expectedRejections: C.SIGNED_REGION_LEN };
  },

  verify(result) {
    return result.totalRejections === result.expectedRejections;
  },
};
