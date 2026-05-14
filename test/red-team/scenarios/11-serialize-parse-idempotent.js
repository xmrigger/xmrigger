'use strict';
/**
 * Scenario 11 — serialize / parse idempotency property (library mode).
 *
 * Property:
 *   parse(wrap(serializeSignedRegion(s), sig)) reproduces s field-by-field
 *   for 200 random valid structs across the three types.
 *
 * Library mode: runs without the network.
 */

const crypto   = require('crypto');
const C        = require('../../../src/federation/consts');
const wire     = require('../../../src/federation/wire');
const cryptoFn = require('../../../src/federation/crypto');

function randomU64() {
  return BigInt('0x' + crypto.randomBytes(8).toString('hex'));
}

module.exports = {
  id: '11',
  name: 'serialize ∘ parse and parse ∘ serialize are identity (property, 200 cases)',
  spec: 'SPEC-FEDERATION-v1.md §3.1',
  attack_vector: 'E21 serialization malleability',
  expected_outcome: 'all 200 round-trips are byte-exact',
  requires_impl: false,

  async run() {
    const ed = cryptoFn.generateEd25519();
    let total = 0, ok = 0;

    for (let i = 0; i < 200; i++) {
      const type = (i % 3) === 0 ? C.TYPE_HELLO
                 : (i % 3) === 1 ? C.TYPE_PREVHASH
                                 : C.TYPE_GUARD;
      let payload;
      if (type === C.TYPE_HELLO) {
        payload = wire.serializeHelloPayload({
          ephPub:   crypto.randomBytes(32),
          prevhash: crypto.randomBytes(32),
          nonce:    crypto.randomBytes(16),
        });
      } else if (type === C.TYPE_PREVHASH) {
        payload = wire.serializePrevhashPayload({
          poolId:      randomU64(),
          prevhash:    crypto.randomBytes(32),
          blockHeight: randomU64(),
        });
      } else {
        payload = wire.serializeGuardPayload({
          ppm:           Math.floor(Math.random() * 1_000_001),
          observedPeers: Math.floor(Math.random() * 256),
          windowStart:   Number(randomU64() & 0x1FFFFFFFFFFFFFn),
        });
      }
      const signed = wire.serializeSignedRegion({
        type, timestamp: Date.now(), identity: ed.publicKeyRaw, payload,
      });
      const sig = cryptoFn.ed25519Sign(ed.privateKey, signed);
      const frame = wire.wrapSignature(signed, sig);

      const parsed = wire.parse(frame);
      if (!parsed) { total += 1; continue; }

      // Re-serialize from parsed → byte-exact
      const reSigned = wire.serializeSignedRegion({
        type:      parsed.type,
        timestamp: parsed.timestamp,
        identity:  Buffer.from(parsed.identity),
        payload:   Buffer.from(parsed.payload),
      });
      const reFrame = wire.wrapSignature(reSigned, Buffer.from(parsed.signature));
      total += 1;
      if (reFrame.equals(frame)) ok += 1;
    }
    return { total, ok };
  },

  verify(result) {
    return result.total === 200 && result.ok === 200;
  },
};
