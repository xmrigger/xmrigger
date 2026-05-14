'use strict';
/**
 * Scenario 16 — AEAD AAD policy matches SPEC erratum E-AEAD-AAD.
 *
 * Original red-team finding: SPEC §3.6 D8 mandated "AAD = signed region
 * byte-exact" but the implementation passed AAD = empty. The asymmetry
 * was a real spec-vs-impl drift.
 *
 * Resolution (committed to SPEC §3.6 erratum E-AEAD-AAD on 2026-05-13):
 * AAD = empty is the canonical wire encoding. End-to-end integrity is
 * provided by the Ed25519 signature embedded in the plaintext, which is
 * what binds the full signed region. AEAD provides confidentiality and
 * per-hop authentication.
 *
 * This scenario verifies the post-fix posture: the implementation matches
 * the spec, both encode AAD = empty, and frame integrity is preserved
 * by the inner Ed25519 signature against on-path tampering.
 */

const cryptoFn = require('../../../src/federation/crypto');
const wire     = require('../../../src/federation/wire');
const ident    = require('../../../src/federation/identity');
const C        = require('../../../src/federation/consts');

module.exports = {
  id: '16',
  name: 'AEAD AAD policy and inner Ed25519 signature provide integrity (erratum applied)',
  spec: 'SPEC-FEDERATION-v1.md §3.6 erratum E-AEAD-AAD',
  attack_vector: 'spec/impl drift — verified resolved post-erratum',
  expected_outcome: 'AEAD AAD = empty, integrity from inner Ed25519; tampering rejected',
  requires_impl: false,

  async run() {
    const me  = new ident.Identity();
    const eph = cryptoFn.generateX25519();
    const pe2 = cryptoFn.generateX25519();
    const sk  = cryptoFn.deriveSessionKey(
      cryptoFn.x25519Diffie(eph.privateKey, pe2.publicKeyRaw)
    );

    // Build a valid signed frame.
    const plain = ident.buildHello(me, eph.publicKeyRaw, Buffer.alloc(32, 0xAB));
    const wireBytes = cryptoFn.aeadEncrypt(sk, plain);

    // (1) round-trip recovers original
    const recovered = cryptoFn.aeadDecrypt(sk, wireBytes);
    const rt_ok = recovered !== null && recovered.equals(plain);

    // (2) on-path mutation of ciphertext is rejected by AEAD tag
    const tampered = Buffer.from(wireBytes);
    tampered[60] ^= 1;
    const tamper_rejected = cryptoFn.aeadDecrypt(sk, tampered) === null;

    // (3) mutation of the Ed25519 signature inside the plaintext invalidates
    //     verifyFrame (defense-in-depth even if AEAD passes).
    const sk2     = cryptoFn.deriveSessionKey(cryptoFn.x25519Diffie(pe2.privateKey, eph.publicKeyRaw));
    const mutated = Buffer.from(plain);
    mutated[mutated.length - 1] ^= 1;     // last byte of signature
    const reWrap  = cryptoFn.aeadEncrypt(sk, mutated);
    const decoded = cryptoFn.aeadDecrypt(sk2, reWrap);
    const innerVerdict = decoded ? ident.verifyFrame(decoded, me.publicKeyRaw) : { ok: true };
    const inner_sig_rejected = !innerVerdict.ok;

    return {
      aead_arity_2:      cryptoFn.aeadEncrypt.length === 2 && cryptoFn.aeadDecrypt.length === 2,
      roundtrip_ok:      rt_ok,
      tamper_rejected,
      inner_sig_rejected,
    };
  },

  verify(result) {
    return result.aead_arity_2 === true &&
           result.roundtrip_ok === true &&
           result.tamper_rejected === true &&
           result.inner_sig_rejected === true;
  },
};
