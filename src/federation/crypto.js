'use strict';
/**
 * crypto.js — federation cryptographic primitives.
 *
 * @license LGPL-2.1
 *
 * All primitives via Node built-in `crypto`. No external library.
 *
 * Identity:    Ed25519 (RFC 8032), strict.
 * Key exchange: X25519 ephemeral per session.
 * KDF:         HKDF-SHA256.
 * AEAD:        ChaCha20-Poly1305 (12 B nonce, 16 B tag).
 * Hash:        SHA-256 used for pool_id derivation.
 *
 * SPEC-FEDERATION-v1.md §3.5, §3.6.
 */

const crypto = require('crypto');
const C = require('./consts');

// ── Ed25519 identity ────────────────────────────────────────────────────────

/**
 * Generate a fresh Ed25519 keypair.
 * @returns {{ privateKey: KeyObject, publicKeyRaw: Buffer }}
 */
function generateEd25519() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKeyRaw: ed25519PublicKeyRaw(publicKey) };
}

/** Extract the raw 32-byte Ed25519 pubkey from a KeyObject (DER-wrapped). */
function ed25519PublicKeyRaw(keyObject) {
  // Node always exposes Ed25519 SPKI DER. Last 32 bytes are the raw key.
  const der = keyObject.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 32);
}

/** Build a public KeyObject from a raw 32-byte Ed25519 pubkey. */
function ed25519PublicKeyFromRaw(raw32) {
  if (!Buffer.isBuffer(raw32) || raw32.length !== 32) {
    throw new Error('raw32 must be 32 bytes');
  }
  // Standard SPKI DER prefix for Ed25519: 12-byte AlgorithmIdentifier + BIT STRING header.
  const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
  return crypto.createPublicKey({
    key:    Buffer.concat([SPKI_PREFIX, raw32]),
    format: 'der',
    type:   'spki',
  });
}

/** Sign 128-byte signed region with Ed25519. Returns 64-byte signature. */
function ed25519Sign(privateKey, signedRegion) {
  return crypto.sign(null, signedRegion, privateKey);
}

/** Verify Ed25519 signature against raw 32-byte pubkey. Returns true/false. */
function ed25519Verify(rawPubkey, signedRegion, signature) {
  if (!Buffer.isBuffer(rawPubkey) || rawPubkey.length !== 32)  return false;
  if (!Buffer.isBuffer(signedRegion) || signedRegion.length !== C.SIGNED_REGION_LEN) return false;
  if (!Buffer.isBuffer(signature)    || signature.length    !== C.SIGNATURE_LEN)     return false;
  let pub;
  try { pub = ed25519PublicKeyFromRaw(rawPubkey); } catch { return false; }
  try { return crypto.verify(null, signedRegion, pub, signature); } catch { return false; }
}

// ── X25519 ECDH ─────────────────────────────────────────────────────────────

/**
 * Generate an ephemeral X25519 keypair.
 * @returns {{ privateKey: KeyObject, publicKeyRaw: Buffer }}
 */
function generateX25519() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  return { privateKey, publicKeyRaw: x25519PublicKeyRaw(publicKey) };
}

function x25519PublicKeyRaw(keyObject) {
  const der = keyObject.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 32);
}

function x25519PublicKeyFromRaw(raw32) {
  if (!Buffer.isBuffer(raw32) || raw32.length !== 32) {
    throw new Error('raw32 must be 32 bytes');
  }
  const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
  return crypto.createPublicKey({
    key:    Buffer.concat([SPKI_PREFIX, raw32]),
    format: 'der',
    type:   'spki',
  });
}

/** Compute X25519 shared secret. */
function x25519Diffie(myPrivKey, peerRawPub) {
  const peerPub = x25519PublicKeyFromRaw(peerRawPub);
  return crypto.diffieHellman({ privateKey: myPrivKey, publicKey: peerPub });
}

// ── HKDF-SHA256 ─────────────────────────────────────────────────────────────

/**
 * Derive a 32-byte session key from an X25519 shared secret. Info string
 * is hardcoded per SPEC §3.6 to bind keys to this protocol version.
 */
function deriveSessionKey(sharedSecret) {
  // crypto.hkdfSync returns ArrayBuffer in some Node versions; normalise.
  const out = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0),
                              Buffer.from(C.HKDF_INFO, 'utf8'), 32);
  return Buffer.from(out);
}

// ── AEAD ChaCha20-Poly1305 ──────────────────────────────────────────────────

/**
 * Encrypt a 192-byte canonical frame.
 *   ad    = first 128 bytes of the canonical frame (signed region)
 *   nonce = 12 random bytes
 * Returns wire bytes: nonce ‖ ciphertext ‖ tag (220 bytes).
 */
function aeadEncrypt(sessionKey, canonical192) {
  if (canonical192.length !== C.FRAME_LEN) {
    throw new Error(`canonical192 must be ${C.FRAME_LEN} B`);
  }
  const nonce = crypto.randomBytes(C.AEAD_NONCE_LEN);
  const cipher = crypto.createCipheriv('chacha20-poly1305', sessionKey, nonce, {
    authTagLength: C.AEAD_TAG_LEN,
  });
  // AAD = empty. The signed region inside the plaintext is end-to-end
  // authenticated by the Ed25519 signature (last 64 bytes of plaintext).
  // AEAD here provides confidentiality + on-path integrity for the hop.
  // SPEC §3.6 to be amended (erratum E-AEAD-AAD): the original "AAD =
  // signed region byte-exact" wording requires AAD known to receiver
  // before decryption, which is impossible since AAD = plaintext prefix.
  const ct  = Buffer.concat([cipher.update(canonical192), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag], C.WIRE_FRAME_LEN);
}

/**
 * Decrypt a 220-byte wire frame. AAD is the first 128 bytes of the
 * recovered plaintext (signed region) — but we need the plaintext to
 * derive the AAD, which is impossible without first running decrypt.
 *
 * Resolution: the AAD is structurally tied to the FRAME, not separately
 * carried on the wire. We compute the AAD AFTER decryption and verify
 * the tag matches by re-running the AEAD with the recovered AAD. The
 * detail: ChaCha20-Poly1305 tag is computed over (AAD || ciphertext),
 * so we cannot retroactively check AAD. Therefore we MUST commit to AAD
 * at decryption time.
 *
 * The trick: we know the AAD is "the first 128 bytes of the plaintext",
 * but the plaintext is what we're trying to recover. The pattern is to
 * make AAD = the first 128 bytes of the CIPHERTEXT instead — they are
 * unrelated under a stream cipher (XOR'd with keystream). NO — that
 * doesn't bind the right thing either.
 *
 * Correct pattern, used here: the SENDER computes ad = signed_region of
 * the plaintext (known to them). The RECEIVER must somehow know the AAD
 * to decrypt. We carry AAD on the wire OUTSIDE the ciphertext but inside
 * the AEAD computation by... no. AEAD with authenticated data needs the
 * receiver to supply the AAD at decryption time, ad-supplied = ad-computed
 * by sender. Since AAD for us IS the first 128 bytes of plaintext, the
 * receiver does not know it before decrypting.
 *
 * Workaround that preserves SPEC intent without redundancy: skip AEAD AAD
 * here entirely. The signature inside the plaintext (last 64 bytes)
 * already authenticates the first 128 bytes. AEAD authenticity protects
 * the channel against on-path mutation; the Ed25519 signature inside
 * provides end-to-end authentication. AAD = empty.
 *
 * SPEC §3.6 currently states "ad = signed region byte-exact". We implement
 * that by passing AAD = empty bytes to AEAD, and noting in the SPEC that
 * the signature inside the plaintext is the binding integrity check. This
 * deviation is recorded as a SPEC erratum to fix.
 */
function aeadDecrypt(sessionKey, wireBytes) {
  if (!Buffer.isBuffer(wireBytes) || wireBytes.length !== C.WIRE_FRAME_LEN) return null;
  const nonce = wireBytes.subarray(0, C.AEAD_NONCE_LEN);
  const ct    = wireBytes.subarray(C.AEAD_NONCE_LEN, C.AEAD_NONCE_LEN + C.FRAME_LEN);
  const tag   = wireBytes.subarray(C.AEAD_NONCE_LEN + C.FRAME_LEN);
  try {
    const decipher = crypto.createDecipheriv('chacha20-poly1305', sessionKey, nonce, {
      authTagLength: C.AEAD_TAG_LEN,
    });
    decipher.setAuthTag(tag);
    // AAD = empty. Frame integrity beyond AEAD comes from the Ed25519
    // signature embedded in the last 64 bytes of the plaintext, which
    // signs the first 128 bytes (the signed region).
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt;
  } catch {
    return null;
  }
}

// ── Misc helpers ────────────────────────────────────────────────────────────

/**
 * Derive a stable 8-byte pool_id from a pool endpoint string.
 * SHA-256 truncated. Used in PREVHASH frame (§3.4.2).
 */
function poolIdFromEndpoint(endpoint) {
  const h = crypto.createHash('sha256').update(endpoint, 'utf8').digest();
  return h.readBigUInt64BE(0);
}

module.exports = {
  generateEd25519,
  ed25519PublicKeyRaw,
  ed25519PublicKeyFromRaw,
  ed25519Sign,
  ed25519Verify,
  generateX25519,
  x25519PublicKeyRaw,
  x25519PublicKeyFromRaw,
  x25519Diffie,
  deriveSessionKey,
  aeadEncrypt,
  aeadDecrypt,
  poolIdFromEndpoint,
};
