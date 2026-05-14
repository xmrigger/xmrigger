'use strict';
/**
 * federation-unit.js — unit tests for src/federation/ modules.
 *
 * @license LGPL-2.1
 *
 * Each module is exercised in isolation. The end-to-end behaviour is in
 * federation-e2e.js. Red-team adversarial scenarios live in test/red-team/.
 *
 * Run:    node test/federation-unit.js
 * Quick:  npm run test:federation
 */

const { test, describe } = require('node:test');
const assert             = require('node:assert/strict');
const crypto             = require('crypto');

const C        = require('../src/federation/consts');
const wire     = require('../src/federation/wire');
const cryptoFn = require('../src/federation/crypto');
const ident    = require('../src/federation/identity');
const eqMod    = require('../src/federation/equivocation');
const lim      = require('../src/federation/limits');

// ── consts: invariants on the SPEC numbers ─────────────────────────────────

describe('consts — SPEC numbers wired correctly', () => {
  test('frame layout sums to 192', () => {
    assert.strictEqual(
      C.HEADER_LEN + C.IDENTITY_LEN + C.PAYLOAD_LEN + C.SIGNATURE_LEN,
      C.FRAME_LEN
    );
    assert.strictEqual(C.SIGNED_REGION_LEN, C.HEADER_LEN + C.IDENTITY_LEN + C.PAYLOAD_LEN);
  });

  test('AEAD wire frame = nonce + frame + tag', () => {
    assert.strictEqual(C.WIRE_FRAME_LEN, C.AEAD_NONCE_LEN + C.FRAME_LEN + C.AEAD_TAG_LEN);
  });

  test('protocol version is 2', () => assert.strictEqual(C.PROTO_V, 2));
});

// ── wire: serialize / parse ────────────────────────────────────────────────

describe('wire — HELLO round-trip', () => {
  test('serialize then parse reproduces the inputs', () => {
    const ed = cryptoFn.generateEd25519();
    const x  = cryptoFn.generateX25519();
    const ts = Date.now();
    const payload = wire.serializeHelloPayload({
      ephPub:   x.publicKeyRaw,
      prevhash: Buffer.alloc(32, 0xAB),
      nonce:    Buffer.alloc(16, 0xCD),
    });
    const signed = wire.serializeSignedRegion({
      type: C.TYPE_HELLO, timestamp: ts, identity: ed.publicKeyRaw, payload,
    });
    const sig = cryptoFn.ed25519Sign(ed.privateKey, signed);
    const frame = wire.wrapSignature(signed, sig);

    assert.strictEqual(frame.length, C.FRAME_LEN);
    const parsed = wire.parse(frame);
    assert.ok(parsed);
    assert.strictEqual(parsed.type, C.TYPE_HELLO);
    assert.strictEqual(parsed.timestamp, ts);
    assert.ok(parsed.identity.equals(ed.publicKeyRaw));
    const helloP = wire.parseHelloPayload(parsed.payload);
    assert.ok(helloP.ephPub.equals(x.publicKeyRaw));
    assert.ok(helloP.prevhash.equals(Buffer.alloc(32, 0xAB)));
    assert.ok(helloP.nonce.equals(Buffer.alloc(16, 0xCD)));
  });
});

describe('wire — PREVHASH round-trip', () => {
  test('uint64 fields survive', () => {
    const payload = wire.serializePrevhashPayload({
      poolId:      0xDEADBEEFCAFEBABEn,
      prevhash:    Buffer.alloc(32, 0x11),
      blockHeight: 9_999_999_999n,
    });
    const p = wire.parsePrevhashPayload(payload);
    assert.strictEqual(p.poolId,      0xDEADBEEFCAFEBABEn);
    assert.ok(p.prevhash.equals(Buffer.alloc(32, 0x11)));
    assert.strictEqual(p.blockHeight, 9_999_999_999n);
  });
});

describe('wire — GUARD round-trip', () => {
  test('all fields survive', () => {
    const payload = wire.serializeGuardPayload({
      ppm:           300_000,
      observedPeers: 7,
      windowStart:   1_700_000_000_000,
    });
    const g = wire.parseGuardPayload(payload);
    assert.strictEqual(g.ppm, 300_000);
    assert.strictEqual(g.observedPeers, 7);
    assert.strictEqual(g.windowStart, 1_700_000_000_000n);
  });
});

describe('wire — invariants', () => {
  function buildValidHello() {
    const ed = cryptoFn.generateEd25519();
    const payload = wire.serializeHelloPayload({
      ephPub: Buffer.alloc(32, 1), prevhash: Buffer.alloc(32, 2), nonce: Buffer.alloc(16, 3),
    });
    const signed = wire.serializeSignedRegion({
      type: 1, timestamp: Date.now(), identity: ed.publicKeyRaw, payload,
    });
    return wire.wrapSignature(signed, cryptoFn.ed25519Sign(ed.privateKey, signed));
  }

  test('parse returns null on wrong size (191)', () => {
    assert.strictEqual(wire.parse(Buffer.alloc(191)), null);
  });
  test('parse returns null on wrong size (193)', () => {
    assert.strictEqual(wire.parse(Buffer.alloc(193)), null);
  });
  test('parse returns null on wrong proto_v', () => {
    const f = buildValidHello();
    f[0] = 1;
    assert.strictEqual(wire.parse(f), null);
  });
  test('parse returns null on type out of range', () => {
    for (const t of [0, 4, 99, 0xFF]) {
      const f = buildValidHello();
      f[1] = t;
      assert.strictEqual(wire.parse(f), null);
    }
  });
  test('parse returns null on header reserved != 0', () => {
    for (let off = 10; off < 16; off++) {
      const f = buildValidHello();
      f[off] = 1;
      assert.strictEqual(wire.parse(f), null, `offset ${off}`);
    }
  });
  test('parse returns null on PREVHASH reserved != 0', () => {
    const ed = cryptoFn.generateEd25519();
    const payload = wire.serializePrevhashPayload({
      poolId: 1n, prevhash: Buffer.alloc(32, 1), blockHeight: 1n,
    });
    payload[60] = 1;     // poison reserved
    const signed = wire.serializeSignedRegion({
      type: 2, timestamp: Date.now(), identity: ed.publicKeyRaw, payload,
    });
    const f = wire.wrapSignature(signed, cryptoFn.ed25519Sign(ed.privateKey, signed));
    assert.strictEqual(wire.parse(f), null);
  });
});

// ── crypto ─────────────────────────────────────────────────────────────────

describe('crypto — Ed25519 sign / verify round-trip', () => {
  test('valid signature verifies', () => {
    const ed = cryptoFn.generateEd25519();
    const msg = Buffer.alloc(C.SIGNED_REGION_LEN, 0x42);
    const sig = cryptoFn.ed25519Sign(ed.privateKey, msg);
    assert.ok(cryptoFn.ed25519Verify(ed.publicKeyRaw, msg, sig));
  });
  test('mutated signature rejects', () => {
    const ed = cryptoFn.generateEd25519();
    const msg = Buffer.alloc(C.SIGNED_REGION_LEN, 0x42);
    const sig = cryptoFn.ed25519Sign(ed.privateKey, msg);
    sig[0] ^= 1;
    assert.strictEqual(cryptoFn.ed25519Verify(ed.publicKeyRaw, msg, sig), false);
  });
  test('wrong pubkey rejects', () => {
    const a = cryptoFn.generateEd25519();
    const b = cryptoFn.generateEd25519();
    const msg = Buffer.alloc(C.SIGNED_REGION_LEN, 0x42);
    const sig = cryptoFn.ed25519Sign(a.privateKey, msg);
    assert.strictEqual(cryptoFn.ed25519Verify(b.publicKeyRaw, msg, sig), false);
  });
});

describe('crypto — X25519 ECDH agreement', () => {
  test('two parties derive identical session key', () => {
    const a = cryptoFn.generateX25519();
    const b = cryptoFn.generateX25519();
    const sa = cryptoFn.x25519Diffie(a.privateKey, b.publicKeyRaw);
    const sb = cryptoFn.x25519Diffie(b.privateKey, a.publicKeyRaw);
    assert.ok(sa.equals(sb));
    const ka = cryptoFn.deriveSessionKey(sa);
    const kb = cryptoFn.deriveSessionKey(sb);
    assert.ok(ka.equals(kb));
    assert.strictEqual(ka.length, 32);
  });
});

describe('crypto — AEAD ChaCha20-Poly1305', () => {
  const ed = cryptoFn.generateEd25519();
  const xa = cryptoFn.generateX25519();
  const xb = cryptoFn.generateX25519();
  const sk = cryptoFn.deriveSessionKey(cryptoFn.x25519Diffie(xa.privateKey, xb.publicKeyRaw));

  function makeFrame() {
    const payload = wire.serializeHelloPayload({
      ephPub: xa.publicKeyRaw, prevhash: Buffer.alloc(32, 5), nonce: Buffer.alloc(16, 6),
    });
    const signed = wire.serializeSignedRegion({
      type: 1, timestamp: Date.now(), identity: ed.publicKeyRaw, payload,
    });
    return wire.wrapSignature(signed, cryptoFn.ed25519Sign(ed.privateKey, signed));
  }

  test('encrypt then decrypt recovers plaintext', () => {
    const frame = makeFrame();
    const wireBytes = cryptoFn.aeadEncrypt(sk, frame);
    assert.strictEqual(wireBytes.length, C.WIRE_FRAME_LEN);
    const decoded = cryptoFn.aeadDecrypt(sk, wireBytes);
    assert.ok(decoded.equals(frame));
  });
  test('tampered ciphertext returns null', () => {
    const wireBytes = cryptoFn.aeadEncrypt(sk, makeFrame());
    wireBytes[50] ^= 1;
    assert.strictEqual(cryptoFn.aeadDecrypt(sk, wireBytes), null);
  });
  test('wrong key returns null', () => {
    const wireBytes = cryptoFn.aeadEncrypt(sk, makeFrame());
    const otherKey  = crypto.randomBytes(32);
    assert.strictEqual(cryptoFn.aeadDecrypt(otherKey, wireBytes), null);
  });
});

// ── identity ───────────────────────────────────────────────────────────────

describe('identity — buildHello / validateHello', () => {
  const id = new ident.Identity();
  const eph = cryptoFn.generateX25519();
  const sharedPrev = Buffer.alloc(32, 0xAB);
  const chainView = {
    ownPrevhash: () => sharedPrev,
    freshPeerPrevhashes: () => [],
  };

  test('valid HELLO validates', () => {
    const frame = ident.buildHello(id, eph.publicKeyRaw, sharedPrev);
    const v = ident.validateHello(frame, chainView);
    assert.ok(v.ok, JSON.stringify(v));
    assert.ok(v.identity.equals(id.publicKeyRaw));
    assert.ok(v.ephPub.equals(eph.publicKeyRaw));
  });

  test('mining-bound: unknown prevhash rejects', () => {
    const wrongPrev = Buffer.alloc(32, 0x99);
    const frame = ident.buildHello(id, eph.publicKeyRaw, wrongPrev);
    const v = ident.validateHello(frame, chainView);
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.reason, 'mining-bound');
  });

  test('mining-bound: bypass under bootstrap=true', () => {
    const wrongPrev = Buffer.alloc(32, 0x99);
    const frame = ident.buildHello(id, eph.publicKeyRaw, wrongPrev);
    const v = ident.validateHello(frame, chainView, Date.now(), { bootstrap: true });
    assert.ok(v.ok);
  });

  test('ts skew > tolerance rejects', () => {
    const frame = ident.buildHello(id, eph.publicKeyRaw, sharedPrev,
                                   Date.now() - 10 * 60 * 1000);
    const v = ident.validateHello(frame, chainView);
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.reason, 'ts-skew');
  });
});

// ── equivocation ───────────────────────────────────────────────────────────

describe('equivocation — cache detects conflicts', () => {
  test('same id_pub × same height × different prevhash → evidence', () => {
    const cache = new eqMod.EquivocationCache();
    const id   = Buffer.alloc(32, 1);
    const r1   = cache.observe(id, 100n, Buffer.alloc(32, 0xAA));
    const r2   = cache.observe(id, 100n, Buffer.alloc(32, 0xBB));
    assert.strictEqual(r1, null);
    assert.ok(r2 !== null && r2.observed.equals(Buffer.alloc(32, 0xBB)));
  });
  test('same id_pub × different heights × different prevhash → no evidence', () => {
    const cache = new eqMod.EquivocationCache();
    const id   = Buffer.alloc(32, 1);
    cache.observe(id, 100n, Buffer.alloc(32, 0xAA));
    const r2 = cache.observe(id, 101n, Buffer.alloc(32, 0xBB));
    assert.strictEqual(r2, null);
  });
  test('different id_pub × same height × different prevhash → no evidence', () => {
    const cache = new eqMod.EquivocationCache();
    cache.observe(Buffer.alloc(32, 1), 100n, Buffer.alloc(32, 0xAA));
    const r2 = cache.observe(Buffer.alloc(32, 2), 100n, Buffer.alloc(32, 0xBB));
    assert.strictEqual(r2, null);
  });
  test('expiry: observation outside window does not count', () => {
    let t = 1_000_000;
    const cache = new eqMod.EquivocationCache({ now: () => t });
    const id = Buffer.alloc(32, 1);
    cache.observe(id, 100n, Buffer.alloc(32, 0xAA));
    t += C.EQUIVOCATION_WINDOW_MS + 1;
    const r2 = cache.observe(id, 100n, Buffer.alloc(32, 0xBB));
    assert.strictEqual(r2, null, 'window expired, second observation overwrites');
  });
});

// ── limits ─────────────────────────────────────────────────────────────────

describe('limits — TokenBucket', () => {
  test('starts at capacity', () => {
    const b = new lim.TokenBucket(10, 1);
    assert.strictEqual(b.tokens, 10);
  });
  test('exhausts and refills', () => {
    const b = new lim.TokenBucket(5, 5);
    b.last = 0; b.tokens = 0;
    assert.ok(!b.take(1, 0));
    assert.ok(b.take(1, 1000));
  });
});

describe('limits — BanList', () => {
  test('add then isBanned', () => {
    const bl = new lim.BanList();
    bl.add('1.2.3.4', 60_000);
    assert.ok(bl.isBanned('1.2.3.4'));
    assert.ok(!bl.isBanned('1.2.3.5'));
  });
  test('TTL expiry', () => {
    let t = 1000;
    const bl = new lim.BanList({ now: () => t });
    bl.add('5.6.7.8', 100);
    assert.ok(bl.isBanned('5.6.7.8'));
    t += 200;
    assert.ok(!bl.isBanned('5.6.7.8'));
  });
});

describe('limits — PerIpRate', () => {
  test('handshake rate cap', () => {
    const r = new lim.PerIpRate();
    const ip = '203.0.113.1';
    for (let i = 0; i < C.IP_HANDSHAKE_RATE; i++) {
      assert.ok(r.allowHandshake(ip));
    }
    assert.ok(!r.allowHandshake(ip));
  });
  test('half-open cap', () => {
    const r = new lim.PerIpRate();
    const ip = '203.0.113.2';
    for (let i = 0; i < C.IP_HALF_OPEN_CAP; i++) assert.ok(r.acquireHalfOpen(ip));
    assert.ok(!r.acquireHalfOpen(ip));
    r.releaseHalfOpen(ip);
    assert.ok(r.acquireHalfOpen(ip));
  });
});

describe('limits — PerPeerLimiter strike escalation', () => {
  test('soft → hard → ban escalation', () => {
    let t = 1000;
    const bl  = new lim.BanList({ now: () => t });
    const lm  = new lim.PerPeerLimiter({ banList: bl, now: () => t });
    const id  = 'aa'.repeat(32);
    const ip  = '203.0.113.99';

    let escalations = [];
    for (let i = 0; i < C.STRIKE_HARD_THRESHOLD + 1; i++) {
      const v = lm.strike(id, ip, 'test');
      if (v.escalate) escalations.push(v.escalate);
      t += 1; // tiny advance to keep within strike window
    }
    assert.ok(escalations.includes('soft'));
    assert.ok(escalations.includes('hard'));
    assert.ok(bl.isBanned(ip));
  });
});
