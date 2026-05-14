'use strict';
/**
 * federation-e2e.js — full-stack 2-node end-to-end tests.
 *
 * @license LGPL-2.1
 *
 * Spins up two real FederationNode instances on loopback ports and
 * verifies the full flow: HELLO mining-bound handshake, AEAD-wrapped
 * PREVHASH and GUARD broadcasts, equivocation detection with live ban,
 * and clean shutdown.
 *
 * Run:    node test/federation-e2e.js
 * Quick:  npm run test:federation:e2e
 */

const { test, describe } = require('node:test');
const assert             = require('node:assert/strict');

const { FederationNode } = require('../src/federation');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function untilTrue(fn, deadlineMs = 3000, intervalMs = 25) {
  const t0 = Date.now();
  while (Date.now() - t0 < deadlineMs) {
    if (fn()) return true;
    await wait(intervalMs);
  }
  return false;
}

function makeChainView(prevhashBuf) {
  return {
    ownPrevhash:         () => prevhashBuf,
    freshPeerPrevhashes: () => [prevhashBuf],
  };
}

describe('federation E2E — basic 2-node flow', () => {
  test('two nodes establish session, exchange PREVHASH', async () => {
    const ph = Buffer.alloc(32, 0xAB);
    const A = new FederationNode({ port: 0, seeds: [],
                                   chainView: makeChainView(ph),
                                   getRecentPrevhash: () => ph });
    await A.start();
    const B = new FederationNode({ port: 0,
                                   seeds: [`ws://127.0.0.1:${A.port}`],
                                   chainView: makeChainView(ph),
                                   getRecentPrevhash: () => ph });

    const announces = [];
    A.on('prevhash-announce', (ev) => announces.push(ev));

    await B.start();
    assert.ok(await untilTrue(() => A.peerCount === 1 && B.peerCount === 1),
              'peers must converge to 1 on each side');

    const sent = B.broadcastPrevhash({ prevhash: Buffer.alloc(32, 0x42), blockHeight: 100n });
    assert.strictEqual(sent, 1);

    assert.ok(await untilTrue(() => announces.length === 1));
    assert.strictEqual(announces[0].prevhash, '42'.repeat(32));
    assert.strictEqual(announces[0].blockHeight, 100n);

    A.stop(); B.stop();
    await wait(50);
  });

  test('GUARD broadcast lands at the peer with all fields', async () => {
    const ph = Buffer.alloc(32, 0xCD);
    const A = new FederationNode({ port: 0, seeds: [],
                                   chainView: makeChainView(ph),
                                   getRecentPrevhash: () => ph });
    await A.start();
    const B = new FederationNode({ port: 0,
                                   seeds: [`ws://127.0.0.1:${A.port}`],
                                   chainView: makeChainView(ph),
                                   getRecentPrevhash: () => ph });

    const guards = [];
    A.on('guard-hint', (ev) => guards.push(ev));

    await B.start();
    assert.ok(await untilTrue(() => A.peerCount === 1));

    B.broadcastGuard({ ppm: 320_000, observedPeers: 4, windowStart: 1_700_000_000_000 });
    assert.ok(await untilTrue(() => guards.length === 1));
    assert.strictEqual(guards[0].ppm, 320_000);
    assert.strictEqual(guards[0].observedPeers, 4);
    assert.strictEqual(guards[0].windowStart, 1_700_000_000_000n);

    A.stop(); B.stop();
    await wait(50);
  });
});

describe('federation E2E — equivocation detection live', () => {
  test('two conflicting PREVHASH same id × same height → peer-banned + session closed', async () => {
    const ph = Buffer.alloc(32, 0xEE);
    const A = new FederationNode({ port: 0, seeds: [],
                                   chainView: makeChainView(ph),
                                   getRecentPrevhash: () => ph });
    await A.start();
    const B = new FederationNode({ port: 0,
                                   seeds: [`ws://127.0.0.1:${A.port}`],
                                   chainView: makeChainView(ph),
                                   getRecentPrevhash: () => ph });

    const bans = [];
    const disc = [];
    A.on('peer-banned',     (ev) => bans.push(ev));
    A.on('peer-disconnected', (ev) => disc.push(ev));

    await B.start();
    assert.ok(await untilTrue(() => A.peerCount === 1));

    // First PREVHASH at height 7 is the canonical one. Second at same height
    // with a different prevhash is the equivocation.
    B.broadcastPrevhash({ prevhash: Buffer.alloc(32, 0x11), blockHeight: 7n });
    await wait(80);
    B.broadcastPrevhash({ prevhash: Buffer.alloc(32, 0x22), blockHeight: 7n });

    assert.ok(await untilTrue(() => bans.length === 1, 1500),
              'peer-banned event must fire on equivocation');
    assert.strictEqual(bans[0].reason, 'equivocation');
    assert.ok(await untilTrue(() => disc.length === 1, 1500),
              'session must be closed after ban');

    A.stop(); B.stop();
    await wait(50);
  });
});

describe('federation E2E — handshake gates', () => {
  test('peer with unrecognised prevhash is rejected (mining-bound)', async () => {
    const realPh = Buffer.alloc(32, 0xAB);
    const fakePh = Buffer.alloc(32, 0x99);

    const A = new FederationNode({ port: 0, seeds: [],
                                   chainView: makeChainView(realPh),
                                   getRecentPrevhash: () => realPh });
    await A.start();
    const B = new FederationNode({ port: 0,
                                   seeds: [`ws://127.0.0.1:${A.port}`],
                                   chainView: makeChainView(fakePh),
                                   getRecentPrevhash: () => fakePh });
    await B.start();

    // A should NOT accept B's HELLO because B announces a prevhash A has
    // never seen. Wait then assert peerCount stays at 0.
    await wait(500);
    assert.strictEqual(A.peerCount, 0,
                       'A must not accept HELLO with unknown prevhash');

    A.stop(); B.stop();
    await wait(50);
  });
});
