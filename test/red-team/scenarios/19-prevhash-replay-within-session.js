'use strict';
/**
 * Scenario 19 — PREVHASH replay end-to-end (post-fix).
 *
 * Pre-fix: identity.verifyFrame is stateless; the Session module forwarded
 * every decrypted+verified frame to the upstream. A byte-exact replay of
 * a previously delivered PREVHASH frame produced a duplicate emit.
 *
 * Blue-team fix (#19): FederationNode._framePostSeen maintains a per-peer
 * LRU (SEEN_NONCE_PER_PEER entries) keyed on a compact digest of the
 * frame. Replay produces a policy-violation event instead of a duplicate
 * dispatch.
 *
 * This scenario verifies end-to-end via two real FederationNodes that B
 * sends the same PREVHASH twice; A must emit exactly once.
 *
 * NOTE: a wire-level replay requires capturing the AEAD ciphertext, but
 * since A controls how many times its own Session forwards a frame, the
 * cleanest end-to-end check is to drive the Session manually via the
 * exposed module. Easier: send via broadcastPrevhash from B twice in a row
 * with identical (prevhash, height, timestamp). The second one's frame
 * shares the signed-region prefix; replay detection should fire.
 *
 * Important: broadcastPrevhash builds a NEW frame each time with a fresh
 * timestamp (Date.now()), so two consecutive sends produce frames that
 * differ in the timestamp field. To replay byte-exact, we drive Session
 * directly with the same buffer twice.
 */

const { FederationNode } = require('../../../src/federation');
const ident              = require('../../../src/federation/identity');
const cryptoFn           = require('../../../src/federation/crypto');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

module.exports = {
  id: '19',
  name: 'PREVHASH replay byte-exact is detected and dropped end-to-end',
  spec: 'SPEC-FEDERATION-v1.md §3.6 erratum (per-process replay set)',
  attack_vector: 'E2 replay extended to data frames',
  expected_outcome: 'one emit only; second identical frame triggers policy-violation',
  requires_impl: false,

  async run() {
    const sharedPrev = Buffer.alloc(32, 0xAB);
    const chainView = {
      ownPrevhash:         () => sharedPrev,
      freshPeerPrevhashes: () => [sharedPrev],
    };

    const A = new FederationNode({ port: 0, seeds: [], chainView,
                                   getRecentPrevhash: () => sharedPrev });
    await A.start();
    const B = new FederationNode({ port: 0,
                                   seeds: [`ws://127.0.0.1:${A.port}`],
                                   chainView,
                                   getRecentPrevhash: () => sharedPrev });

    const announces = [];
    A.on('prevhash-announce', (ev) => announces.push(ev));

    await B.start();
    const t0 = Date.now();
    while (A.peerCount === 0 && Date.now() - t0 < 1500) await wait(20);

    // Build a single PREVHASH frame to be sent twice byte-exact.
    const frame = ident.buildPrevhash(B.identity, 0n, Buffer.alloc(32, 0x7F), 42n);

    // Send the same frame twice via the live session.
    const session = Array.from(B._sessions.values())[0];
    if (!session) {
      A.stop(); B.stop();
      return { error: 'no session', sentCount: 0 };
    }
    session.sendFrame(frame);
    await wait(60);
    session.sendFrame(frame);
    await wait(200);

    const result = { announces: announces.length };
    A.stop(); B.stop();
    await wait(80);
    return result;
  },

  verify(result) {
    return result.announces === 1;
  },
};
