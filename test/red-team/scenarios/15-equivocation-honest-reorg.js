'use strict';
/**
 * Scenario 15 — Equivocation cache + honest-reorg heuristic (end-to-end).
 *
 * After blue-team #15 fix in node.js (_looksLikeHonestReorg), the
 * EquivocationCache still raises evidence on every conflicting prevhash,
 * but FederationNode demotes the verdict from "ban" to "log" when at
 * least one OTHER peer has independently observed the existing prevhash
 * for the same height. The interpretation: the chain visibly reorged
 * from many viewpoints, not a single equivocator.
 *
 * This scenario runs three FederationNode instances. Two of them
 * (observers) announce the same prevhash for height H first. Then one
 * of those nodes announces a DIFFERENT prevhash for the same height H
 * (= it observed a reorg). The receiver must NOT ban it: the prior
 * announcement is supported by another independent observer.
 */

const { FederationNode } = require('../../../src/federation');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

module.exports = {
  id: '15',
  name: 'honest reorg announced after independent observation does NOT ban',
  spec: 'SPEC-FEDERATION-v1.md §5.4',
  attack_vector: 'E3 equivocation false-positive — honest reorg',
  expected_outcome: 'reorg-observed event fires; no peer-banned for the reorger',
  requires_impl: false,

  async run() {
    const sharedPrev = Buffer.alloc(32, 0xAB);
    const chainView = {
      ownPrevhash:         () => sharedPrev,
      freshPeerPrevhashes: () => [sharedPrev],
    };
    const mk = (seeds) => new FederationNode({
      port: 0, seeds, chainView,
      getRecentPrevhash: () => sharedPrev,
    });

    const A = mk([]);
    await A.start();
    const B = mk([`ws://127.0.0.1:${A.port}`]);
    const C = mk([`ws://127.0.0.1:${A.port}`]);

    const bans   = [];
    const reorgs = [];
    A.on('peer-banned',    (e) => bans.push(e));
    A.on('reorg-observed', (e) => reorgs.push(e));

    await B.start();
    await C.start();
    // Wait until both peers connect to A.
    const t0 = Date.now();
    while (A.peerCount < 2 && Date.now() - t0 < 1500) await wait(20);

    const HEIGHT     = 99_999n;
    const canonical  = Buffer.alloc(32, 0xC1);
    const reorgedPh  = Buffer.alloc(32, 0xC2);

    // B and C both announce the canonical tip first.
    B.broadcastPrevhash({ prevhash: canonical, blockHeight: HEIGHT });
    C.broadcastPrevhash({ prevhash: canonical, blockHeight: HEIGHT });
    await wait(120);

    // Now B observes a reorg and re-announces.
    B.broadcastPrevhash({ prevhash: reorgedPh, blockHeight: HEIGHT });
    await wait(300);

    const result = {
      bans:   bans.length,
      reorgs: reorgs.length,
      banReasons: bans.map((b) => b.reason),
    };

    A.stop(); B.stop(); C.stop();
    await wait(80);
    return result;
  },

  verify(result) {
    return result.bans === 0 && result.reorgs >= 1;
  },
};
