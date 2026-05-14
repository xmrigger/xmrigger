'use strict';
/**
 * Scenario 06 — per-IP handshake rate cap (D6).
 *
 * Attack: open N+1 fresh WebSocket sessions in rapid succession from the
 *         same IP, where N is the SPEC limit (3 / 60 s). The (N+1)-th
 *         attempt must be rejected at the connection layer.
 *
 * Defense: §5.2 — 3 handshakes/min/IP, hardcoded.
 *
 * Outcome: first 3 connections succeed; the 4th closes immediately.
 */

module.exports = {
  id: '06',
  name: 'per-IP handshake rate cap (3/min) closes 4th connection immediately',
  spec: 'SPEC-FEDERATION-v1.md §5.2 (D6)',
  attack_vector: 'E5 identity recycling racing / E18 boot-loop',
  expected_outcome: 'first 3 sessions stay open briefly; 4th is closed within 500 ms',
  requires_impl: false,

  async run(harness) {
    const sockets = [];
    for (let i = 0; i < 3; i++) sockets.push(await harness.openWs());

    let fourthClosed;
    let fourthOpened = true;
    try {
      const ws4 = await harness.openWs();
      fourthClosed = await harness.waitForWsClose(ws4, 600);
    } catch (e) {
      // Connection may be refused before 'open' event — that also counts as closed.
      fourthOpened = false;
      fourthClosed = true;
    }
    return { fourthOpened, fourthClosed, baseline: sockets.length };
  },

  verify(result) {
    return result.fourthClosed === true;
  },
};
