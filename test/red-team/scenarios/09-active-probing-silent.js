'use strict';
/**
 * Scenario 09 — active probing receives no diagnostic feedback.
 *
 * Attack: send a sequence of frames each crafted to trigger a different
 *         drop reason (wrong size, wrong type, bad reserved, ts skew). For
 *         every drop, the wire must remain silent — no error message, no
 *         differential timing fingerprint.
 *
 * Defense: §5.6 — drops are silent. Local logs may be detailed; the wire
 *          carries no diagnostic.
 *
 * Outcome: zero messages received from the target across all probes.
 */

module.exports = {
  id: '09',
  name: 'active probing returns zero diagnostic feedback',
  spec: 'SPEC-FEDERATION-v1.md §5.6',
  attack_vector: 'E15 active probing',
  expected_outcome: 'no message returned for any malformed frame',
  requires_impl: false,

  async run(harness) {
    const ws = await harness.openWs();
    const probes = [
      // wrong size
      harness.randomBytes(100),
      harness.randomBytes(193),
      // wrong type
      harness.buildFrameTemplate({ type: 0xAA }),
      // bad reserved
      (() => { const f = harness.buildFrameTemplate({ type: 1 }); f[11] = 0x01; return f; })(),
      // ts skew
      harness.buildFrameTemplate({ type: 1, timestamp: Date.now() - 1_000_000 }),
    ];
    const replies = [];
    for (const p of probes) {
      try { await harness.sendWsRaw(ws, p); } catch {}
      const r = await harness.waitForWsMessage(ws, 250);
      replies.push(r);
    }
    return { replies };
  },

  verify(result) {
    return result.replies.every((r) => r === null);
  },
};
