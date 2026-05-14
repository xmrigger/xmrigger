'use strict';
/**
 * Scenario 05 — frame with timestamp outside ±5 min is dropped.
 *
 * Attack: well-formed 192-byte frame whose timestamp is 6 minutes in the
 *         past, then 6 minutes in the future. Both must be rejected.
 *
 * Defense: §3.2 / §4.3 require |now - timestamp_ms| ≤ 300_000.
 *
 * Outcome: silent drop in both directions.
 */

module.exports = {
  id: '05',
  name: 'timestamp outside ±5 min is dropped (past and future)',
  spec: 'SPEC-FEDERATION-v1.md §3.2, §4.3',
  attack_vector: 'E16 clock skew',
  expected_outcome: 'frames with ts > 5 min skew are dropped silently',
  requires_impl: false,

  async run(harness) {
    // Same connection for both probes — silent drops keep the session open.
    const ws = await harness.openWs();
    const six_min = 6 * 60 * 1000;
    const cases = [
      { label: 'past',   ts: Date.now() - six_min },
      { label: 'future', ts: Date.now() + six_min },
    ];
    const tested = [];
    for (const c of cases) {
      const frame = harness.buildFrameTemplate({ type: 1, timestamp: c.ts });
      try { await harness.sendWsRaw(ws, frame); } catch {}
      const reply = await harness.waitForWsMessage(ws, 200);
      tested.push({ label: c.label, accepted: reply !== null });
    }
    return { tested };
  },

  verify(result) {
    return result.tested.every((t) => t.accepted === false);
  },
};
