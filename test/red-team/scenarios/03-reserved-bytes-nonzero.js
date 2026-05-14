'use strict';
/**
 * Scenario 03 — header reserved bytes ≠ 0 are dropped + striked.
 *
 * Attack: build a structurally well-formed 192-byte frame but write a
 *         non-zero byte in the reserved range x⁰[10..15].
 *
 * Defense: §3.2 mandates `for k in 10..15: byte == 0`. Drop + strike.
 *
 * Outcome: silent drop, optional strike counter increments.
 */

module.exports = {
  id: '03',
  name: 'reserved bytes != 0 in header are dropped + striked',
  spec: 'SPEC-FEDERATION-v1.md §3.2',
  attack_vector: 'E10 zero-byte tolerance',
  expected_outcome: 'frame dropped silently; in real impl, strike recorded',
  requires_impl: false,

  async run(harness) {
    const ws    = await harness.openWs();
    const frame = harness.buildFrameTemplate({ type: 1 });
    frame[12] = 0xFF;   // poison a reserved byte
    await harness.sendWsRaw(ws, frame);
    const reply  = await harness.waitForWsMessage(ws, 400);
    const closed = await harness.waitForWsClose(ws, 200);
    return { reply, closed };
  },

  verify(result) {
    return result.reply === null;
  },
};
