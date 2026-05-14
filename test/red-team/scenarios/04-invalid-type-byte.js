'use strict';
/**
 * Scenario 04 — type byte ∉ {1,2,3} is dropped + striked.
 *
 * Attack: well-formed 192-byte frame with type byte set to a value outside
 *         the three valid types defined in §3.2. Iterate over a sample of
 *         out-of-range type values (0, 4, 0xFF).
 *
 * Defense: §3.2 fixes type ∈ {HELLO=1, PREVHASH=2, GUARD=3}. No extension
 *          range, no reserved range that produces an event. Drop + strike.
 *
 * Outcome: every out-of-range type produces silent drop.
 */

module.exports = {
  id: '04',
  name: 'type byte outside {1,2,3} is dropped (no extension range)',
  spec: 'SPEC-FEDERATION-v1.md §3.2',
  attack_vector: 'E6 parser confusion / E15 active probing',
  expected_outcome: 'each invalid type byte is silently dropped',
  requires_impl: false,

  async run(harness) {
    // Single WS, multiple frames. Drops are silent (§5.6) so the connection
    // stays open and we can iterate without burning the per-IP handshake cap.
    const ws = await harness.openWs();
    const tested = [];
    for (const badType of [0, 4, 7, 0x80, 0xFF]) {
      const frame = harness.buildFrameTemplate({ type: badType });
      try { await harness.sendWsRaw(ws, frame); } catch {}
      const reply = await harness.waitForWsMessage(ws, 200);
      tested.push({ badType, accepted: reply !== null });
    }
    return { tested };
  },

  verify(result) {
    return result.tested.every((t) => t.accepted === false);
  },
};
