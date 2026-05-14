'use strict';
/**
 * Scenario 02 — frame ≠ 192 B is silently dropped.
 *
 * Attack: send 191-byte and 193-byte frames after a fresh connection.
 *         These are within WS maxPayload (256 B) so they do NOT trigger
 *         §5.5 oversized close. They reach the protocol layer, which must
 *         drop them silently because of the fixed-size invariant in §3.1.
 *
 * Defense: parser asserts plain.length === 192. Anything else returns null
 *          (drop). No reply, no error message, no diagnostic feedback (§5.6).
 *
 * Outcome: connection stays open (silent drop), no message sent back.
 */

module.exports = {
  id: '02',
  name: 'frame size 191 and 193 are silently dropped (no diagnostic)',
  spec: 'SPEC-FEDERATION-v1.md §3.1, §5.6',
  attack_vector: 'E6 parser path-confusion',
  expected_outcome: 'connection remains open, no response sent for either frame',
  requires_impl: false,

  async run(harness) {
    const ws = await harness.openWs();
    await harness.sendWsRaw(ws, harness.randomBytes(191));
    await harness.sendWsRaw(ws, harness.randomBytes(193));
    const reply  = await harness.waitForWsMessage(ws, 500);
    const closed = await harness.waitForWsClose(ws, 200);
    return { reply, closed };
  },

  verify(result) {
    return result.reply === null && result.closed === false;
  },
};
