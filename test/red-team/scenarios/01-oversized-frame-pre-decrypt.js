'use strict';
/**
 * Scenario 01 — oversized frame is dropped pre-decrypt by WS maxPayload.
 *
 * Attack: open a WebSocket session, immediately send a frame much larger
 *         than 192 + AEAD overhead. The WS layer must reject before any
 *         protocol logic runs.
 *
 * Defense: SPEC-FEDERATION-v1.md §5.5 sets WS maxPayload = 256 B. The ws
 *          library closes the connection with code 1009 "Message too big"
 *          before invoking any application handler.
 *
 * Outcome: the connection closes within the budget.
 */

module.exports = {
  id: '01',
  name: 'oversized frame is dropped pre-decrypt by WS maxPayload',
  spec: 'SPEC-FEDERATION-v1.md §5.5',
  attack_vector: 'E7 length-prefix abuse / generic flood',
  expected_outcome: 'WS connection closed before any protocol handler runs',
  requires_impl: false,

  async run(harness) {
    const ws = await harness.openWs();
    const oversized = harness.randomBytes(10 * 1024); // 10 KB
    let sendError = null;
    try {
      await harness.sendWsRaw(ws, oversized);
    } catch (e) { sendError = e.message; }
    const closed = await harness.waitForWsClose(ws, 1500);
    return { closed, sendError };
  },

  verify(result) {
    return result.closed === true;
  },
};
