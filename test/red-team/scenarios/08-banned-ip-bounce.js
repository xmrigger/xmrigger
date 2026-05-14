'use strict';
/**
 * Scenario 08 — banned IP cannot reconnect.
 *
 * Attack: seed a ban for 127.0.0.1 via the debug API, then attempt to open
 *         a WebSocket connection. Must be closed immediately.
 *
 * Defense: §5.3 — IP ban applied pre-handshake. The mock target accepts
 *          a /__debug/inject-ban call so this scenario runs against mock
 *          without needing real strike escalation.
 *
 * Outcome: WS open fails or closes within budget.
 */

const http = require('http');

function injectBan(debugUrl, ip, ttlMs) {
  return new Promise((resolve, reject) => {
    const url = `${debugUrl}/__debug/inject-ban?ip=${encodeURIComponent(ip)}&ttl=${ttlMs}`;
    http.get(url, (res) => { res.resume(); resolve(res.statusCode === 200); })
        .on('error', reject);
  });
}

module.exports = {
  id: '08',
  name: 'banned IP cannot reconnect — closed pre-handshake',
  spec: 'SPEC-FEDERATION-v1.md §5.3',
  attack_vector: 'E20 ban list spam recovery / general ban check',
  expected_outcome: 'connection from banned IP closes immediately',
  requires_impl: false,

  async run(harness) {
    await injectBan(harness.targetCtx.debugUrl, '127.0.0.1', 60_000);
    let opened = false, closed = true;
    try {
      const ws = await harness.openWs();
      opened = true;
      closed = await harness.waitForWsClose(ws, 600);
    } catch (e) {
      // refused before 'open' event — that's the expected branch
      opened = false;
      closed = true;
    }
    const stillBanned = await harness.isIpBanned('127.0.0.1');
    return { opened, closed, stillBanned };
  },

  verify(result) {
    return result.closed === true && result.stillBanned === true;
  },
};
