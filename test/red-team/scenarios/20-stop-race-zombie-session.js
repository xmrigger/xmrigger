'use strict';
/**
 * Scenario 20 — stop() race: a WebSocket whose 'open' event fires AFTER
 *               stop() is called creates a Session that re-populates the
 *               cleared _sessions Map.
 *
 * In node.js:
 *   _connectOut(url) opens a ws.  On 'open', it builds a new Session and
 *   wires it via _wireSession.  Neither path checks this._stopped.
 *   stop() sets _stopped=true, clears _sessions, but cannot un-do a
 *   pending TCP connect that resolves after the call.
 *
 * Outcome of the race:
 *   - _sessions cleared by stop()
 *   - ws 'open' fires post-stop
 *   - Session constructor runs, sends HELLO on a half-stopped node
 *   - eventually, if the peer responds, Session emits 'ready' and the
 *     'ready' handler does this._sessions.set(peerIdHex, session) — adding
 *     a session to a Map on a node that the caller believes is stopped.
 *
 * The leak surfaces in tests as "after stop(), peerCount > 0" once the
 * race resolves; in production it means resources continue to be used
 * (ws connection, key material in memory) after stop() returns.
 *
 * Severity: LOW (resource leak; not data integrity). Class of bug: missing
 * "_stopped" check in async continuations.
 *
 * What this scenario does: starts a real FederationNode, schedules an
 * outbound _connectOut to a dead URL that will never reach 'open', then
 * calls stop(). Verifies that the reconnect timer is not re-armed and
 * _sessions stays empty even after sleeping long enough for any pending
 * setTimeout(RECONNECT_MS=15s) to fire.
 *
 * Adapted to be fast: we directly inspect the internal _reconnectTimers
 * Map and _sessions Map after a stop().
 */

const { FederationNode } = require('../../../src/federation');

module.exports = {
  id: '20',
  name: 'stop() race: pending connectOut continuations may zombie-populate _sessions',
  spec: 'SPEC-FEDERATION-v1.md §4.5 (session termination), implicit lifecycle',
  attack_vector: 'lifecycle / race; resource leak after stop()',
  expected_outcome: 'after stop(), _sessions stays empty and _reconnectTimers stays empty',
  requires_impl: false,

  async run() {
    const sharedPrevhash = Buffer.alloc(32, 0xAB);
    // Use a definitely-unreachable port; ws will fail to connect.
    const deadUrl = 'ws://127.0.0.1:1';
    const node = new FederationNode({
      port: 0,
      seeds: [deadUrl],
      chainView: { ownPrevhash: () => sharedPrevhash, freshPeerPrevhashes: () => [sharedPrevhash] },
      getRecentPrevhash: () => sharedPrevhash,
    });
    await node.start();
    // Let outbound _connectOut be scheduled at least once (it has fired
    // synchronously from start()). The ws will error → _scheduleReconnect
    // arms a 15s timer.
    await new Promise((r) => setTimeout(r, 60));
    const timersBeforeStop = node._reconnectTimers.size;

    node.stop();

    // Inspect internals immediately and after a short delay.
    const sessionsImmediately = node._sessions.size;
    const timersImmediately   = node._reconnectTimers.size;
    await new Promise((r) => setTimeout(r, 100));
    const sessionsLater = node._sessions.size;
    const timersLater   = node._reconnectTimers.size;
    const stopped = node._stopped === true;

    return {
      timersBeforeStop,
      sessionsImmediately,
      timersImmediately,
      sessionsLater,
      timersLater,
      stopped,
    };
  },

  verify(result) {
    return result.stopped === true &&
           result.sessionsImmediately === 0 &&
           result.timersImmediately === 0 &&
           result.sessionsLater === 0 &&
           result.timersLater === 0;
  },
};
