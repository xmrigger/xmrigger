'use strict';
/**
 * Scenario 13 — WS close `reason` string leaks the failed check to the wire.
 *
 * Attack: send a series of malformed handshake frames, each crafted to
 *         trigger a distinct internal drop reason (wire-len short, wire-len
 *         long, parse fail, etc.). Read the WebSocket close `reason` payload
 *         the server sends back. If the reason carries a human string
 *         ("wire", "handshake-rate", "banned", "half-open-cap",
 *         "handshake-timeout", "equivocation", …), the server has provided
 *         the active prober with a differential signal that distinguishes
 *         which guard fired.
 *
 * Defense (claimed): SPEC-FEDERATION-v1.md §5.6 — "A peer whose frame is
 *         dropped gets no acknowledgement, no error code, no log message
 *         visible to it. Silence." (E15 mitigation, marked Structural in §6.)
 *
 * Outcome: every probe must close with an empty `reason` payload. Any
 *          non-empty reason violates §5.6 and gives the attacker a
 *          differential fingerprint.
 *
 * Why scenario 09 missed it: scenario 09 listens for ws *messages*; the WS
 * close reason is delivered out-of-band (close frame payload), not as a
 * data message. The information leak is invisible to a message-only probe.
 */

module.exports = {
  id: '13',
  name: 'WS close reason string leaks which guard fired (violates §5.6)',
  spec: 'SPEC-FEDERATION-v1.md §5.6 (no diagnostic feedback)',
  attack_vector: 'E15 active probing via WS close-frame reason payload',
  expected_outcome: 'every close.reason is empty regardless of which check failed',
  requires_impl: true,

  async run(harness) {
    // Each probe is designed to hit a different internal close site.
    const probes = [
      { label: 'short-frame',  payload: Buffer.alloc(50) },     // → 'wire'
      { label: 'long-frame',   payload: Buffer.alloc(193) },    // → 'wire' (different size)
      { label: 'bad-proto-v',  payload: (() => {
          const f = harness.buildFrameTemplate({ type: 1 });
          f[0] = 0xFF;
          return f;
        })() },
      { label: 'bad-type',     payload: harness.buildFrameTemplate({ type: 0xAA }) },
      { label: 'ts-skew',      payload: harness.buildFrameTemplate({ type: 1, timestamp: Date.now() - 1_000_000 }) },
    ];

    const observed = [];
    for (const p of probes) {
      let ws;
      try { ws = await harness.openWs(); } catch { observed.push({ label: p.label, refused: true }); continue; }
      const closePromise = new Promise((resolve) => {
        ws.once('close', (code, reason) => {
          const r = Buffer.isBuffer(reason) ? reason.toString('utf8') : String(reason || '');
          resolve({ label: p.label, code, reason: r });
        });
        setTimeout(() => resolve({ label: p.label, code: null, reason: null, timeout: true }), 1500);
      });
      try { await harness.sendWsRaw(ws, p.payload); } catch {}
      observed.push(await closePromise);
    }

    const leaking = observed.filter((o) => o.reason && o.reason.length > 0);
    return { observed, leakingCount: leaking.length, leakingLabels: leaking.map((l) => `${l.label}=${l.reason}`) };
  },

  verify(result) {
    // §5.6 promise: zero leaking reasons.
    return result.leakingCount === 0;
  },
};
