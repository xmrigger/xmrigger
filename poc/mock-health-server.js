#!/usr/bin/env node
/**
 * mock-health-server.js — Mock /pool/health server for xmrigger POC
 *
 * Simulates a pool's hashrate concentration evolving over time so you can
 * observe the guard's warn → crit → grace → evacuate sequence locally
 * without waiting for a real pool to exceed the threshold.
 *
 * Also exposes /api/networkinfo (same shape as xmrchain.net) so the POC
 * runs fully offline without hitting external APIs.
 *
 * Usage:
 *   node mock-health-server.js [--port 19999] [--phase-secs 20]
 *
 * Phases:
 *   SAFE  (10%) → WARN (27%) → CRIT (32%) → FORK → SAFE2 (8%)
 *
 * @version  0.1.0
 * @released 2026-04-18
 * @license  LGPL-2.1
 */
'use strict';

const http = require('http');

const args = process.argv.slice(2);
function getArg(name, def) {
  const idx = args.indexOf('--' + name);
  return idx >= 0 && args[idx + 1] ? args[idx + 1] : def;
}

const PORT       = parseInt(getArg('port', '19999'));
const PHASE_SECS = parseInt(getArg('phase-secs', '20'));

const NETWORK_HASHRATE = 1_000_000_000; // 1 GH/s mock
const NETWORK_DIFF     = NETWORK_HASHRATE * 120;

const PHASES = [
  { name: 'SAFE',  hashratePct: 0.10, forkDetected: false },
  { name: 'WARN',  hashratePct: 0.27, forkDetected: false },
  { name: 'CRIT',  hashratePct: 0.32, forkDetected: false },
  { name: 'FORK',  hashratePct: 0.32, forkDetected: true  },
  { name: 'SAFE2', hashratePct: 0.08, forkDetected: false },
];

let phaseIdx = 0;
let phaseStart = Date.now();

function currentPhase() { return PHASES[phaseIdx % PHASES.length]; }
function advancePhase() {
  phaseIdx = (phaseIdx + 1) % PHASES.length;
  phaseStart = Date.now();
  const p = currentPhase();
  console.log(`[mock] → ${p.name}  hashratePct=${p.hashratePct}  fork=${p.forkDetected}`);
}

setInterval(advancePhase, PHASE_SECS * 1000);

http.createServer((req, res) => {
  const p = currentPhase();

  if (req.url === '/pool/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      hashratePct:       p.hashratePct,
      avgBlockTimeMs:    120000 + (p.name === 'CRIT' ? 80000 : 0),
      orphanRate:        p.name === 'CRIT' ? 0.06 : 0.01,
      forkDetected:      p.forkDetected,
      federationAlerted: p.name === 'FORK',
      gracePeriodEndsAt: null,
      _mock: { phase: p.name, secsInPhase: Math.floor((Date.now() - phaseStart) / 1000) },
    }));
    console.log(`[mock] /pool/health → ${p.name} (${p.hashratePct * 100}%)`);

  } else if (req.url === '/api/networkinfo') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ difficulty: NETWORK_DIFF, height: 3200000, _mock: true }));

  } else {
    res.writeHead(404); res.end('not found');
  }
}).listen(PORT, () => {
  console.log(`\n[mock] Listening on http://127.0.0.1:${PORT}`);
  console.log(`[mock] Phase duration: ${PHASE_SECS}s\n`);
  PHASES.forEach((p, i) =>
    console.log(`[mock]   ${String(i+1).padStart(2)}. ${p.name.padEnd(6)}  ${(p.hashratePct*100).toFixed(0).padStart(3)}%  fork=${p.forkDetected}  t+${i*PHASE_SECS}s`)
  );
  console.log();
});
