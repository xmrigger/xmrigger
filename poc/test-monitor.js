#!/usr/bin/env node
/**
 * test-monitor.js — exercise HashrateMonitor against the mock server
 * No XMRig required. Prints all events with timestamps.
 *
 * @version  0.1.0
 * @released 2026-04-18
 * @license  LGPL-2.1
 */
'use strict';

const { HashrateMonitor } = require('../src/hashrate-monitor');

const ts = () => new Date().toISOString().slice(11, 23);

const monitor = new HashrateMonitor({
  poolHealthUrl:   'http://127.0.0.1:19999/pool/health',
  networkDiffUrls: ['http://127.0.0.1:19999/api/networkinfo'],
  threshold:       0.05,   // 5% — così scatta con le fasi mock
  pollIntervalMs:  5_000,  // ogni 5s
  gracePeriodMs:   15_000, // 15s grace
  fallbackPools:   [
    { host: 'pool.supportxmr.com',    port: 3333  },
    { host: 'gulf.moneroocean.stream', port: 10128 },
  ],
});

monitor.on('warn',       e => console.log(`[${ts()}] ⚠  WARN      pool=${(e.hashratePct*100).toFixed(1)}%  limit=${(e.threshold*100).toFixed(0)}%  source=${e.source}`));
monitor.on('crit',       e => console.log(`[${ts()}] 🔴 CRIT      pool=${(e.hashratePct*100).toFixed(1)}%  grace=15s  source=${e.source}`));
monitor.on('grace-tick', e => { if (e.secsLeft % 5 === 0 || e.secsLeft <= 3) console.log(`[${ts()}]    grace-tick secsLeft=${e.secsLeft}`); });
monitor.on('fork',       () => console.log(`[${ts()}] ⚡ FORK      immediate evacuate`));
monitor.on('safe',       e => console.log(`[${ts()}] ✓  SAFE      pool=${(e.hashratePct*100).toFixed(1)}%`));
monitor.on('evacuate',   e => {
  console.log(`[${ts()}] 🚨 EVACUATE  reason=${e.reason}  fallback=${e.fallback ? e.fallback.host+':'+e.fallback.port : 'none'}`);
  console.log(`[${ts()}]    → miner restarted on fallback, resuming monitor`);
  monitor.start();
});

console.log(`[${ts()}] HashrateMonitor started — threshold=5%  poll=5s  grace=15s`);
console.log(`[${ts()}] Mock phases: SAFE(10%) → WARN(27%) → CRIT(32%) → FORK → SAFE2(8%)  [20s each]\n`);

monitor.start();

// Auto-exit after 130s (all 5 phases × 20s + buffer)
setTimeout(() => { monitor.stop(); console.log(`\n[${ts()}] Test complete.`); process.exit(0); }, 130_000);
