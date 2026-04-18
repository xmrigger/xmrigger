#!/usr/bin/env node
/**
 * xmrig-guard — XMRig wrapper with hashrate concentration guard
 *
 * Wraps XMRig and monitors the pool's share of total Monero network hashrate.
 * When the pool exceeds the configured threshold, XMRig is gracefully
 * restarted pointing to the next fallback pool.
 *
 * Pool hashrate is measured from INDEPENDENT sources — a pool that refuses
 * to expose its stats cannot hide concentration from this guard.
 *
 * Usage:
 *   node xmrig-guard.js \
 *     --pool      pool.hashvault.pro:3333 \
 *     --wallet    <your-monero-address> \
 *     --pool-stats  https://third-party-stats/api/hashvault \
 *     --pool-health http://pool.hashvault.pro/pool/health \
 *     --fallback  pool.supportxmr.com:3333 \
 *     --fallback  gulf.moneroocean.stream:10128 \
 *     [--threshold 0.30]  (default: 30%)
 *     [--grace 60]        (default: 60s)
 *     [--poll 30]         (default: 30s)
 *     [--threads 2]
 *     [--xmrig /path/to/xmrig]
 *     [--network-diff-url http://custom/networkinfo]  (for testing)
 *
 * @license LGPL-2.1
 */
'use strict';

const { spawn }           = require('child_process');
const { HashrateMonitor } = require('../src/hashrate-monitor');
const fs                  = require('fs');

// ── Arg parsing ──────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
function getArg(name, def) {
  const idx = args.indexOf('--' + name);
  return idx >= 0 && args[idx + 1] ? args[idx + 1] : def;
}
function getAllArgs(name) {
  const result = [];
  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] === '--' + name) result.push(args[i + 1]);
  }
  return result;
}

const primaryPool       = getArg('pool',             'pool.hashvault.pro:3333');
const poolStatsUrl      = getArg('pool-stats',       null);
const poolHealthUrl     = getArg('pool-health',      null);
const networkDiffUrlArg = getArg('network-diff-url', null);
const wallet            = getArg('wallet',           null);
const threads           = parseInt(getArg('threads', '1'));
const threshold         = parseFloat(getArg('threshold', '0.30'));
const graceSecs         = parseInt(getArg('grace',   '60'));
const pollSecs          = parseInt(getArg('poll',    '30'));

// Auto-detect XMRig
function findXmrig() {
  const candidates = [
    getArg('xmrig', null),
    process.env.XMRIG_PATH,
    '/usr/bin/xmrig',
    '/usr/local/bin/xmrig',
    'xmrig',
  ].filter(Boolean);
  for (const p of candidates) {
    try { if (fs.existsSync(p)) return p; } catch {}
  }
  return 'xmrig';
}
const xmrigPath = findXmrig();

if (!wallet) {
  console.error('[xmrig-guard] --wallet <monero-address> is required');
  process.exit(1);
}
if (!poolStatsUrl && !poolHealthUrl) {
  console.error('[xmrig-guard] Provide --pool-stats (independent) and/or --pool-health');
  process.exit(1);
}

const fallbackArgs = getAllArgs('fallback');
const allPools = [primaryPool, ...fallbackArgs].map((s) => {
  const [host, portStr] = s.split(':');
  return { host, port: parseInt(portStr) || 3333 };
});

// ── State ────────────────────────────────────────────────────────────────────

let currentPool = allPools[0];
let xmrigProc   = null;
let shuttingDown = false;

// ── XMRig launcher ───────────────────────────────────────────────────────────

function startXMRig(pool) {
  if (xmrigProc) { try { xmrigProc.kill(); } catch {} xmrigProc = null; }

  const xmrigArgs = [
    '--algo', 'rx/0',
    '--url',  `${pool.host}:${pool.port}`,
    '--user', wallet,
    '--pass', 'x',
    '--threads', String(threads),
    '--no-color',
  ];

  console.log(`[xmrig-guard] Starting XMRig → ${pool.host}:${pool.port}`);
  xmrigProc = spawn(xmrigPath, xmrigArgs, { stdio: 'inherit' });
  xmrigProc.on('exit', (code) => {
    if (!shuttingDown) {
      console.warn(`[xmrig-guard] XMRig exited (${code}) — restarting in 5s`);
      setTimeout(() => startXMRig(currentPool), 5000);
    }
  });
}

// ── Hashrate monitor ─────────────────────────────────────────────────────────

const monitor = new HashrateMonitor({
  poolStatsUrl,
  poolHealthUrl,
  networkDiffUrls: networkDiffUrlArg ? [networkDiffUrlArg] : undefined,
  threshold,
  pollIntervalMs:  pollSecs * 1000,
  gracePeriodMs:   graceSecs * 1000,
  fallbackPools:   allPools.slice(1),
});

monitor.on('warn', ({ hashratePct, source }) => {
  console.warn(`[xmrig-guard] WARNING  pool=${(hashratePct*100).toFixed(1)}%  limit=${(threshold*100).toFixed(0)}%  source=${source}`);
});
monitor.on('crit', ({ hashratePct, source }) => {
  console.error(`[xmrig-guard] CRITICAL pool=${(hashratePct*100).toFixed(1)}%  grace=${graceSecs}s  source=${source}`);
});
monitor.on('grace-tick', ({ secsLeft }) => {
  if (secsLeft % 10 === 0 || secsLeft <= 5) {
    console.warn(`[xmrig-guard] Disconnecting in ${secsLeft}s…`);
  }
});
monitor.on('fork', () => {
  console.error('[xmrig-guard] FORK DETECTED — switching pool immediately');
});
monitor.on('evacuate', ({ reason, fallback }) => {
  if (fallback) {
    currentPool = fallback;
    console.error(`[xmrig-guard] EVACUATE (${reason}) → ${fallback.host}:${fallback.port}`);
    startXMRig(fallback);
    monitor.start();
  } else {
    console.error('[xmrig-guard] No fallback configured — stopping for 5 min then retrying primary');
    if (xmrigProc) { try { xmrigProc.kill(); } catch {} xmrigProc = null; }
    setTimeout(() => { currentPool = allPools[0]; monitor.start(); startXMRig(currentPool); }, 300_000);
  }
});
monitor.on('safe', ({ hashratePct }) => {
  console.log(`[xmrig-guard] Pool safe at ${(hashratePct*100).toFixed(1)}%`);
});

// ── Main ─────────────────────────────────────────────────────────────────────

console.log(`
┌─────────────────────────────────────────────┐
│           xmrigger  v0.1.0             │
├─────────────────────────────────────────────┤
│  Pool      ${(primaryPool + '                         ').slice(0,33)}│
│  Threshold ${((threshold*100).toFixed(0)+'%'+'                         ').slice(0,33)}│
│  Grace     ${(graceSecs+'s'+'                         ').slice(0,33)}│
│  Fallbacks ${(String(fallbackArgs.length)+' configured'+'                  ').slice(0,33)}│
│  XMRig     ${(xmrigPath+'                         ').slice(0,33)}│
└─────────────────────────────────────────────┘
`);

startXMRig(currentPool);
monitor.start();

process.on('SIGINT',  () => { shuttingDown = true; monitor.stop(); if (xmrigProc) { try { xmrigProc.kill(); } catch {} } process.exit(0); });
process.on('SIGTERM', () => { shuttingDown = true; monitor.stop(); if (xmrigProc) { try { xmrigProc.kill(); } catch {} } process.exit(0); });
