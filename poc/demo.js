#!/usr/bin/env node
/**
 * poc/demo.js — xmrigger self-contained demonstration
 *
 * No XMRig required. No external network calls. One command:
 *
 *   node poc/demo.js
 *
 * Starts a local mock HTTP server that cycles through five phases,
 * then runs HashrateMonitor against it. Exits automatically in ~75s.
 *
 * Phase sequence (12s each):
 *   SAFE  (10%)         — below warn threshold
 *   WARN  (40%)         — ⚠ warn event  [threshold=43%, warn=36.6%]
 *   CRIT  (50%)         — 🔴 crit + grace countdown → 🚨 evacuate
 *   FORK  (50%+fork)    — ⚡ fork detected → 🚨 immediate evacuate
 *   SAFE2  (8%)         — ✓ safe — mining resumed
 *
 * @license LGPL-2.1
 */
'use strict';

const http  = require('http');
const { HashrateMonitor } = require('../src/hashrate-monitor');

// ── Terminal colours ──────────────────────────────────────────────────────────
const R      = '\x1b[0m';
const B      = s => `\x1b[1m${s}${R}`;
const green  = s => `\x1b[32m${s}${R}`;
const yellow = s => `\x1b[33m${s}${R}`;
const red    = s => `\x1b[31m${s}${R}`;
const cyan   = s => `\x1b[36m${s}${R}`;
const grey   = s => `\x1b[90m${s}${R}`;
const magenta= s => `\x1b[35m${s}${R}`;

const ts  = () => new Date().toISOString().slice(11, 23);
const pad = (label, width = 10) => label.padEnd(width);

function line(colour, label, msg) {
  process.stdout.write(`${grey(ts())}  ${colour(pad(label))}  ${msg}\n`);
}

// ── Mock HTTP server (embedded — no child process) ────────────────────────────

const NETWORK_DIFF = 1_000_000_000 * 120;   // difficulty → 1 GH/s network

const PHASES = [
  { name: 'SAFE',  pct: 0.10, fork: false },
  { name: 'WARN',  pct: 0.40, fork: false },
  { name: 'CRIT',  pct: 0.50, fork: false },
  { name: 'FORK',  pct: 0.50, fork: true  },
  { name: 'SAFE2', pct: 0.08, fork: false },
];
const PHASE_MS = 12_000;

let phaseIdx = 0;
const phaseTimer = setInterval(() => {
  phaseIdx = (phaseIdx + 1) % PHASES.length;
  const p = PHASES[phaseIdx];
  line(magenta, '[mock]', `→ phase ${B(p.name.padEnd(5))}  ${(p.pct * 100).toFixed(0).padStart(3)}%  fork=${p.fork}`);
}, PHASE_MS);

const server = http.createServer((req, res) => {
  const p = PHASES[phaseIdx];
  res.setHeader('Content-Type', 'application/json');
  if (req.url === '/pool/health') {
    res.end(JSON.stringify({
      hashratePct:    p.pct,
      forkDetected:   p.fork,
      _phase:         p.name,
    }));
  } else if (req.url === '/api/networkinfo') {
    res.end(JSON.stringify({ difficulty: NETWORK_DIFF }));
  } else {
    res.writeHead(404); res.end();
  }
});

server.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  runDemo(port);
});

// ── Demo ──────────────────────────────────────────────────────────────────────

function runDemo(port) {
  const BASE = `http://127.0.0.1:${port}`;

  console.log(`
${B('╔══════════════════════════════════════════════════════════╗')}
${B('║')}           ${B('xmrigger v0.1.0  —  Live Demo')}            ${B('║')}
${B('╠══════════════════════════════════════════════════════════╣')}
${B('║')}  Threshold : 43%    Warn at : 36.6%                     ${B('║')}
${B('║')}  Grace     : 9 s    Poll    : every 3 s                 ${B('║')}
${B('║')}  Sequence  : SAFE → WARN → CRIT → FORK → SAFE2          ${B('║')}
${B('║')}             12 s each  ·  ~75 s total  ·  no XMRig      ${B('║')}
${B('╚══════════════════════════════════════════════════════════╝')}
`);

  const monitor = new HashrateMonitor({
    poolHealthUrl:   `${BASE}/pool/health`,
    networkDiffUrls: [`${BASE}/api/networkinfo`],
    threshold:       0.43,
    pollIntervalMs:  3_000,
    gracePeriodMs:   9_000,
    fallbackPools: [
      { host: 'pool.supportxmr.com',     port: 3333  },
      { host: 'gulf.moneroocean.stream',  port: 10128 },
    ],
  });

  // ── Event handlers ──────────────────────────────────────────────────────────

  monitor.on('warn', e => {
    line(yellow, '⚠  WARN', `pool = ${yellow((e.hashratePct * 100).toFixed(1) + '%')}  threshold = ${(e.threshold * 100).toFixed(0)}%  source = ${e.source}`);
  });

  monitor.on('crit', e => {
    line(red, '🔴 CRIT', `pool = ${red((e.hashratePct * 100).toFixed(1) + '%')}  grace = 9s  source = ${e.source}`);
  });

  monitor.on('grace-tick', e => {
    if (e.secsLeft % 3 === 0 || e.secsLeft <= 3) {
      line(red, '   tick', `evacuating in ${red(e.secsLeft + 's')}…`);
    }
  });

  monitor.on('fork', () => {
    line(red, '⚡ FORK', red('chain fork detected — skipping grace period'));
  });

  monitor.on('evacuate', e => {
    const dest = e.fallback ? `${e.fallback.host}:${e.fallback.port}` : 'none';
    line(red, '🚨 EVACUATE', `reason = ${red(e.reason)}   fallback = ${B(dest)}`);
    line(cyan, '   action', 'XMRig stopped · restarting on fallback · resuming guard');
    monitor.start();
  });

  monitor.on('safe', e => {
    line(green, '✓  SAFE', green(`pool back to ${(e.hashratePct * 100).toFixed(1)}%  —  mining safely resumed`));
  });

  // ── Start ───────────────────────────────────────────────────────────────────

  line(cyan, '[guard]', `monitor started  threshold=43%  warn=36.6%  poll=3s  grace=9s\n`);
  monitor.start();

  // Auto-exit after all phases + small buffer
  const totalMs = PHASES.length * PHASE_MS + 15_000;
  setTimeout(() => {
    monitor.stop();
    clearInterval(phaseTimer);
    server.close();
    console.log(`\n${green('═'.repeat(60))}`);
    console.log(`${B(green('  Demo complete.'))}  All five events demonstrated successfully.`);
    console.log(green('═'.repeat(60)));
    console.log();
    process.exit(0);
  }, totalMs);
}
