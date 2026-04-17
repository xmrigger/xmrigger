#!/usr/bin/env node
/**
 * poc/demo-prevhash.js — prevhash divergence detector, self-contained demo
 *
 * No XMRig. No real pools. One command:
 *
 *   node poc/demo-prevhash.js
 *
 * Simulates two proxies connected to different pools in a federation.
 * When one pool starts building on a private chain, the divergence is
 * detected by comparing the prevhash values the pools leak in their
 * Stratum job messages.
 *
 * Phases (12 s each, ~60 s total):
 *   SYNC      — both pools on block_100  (same chain, all good)
 *   FORK      — Pool B switches to block_101_private  (selfish mining starts)
 *   [9 s in]  — divergence confirmed after persistence threshold
 *   REVEAL    — Pool B switches to block_101_public   (resolved)
 *
 * @license LGPL-2.1
 */
'use strict';

const http = require('http');
const { PrevhashMonitor } = require('../src/prevhash-monitor');

// ── ANSI ──────────────────────────────────────────────────────────────────────
const R      = '\x1b[0m';
const B      = s => `\x1b[1m${s}${R}`;
const green  = s => `\x1b[32m${s}${R}`;
const yellow = s => `\x1b[33m${s}${R}`;
const red    = s => `\x1b[31m${s}${R}`;
const cyan   = s => `\x1b[36m${s}${R}`;
const grey   = s => `\x1b[90m${s}${R}`;
const magenta= s => `\x1b[35m${s}${R}`;

const ts  = () => new Date().toISOString().slice(11, 23);
function line(colour, label, msg) {
  process.stdout.write(`${grey(ts())}  ${colour(label.padEnd(14))}  ${msg}\n`);
}

// ── Mock prevhash values ──────────────────────────────────────────────────────
// Shortened for readability; real prevhash = 64 hex chars
const BLOCK_100        = 'a1b2c3d4e5f6...100';   // current public tip
const BLOCK_101_PRIV   = 'deadbeef0000...101P';   // private fork (Pool B only)
const BLOCK_101_PUB    = 'f1e2d3c4b5a6...101';    // next public block after reveal

// ── Phase state ───────────────────────────────────────────────────────────────
const PHASES = [
  { name: 'SYNC',   phA: BLOCK_100,      phB: BLOCK_100,      desc: 'Both pools on same chain tip' },
  { name: 'FORK',   phA: BLOCK_100,      phB: BLOCK_101_PRIV, desc: 'Pool B on private fork!' },
  { name: 'REVEAL', phA: BLOCK_101_PUB,  phB: BLOCK_101_PUB,  desc: 'Pool B reveals — chains sync' },
  { name: 'SYNC2',  phA: BLOCK_101_PUB,  phB: BLOCK_101_PUB,  desc: 'Normal operation resumed' },
];
const PHASE_MS = 12_000;

let phaseIdx = 0;
const phaseTimer = setInterval(() => {
  phaseIdx = Math.min(phaseIdx + 1, PHASES.length - 1);
  const p = PHASES[phaseIdx];
  line(magenta, '[phase →]', `${B(p.name.padEnd(7))}  ${p.desc}`);
  line(magenta, '  Pool A', `prevhash = ${p.phA}`);
  line(magenta, '  Pool B', `prevhash = ${p.phB}`);
}, PHASE_MS);

// ── Mock HTTP server (both pool endpoints on one server) ──────────────────────
const server = http.createServer((req, res) => {
  const ph = PHASES[phaseIdx];
  res.setHeader('Content-Type', 'application/json');
  if (req.url === '/pool/a/prevhash') {
    res.end(JSON.stringify({ prevhash: ph.phA, pool: 'Pool-A' }));
  } else if (req.url === '/pool/b/prevhash') {
    res.end(JSON.stringify({ prevhash: ph.phB, pool: 'Pool-B' }));
  } else {
    res.writeHead(404); res.end();
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function fetchPrevhash(url) {
  return new Promise((resolve) => {
    http.get(url, (res) => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try { resolve(JSON.parse(raw).prevhash); } catch { resolve(null); }
      });
    }).on('error', () => resolve(null));
  });
}

// ── Start demo ────────────────────────────────────────────────────────────────
server.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  const BASE = `http://127.0.0.1:${port}`;

  console.log(`
${B('╔══════════════════════════════════════════════════════════╗')}
${B('║')}    ${B('xmr-hashguard — Prevhash Divergence Demo (v0.1.0)')}    ${B('║')}
${B('╠══════════════════════════════════════════════════════════╣')}
${B('║')}  Technique : cross-pool prevhash comparison             ${B('║')}
${B('║')}  Requires  : zero protocol changes                      ${B('║')}
${B('║')}  Threshold : 9 s persistence before alert               ${B('║')}
${B('║')}  Phases    : SYNC → FORK → REVEAL → SYNC2               ${B('║')}
${B('║')}             12 s each  ·  ~60 s total                   ${B('║')}
${B('╚══════════════════════════════════════════════════════════╝')}
`);

  // ── Proxy A monitors Pool A ───────────────────────────────────────────────
  let _prevhashA = null;
  const monA = new PrevhashMonitor({
    poolId:        'Pool-A (honest)',
    getPrevhash:   () => _prevhashA,
    pollIntervalMs: 3_000,
    divergenceMs:   9_000,
  });

  // ── Proxy B monitors Pool B ───────────────────────────────────────────────
  let _prevhashB = null;
  const monB = new PrevhashMonitor({
    poolId:        'Pool-B (suspect)',
    getPrevhash:   () => _prevhashB,
    pollIntervalMs: 3_000,
    divergenceMs:   9_000,
  });

  // ── Federation: proxies share prevhash announcements ─────────────────────
  // In production this goes over the WebSocket federation mesh.
  // In this demo we wire them directly.

  monA.on('announce', ({ prevhash }) => {
    line(cyan, '[A→fed]', `prevhash = ${prevhash}`);
    monB.onPeerAnnounce('Proxy-A', prevhash);
  });

  monB.on('announce', ({ prevhash }) => {
    line(cyan, '[B→fed]', `prevhash = ${prevhash}`);
    monA.onPeerAnnounce('Proxy-B', prevhash);
  });

  // ── Proxy A events ────────────────────────────────────────────────────────
  monA.on('divergence', ({ ownPrevhash, divergentPeers, seenMs }) => {
    line(red, '🔴 [A] DIV', `Proxy-A sees ${red(ownPrevhash)}`);
    for (const p of divergentPeers) {
      line(red, '   ↳ peer', `${p.peerId} reports ${red(p.prevhash)}  (divergence: ${Math.round(seenMs/1000)}s)`);
    }
    line(red, '   ⚠ action', red('Pool-A diverges from federation — possible selfish mining'));
  });

  monA.on('resolved', ({ prevhash }) => {
    line(green, '✓ [A] SYNC', green(`chains agree again  prevhash = ${prevhash}`));
  });

  // ── Proxy B events ────────────────────────────────────────────────────────
  monB.on('divergence', ({ ownPrevhash, divergentPeers, seenMs }) => {
    line(red, '🔴 [B] DIV', `Proxy-B sees ${red(ownPrevhash)}`);
    for (const p of divergentPeers) {
      line(red, '   ↳ peer', `${p.peerId} reports ${red(p.prevhash)}  (divergence: ${Math.round(seenMs/1000)}s)`);
    }
    line(red, '   🚨 alert', red('Pool-B on private fork — SELFISH MINING DETECTED'));
    line(yellow, '   action', 'evacuating miners from Pool-B → fallback pool');
  });

  monB.on('resolved', ({ prevhash }) => {
    line(green, '✓ [B] SYNC', green(`Pool-B back on public chain  prevhash = ${prevhash}`));
  });

  // ── Fetch loop (simulates proxy intercepting Stratum prevhash) ────────────
  async function fetchAll() {
    const [a, b] = await Promise.all([
      fetchPrevhash(`${BASE}/pool/a/prevhash`),
      fetchPrevhash(`${BASE}/pool/b/prevhash`),
    ]);
    _prevhashA = a;
    _prevhashB = b;
  }

  fetchAll();  // prime before start()
  setInterval(fetchAll, 3_000);

  // ── Start monitors ────────────────────────────────────────────────────────
  const p0 = PHASES[0];
  line(cyan, '[guard]', `monitors started  poll=3s  divergence-threshold=9s\n`);
  line(magenta, '[phase →]', `${B(p0.name.padEnd(7))}  ${p0.desc}`);
  line(magenta, '  Pool A', `prevhash = ${p0.phA}`);
  line(magenta, '  Pool B', `prevhash = ${p0.phB}\n`);

  monA.start();
  monB.start();

  // ── Auto-exit ─────────────────────────────────────────────────────────────
  const totalMs = PHASES.length * PHASE_MS + 12_000;
  setTimeout(() => {
    monA.stop(); monB.stop();
    clearInterval(phaseTimer);
    server.close();
    console.log(`\n${green('═'.repeat(60))}`);
    console.log(`${B(green('  Demo complete.'))}  Prevhash divergence detected without protocol changes.`);
    console.log(green('═'.repeat(60))+ '\n');
    process.exit(0);
  }, totalMs);
});
