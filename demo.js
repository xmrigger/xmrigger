#!/usr/bin/env node
/**
 * demo.js — xmr-hashguard combined demonstration
 *
 * Runs both guards back-to-back in a single terminal session.
 * No XMRig required. No external network calls. No configuration.
 *
 *   node demo.js          (or:  npm run demo)
 *
 * Part 1 — Hashrate Concentration Guard  (~50 s)
 *   Shows the full SAFE → WARN → CRIT → EVACUATE → FORK → SAFE cycle.
 *
 * Part 2 — Selfish Mining Detection  (~50 s)
 *   Shows two proxies in federation detecting prevhash divergence when
 *   one pool starts building on a private chain.
 *
 * Total runtime: ~100 s
 *
 * @license LGPL-2.1
 */
'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

const B     = s => `\x1b[1m${s}\x1b[0m`;
const cyan  = s => `\x1b[36m${s}\x1b[0m`;
const green = s => `\x1b[32m${s}\x1b[0m`;
const grey  = s => `\x1b[90m${s}\x1b[0m`;

function banner(part, title, desc) {
  const line = '═'.repeat(60);
  console.log(`\n${cyan(line)}`);
  console.log(`${B(cyan(`  Part ${part} of 2 — ${title}`))}`);
  console.log(`  ${grey(desc)}`);
  console.log(`${cyan(line)}\n`);
}

function run(file) {
  spawnSync(process.execPath, [path.join(__dirname, file)], { stdio: 'inherit' });
}

console.log(`
${B('╔══════════════════════════════════════════════════════════╗')}
${B('║')}              ${B('xmr-hashguard  v0.1.0  —  Demo')}              ${B('║')}
${B('╠══════════════════════════════════════════════════════════╣')}
${B('║')}  Two guards, two threats, zero protocol changes.        ${B('║')}
${B('║')}  Runtime: ~100 s  ·  No XMRig  ·  No network calls     ${B('║')}
${B('╚══════════════════════════════════════════════════════════╝')}
`);

banner(1, 'Hashrate Concentration Guard',
  'Auto-evacuate when a pool exceeds 30% of network hashrate.');
run('poc/demo.js');

banner(2, 'Selfish Mining Detection (Prevhash)',
  'Detect private forks by comparing prevhash across a proxy federation.');
run('poc/demo-prevhash.js');

const line = '═'.repeat(60);
console.log(`\n${green(line)}`);
console.log(`${B(green('  Both guards demonstrated successfully.'))}`);
console.log(`  ${grey('See SPEC.md for protocol details.')}`);
console.log(`${green(line)}\n`);
