'use strict';
/**
 * integration.js — Federated multi-instance integration test for PrevhashMonitor.
 *
 * @license LGPL-2.1
 *
 * What this verifies
 * ──────────────────
 * Three PrevhashMonitor instances ("pool-A", "pool-B", "pool-C") run side by
 * side, federated through an in-process broadcast bus, and are walked through
 * five scenarios that cover the contract of the v0.2 design:
 *
 *   S1  Unanimous consensus across rolling blocks → no alerts, no resolveds.
 *   S2  One pool mines a private tip, the other two stay honest → only the
 *       guilty pool raises divergence on itself; honest pools stay silent.
 *   S3  A single Sybil node spams a fake tip into the federation → majority
 *       vote neutralises it, no alerts anywhere.
 *   S4  One pool lags 1–2 ticks behind on every new block (propagation jitter)
 *       → historyK absorbs it, no alerts.
 *   S5  Selfish pool raises divergence, then rejoins the canonical chain
 *       → exactly one 'divergence' followed by exactly one 'resolved'.
 *
 * Determinism
 * ───────────
 * Time is driven by a VirtualClock that advances in fixed 1 ms increments.
 * No setTimeout, no setInterval, no wall-clock. The same input produces the
 * same output bit-perfect on every machine; a third party reproducing the run
 * gets identical numbers.
 *
 * Reproduce
 * ─────────
 *   cd <repo-root>
 *   node test/integration.js
 *
 * Exit code 0 if every assertion holds, 1 otherwise. A machine-readable JSON
 * summary is printed on the last line, suitable for CI grepping.
 */

const path                          = require('path');
const { EventEmitter }              = require('events');
const { PrevhashMonitor }           = require(path.join('..', 'src', 'prevhash-monitor'));

// ── VirtualClock ─────────────────────────────────────────────────────────────
// Drop-in replacement for {now, setInterval, clearInterval}. Time only moves
// forward when advance(ms) is called. Timer callbacks fire in deterministic
// order: by next-fire time first, then by insertion order on ties.

class VirtualClock {
  constructor() {
    this.t        = 0;
    this._timers  = new Map();   // id → { fn, period, next, seq }
    this._nextId  = 1;
    this._seq     = 0;
  }
  now() { return this.t; }
  setInterval(fn, ms) {
    const id = this._nextId++;
    this._timers.set(id, { fn, period: ms, next: this.t + ms, seq: this._seq++ });
    return id;
  }
  clearInterval(id) { this._timers.delete(id); }
  /**
   * Advance virtual time by `ms`. Any timer whose nextFire falls inside the
   * window is invoked at that exact virtual time, then rescheduled by its
   * period. Order: nextFire ascending, then insertion order.
   */
  advance(ms) {
    const target = this.t + ms;
    while (true) {
      // Find the timer with the smallest (next, seq) tuple, next <= target.
      let pick = null;
      for (const [id, t] of this._timers) {
        if (t.next > target) continue;
        if (pick === null) { pick = { id, t }; continue; }
        if (t.next < pick.t.next ||
            (t.next === pick.t.next && t.seq < pick.t.seq)) {
          pick = { id, t };
        }
      }
      if (pick === null) break;
      this.t = pick.t.next;
      pick.t.next += pick.t.period;
      pick.t.fn();
    }
    this.t = target;
  }
}

// ── Federation bus ───────────────────────────────────────────────────────────
// In-process broadcast bus. Each monitor publishes its own announces, and
// subscribes to everyone else's. A node id stamps each announce so a monitor
// can filter out its own echo.

class FederationBus extends EventEmitter {}

function federate(bus, monitor, nodeId, clock) {
  monitor.on('announce', ({ prevhash }) => {
    bus.emit('announce', { from: nodeId, prevhash, ts: clock.now() });
  });
  bus.on('announce', ({ from, prevhash, ts }) => {
    if (from === nodeId) return;
    monitor.onPeerAnnounce(from, prevhash, ts);
  });
  return monitor;
}

// ── Tiny assertion harness ───────────────────────────────────────────────────

const results = [];
function record(name, ok, detail = '') {
  results.push({ name, ok, detail });
  process.stdout.write(`  [${ok ? 'PASS' : 'FAIL'}] ${name}` +
                       (detail ? '  -- ' + detail : '') + '\n');
}
function section(title) {
  process.stdout.write('\n' + '-'.repeat(72) + '\n' + title + '\n' + '-'.repeat(72) + '\n');
}

// ── Test fixture ─────────────────────────────────────────────────────────────

function build() {
  const clock = new VirtualClock();
  const bus   = new FederationBus();
  bus.setMaxListeners(50);

  const tip = { A: null, B: null, C: null };

  // Polling cadence: 10 ms virtual.
  // historyK = 3       -> minimum 3 polling ticks = 30 ms
  // divergenceMs = 50  -> wall-clock floor
  // Both must be satisfied. With these values, an alert fires after >= 50 ms
  // of stable minority that includes >= 3 polls.
  const common = {
    pollIntervalMs:   10,
    divergenceMs:     50,
    minPeersForAlert: 1,
    historyK:         3,
    majorityVote:     true,
    clock,
  };

  const mA = federate(bus, new PrevhashMonitor({
    poolId: 'pool-A', getPrevhash: () => tip.A, ...common,
  }), 'pool-A', clock);
  const mB = federate(bus, new PrevhashMonitor({
    poolId: 'pool-B', getPrevhash: () => tip.B, ...common,
  }), 'pool-B', clock);
  const mC = federate(bus, new PrevhashMonitor({
    poolId: 'pool-C', getPrevhash: () => tip.C, ...common,
  }), 'pool-C', clock);

  return { clock, bus, tip, mA, mB, mC };
}

function attach(monitor, label, alerts, resolveds) {
  monitor.on('divergence', (ev) => alerts.push({ at: label, ...ev }));
  monitor.on('resolved',   (ev) => resolveds.push({ at: label, ...ev }));
}

// ── Scenarios ────────────────────────────────────────────────────────────────

function s1_unanimous() {
  section('S1  Unanimous consensus (no alert anywhere)');
  const { clock, tip, mA, mB, mC } = build();
  const alerts = [], resolveds = [];
  attach(mA, 'A', alerts, resolveds);
  attach(mB, 'B', alerts, resolveds);
  attach(mC, 'C', alerts, resolveds);

  tip.A = tip.B = tip.C = 'block-100';
  mA.start(); mB.start(); mC.start();
  clock.advance(200);

  tip.A = tip.B = tip.C = 'block-101';
  clock.advance(200);

  mA.stop(); mB.stop(); mC.stop();

  record('S1.1 zero divergence alerts',
         alerts.length === 0, `got ${alerts.length}`);
  record('S1.2 zero resolved events',
         resolveds.length === 0, `got ${resolveds.length}`);
}

function s2_selfishMining() {
  section('S2  Selfish mining: A on private tip vs honest B and C');
  const { clock, tip, mA, mB, mC } = build();
  const alerts = [], resolveds = [];
  attach(mA, 'A', alerts, resolveds);
  attach(mB, 'B', alerts, resolveds);
  attach(mC, 'C', alerts, resolveds);

  tip.A = tip.B = tip.C = 'block-200';
  mA.start(); mB.start(); mC.start();
  clock.advance(100);

  tip.B = 'block-201';
  tip.C = 'block-201';
  tip.A = 'block-200x';   // private fork tip
  clock.advance(200);     // > divergenceMs and > historyK polls

  mA.stop(); mB.stop(); mC.stop();

  const atA = alerts.filter(a => a.at === 'A');
  const atB = alerts.filter(a => a.at === 'B');
  const atC = alerts.filter(a => a.at === 'C');

  record('S2.1 guilty pool A raises divergence on itself',
         atA.length >= 1, `alerts@A=${atA.length}`);
  record('S2.2 honest pool B stays silent',
         atB.length === 0, `alerts@B=${atB.length}`);
  record('S2.3 honest pool C stays silent',
         atC.length === 0, `alerts@C=${atC.length}`);
  if (atA[0]) {
    record('S2.4 canonical verdict at A equals honest tip',
           atA[0].canonical === 'block-201',
           `canonical=${atA[0].canonical}`);
    record('S2.5 ownPrevhash at A differs from canonical',
           atA[0].ownPrevhash === 'block-200x',
           `own=${atA[0].ownPrevhash}`);
    record('S2.6 sampleCount at A is at least historyK=3',
           atA[0].sampleCount >= 3, `sampleCount=${atA[0].sampleCount}`);
  }
}

function s3_singleSybil() {
  section('S3  Single Sybil peer announces a fake tip');
  const { clock, bus, tip, mA, mB, mC } = build();
  const alerts = [], resolveds = [];
  attach(mA, 'A', alerts, resolveds);
  attach(mB, 'B', alerts, resolveds);
  attach(mC, 'C', alerts, resolveds);

  tip.A = tip.B = tip.C = 'block-300';
  mA.start(); mB.start(); mC.start();
  clock.advance(50);

  // Sybil spam: a synthetic node posts a fake tip at every tick.
  // We mount a setInterval-on-the-virtual-clock that fires alongside the
  // monitors' own polls.
  const spamId = clock.setInterval(() => {
    bus.emit('announce', {
      from: 'sybil-pool', prevhash: 'block-fake', ts: clock.now(),
    });
  }, 10);
  clock.advance(200);
  clock.clearInterval(spamId);

  mA.stop(); mB.stop(); mC.stop();

  record('S3.1 A silent (majority neutralises Sybil)',
         alerts.filter(a => a.at === 'A').length === 0,
         `alerts@A=${alerts.filter(a => a.at === 'A').length}`);
  record('S3.2 B silent',
         alerts.filter(a => a.at === 'B').length === 0,
         `alerts@B=${alerts.filter(a => a.at === 'B').length}`);
  record('S3.3 C silent',
         alerts.filter(a => a.at === 'C').length === 0,
         `alerts@C=${alerts.filter(a => a.at === 'C').length}`);
}

function s4_propagationJitter() {
  section('S4  Propagation jitter: A lags 2 ticks behind on every roll');
  const { clock, tip, mA, mB, mC } = build();
  const alerts = [], resolveds = [];
  attach(mA, 'A', alerts, resolveds);
  attach(mB, 'B', alerts, resolveds);
  attach(mC, 'C', alerts, resolveds);

  tip.A = tip.B = tip.C = 'block-400';
  mA.start(); mB.start(); mC.start();
  clock.advance(50);

  for (let i = 1; i <= 3; i++) {
    const next = `block-40${i}`;
    tip.B = next;
    tip.C = next;
    // A lags by 20 ms (= 2 polling ticks at 10 ms each). Under divergenceMs=50
    // AND under historyK=3 consecutive *fully* minority ticks, this cannot
    // accumulate into an alert because A catches up before historyK is met.
    clock.advance(20);
    tip.A = next;
    clock.advance(50);
  }

  clock.advance(50);
  mA.stop(); mB.stop(); mC.stop();

  record('S4.1 A silent (historyK absorbs the lag)',
         alerts.filter(a => a.at === 'A').length === 0,
         `alerts@A=${alerts.filter(a => a.at === 'A').length}`);
  record('S4.2 B silent',
         alerts.filter(a => a.at === 'B').length === 0,
         `alerts@B=${alerts.filter(a => a.at === 'B').length}`);
  record('S4.3 C silent',
         alerts.filter(a => a.at === 'C').length === 0,
         `alerts@C=${alerts.filter(a => a.at === 'C').length}`);
}

function s5_divergeThenResolve() {
  section('S5  Divergence followed by rejoin: exactly one divergence + one resolved');
  const { clock, tip, mA, mB, mC } = build();
  const alerts = [], resolveds = [];
  attach(mA, 'A', alerts, resolveds);
  attach(mB, 'B', alerts, resolveds);
  attach(mC, 'C', alerts, resolveds);

  tip.A = tip.B = tip.C = 'block-500';
  mA.start(); mB.start(); mC.start();
  clock.advance(50);

  tip.B = 'block-501';
  tip.C = 'block-501';
  tip.A = 'block-500x';
  clock.advance(200);   // divergence fires at A

  tip.A = 'block-501';  // A abandons private fork
  clock.advance(100);

  mA.stop(); mB.stop(); mC.stop();

  const aA = alerts.filter(a => a.at === 'A');
  const rA = resolveds.filter(r => r.at === 'A');

  record('S5.1 exactly one divergence at A',
         aA.length === 1, `alerts@A=${aA.length}`);
  record('S5.2 exactly one resolved at A',
         rA.length === 1, `resolved@A=${rA.length}`);
  if (rA[0]) {
    record('S5.3 resolved prevhash equals canonical block-501',
           rA[0].prevhash === 'block-501',
           `resolved.prevhash=${rA[0].prevhash}`);
  }
  record('S5.4 honest pools stayed silent',
         alerts.filter(a => a.at !== 'A').length === 0,
         `alerts@B+C=${alerts.filter(a => a.at !== 'A').length}`);
}

// ── Main ─────────────────────────────────────────────────────────────────────

process.stdout.write('\nPrevhashMonitor v0.2 -- federated integration (deterministic)\n');

s1_unanimous();
s2_selfishMining();
s3_singleSybil();
s4_propagationJitter();
s5_divergeThenResolve();

const passed = results.filter(r => r.ok).length;
const failed = results.filter(r => !r.ok).length;

process.stdout.write('\n' + '='.repeat(72) + '\n');
process.stdout.write(`SUMMARY: ${passed} passed, ${failed} failed (${results.length} checks)\n`);
process.stdout.write('='.repeat(72) + '\n');

if (failed > 0) {
  process.stdout.write('\nFailures:\n');
  for (const r of results.filter(x => !x.ok)) {
    process.stdout.write(`  - ${r.name}  (${r.detail})\n`);
  }
}

// Machine-readable last line for CI parsing.
process.stdout.write('\n' + JSON.stringify({
  suite:    'prevhash-monitor-integration',
  total:    results.length,
  passed,
  failed,
  failures: results.filter(r => !r.ok).map(r => ({ name: r.name, detail: r.detail })),
}) + '\n');

process.exit(failed === 0 ? 0 : 1);
