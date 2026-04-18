'use strict';
/**
 * xmrigger test suite — HashrateMonitor + PrevhashMonitor
 * Run: node test/index.js
 */

const { test, describe } = require('node:test');
const assert             = require('node:assert/strict');
const { HashrateMonitor } = require('../src/hashrate-monitor');
const { PrevhashMonitor } = require('../src/prevhash-monitor');

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Build a HashrateMonitor with:
 *   - localHashrate callback returning `poolH`
 *   - networkDiffUrls monkey-patched to return a fixed network hashrate via
 *     _fetchNetworkHashrate override — no real HTTP calls
 *   - gracePeriodMs defaults to 200 ms so tests finish quickly
 */
function makeMonitor(poolHashrate, networkHashrate, opts = {}) {
  const mon = new HashrateMonitor({
    localHashrate:   () => poolHashrate,
    networkDiffUrls: [],           // unused — we override below
    threshold:       opts.threshold       ?? 0.43,
    pollIntervalMs:  opts.pollIntervalMs  ?? 50,
    gracePeriodMs:   opts.gracePeriodMs   ?? 200,
    fallbackPools:   opts.fallbackPools   ?? [],
    enabled:         true,
  });
  // Override the internal network-fetch so no real HTTP is needed.
  mon._fetchNetworkHashrate = async () => networkHashrate;
  return mon;
}

/**
 * Resolve after `ms` milliseconds.
 */
const wait = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * Collect events from an emitter into an array.
 */
function collect(emitter, eventName) {
  const events = [];
  emitter.on(eventName, (data) => events.push(data));
  return events;
}

// ── HashrateMonitor ───────────────────────────────────────────────────────────

describe('HashrateMonitor state machine', () => {

  test('emits warn when hashratePct is in [threshold*0.85, threshold)', async () => {
    // threshold = 0.43 → warnLevel = 0.3655
    // poolHashrate / networkHashrate = 0.38 → in warn zone
    const networkH = 1_000_000;
    const poolH    = 380_000;  // 38% — above 36.55% warn, below 43% crit
    const mon = makeMonitor(poolH, networkH, { pollIntervalMs: 50 });
    const warns = collect(mon, 'warn');
    const crits = collect(mon, 'crit');

    mon.start();
    await wait(120);
    mon.stop();

    assert.ok(warns.length >= 1, 'should have emitted at least one warn');
    assert.strictEqual(crits.length, 0, 'should not have emitted crit');
    assert.ok(warns[0].hashratePct >= 0.43 * 0.85, 'hashratePct at or above warnLevel');
    assert.ok(warns[0].hashratePct < 0.43, 'hashratePct below threshold');
  });

  test('emits crit when hashratePct >= threshold', async () => {
    const networkH = 1_000_000;
    const poolH    = 500_000;  // 50% — above 43% threshold
    const mon = makeMonitor(poolH, networkH, { pollIntervalMs: 50, gracePeriodMs: 10_000 });
    const crits = collect(mon, 'crit');

    mon.start();
    await wait(120);
    mon.stop();

    assert.ok(crits.length >= 1, 'should have emitted at least one crit');
    assert.ok(crits[0].hashratePct >= 0.43, 'hashratePct at or above threshold');
  });

  test('emits safe when dropping below warn after being in warn zone', async () => {
    // We control poolHashrate via a mutable reference
    const state = { poolH: 380_000 };  // warn zone initially
    const networkH = 1_000_000;

    const mon = new HashrateMonitor({
      localHashrate:   () => state.poolH,
      networkDiffUrls: [],
      threshold:       0.43,
      pollIntervalMs:  50,
      gracePeriodMs:   10_000,
      enabled:         true,
    });
    mon._fetchNetworkHashrate = async () => networkH;

    const safes = collect(mon, 'safe');
    const warns = collect(mon, 'warn');

    mon.start();
    await wait(80);  // should have triggered warn

    // Drop to safe zone
    state.poolH = 100_000;  // 10%
    await wait(120);
    mon.stop();

    assert.ok(warns.length >= 1, 'should have emitted warn before drop');
    assert.ok(safes.length >= 1, 'should have emitted safe after drop');
    assert.ok(safes[0].hashratePct < 0.43 * 0.85, 'safe hashratePct below warnLevel');
  });

  test('evacuate NOT emitted before gracePeriodMs elapses', async () => {
    const networkH = 1_000_000;
    const poolH    = 600_000;  // 60% — crit
    const gracePeriodMs = 500;
    const mon = makeMonitor(poolH, networkH, {
      pollIntervalMs: 50,
      gracePeriodMs,
    });
    const evacuates = collect(mon, 'evacuate');

    mon.start();
    await wait(300);  // well within grace period
    mon.stop();

    assert.strictEqual(evacuates.length, 0,
      `evacuate must not fire within ${gracePeriodMs}ms grace period`);
  });

  test('evacuate emitted after gracePeriodMs if still in CRIT', async () => {
    const networkH = 1_000_000;
    const poolH    = 600_000;  // 60% — crit
    const gracePeriodMs = 200;
    const mon = makeMonitor(poolH, networkH, {
      pollIntervalMs:  50,
      gracePeriodMs,
      fallbackPools:   [{ host: 'fallback.pool', port: 3333 }],
    });
    const evacuates = collect(mon, 'evacuate');

    mon.start();
    // Wait: pollIntervalMs(50) + gracePeriodMs(200) + grace tick overhead (1000ms per tick by design)
    // The _startGrace uses setInterval(1s ticks) and fires evacuate when secsLeft <= 0.
    // gracePeriodMs=200 → secsLeft=1 (ceil(200/1000)) → fires after ~1s.
    // So wait at least 1100ms to be safe.
    await wait(1300);
    mon.stop();

    assert.ok(evacuates.length >= 1, 'evacuate must fire after grace period');
    assert.strictEqual(evacuates[0].fallback?.host, 'fallback.pool',
      'fallback pool should be provided in evacuate event');
  });

  test('fork detection: emits fork + immediate evacuate (no grace period)', async () => {
    // Use poolHealthUrl path which supports forkDetected flag
    const mon = new HashrateMonitor({
      poolHealthUrl:   'http://fake-pool/health',
      networkDiffUrls: [],
      threshold:       0.43,
      pollIntervalMs:  50,
      gracePeriodMs:   10_000,  // large — evacuate must arrive before this
      fallbackPools:   [{ host: 'safe.pool', port: 3333 }],
      enabled:         true,
    });

    // Stub both fetch methods
    mon._fetchNetworkHashrate = async () => 1_000_000;
    mon._fetchPoolHealth = async () => ({
      hashratePct: 0.30,  // below threshold
      forkDetected: true,
    });

    const forks     = collect(mon, 'fork');
    const evacuates = collect(mon, 'evacuate');

    mon.start();
    await wait(200);  // one or two polls, no grace period needed for fork
    mon.stop();

    assert.ok(forks.length >= 1,     'fork event must be emitted');
    assert.ok(evacuates.length >= 1, 'evacuate must be emitted immediately on fork');
    // Verify it arrived quickly — well before the 10s grace period
    assert.strictEqual(evacuates[0].reason, 'fork', 'evacuate reason must be fork');
  });

});

// ── PrevhashMonitor ───────────────────────────────────────────────────────────

describe('PrevhashMonitor divergence detection', () => {

  test('no alert with fewer than minPeersForAlert peers', async () => {
    let ownPrevhash = 'aabbccdd';
    const mon = new PrevhashMonitor({
      poolId:           'test-pool',
      getPrevhash:      () => ownPrevhash,
      pollIntervalMs:   30,
      divergenceMs:     50,
      minPeersForAlert: 2,  // require 2 peers
    });

    const divergences = collect(mon, 'divergence');

    mon.start();
    // Inject only ONE peer with a different prevhash
    mon.onPeerAnnounce('peer-A', 'deadbeef');
    await wait(150);
    mon.stop();

    assert.strictEqual(divergences.length, 0,
      'should not alert with only 1 peer when minPeersForAlert=2');
  });

  test('no alert when all peers agree with own prevhash', async () => {
    const SHARED = 'cafebabe';
    let ownPrevhash = SHARED;
    const mon = new PrevhashMonitor({
      poolId:           'test-pool',
      getPrevhash:      () => ownPrevhash,
      pollIntervalMs:   30,
      divergenceMs:     50,
      minPeersForAlert: 1,
    });

    const divergences = collect(mon, 'divergence');

    mon.start();
    mon.onPeerAnnounce('peer-A', SHARED);
    mon.onPeerAnnounce('peer-B', SHARED);
    await wait(150);
    mon.stop();

    assert.strictEqual(divergences.length, 0,
      'should not alert when all peers report same prevhash as own');
  });

  test('divergence emitted after divergenceMs when peers disagree', async () => {
    let ownPrevhash = 'aabbccdd';
    const mon = new PrevhashMonitor({
      poolId:           'test-pool',
      getPrevhash:      () => ownPrevhash,
      pollIntervalMs:   30,
      divergenceMs:     80,   // short window for fast test
      minPeersForAlert: 1,
    });

    const divergences = collect(mon, 'divergence');

    mon.start();
    mon.onPeerAnnounce('peer-A', 'deadbeef');  // different hash — start of divergence
    await wait(250);
    mon.stop();

    assert.ok(divergences.length >= 1, 'divergence must be emitted after divergenceMs');
    assert.strictEqual(divergences[0].ownPrevhash, ownPrevhash);
    assert.strictEqual(divergences[0].divergentPeers.length, 1);
    assert.strictEqual(divergences[0].divergentPeers[0].peerId, 'peer-A');
    assert.ok(divergences[0].seenMs >= 80, `seenMs (${divergences[0].seenMs}) should be >= divergenceMs`);
  });

  test('resolved emitted when peers return to same prevhash as own', async () => {
    let ownPrevhash = 'aabbccdd';
    const mon = new PrevhashMonitor({
      poolId:           'test-pool',
      getPrevhash:      () => ownPrevhash,
      pollIntervalMs:   30,
      divergenceMs:     60,
      minPeersForAlert: 1,
    });

    const divergences = collect(mon, 'divergence');
    const resolveds   = collect(mon, 'resolved');

    mon.start();
    mon.onPeerAnnounce('peer-A', 'deadbeef');  // diverge
    await wait(150);  // divergence fires

    assert.ok(divergences.length >= 1, 'divergence must have fired first');

    // Peer rejoins our chain
    mon.onPeerAnnounce('peer-A', ownPrevhash);
    await wait(100);
    mon.stop();

    assert.ok(resolveds.length >= 1, 'resolved must be emitted when peers agree again');
    assert.strictEqual(resolveds[0].prevhash, ownPrevhash);
  });

});
