'use strict';
/**
 * xmrigger test suite — HashrateMonitor + PrevhashMonitor
 * Run: node test/index.js
 *
 * @version  0.1.0
 * @released 2026-04-18
 * @license  LGPL-2.1
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

describe('PrevhashMonitor v0.2 — majority vote + short history', () => {

  test('no alert with fewer than minPeersForAlert peers', async () => {
    let ownPrevhash = 'aabbccdd';
    const mon = new PrevhashMonitor({
      poolId:           'test-pool',
      getPrevhash:      () => ownPrevhash,
      pollIntervalMs:   30,
      divergenceMs:     50,
      historyK:         1,
      minPeersForAlert: 2,
    });

    const divergences = collect(mon, 'divergence');

    mon.start();
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
      historyK:         1,
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

  test('1-vs-1 tie is indeterminate — no alert', async () => {
    // Self holds X, single peer holds Y. Tally: {X:1, Y:1} → tie → verdict null.
    // Under majority vote, ties never raise (correct: not enough info to decide).
    let ownPrevhash = 'aabbccdd';
    const mon = new PrevhashMonitor({
      poolId:           'test-pool',
      getPrevhash:      () => ownPrevhash,
      pollIntervalMs:   30,
      divergenceMs:     50,
      historyK:         1,
    });

    const divergences = collect(mon, 'divergence');

    mon.start();
    mon.onPeerAnnounce('peer-A', 'deadbeef');
    await wait(200);
    mon.stop();

    assert.strictEqual(divergences.length, 0,
      '1-vs-1 tie must NOT raise divergence under majority vote');
  });

  test('Sybil peer in minority does NOT raise alert (2:1 in favour of self)', async () => {
    // Self + 1 honest peer agree on X; 1 Sybil peer announces Y.
    // Tally: {X:2, Y:1} → verdict X (self in majority). No alert.
    const HONEST = 'cafe0001';
    let ownPrevhash = HONEST;
    const mon = new PrevhashMonitor({
      poolId:           'test-pool',
      getPrevhash:      () => ownPrevhash,
      pollIntervalMs:   30,
      divergenceMs:     50,
      historyK:         1,
    });

    const divergences = collect(mon, 'divergence');

    mon.start();
    mon.onPeerAnnounce('peer-honest', HONEST);
    mon.onPeerAnnounce('peer-sybil',  'deadbeef');
    await wait(200);
    mon.stop();

    assert.strictEqual(divergences.length, 0,
      'majority vote must neutralise a single Sybil peer');
  });

  test('self in minority (1 vs 2 honest peers) raises divergence', async () => {
    // Self holds X (selfish pool tip); 2 honest peers hold Y.
    // Tally: {X:1, Y:2} → verdict Y → self in minority → alert.
    let ownPrevhash = 'selfishtip';
    const mon = new PrevhashMonitor({
      poolId:           'test-pool',
      getPrevhash:      () => ownPrevhash,
      pollIntervalMs:   30,
      divergenceMs:     80,
      historyK:         3,
    });

    const divergences = collect(mon, 'divergence');

    mon.start();
    mon.onPeerAnnounce('peer-A', 'honesttip');
    mon.onPeerAnnounce('peer-B', 'honesttip');
    await wait(300);  // enough for both historyK ticks and divergenceMs
    mon.stop();

    assert.ok(divergences.length >= 1, 'divergence must fire when self is in minority');
    const ev = divergences[0];
    assert.strictEqual(ev.ownPrevhash, 'selfishtip');
    assert.strictEqual(ev.canonical, 'honesttip',
      'canonical must be the majority verdict');
    assert.ok(ev.divergentPeers.length === 0,
      'peers on canonical chain are NOT divergent (only self is)');
    assert.ok(ev.seenMs >= 80, `seenMs (${ev.seenMs}) should be >= divergenceMs`);
    assert.ok(ev.sampleCount >= 3, `sampleCount (${ev.sampleCount}) should be >= historyK`);
  });

  test('historyK gating: divergence held back until K stable ticks', async () => {
    // 1 vs 2 minority scenario, but with historyK=5 and short divergenceMs=10.
    // Wall-clock is satisfied almost immediately; the *sample count* gate
    // is what must keep the alert from firing too eagerly.
    let ownPrevhash = 'minoritytip';
    const mon = new PrevhashMonitor({
      poolId:           'test-pool',
      getPrevhash:      () => ownPrevhash,
      pollIntervalMs:   40,
      divergenceMs:     10,
      historyK:         5,
    });

    const divergences = collect(mon, 'divergence');

    mon.start();
    mon.onPeerAnnounce('peer-A', 'majoritytip');
    mon.onPeerAnnounce('peer-B', 'majoritytip');

    // After ~80 ms only 2-3 ticks have passed — must NOT have fired yet.
    await wait(80);
    assert.strictEqual(divergences.length, 0,
      `historyK=5 must hold back alert until enough ticks accumulate (got ${divergences.length})`);

    // Wait long enough for 5+ ticks.
    await wait(250);
    mon.stop();

    assert.ok(divergences.length >= 1, 'divergence must eventually fire after historyK ticks');
    assert.ok(divergences[0].sampleCount >= 5,
      `sampleCount (${divergences[0].sampleCount}) must reach historyK=5`);
  });

  test('resolved emitted when self rejoins the majority verdict', async () => {
    // Start: 1 (self) vs 2 (peers) → divergence
    // Then:  self switches to the majority hash → resolved
    let ownPrevhash = 'mineline';
    const mon = new PrevhashMonitor({
      poolId:           'test-pool',
      getPrevhash:      () => ownPrevhash,
      pollIntervalMs:   30,
      divergenceMs:     60,
      historyK:         2,
    });

    const divergences = collect(mon, 'divergence');
    const resolveds   = collect(mon, 'resolved');

    mon.start();
    mon.onPeerAnnounce('peer-A', 'majoritytip');
    mon.onPeerAnnounce('peer-B', 'majoritytip');
    await wait(200);  // divergence fires

    assert.ok(divergences.length >= 1, 'divergence must have fired first');

    // Self switches to canonical chain
    ownPrevhash = 'majoritytip';
    await wait(120);
    mon.stop();

    assert.ok(resolveds.length >= 1, 'resolved must be emitted when self rejoins majority');
    assert.strictEqual(resolveds[0].prevhash, 'majoritytip');
  });

  test('legacy mode (majorityVote=false) preserves v0.1 self-as-oracle behaviour', async () => {
    // In legacy mode, a single divergent peer raises an alert (no majority needed).
    let ownPrevhash = 'aabbccdd';
    const mon = new PrevhashMonitor({
      poolId:           'test-pool',
      getPrevhash:      () => ownPrevhash,
      pollIntervalMs:   30,
      divergenceMs:     80,
      historyK:         1,
      majorityVote:     false,
    });

    const divergences = collect(mon, 'divergence');

    mon.start();
    mon.onPeerAnnounce('peer-A', 'deadbeef');
    await wait(250);
    mon.stop();

    assert.ok(divergences.length >= 1,
      'legacy mode must alert on any divergent peer (no majority required)');
    assert.strictEqual(divergences[0].divergentPeers[0].peerId, 'peer-A');
  });

});
