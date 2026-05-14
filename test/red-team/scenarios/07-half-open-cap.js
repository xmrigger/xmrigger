'use strict';
/**
 * Scenario 07 — per-IP half-open cap (D7) — library mode against PerIpRate.
 *
 * Drive PerIpRate directly: acquire IP_HALF_OPEN_CAP slots, then attempt
 * one more — must be denied. After releasing one, must be granted again.
 *
 * The handshake-rate cap (3/min) would block a wire-level test of this
 * specific guard, since it triggers first. Library-mode test isolates
 * half-open semantics cleanly.
 */

const C   = require('../../../src/federation/consts');
const lim = require('../../../src/federation/limits');

module.exports = {
  id: '07',
  name: 'per-IP half-open cap (5 concurrent) rejects 6th slot',
  spec: 'SPEC-FEDERATION-v1.md §5.2 (D7)',
  attack_vector: 'E19 half-open slowloris',
  expected_outcome: 'first IP_HALF_OPEN_CAP acquires succeed, next denied, after release one re-grants',
  requires_impl: false,

  async run() {
    const r = new lim.PerIpRate();
    const ip = '203.0.113.7';   // documentation range, distinct from any other test
    const acquires = [];
    for (let i = 0; i < C.IP_HALF_OPEN_CAP; i++) {
      acquires.push(r.acquireHalfOpen(ip));
    }
    const denied = r.acquireHalfOpen(ip);     // expect false
    r.releaseHalfOpen(ip);
    const reGrant = r.acquireHalfOpen(ip);    // expect true
    return {
      allAcquired: acquires.every((x) => x === true),
      acquireCount: acquires.length,
      denied,
      reGrant,
    };
  },

  verify(result) {
    return result.allAcquired === true &&
           result.acquireCount === C.IP_HALF_OPEN_CAP &&
           result.denied === false &&
           result.reGrant === true;
  },
};
