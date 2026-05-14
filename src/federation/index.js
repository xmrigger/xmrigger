'use strict';
/**
 * federation public API.
 *
 * @license LGPL-2.1
 *
 * Implements the federation transport defined in SPEC-FEDERATION-v1.md.
 * Designed to plug straight into PrevhashMonitor v0.2 via the API contract:
 *
 *   const { FederationNode } = require('xmrigger/src/federation');
 *
 *   const fed = new FederationNode({
 *     port:      8765,
 *     seeds:     ['ws://peer.example.com:8765'],
 *     getRecentPrevhash: () => proxy.lastPrevhashBuffer,
 *     chainView: {
 *       ownPrevhash:         () => proxy.lastPrevhashBuffer,
 *       freshPeerPrevhashes: () => Array.from(monitor.peers).map(p => p.prevhashBuffer),
 *     },
 *   });
 *   await fed.start();
 *
 *   monitor.on('announce',           ({ prevhash }) =>
 *     fed.broadcastPrevhash({ prevhash }));
 *   fed.on('prevhash-announce',      ({ from, prevhash, ts }) =>
 *     monitor.onPeerAnnounce(from, prevhash, ts));
 *   fed.on('peer-banned',            ({ ip, reason }) =>
 *     console.warn(`banned ${ip}: ${reason}`));
 */

module.exports = {
  FederationNode:    require('./node').FederationNode,
  // Lower-level surfaces, exposed for tests and downstream extension only.
  // Stable enough to publish but not part of the high-level integration API.
  Identity:          require('./identity').Identity,
  Session:           require('./session').Session,
  EquivocationCache: require('./equivocation').EquivocationCache,
  BanList:           require('./limits').BanList,
  PerIpRate:         require('./limits').PerIpRate,
  PerPeerLimiter:    require('./limits').PerPeerLimiter,
  TokenBucket:       require('./limits').TokenBucket,
  consts:            require('./consts'),
  wire:              require('./wire'),
  crypto:            require('./crypto'),
  identity:          require('./identity'),
};
