'use strict';
/**
 * index.js — xmrigger public API
 *
 * @version  0.1.0
 * @released 2026-04-18
 * @license  LGPL-2.1
 */
// xmrigger public API: exports HashrateMonitor and PrevhashMonitor.
module.exports = {
  ...require('./src/hashrate-monitor'),
  ...require('./src/prevhash-monitor'),
};
