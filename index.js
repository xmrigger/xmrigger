'use strict';
// xmr-hashguard public API: exports HashrateMonitor and PrevhashMonitor.
module.exports = {
  ...require('./src/hashrate-monitor'),
  ...require('./src/prevhash-monitor'),
};
