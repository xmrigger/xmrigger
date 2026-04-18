/**
 * basic.js — minimal HashrateMonitor usage example
 *
 * Shows how to integrate the guard into any existing miner wrapper
 * without using xmrig-guard.js.
 */
'use strict';

const { HashrateMonitor } = require('xmrigger');

const monitor = new HashrateMonitor({
  // Preferred: independent third-party source for pool hashrate
  // poolStatsUrl: 'https://miningpoolstats.stream/api/monero/hashvault',

  // Fallback: pool's own endpoint (less trusted — pool could lie)
  poolHealthUrl: 'http://your-pool.example.com/pool/health',

  // Network hashrate: fetched from 6 independent Monero nodes automatically.
  // Override only for testing:
  // networkDiffUrls: ['http://127.0.0.1:19999/api/networkinfo'],

  threshold:      0.30,   // 30% of Monero network hashrate
  pollIntervalMs: 30_000, // check every 30s
  gracePeriodMs:  60_000, // 60s countdown before disconnect

  fallbackPools: [
    { host: 'pool.supportxmr.com',          port: 3333  },
    { host: 'gulf.moneroocean.stream',       port: 10128 },
  ],
});

monitor.on('warn',       ({ hashratePct }) => console.log(`Pool at ${(hashratePct*100).toFixed(1)}% — approaching limit`));
monitor.on('crit',       ({ hashratePct }) => console.log(`Pool at ${(hashratePct*100).toFixed(1)}% — grace period started`));
monitor.on('grace-tick', ({ secsLeft })    => console.log(`Disconnecting in ${secsLeft}s`));
monitor.on('fork',       ()               => console.log('Fork detected — evacuating'));
monitor.on('safe',       ({ hashratePct }) => console.log(`Pool back to safe: ${(hashratePct*100).toFixed(1)}%`));

monitor.on('evacuate', ({ reason, fallback }) => {
  console.log(`EVACUATE (${reason}) → ${fallback ? fallback.host : 'no fallback'}`);
  // Your miner restart logic here
  monitor.start(); // resume monitoring on fallback
});

monitor.start();
