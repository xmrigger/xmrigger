'use strict';
/**
 * real-target.js — start a real FederationNode + a debug HTTP probe server,
 * matching the ctx shape produced by mock-target.js.
 *
 * @license LGPL-2.1
 *
 * Used by `node test/red-team/run.js --target real`. Tests against the
 * actual src/federation/ implementation. Scenarios that depend on
 * cryptographic primitives or equivocation cache will produce real verdicts
 * here, not stubs.
 */

const http = require('http');
const { FederationNode } = require('../../src/federation');

async function startRealTarget() {
  // Stable shared prevhash so peer HELLOs validate against our chainView.
  const sharedPrevhash = Buffer.alloc(32, 0xAB);

  const node = new FederationNode({
    port: 0,
    seeds: [],
    chainView: {
      ownPrevhash:         () => sharedPrevhash,
      freshPeerPrevhashes: () => [sharedPrevhash],
    },
    getRecentPrevhash: () => sharedPrevhash,
  });
  await node.start();

  // Debug HTTP server, same shape as MockTarget's
  const debugSrv = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (url.pathname === '/__debug/ban') {
      const ip     = url.searchParams.get('ip');
      const banned = node.banList.isBanned(ip);
      reply(res, { banned, reason: null });
      return;
    }
    if (url.pathname === '/__debug/halfopen') {
      const ip = url.searchParams.get('ip');
      reply(res, { count: node.ipRate.halfOpenCount(ip) });
      return;
    }
    if (url.pathname === '/__debug/strikes') {
      const id  = url.searchParams.get('id');
      const snap = node.limiter.snapshot(id);
      reply(res, { count: snap ? snap.strikes : 0 });
      return;
    }
    if (url.pathname === '/__debug/inject-ban') {
      const ip    = url.searchParams.get('ip');
      const ttlMs = Number(url.searchParams.get('ttl') || 60_000);
      node.banList.add(ip, ttlMs, 'injected');
      reply(res, { ok: true });
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise((r) => debugSrv.listen(0, r));
  const debugPort = debugSrv.address().port;

  return {
    ctx: {
      host:     '127.0.0.1',
      port:     node.port,
      wsUrl:    `ws://127.0.0.1:${node.port}`,
      debugUrl: `http://127.0.0.1:${debugPort}`,
    },
    node,
    stop: async () => {
      node.stop();
      await new Promise((r) => debugSrv.close(r));
    },
  };
}

function reply(res, obj) {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(obj));
}

module.exports = { startRealTarget };
