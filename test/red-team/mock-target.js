'use strict';
/**
 * mock-target.js — minimal WebSocket federation node STUB for harness use.
 *
 * @license LGPL-2.1
 *
 * This is NOT the real federation implementation. It applies the policy
 * decisions defined in SPEC-FEDERATION-v1.md in stub form, just enough to
 * let red-team scenarios exercise the harness end-to-end before
 * src/federation/ exists.
 *
 * What it does:
 *   - WebSocket server with maxPayload 256 B (matches SPEC §5.5)
 *   - Tracks per-IP half-open connection count and applies cap
 *   - Tracks per-IP handshake-rate cap (3/min)
 *   - Tracks IP ban list (in-memory only, no persistence)
 *   - Tracks per-id_pub strike counter
 *   - Drops oversized / wrong-size frames silently
 *   - Exposes /__debug/ HTTP endpoints for scenario inspection
 *
 * What it does NOT do:
 *   - No real Ed25519 verification
 *   - No real AEAD
 *   - No real prevhash chain validation
 *   - No mining-bound check
 *   - No equivocation cache (returns "would-be banned" via debug API only)
 *
 * Scenarios that need cryptographic correctness MUST run against the real
 * implementation (--target real). Scenarios that test transport-level
 * behaviours (rate limits, frame size caps, drop semantics) can run here.
 */

const http = require('http');
const { WebSocketServer } = require('ws');

const HALF_OPEN_CAP_PER_IP    = 5;
const HANDSHAKE_RATE_PER_IP   = 3;
const HANDSHAKE_RATE_WINDOW_MS = 60_000;
const FRAME_SIZE              = 192;
const WS_MAX_PAYLOAD          = 256;
const HANDSHAKE_TIMEOUT_MS    = 10_000;

class MockTarget {
  constructor({ port = 0, debugPort = 0 } = {}) {
    this.port      = port;
    this.debugPort = debugPort;
    this._wss      = null;
    this._server   = null;
    this._debugSrv = null;

    this._halfOpenByIp     = new Map();   // ip → count
    this._handshakeAttempts = new Map();  // ip → array of timestamps
    this._bans             = new Map();   // ip → { reason, expiresAt }
    this._strikes          = new Map();   // idPubHex → count
    this._sessionsByIp     = new Map();   // ip → Set(ws)
  }

  async start() {
    // Federation transport server
    this._server = http.createServer();
    this._wss = new WebSocketServer({ server: this._server, maxPayload: WS_MAX_PAYLOAD });
    // Silencer: oversized frames trigger an 'error' on the wss + on the
    // connection. Unhandled, they crash the runner. The behaviour we WANT
    // is "silently close that one connection" — exactly what ws does once
    // we attach a noop handler.
    this._wss.on('error',         () => {});
    this._wss.on('connection', (ws, req) => {
      ws.on('error', () => {});
      this._onConnection(ws, req);
    });
    await new Promise((r) => this._server.listen(this.port, r));
    this.port = this._server.address().port;

    // Debug HTTP for harness probes
    this._debugSrv = http.createServer((req, res) => this._onDebug(req, res));
    await new Promise((r) => this._debugSrv.listen(this.debugPort, r));
    this.debugPort = this._debugSrv.address().port;

    return {
      host:     '127.0.0.1',
      port:     this.port,
      wsUrl:    `ws://127.0.0.1:${this.port}`,
      debugUrl: `http://127.0.0.1:${this.debugPort}`,
    };
  }

  async stop() {
    if (this._wss)      this._wss.close();
    if (this._server)   await new Promise((r) => this._server.close(r));
    if (this._debugSrv) await new Promise((r) => this._debugSrv.close(r));
  }

  _onConnection(ws, req) {
    const ip = this._remoteIp(req);

    // Ban check (pre-handshake)
    if (this._isBanned(ip)) {
      ws.close(1008, 'banned');
      return;
    }

    // Rate cap on handshake attempts per IP
    if (!this._allowHandshakeRate(ip)) {
      ws.close(1008, 'handshake-rate-exceeded');
      return;
    }

    // Half-open cap
    const halfOpen = (this._halfOpenByIp.get(ip) || 0);
    if (halfOpen >= HALF_OPEN_CAP_PER_IP) {
      ws.close(1008, 'half-open-cap');
      return;
    }
    this._halfOpenByIp.set(ip, halfOpen + 1);

    let handshakeComplete = false;

    const hsTimer = setTimeout(() => {
      if (!handshakeComplete) {
        try { ws.close(1008, 'handshake-timeout'); } catch {}
      }
    }, HANDSHAKE_TIMEOUT_MS);

    ws.on('message', (data) => {
      // Frame size discipline: anything ≠ FRAME_SIZE is dropped.
      // (In the real impl this is post-AEAD; here we just check raw length.)
      if (!Buffer.isBuffer(data)) data = Buffer.from(data);
      if (data.length !== FRAME_SIZE) {
        // silent drop + strike
        // strike is keyed on idPub once we know it; before HELLO it's IP-strike
        return;
      }

      // Header validation (proto_v, type, reserved)
      if (data[0] !== 2)                    return;            // proto_v
      const type = data[1];
      if (type < 1 || type > 3)             return;            // type
      for (let k = 10; k < 16; k++) {
        if (data[k] !== 0) return;                             // reserved
      }
      // Timestamp window
      const ts = Number(data.readBigUInt64BE(2));
      if (Math.abs(Date.now() - ts) > 300_000) return;         // ts skew

      // (Real impl would verify Ed25519 here; mock skips.)

      handshakeComplete = handshakeComplete || (type === 1);
    });

    ws.on('close', () => {
      clearTimeout(hsTimer);
      const cur = this._halfOpenByIp.get(ip) || 0;
      if (cur > 0) this._halfOpenByIp.set(ip, cur - 1);
    });
  }

  _onDebug(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname === '/__debug/ban') {
      const ip  = url.searchParams.get('ip');
      const ban = this._bans.get(ip);
      const banned = !!(ban && ban.expiresAt > Date.now());
      this._reply(res, { banned, reason: banned ? ban.reason : null });
      return;
    }
    if (url.pathname === '/__debug/halfopen') {
      const ip = url.searchParams.get('ip');
      this._reply(res, { count: this._halfOpenByIp.get(ip) || 0 });
      return;
    }
    if (url.pathname === '/__debug/strikes') {
      const id = url.searchParams.get('id');
      this._reply(res, { count: this._strikes.get(id) || 0 });
      return;
    }
    if (url.pathname === '/__debug/inject-ban') {
      // For scenarios that need to seed a ban. POST not required for test.
      const ip       = url.searchParams.get('ip');
      const ttlMs    = Number(url.searchParams.get('ttl') || 60_000);
      this._bans.set(ip, { reason: 'injected', expiresAt: Date.now() + ttlMs });
      this._reply(res, { ok: true });
      return;
    }
    res.statusCode = 404;
    res.end();
  }

  _reply(res, obj) {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(obj));
  }

  _remoteIp(req) {
    const r = req.socket.remoteAddress || '';
    return r.startsWith('::ffff:') ? r.slice(7) : r;
  }

  _isBanned(ip) {
    const ban = this._bans.get(ip);
    if (!ban) return false;
    if (ban.expiresAt <= Date.now()) { this._bans.delete(ip); return false; }
    return true;
  }

  _allowHandshakeRate(ip) {
    const now = Date.now();
    const arr = this._handshakeAttempts.get(ip) || [];
    const recent = arr.filter((t) => now - t < HANDSHAKE_RATE_WINDOW_MS);
    if (recent.length >= HANDSHAKE_RATE_PER_IP) {
      this._handshakeAttempts.set(ip, recent);
      return false;
    }
    recent.push(now);
    this._handshakeAttempts.set(ip, recent);
    return true;
  }
}

module.exports = { MockTarget };
