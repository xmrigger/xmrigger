'use strict';
/**
 * attack-harness.js — adversarial test framework for the federation transport.
 *
 * @license LGPL-2.1
 *
 * Provides primitives a scenario can use to talk to a federation target at
 * the rawest reasonable level (TCP / WebSocket / individual frames),
 * record attempted attacks with their outcomes, and produce a deterministic
 * report.
 *
 * Two target modes:
 *
 *   - mock:  in-process MockTarget (mock-target.js) that applies SPEC policy
 *            in stub form. Lets the harness and scenarios be developed and
 *            reviewed before the federation implementation exists.
 *   - real:  a federation node binary started by the test runner. Requires
 *            src/federation/ to exist. Selected with --target real.
 *
 * The harness intentionally avoids cleverness. Each helper is one obvious
 * thing. The interesting code lives in the scenarios.
 */

const http   = require('http');
const net    = require('net');
const crypto = require('crypto');

let WebSocket;
try {
  // Optional: the federation transport will eventually need ws as a runtime
  // dep. Until then we run without it and skip WS-based scenarios.
  WebSocket = require('ws');
} catch { WebSocket = null; }

// ── Outcome vocabulary ──────────────────────────────────────────────────────
//
// Every scenario.run() must resolve to an object with at least { outcome }.
// Vocabulary is deliberately small so verify() functions stay declarative.

const OUTCOMES = Object.freeze({
  CONNECTION_REFUSED:    'connection-refused',     // TCP/WS connect was rejected
  CLOSED_BEFORE_HELLO:   'closed-before-hello',    // server closed during handshake
  CLOSED_AFTER_HELLO:    'closed-after-hello',     // server closed mid-session
  DROPPED_FRAME:         'dropped-frame',          // frame was silently dropped
  ACCEPTED_FRAME:        'accepted-frame',         // frame was accepted (may be wrong!)
  BANNED:                'banned',                 // peer landed in a ban list
  STRIKED:               'striked',                // strike counter incremented
  TIMEOUT:               'timeout',                // no response within scenario budget
  ACK_RECEIVED:          'ack-received',           // server confirmed ok (may be wrong!)
  ERROR:                 'error',                  // harness-level error, not a defense outcome
});

// ── AttackHarness ───────────────────────────────────────────────────────────

class AttackHarness {
  /**
   * @param {object}   opts
   * @param {string}   opts.targetMode      'mock' | 'real'
   * @param {object}   [opts.targetCtx]     populated by start(); host, port, wsUrl, debug API
   * @param {number}   [opts.scenarioBudgetMs=2000]   default per-scenario timeout
   */
  constructor({ targetMode = 'mock', scenarioBudgetMs = 2000 } = {}) {
    this.targetMode = targetMode;
    this.targetCtx  = null;
    this.budget     = scenarioBudgetMs;
    this._sockets   = [];
    this._wsClients = [];
  }

  /** Set the live target context (host/port/wsUrl + optional debug accessors). */
  attachTarget(ctx) { this.targetCtx = ctx; return this; }

  // ── Connection primitives ─────────────────────────────────────────────────

  /**
   * Open a raw TCP socket. Caller is responsible for the protocol on top.
   * Tracked for cleanup.
   * @returns {Promise<net.Socket>}
   */
  openTcp({ host, port } = {}) {
    return new Promise((resolve, reject) => {
      const sock = net.createConnection({
        host: host || this.targetCtx.host,
        port: port || this.targetCtx.port,
      });
      sock.once('connect', () => { this._sockets.push(sock); resolve(sock); });
      sock.once('error',   reject);
    });
  }

  /**
   * Open a WebSocket connection. Tracked for cleanup.
   * @returns {Promise<WebSocket>}
   */
  openWs({ url } = {}) {
    if (!WebSocket) throw new Error('ws not installed — WebSocket scenarios skipped');
    const target = url || this.targetCtx.wsUrl;
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(target, { maxPayload: 65536 });
      let opened = false;
      ws.once('open',  () => {
        opened = true;
        // Attach a permanent noop error handler so server-side teardowns
        // (close 1009, abrupt RST) do not throw an unhandled 'error' that
        // crashes the runner. Scenarios observe outcomes via wait helpers.
        ws.on('error', () => {});
        this._wsClients.push(ws);
        resolve(ws);
      });
      ws.once('error', (e) => { if (!opened) reject(e); });
    });
  }

  /**
   * Send raw bytes over a WebSocket. Useful for malformed-frame scenarios:
   * wraps the payload as a single binary message regardless of size.
   */
  sendWsRaw(ws, bytes) {
    return new Promise((resolve, reject) => {
      ws.send(bytes, { binary: true }, (err) => err ? reject(err) : resolve());
    });
  }

  // ── Wait helpers ──────────────────────────────────────────────────────────

  /** Resolve true if the WS is closed within `ms`, false otherwise. */
  waitForWsClose(ws, ms = this.budget) {
    return new Promise((resolve) => {
      let done = false;
      const finish = (result) => { if (!done) { done = true; resolve(result); } };
      ws.once('close', () => finish(true));
      setTimeout(() => finish(false), ms);
    });
  }

  /** Resolve true if a TCP socket is closed within `ms`, false otherwise. */
  waitForTcpClose(sock, ms = this.budget) {
    return new Promise((resolve) => {
      let done = false;
      const finish = (result) => { if (!done) { done = true; resolve(result); } };
      sock.once('close', () => finish(true));
      setTimeout(() => finish(false), ms);
    });
  }

  /** Resolve with the next message received on the WS, or null on timeout. */
  waitForWsMessage(ws, ms = this.budget) {
    return new Promise((resolve) => {
      let done = false;
      const finish = (data) => { if (!done) { done = true; resolve(data); } };
      ws.once('message', (data) => finish(data));
      setTimeout(() => finish(null), ms);
    });
  }

  /** Sleep helper (deliberate use, e.g. to let server-side timers fire). */
  sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

  // ── Defense-state probes (require target debug API) ───────────────────────

  /**
   * Whether an IP is in the target's ban list. Requires the target to expose
   * a debug endpoint at GET /__debug/ban?ip=... returning {banned:bool,
   * reason:string|null, expiresAt:number|null}.
   */
  isIpBanned(ip) {
    return this._debugFetch(`/__debug/ban?ip=${encodeURIComponent(ip)}`)
      .then((r) => !!(r && r.banned))
      .catch(() => false);
  }

  /** Number of active sessions per IP, for half-open / boot-loop scenarios. */
  halfOpenForIp(ip) {
    return this._debugFetch(`/__debug/halfopen?ip=${encodeURIComponent(ip)}`)
      .then((r) => (r && typeof r.count === 'number') ? r.count : 0)
      .catch(() => 0);
  }

  /** Number of strike events recorded for an id_pub. */
  strikesFor(idPub) {
    return this._debugFetch(`/__debug/strikes?id=${encodeURIComponent(idPub)}`)
      .then((r) => (r && typeof r.count === 'number') ? r.count : 0)
      .catch(() => 0);
  }

  _debugFetch(path) {
    if (!this.targetCtx || !this.targetCtx.debugUrl) return Promise.resolve(null);
    const url = this.targetCtx.debugUrl + path;
    return new Promise((resolve, reject) => {
      http.get(url, { timeout: 1000 }, (res) => {
        if (res.statusCode !== 200) { res.resume(); return resolve(null); }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
          catch { resolve(null); }
        });
      }).on('error', reject).on('timeout', () => reject(new Error('timeout')));
    });
  }

  // ── Cleanup ───────────────────────────────────────────────────────────────

  async cleanup() {
    for (const sock of this._sockets) { try { sock.destroy(); } catch {} }
    for (const ws   of this._wsClients) { try { ws.close(); ws.terminate(); } catch {} }
    this._sockets   = [];
    this._wsClients = [];
  }

  // ── Misc utilities scenarios may want ─────────────────────────────────────

  randomBytes(n) { return crypto.randomBytes(n); }

  /**
   * Construct a 192-byte plaintext frame ready for AEAD-wrapping by the
   * caller. All fields are optional and default to schema-valid values.
   * Useful for scenarios that need a "valid except for X" frame.
   *
   * NOTE: this does NOT sign the frame. Signing requires Ed25519 priv held
   * by the caller. The scenarios that need a real signature carry their own
   * keypair.
   */
  buildFrameTemplate({
    proto_v   = 2,
    type      = 1,
    timestamp = Date.now(),
    identity  = Buffer.alloc(32, 0xAA),    // dummy id_pub
    payload   = Buffer.alloc(80, 0),
    signature = Buffer.alloc(64, 0),       // dummy
  } = {}) {
    if (identity.length !== 32) throw new Error('identity must be 32 bytes');
    if (payload.length  !== 80) throw new Error('payload must be 80 bytes');
    if (signature.length !== 64) throw new Error('signature must be 64 bytes');
    const buf = Buffer.alloc(192);
    buf[0] = proto_v & 0xFF;
    buf[1] = type & 0xFF;
    buf.writeBigUInt64BE(BigInt(timestamp), 2);
    // bytes 10..15 reserved zero (already zero from Buffer.alloc)
    identity.copy(buf, 16);
    payload.copy(buf, 48);
    signature.copy(buf, 128);
    return buf;
  }
}

module.exports = { AttackHarness, OUTCOMES };
