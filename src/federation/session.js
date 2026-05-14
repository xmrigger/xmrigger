'use strict';
/**
 * session.js — encrypted federation session over a WebSocket.
 *
 * @license LGPL-2.1
 *
 * SPEC-FEDERATION-v1.md §3, §4.
 *
 * Each Session wraps a single WebSocket. Lifecycle:
 *
 *   construct → (initiator-only: send HELLO immediately)
 *     → on first inbound: validateHello(), derive session key, emit 'ready'
 *     → for each subsequent inbound:  AEAD-decrypt, verify sig, emit 'frame'
 *     → on policy violation:           emit 'policy-violation'
 *     → on close:                      emit 'close'
 *
 * Events are intentionally narrow. Higher-level dispatch (rate limit,
 * equivocation, ban escalation) lives in node.js.
 */

const { EventEmitter } = require('events');
const C        = require('./consts');
const wire     = require('./wire');
const cryptoFn = require('./crypto');
const identity = require('./identity');

class Session extends EventEmitter {
  /**
   * @param {object} opts
   * @param {WebSocket}  opts.ws
   * @param {boolean}    opts.isInitiator
   * @param {Identity}   opts.localIdentity     long-term identity for this process
   * @param {Buffer}     opts.recentPrevhash    32 B; what we'll put in our HELLO
   * @param {object}     opts.chainView         used by responder to validate inbound HELLO
   * @param {string}     [opts.remoteIp]        for ban-list lookups upstream
   */
  constructor({ ws, isInitiator, localIdentity, recentPrevhash, chainView, remoteIp,
                helloNonceSeen, framePostHandshakeSeen }) {
    super();
    this.ws             = ws;
    this.isInitiator    = isInitiator;
    this.local          = localIdentity;
    this.recentPrevhash = recentPrevhash;
    this.chainView      = chainView || { ownPrevhash: () => null, freshPeerPrevhashes: () => [] };
    this.remoteIp       = remoteIp || null;
    // Per-process replay hooks (set by FederationNode). Default no-op
    // accepters keep the class usable in isolation tests.
    this._helloNonceSeen        = helloNonceSeen        || (() => false);
    this._framePostHandshakeSeen = framePostHandshakeSeen || (() => false);

    this._eph           = cryptoFn.generateX25519();
    this._peerIdRaw     = null;     // 32 B set after HELLO
    this._peerIdHex     = null;
    this._sessionKey    = null;
    this._ready         = false;
    this._hsTimer       = null;

    ws.on('message', (data) => this._onRaw(data));
    ws.on('close',   ()     => {
      if (this._hsTimer) { clearTimeout(this._hsTimer); this._hsTimer = null; }
      this.emit('close');
    });
    ws.on('error',   ()     => {
      // Silenced; the close event will fire afterward and the upstream
      // listener acts on that. No diagnostic emit (§5.6).
    });

    this._hsTimer = setTimeout(() => {
      this._hsTimer = null;
      if (!this._ready) {
        // Fix red-team #13: no reason string. Bare close code only — denies
        // the attacker a differential signal about which guard fired.
        try { ws.close(1008); } catch {}
      }
    }, C.HANDSHAKE_TIMEOUT_MS);

    if (isInitiator) this._sendHello();
  }

  get peerIdRaw() { return this._peerIdRaw; }
  get peerIdHex() { return this._peerIdHex; }
  get ready()     { return this._ready;     }

  // ── Sending ──────────────────────────────────────────────────────────────

  _sendHello() {
    const frame = identity.buildHello(
      this.local,
      this._eph.publicKeyRaw,
      this.recentPrevhash,
    );
    // Pre-handshake HELLO is sent in the clear (no session key yet).
    try { this.ws.send(frame, { binary: true }); } catch {}
  }

  /**
   * Send a PREVHASH or GUARD frame on this session, AEAD-wrapped.
   * Returns true if sent, false if not ready or send failed.
   */
  sendFrame(canonical192) {
    if (!this._ready) return false;
    if (!Buffer.isBuffer(canonical192) || canonical192.length !== C.FRAME_LEN) return false;
    try {
      const wireFrame = cryptoFn.aeadEncrypt(this._sessionKey, canonical192);
      this.ws.send(wireFrame, { binary: true });
      return true;
    } catch { return false; }
  }

  // ── Receiving ────────────────────────────────────────────────────────────

  _onRaw(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);

    if (!this._ready) { this._onHandshake(buf); return; }

    // AEAD-wrapped frame: must be exactly WIRE_FRAME_LEN
    if (buf.length !== C.WIRE_FRAME_LEN) {
      this.emit('policy-violation', { reason: 'wire-len' });
      return;
    }
    const plaintext = cryptoFn.aeadDecrypt(this._sessionKey, buf);
    if (!plaintext) {
      this.emit('policy-violation', { reason: 'aead' });
      return;
    }
    const verdict = identity.verifyFrame(plaintext, this._peerIdRaw);
    if (!verdict.ok) {
      this.emit('policy-violation', { reason: verdict.reason });
      return;
    }
    // Fix red-team #19: per-peer post-handshake replay set.
    if (this._framePostHandshakeSeen(this._peerIdHex, verdict.parsed, plaintext)) {
      this.emit('policy-violation', { reason: 'replay' });
      return;
    }
    this.emit('frame', { parsed: verdict.parsed, plaintext });
  }

  _onHandshake(buf) {
    // No reason strings in any close: fix red-team #13 (no diagnostic leak).
    if (buf.length !== C.FRAME_LEN) {
      try { this.ws.close(1008); } catch {}
      return;
    }
    const v = identity.validateHello(buf, this.chainView);
    if (!v.ok) {
      try { this.ws.close(1008); } catch {}
      return;
    }

    // Per-process replay window (fix red-team #14): if this nonce was
    // already seen by ANY session of this process within the freshness
    // window, this is a replay. Captured HELLO bytes cannot be re-used
    // on a fresh connection.
    if (this._helloNonceSeen(v.nonce)) {
      try { this.ws.close(1008); } catch {}
      return;
    }

    // Establish session.
    this._peerIdRaw  = v.identity;
    this._peerIdHex  = v.identity.toString('hex');
    const shared     = cryptoFn.x25519Diffie(this._eph.privateKey, v.ephPub);
    this._sessionKey = cryptoFn.deriveSessionKey(shared);
    this._ready      = true;
    if (this._hsTimer) { clearTimeout(this._hsTimer); this._hsTimer = null; }

    // Responder replies with its own HELLO so the initiator can derive too.
    if (!this.isInitiator) this._sendHello();

    this.emit('ready', { peerIdRaw: this._peerIdRaw, peerIdHex: this._peerIdHex });
  }

  close(code = 1000) {
    // No reason string ever — fix red-team #13.
    try { this.ws.close(code); } catch {}
  }
}

module.exports = { Session };
