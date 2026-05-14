'use strict';
/**
 * node.js — FederationNode: WSS server + outbound client + dispatch.
 *
 * @license LGPL-2.1
 *
 * SPEC-FEDERATION-v1.md (whole document).
 *
 * Owns:
 *   - the per-process Identity
 *   - the WSS server
 *   - outbound seed connections + reconnect timers
 *   - PerIpRate, PerPeerLimiter, BanList, EquivocationCache
 *   - chainView accessors for HELLO mining-bound check
 *
 * Public API consumed by xmrigger:
 *   broadcastPrevhash({ prevhash, blockHeight, poolId })
 *   broadcastGuard({ ppm, observedPeers, windowStart })
 *   on('prevhash-announce', cb({ from, prevhash, blockHeight, ts }))
 *   on('guard-hint',        cb({ from, ppm, observedPeers, windowStart, ts }))
 *   on('peer-banned',       cb({ ip, reason }))
 *   on('peer-connected',    cb({ peerIdHex }))
 *   on('peer-disconnected', cb({ peerIdHex }))
 */

const { EventEmitter }         = require('events');
const http                     = require('http');
const { WebSocket, WebSocketServer } = require('ws');

const C        = require('./consts');
const wire     = require('./wire');
const cryptoFn = require('./crypto');
const ident    = require('./identity');
const eq       = require('./equivocation');
const lim      = require('./limits');

const RECONNECT_MS = 15_000;

class FederationNode extends EventEmitter {
  /**
   * @param {object}   opts
   * @param {number}   [opts.port=8765]
   * @param {string[]} [opts.seeds]                 list of ws:// URLs
   * @param {object}   opts.chainView               { ownPrevhash:()=>Buffer|null,
   *                                                  freshPeerPrevhashes:()=>Buffer[] }
   * @param {Function} opts.getRecentPrevhash       () => Buffer 32 B (mine for HELLO)
   * @param {object}   [opts.tls]                   { cert, key } for WSS
   */
  constructor({
    port              = 8765,
    seeds             = [],
    chainView,
    getRecentPrevhash,
    tls               = null,
  } = {}) {
    super();
    if (typeof getRecentPrevhash !== 'function') {
      throw new Error('getRecentPrevhash callback required');
    }
    this.port              = port;
    this.seeds             = seeds;
    this.chainView         = chainView || { ownPrevhash: () => null, freshPeerPrevhashes: () => [] };
    this.getRecentPrevhash = getRecentPrevhash;
    this.tls               = tls;

    this.identity = new ident.Identity();
    this.banList  = new lim.BanList();
    this.ipRate   = new lim.PerIpRate();
    this.limiter  = new lim.PerPeerLimiter({ banList: this.banList });
    this.equivocCache = new eq.EquivocationCache();

    /** peerIdHex → Session */
    this._sessions = new Map();
    /** Map<url, NodeJS.Timeout> */
    this._reconnectTimers = new Map();
    this._server  = null;
    this._wss     = null;
    this._stopped = false;

    /**
     * Per-height observation log: heightStr → Map(prevhashHex → Set(idHex))
     *
     * Used by _looksLikeHonestReorg to distinguish honest reorgs (multiple
     * peers see a prevhash) from malicious double-sign (one peer flips).
     * Bounded to OBSERVATION_HEIGHT_CAP entries with LRU eviction.
     */
    this._observedByHeight = new Map();

    /**
     * Per-PROCESS seen-HELLO-nonces (anti-replay).
     *
     * Fix for red-team finding #14 (CRITICAL): if this lived inside Session
     * (per WS), an attacker could replay a captured HELLO frame on a fresh
     * WS connection; the new session's local nonce set would be empty and
     * the replay would establish a session impersonating the original
     * signer. Moving to per-process closes that path.
     *
     * Map: nonceHex → ts. Bounded by HELLO_NONCE_CACHE_MAX with LRU eviction.
     * Entries older than 2 × ts-skew tolerance are dropped on insert.
     */
    this._helloNonces = new Map();
    /** Per-peer post-handshake replay set: peerIdHex → Map(frameKey→ts) */
    this._frameReplay = new Map();

    /** Local block-height counter for our own announcements. Distinguishes
     *  multiple prevhash announcements in time. Equivocation cache lookups
     *  use the height value as declared by the SENDER, so this value is
     *  best-effort honest on our side; receivers don't need to trust it. */
    this._blockHeightCounter = 0n;
  }

  // ── Lifecycle ────────────────────────────────────────────────────────────

  async start() {
    await this._listen();
    for (const url of this.seeds) this._connectOut(url);
    return this;
  }

  stop() {
    this._stopped = true;
    for (const [, s] of this._sessions) s.close();
    for (const [, t] of this._reconnectTimers) clearTimeout(t);
    this._reconnectTimers.clear();
    if (this._wss)    try { this._wss.close(); } catch {}
    if (this._server) try { this._server.close(); } catch {}
    this._sessions.clear();
  }

  get peerCount() { return this._sessions.size; }
  get idHex()     { return this.identity.idHex; }

  // ── Public API consumed by xmrigger guards ───────────────────────────────

  /**
   * Broadcast a PREVHASH frame to all connected peers.
   * @param {object} arg
   * @param {Buffer|string} arg.prevhash      32 B Buffer or 64-char hex
   * @param {bigint|number} [arg.blockHeight] declared height for equivocation key
   * @param {bigint|number} [arg.poolId]      8 B uint64 (pool fingerprint)
   * @returns {number} sent count
   */
  broadcastPrevhash({ prevhash, blockHeight, poolId }) {
    const ph = this._toBuffer32(prevhash);
    if (!ph) return 0;
    if (blockHeight === undefined || blockHeight === null) {
      this._blockHeightCounter += 1n;
      blockHeight = this._blockHeightCounter;
    }
    if (poolId === undefined || poolId === null) poolId = 0n;
    const frame = ident.buildPrevhash(this.identity, poolId, ph, blockHeight);
    return this._broadcast(frame);
  }

  /**
   * Broadcast a GUARD frame to all connected peers.
   */
  broadcastGuard({ ppm, observedPeers, windowStart }) {
    const frame = ident.buildGuard(this.identity, ppm, observedPeers, windowStart);
    return this._broadcast(frame);
  }

  // ── Internal: server ─────────────────────────────────────────────────────

  _listen() {
    return new Promise((resolve) => {
      this._server = this.tls
        ? require('https').createServer({ cert: this.tls.cert, key: this.tls.key })
        : http.createServer();
      this._wss = new WebSocketServer({
        server:     this._server,
        maxPayload: C.WS_MAX_PAYLOAD,
      });
      this._wss.on('error', () => {});         // silence per §5.6
      this._wss.on('connection', (ws, req) => this._accept(ws, req));
      this._server.listen(this.port, () => {
        this.port = this._server.address().port;
        resolve();
      });
    });
  }

  _accept(ws, req) {
    ws.on('error', () => {});                  // silence per §5.6
    const ip = this._remoteIp(req);

    // Pre-handshake gates (§5.2, §5.3).
    // Fix red-team #13: NO reason strings on any ws.close().
    // Fix red-team #17: order is ban → max-peers → half-open → handshake-rate.
    // The handshake-rate budget should be the LAST gate so that attempts
    // rejected by an earlier gate do not consume the victim's budget.
    if (this.banList.isBanned(ip)) {
      try { ws.close(1008); } catch {}
      return;
    }
    if (this._sessions.size >= C.MAX_PEER_SESSIONS) {
      try { ws.close(1013); } catch {}
      return;
    }
    if (!this.ipRate.acquireHalfOpen(ip)) {
      try { ws.close(1008); } catch {}
      return;
    }
    if (!this.ipRate.allowHandshake(ip)) {
      // Release the half-open slot we just acquired — don't strand it.
      this.ipRate.releaseHalfOpen(ip);
      try { ws.close(1008); } catch {}
      return;
    }
    ws.once('close', () => this.ipRate.releaseHalfOpen(ip));

    const session = this._makeSession(ws, false, ip);
    this._wireSession(session, ip);
  }

  // ── Internal: client ─────────────────────────────────────────────────────

  _connectOut(url) {
    const ws = new WebSocket(url, { maxPayload: C.WS_MAX_PAYLOAD });
    ws.on('error', () => {});                  // silence per §5.6
    ws.on('open', () => {
      if (this._stopped) { try { ws.close(); } catch {} return; }
      const session = this._makeSession(ws, true, null);
      this._wireSession(session, null);
    });
    // Single reconnect trigger: 'close' always fires after 'error', so one
    // listener is sufficient and avoids double-scheduling.
    ws.on('close', () => this._scheduleReconnect(url));
  }

  _scheduleReconnect(url) {
    if (this._stopped) return;
    if (this._reconnectTimers.has(url)) return;
    const t = setTimeout(() => {
      this._reconnectTimers.delete(url);
      if (!this._stopped) this._connectOut(url);
    }, RECONNECT_MS);
    this._reconnectTimers.set(url, t);
  }

  _makeSession(ws, isInitiator, remoteIp) {
    const recentPrevhash = this.getRecentPrevhash() || Buffer.alloc(32, 0);
    return new (require('./session').Session)({
      ws, isInitiator,
      localIdentity:    this.identity,
      recentPrevhash,
      chainView:        this.chainView,
      remoteIp,
      // Per-process anti-replay hooks (fix red-team #14, #19)
      helloNonceSeen:   (nonce) => this._helloNonceSeen(nonce),
      framePostHandshakeSeen: (idHex, parsed, plaintext) =>
        this._framePostSeen(idHex, parsed, plaintext),
    });
  }

  // ── Replay guards ────────────────────────────────────────────────────────

  /**
   * Per-process HELLO nonce check. Returns true if the nonce was already
   * seen within the freshness window → caller must reject.
   */
  _helloNonceSeen(nonce) {
    const hex = nonce.toString('hex');
    const now = Date.now();
    // Evict by age first (Map iterates in insertion order ≈ age-order)
    const cutoff = now - 2 * C.TS_SKEW_TOLERANCE_MS;
    for (const [k, ts] of this._helloNonces) {
      if (ts < cutoff) this._helloNonces.delete(k); else break;
    }
    if (this._helloNonces.has(hex)) return true;
    this._helloNonces.set(hex, now);
    // Size cap — generous; 4096 entries × ~28 B each ≈ 110 KB worst-case.
    while (this._helloNonces.size > 4096) {
      const k = this._helloNonces.keys().next().value;
      this._helloNonces.delete(k);
    }
    return false;
  }

  /**
   * Per-peer post-handshake replay check (fix #19). Keys an LRU on a digest
   * of (frame timestamp, frame plaintext suffix). Two identical PREVHASH or
   * GUARD frames from the same peer within the freshness window are
   * detected and dropped.
   */
  /**
   * Record an observation of (blockHeight, prevhash) by a peer for later
   * use by the honest-reorg heuristic.
   */
  _recordObservation(idHex, blockHeight, prevhash) {
    const heightKey = blockHeight.toString();
    let byHash = this._observedByHeight.get(heightKey);
    if (!byHash) {
      byHash = new Map();
      this._observedByHeight.set(heightKey, byHash);
    }
    const phHex = prevhash.toString('hex');
    let observers = byHash.get(phHex);
    if (!observers) {
      observers = new Set();
      byHash.set(phHex, observers);
    }
    observers.add(idHex);
    // Bounded LRU: 256 distinct heights tracked. Monero produces ~720/day,
    // so this is roughly the last 8 h of observations.
    while (this._observedByHeight.size > 256) {
      const k = this._observedByHeight.keys().next().value;
      this._observedByHeight.delete(k);
    }
  }

  /**
   * Fix red-team #15: distinguish honest reorg from malicious double-sign.
   * Returns true if the "existing" prevhash (the one we already had cached)
   * has been independently observed by at least one OTHER peer. In that
   * case the equivocating peer is plausibly just announcing the same reorg
   * the rest of the network is seeing; we don't ban, we log.
   */
  _looksLikeHonestReorg(blockHeight, evidence) {
    const byHash = this._observedByHeight.get(blockHeight.toString());
    if (!byHash) return false;
    const existingHex = evidence.existing.toString('hex');
    const observers   = byHash.get(existingHex);
    if (!observers) return false;
    return observers.size >= 2;
  }

  _framePostSeen(idHex, parsed, plaintext) {
    let perPeer = this._frameReplay.get(idHex);
    if (!perPeer) { perPeer = new Map(); this._frameReplay.set(idHex, perPeer); }
    // Compact key: timestamp + first 16 bytes of payload + first 8 bytes of signature.
    // Cheap, deterministic, collision-resistant for legitimate frames.
    const key =
      parsed.timestamp.toString(36) + ':' +
      plaintext.subarray(C.HEADER_LEN + C.IDENTITY_LEN,
                         C.HEADER_LEN + C.IDENTITY_LEN + 16).toString('hex') + ':' +
      plaintext.subarray(C.SIGNED_REGION_LEN, C.SIGNED_REGION_LEN + 8).toString('hex');
    const now = Date.now();
    if (perPeer.has(key)) return true;
    perPeer.set(key, now);
    while (perPeer.size > C.SEEN_NONCE_PER_PEER) {
      const k = perPeer.keys().next().value;
      perPeer.delete(k);
    }
    return false;
  }

  _wireSession(session, ip) {
    session.on('ready', ({ peerIdHex }) => {
      // Race: an existing session for the same peerIdHex (rare with ephemeral
      // identities, but possible on concurrent connect). Drop the duplicate.
      if (this._sessions.has(peerIdHex)) {
        session.close(1000);
        return;
      }
      this._sessions.set(peerIdHex, session);
      this.emit('peer-connected', { peerIdHex });
    });

    session.on('frame', ({ parsed, plaintext }) => {
      // Charge the peer-rate buckets first (§5.1)
      const idHex = session.peerIdHex;
      const v = this.limiter.charge(idHex, plaintext.length, ip);
      if (!v.allow) {
        if (v.escalate === 'hard' || v.escalate === 'ban') {
          if (ip) this.emit('peer-banned', { ip, reason: v.reason });
          session.close(1008);   // no reason string — fix red-team #13
          this.limiter.forget(idHex);
        }
        return;
      }

      if (parsed.type === C.TYPE_PREVHASH) {
        const ph = wire.parsePrevhashPayload(parsed.payload);
        if (!ph) return;
        // Update per-height observation log BEFORE equivocation check so
        // the honest-reorg heuristic can see prior observations.
        this._recordObservation(idHex, ph.blockHeight, ph.prevhash);
        // Equivocation check (§5.4)
        const ev = this.equivocCache.observe(parsed.identity, ph.blockHeight, ph.prevhash);
        if (ev) {
          // Fix red-team #15: tolerate honest reorg. If our own chain has
          // changed prevhash for this same height recently, treat the
          // conflicting observation as benign chain divergence rather than
          // malicious double-sign. Downgrade ban → log via emit only.
          const honest = this._looksLikeHonestReorg(ph.blockHeight, ev);
          if (honest) {
            this.emit('reorg-observed', { peerIdHex: idHex, blockHeight: ph.blockHeight });
          } else {
            if (ip) {
              this.banList.add(ip, C.HARD_QUARANTINE_MS, 'equivocation');
              this.emit('peer-banned', { ip, reason: 'equivocation' });
            }
            session.close(1008);     // no reason — fix red-team #13
            this.limiter.forget(idHex);
            return;
          }
        }
        this.emit('prevhash-announce', {
          from:        idHex,
          prevhash:    ph.prevhash.toString('hex'),
          blockHeight: ph.blockHeight,
          ts:          parsed.timestamp,
        });
      } else if (parsed.type === C.TYPE_GUARD) {
        const g = wire.parseGuardPayload(parsed.payload);
        if (!g) return;
        this.emit('guard-hint', {
          from:          idHex,
          ppm:           g.ppm,
          observedPeers: g.observedPeers,
          windowStart:   g.windowStart,
          ts:            parsed.timestamp,
        });
      }
      // TYPE_HELLO post-ready is ignored (handshake already done).
    });

    session.on('policy-violation', ({ reason }) => {
      const idHex = session.peerIdHex;
      if (!idHex) return;
      const v = this.limiter.strike(idHex, ip, reason);
      if (v.escalate === 'hard' || v.escalate === 'ban') {
        if (ip) this.emit('peer-banned', { ip, reason });
        session.close(1008);   // no reason string — fix red-team #13
        this.limiter.forget(idHex);
      }
    });

    session.on('close', () => {
      const idHex = session.peerIdHex;
      if (idHex && this._sessions.get(idHex) === session) {
        this._sessions.delete(idHex);
        this.emit('peer-disconnected', { peerIdHex: idHex });
      }
    });
  }

  // ── Internal helpers ─────────────────────────────────────────────────────

  _broadcast(canonical192) {
    let n = 0;
    for (const [, s] of this._sessions) {
      if (s.ready && s.sendFrame(canonical192)) n++;
    }
    return n;
  }

  _toBuffer32(prevhash) {
    if (Buffer.isBuffer(prevhash) && prevhash.length === 32) return prevhash;
    if (typeof prevhash === 'string' && /^[0-9a-fA-F]{64}$/.test(prevhash)) {
      return Buffer.from(prevhash, 'hex');
    }
    return null;
  }

  _remoteIp(req) {
    const r = (req.socket && req.socket.remoteAddress) || '';
    return r.startsWith('::ffff:') ? r.slice(7) : r;
  }
}

module.exports = { FederationNode };
