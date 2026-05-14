'use strict';
/**
 * Scenario 14 — HELLO replay across sessions / nodes (impersonation).
 *
 * Attack: Alice captures Bob's valid HELLO frame on the wire (Bob → some
 *         third node). The HELLO is a 192-byte plaintext frame signed by
 *         Bob's per-process ephemeral Ed25519 identity, containing a
 *         recent_prevhash that the receiver's chainView accepts, and a
 *         nonce that Alice has NOT seen before (it was negotiated between
 *         Bob and that third node, not this victim).
 *
 *         Alice then opens a fresh WebSocket to the VICTIM node and replays
 *         Bob's HELLO byte-for-byte. The victim:
 *           - parses successfully (frame is well-formed),
 *           - finds the timestamp inside ±5 min (still fresh),
 *           - signature verifies (it's Bob's real signature),
 *           - mining-bound check passes (chainView accepts the prevhash),
 *           - victim's per-session _seenNonces is EMPTY (different session
 *             than Bob ↔ third-node), so replay-detection does not fire,
 *           - session.emit('ready', { peerIdHex: Bob's pubkey }).
 *
 *         Result: Alice has impersonated Bob to the victim. The victim
 *         emits 'peer-connected' with Bob's idHex. From this point Alice
 *         cannot send PREVHASH/GUARD on Bob's behalf (she lacks Bob's
 *         private key for the AEAD-wrapped frames signed by Bob), but:
 *           - she has consumed one of Bob's slots in victim's _sessions map,
 *           - peer-connected events fire with attacker-chosen timing,
 *           - if Bob later legitimately connects, victim refuses him with
 *             session.close(1000, 'duplicate'),
 *           - in a Sybil scenario, Alice can pre-seat MANY captured HELLOs
 *             from many real proxies and hold their slots.
 *
 * Defense expected from SPEC: §3.6 mentions "per-peer seen-nonce LRU set
 *         (capped at 1024 entries) within the timestamp window to detect
 *         replays explicitly". This is described in the SPEC as a property
 *         of "the receiver", suggesting global (per-node), but the impl in
 *         session.js holds _seenNonces inside the Session object — per WS
 *         connection. A fresh connection starts with empty _seenNonces.
 *
 * Outcome that means VULN found:
 *   Replayed HELLO produces 'ready' event (impersonation accepted).
 * Outcome that means defense holds:
 *   Replayed HELLO is rejected before 'ready' (e.g. session never opens).
 *
 * NOTE on suite ordering: when run as part of the full suite this scenario
 * may PASS for the wrong reason — earlier scenarios (08 inject-ban TTL 60s,
 * 13 close-leak which opens many sockets) can leave 127.0.0.1 banned at the
 * victim. The ban shortcuts to close(1008,'banned') before HELLO validation
 * runs. Run in isolation (`--id 14`) for the true verdict.
 */

const C        = require('../../../src/federation/consts');
const wire     = require('../../../src/federation/wire');
const cryptoFn = require('../../../src/federation/crypto');
const ident    = require('../../../src/federation/identity');

module.exports = {
  id: '14',
  name: 'HELLO replay across distinct sessions impersonates the original signer',
  spec: 'SPEC-FEDERATION-v1.md §3.6 (seen-nonce LRU) + §4 (HELLO)',
  attack_vector: 'E2 mining-bound HELLO replay — cross-session variant',
  expected_outcome: 'replayed HELLO must not establish a session on a fresh peer',
  requires_impl: true,

  async run(harness) {
    const real_target = harness.targetCtx;
    const sharedPrevhash = Buffer.alloc(32, 0xAB);   // real-target's chainView accepts this

    // Forge "Bob"'s identity locally; this is the attacker simulating having
    // observed a valid HELLO from Bob (we already control the bytes).
    const bob = new ident.Identity();
    const bobEph = cryptoFn.generateX25519();
    const bobHello = ident.buildHello(bob, bobEph.publicKeyRaw, sharedPrevhash, Date.now());

    // Sanity: validateHello passes against this chainView (mining-bound OK).
    const v = ident.validateHello(bobHello, {
      ownPrevhash: () => sharedPrevhash,
      freshPeerPrevhashes: () => [sharedPrevhash],
    });
    if (!v.ok) return { precondition: false, reason: v.reason };

    // Pretend we (Alice) captured Bob's HELLO and replay it to the victim
    // on a fresh WS. (In the test, Bob never connected to victim; the bytes
    // are simply re-sent on Alice's connection.)
    const ws = await harness.openWs();

    // Pre-attach listeners BEFORE sending so we don't miss the responder
    // HELLO that arrives within microseconds of our send.
    const events = { message: null, close: null };
    const settled = new Promise((resolve) => {
      let done = false;
      const finish = () => { if (!done) { done = true; resolve(); } };
      ws.once('message', (m) => { events.message = m; finish(); });
      ws.once('close',   (code, reason) => {
        events.close = { code, reason: Buffer.isBuffer(reason) ? reason.toString('utf8') : String(reason || '') };
        finish();
      });
      setTimeout(finish, 3500);
    });

    // Send Bob's HELLO bytes; swallow send errors (ws may already be closing).
    try { await harness.sendWsRaw(ws, bobHello); } catch {}
    await settled;

    // Impersonation = the victim responded with its own HELLO frame
    // (i.e., session established under Bob's identity).
    let impersonationAccepted = false;
    if (events.message) {
      const m = Buffer.isBuffer(events.message) ? events.message : Buffer.from(events.message);
      if (m.length === C.FRAME_LEN) impersonationAccepted = true;
    }

    return {
      precondition: true,
      impersonationAccepted,
      closeInfo: events.close,
    };
  },

  verify(result) {
    if (!result.precondition) return false;   // setup failed → inconclusive, count as fail for visibility
    // Defense holds iff impersonation was NOT accepted.
    return result.impersonationAccepted === false;
  },
};
