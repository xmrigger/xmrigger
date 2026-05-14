# Red-team log — xmrigger federation v1.0

A running record of adversarial findings against the federation transport
defined in [SPEC-FEDERATION-v1.md](SPEC-FEDERATION-v1.md). Each entry
documents who looked, what they tried, what broke (or didn't), and the
patch that closed it.

Reproducing every entry: `npm run test:redteam:real` (full suite) or
`node test/red-team/run.js --target real --id NN` for a single scenario.

---

## Convergence summary as of 2026-05-13

| Pass | Reviewer | Scenarios | Findings | Blue-team work |
|------|----------|-----------|----------|----------------|
| #1 | initial (in-band) | 12 | 0 | none required |
| #2 | independent (sub-agent) | 8 (#13–#20) | 6 vuln (1 CRIT, 1 HIGH, 3 MED, 1 LOW-docs) | 6 fixes + 1 spec erratum |
| #3 | post-fix verification | 20 | 0 | none required |

All 20 scenarios pass against the live implementation. Convergence held
on two consecutive independent passes.

---

## Findings

Severity classification: CRITICAL ≥ HIGH ≥ MEDIUM ≥ LOW. CRITICAL closes
within the same session; HIGH/MEDIUM close before the next release; LOW
goes into a documentation or follow-up backlog.

### F-001 (CRITICAL) — HELLO cross-session replay → impersonation

**Found:** pass #2, 2026-05-13
**Scenario:** `test/red-team/scenarios/14-hello-cross-session-replay.js`
**Vector:** an observer captures a peer's valid HELLO frame on the wire,
then replays the byte-exact 192 B on a fresh WS to a different victim.

**Why it worked:** the `_seenNonces` LRU was held inside the `Session`
object, per-WS-connection. A fresh connection always started with an
empty set, so the replay window was never closed across sessions.

**Impact:** a Sybil pre-seater could occupy as many slots in the victim's
`_sessions` map as captured HELLOs they had, all bearing the original
signer's `id_pub` — denying the legitimate signer space and emitting
spurious `peer-connected` events.

**Fix:** moved nonce LRU to `FederationNode._helloNonces` (per-process,
4096-entry LRU, age-bounded by 2 × ts-skew tolerance). Session now
delegates the check via a callback injected by the node.

**Code:** `src/federation/node.js:_helloNonceSeen`,
`src/federation/session.js:_onHandshake`.

**Verification:** `node test/red-team/run.js --target real --id 14` → PASS.

---

### F-002 (HIGH) — WS close `reason` payload leaks which guard fired

**Found:** pass #2
**Scenario:** `13-close-code-reason-leak.js`
**Vector:** `ws.close(1008, '<reason>')` calls embed strings like
`'banned'`, `'handshake-rate'`, `'half-open-cap'`, `'wire'`, `'replay'`,
`'equivocation'`, `'handshake-timeout'`. The close-frame payload is
delivered to the peer, providing exactly the differential signal that
SPEC §5.6 promises to deny.

**Impact:** an active prober can fingerprint defense thresholds and the
current state of any guard, enabling targeted resource exhaustion.

**Fix:** removed every `reason` string from `ws.close(code, ...)` calls
in `session.js` and `node.js`. Close emits bare close code only. Local
operator logs remain detailed; the wire is silent.

**Verification:** scenario 13 PASS.

---

### F-003 (MEDIUM) — Equivocation false positive on honest Monero reorg

**Found:** pass #2
**Scenario:** `15-equivocation-honest-reorg.js`
**Vector:** Monero short reorgs are normal; an honest proxy can legitimately
observe and re-announce a different prevhash for the same height. The
SPEC §5.4 rule "two prevhash for one (id, height) → ban 1 h" was treating
this as malicious.

**Impact:** repeated reorgs over 24 h (plausible on busy proxies) trigger
persistent ban (30 days) of honest peers via the
`HARD_HISTORY_24H_LIMIT` chain.

**Fix:** `FederationNode._looksLikeHonestReorg(height, evidence)` checks
whether the "existing" prevhash for that height has been independently
observed by at least one *other* peer. If yes → emit `reorg-observed`
instead of `peer-banned`. The cache itself still raises evidence;
policy decides what to do with it.

**Heuristic limit:** with two peers total (the receiver plus the
equivocator), no third party can corroborate, and the heuristic still
treats it as malicious. This is a trade-off accepted for v1.0.

**Verification:** scenario 15 PASS.

---

### F-004 (LOW, docs) — AEAD AAD spec/impl drift

**Found:** pass #2
**Scenario:** `16-aead-aad-spec-d8-deviation.js`
**Drift:** SPEC §3.6 D8 originally said `ad = signed region byte-exact`.
Implementing this with ChaCha20-Poly1305 is structurally impossible — AAD
must be known to the receiver before decryption, but in our protocol the
intended AAD *is* the first 128 bytes of plaintext.

**Resolution:** SPEC §3.6 amended with **erratum E-AEAD-AAD** declaring
`AAD = empty` as the canonical wire encoding. End-to-end integrity is
provided by the Ed25519 signature embedded in the plaintext; AEAD
provides confidentiality and per-hop authentication.

The implementation in `crypto.js` already matched the new wording; the
fix was documentation, not code.

**Verification:** scenario 16 PASS (round-trip + on-path tamper rejection
+ inner-sig tamper rejection all green).

---

### F-005 (MEDIUM) — Handshake-rate budget consumed by rejected attempts

**Found:** pass #2
**Scenario:** `17-handshake-count-not-released.js`
**Vector:** in `_accept`, `ipRate.allowHandshake(ip)` was called BEFORE
the half-open cap check. An attacker filling half-open slots could
cause subsequent victim attempts to burn handshake-rate tokens even
though those attempts were going to be rejected at the half-open gate.

**Impact:** asymmetric: attacker pays one zombie TCP per slot held;
victim co-located behind the same NAT pays the entire 3/60 s budget
just for reconnect attempts that never reach handshake. Self-lockout.

**Fix:** reorder gates in `node.js._accept` — ban list, max-peers,
half-open cap, *then* handshake-rate. If handshake-rate later denies,
release the just-acquired half-open slot.

**Verification:** scenario 17 PASS.

---

### F-006 (MEDIUM) — PREVHASH replay within freshness window not detected

**Found:** pass #2
**Scenario:** `19-prevhash-replay-within-session.js`
**Vector:** `verifyFrame` is stateless and `Session._onRaw` post-ready
had no replay check. A byte-exact replay of a previously delivered
PREVHASH ciphertext passed AEAD decrypt (same session key), passed Ed25519
verify (same signature), passed ts skew, and emitted a duplicate
`prevhash-announce`.

**Impact:** an observer with read access to ciphertext on a shared bus
can amplify a chosen signal by re-broadcasting old frames, biasing the
PrevhashMonitor v0.2 majority vote in quiet windows.

**Fix:** `FederationNode._framePostSeen(idHex, parsed, plaintext)` —
per-peer LRU (1024 entries) keyed on `(timestamp, payload prefix,
signature prefix)`. Duplicate detected → emit `policy-violation` with
reason `'replay'`. SPEC §3.6 erratum updated to describe the
post-handshake replay set explicitly.

**Verification:** scenario 19 PASS.

---

## Things tried that DID hold

| Scenario | What pass #2 expected to break | Why it held |
|----------|--------------------------------|-------------|
| 18 BigInt edge cases | `BigInt(-1)` silent wraparound; `0` vs `0n` cache key collision | Node `writeBigUInt64BE` throws on negative; cache key uses `.toString()` so `0` and `0n` correctly collide on the same height. |
| 20 `stop()` race | Pending connectOut continuations might zombie-populate `_sessions` after stop | `stop()` sets `_stopped=true`, clears all timers, clears `_sessions`. `_connectOut.on('open', …)` now checks `_stopped` and closes the new ws if stopped — race window closed in the same patch. |

## Non-security bugs cleaned up in the same pass

- Dead fallback `crypto.randomBytes ? : require('crypto').randomBytes` in
  `identity.js` — the imported `crypto` module reference did not expose
  `randomBytes`, so the ternary was always the fallback branch. Cleaned up.
- Double `ws.on('error', …)` listener on outbound connections in
  `_connectOut`. Removed redundant listener; `close` always fires after
  `error`, so a single reconnect trigger is sufficient.
- Stale backward-compat comment block for the removed `broadcastPrevhash(hex)`
  string form removed from `node.js`.

## How to reproduce / contribute

1. `git clone https://github.com/xmrigger/xmrigger && cd xmrigger`
2. `npm install`
3. `npm test` (suite base, 26 + 18 + 34 + 4 = 82 PASS expected)
4. `npm run test:redteam:real` (live red-team, 20 PASS expected)

To add a new scenario:

1. Drop a file in `test/red-team/scenarios/NN-name.js` following the
   format of existing scenarios (id, name, spec ref, attack_vector,
   `run(harness)`, `verify(result)`).
2. Run `npm run test:redteam:real`. If your scenario returns FAIL, you
   have either found a real vuln or written an over-strict assertion.
3. Open an issue tagged `redteam`. If credible, the maintainers will
   triage, write a fix, and update this log.

Embargo and disclosure policy: see [SECURITY.md](SECURITY.md).
