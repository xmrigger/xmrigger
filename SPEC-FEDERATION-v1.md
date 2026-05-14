# xmrigger Federation Protocol Specification — v1.0 (draft)

Status: **DRAFT** — open decisions D4–D8 resolved; subject to change during
red/blue iteration.
License: LGPL-2.1
Audience: implementers, auditors, red teams.

---

## 0. Document scope

This specification defines the wire protocol, identity discipline, and
defensive posture of the **federation transport** that connects independent
xmrigger-proxy operators. Its sole purpose is to carry the timing-sensitive
mining signals consumed by `HashrateMonitor` (via the federation hint path)
and `PrevhashMonitor` v0.2 (via the federation peer-announce path).

It is **not** a general-purpose pub/sub. It is **not** a marketplace. It is
**not** a discovery service. It is **not** an anonymity network. Forks that
use it for those purposes operate outside the validated scope of this
library; see `README.md` §"Scope and design intent" and `LICENSE` (LGPL-2.1).

The federation API surface this transport implements is minimal and is
already expected by `PrevhashMonitor` v0.2:

```js
federation.broadcastPrevhash(prevhash)
federation.on('prevhash-announce', ({ from, prevhash, ts }) => …)
federation.on('peer-banned',       ({ ip, reason })          => …)
```

---

## 1. Goals and non-goals

### 1.1 Goals

| G# | Goal |
|----|------|
| G1 | Carry the four federation signals consumed by xmrigger guards: peer hello, peer disconnect, prevhash announcement, hashrate concentration alert. |
| G2 | Make every frame delivered to a guard module **cryptographically attributable** to a peer that holds an active mining proxy ("mining-bound identity"). |
| G3 | Make the wire format **structurally narrow**: three frame types, fixed 192-byte size, no extension space. Cannot be repurposed without a wire-breaking version bump. |
| G4 | Defend against the threat catalogue in §6 by construction wherever possible, by runtime check otherwise. |
| G5 | Be deterministically auditable: the entire wire format and parser fits in a few hundred lines of code with explicit byte-level invariants. |
| G6 | Be **Tor-friendly** by being IP-agnostic at the protocol level. |
| G7 | Cohabit cleanly with the existing zero-dependency stance of `xmrigger`. Only Node.js built-in `crypto` is used. |

### 1.2 Non-goals (explicit)

| N# | Non-goal | Rationale |
|----|---------|-----------|
| N1 | K-anonymity of the signing identity (ring signatures) | Out of scope for v1.0; deferred to v1.1 contingent on independent crypto review of a CLSAG implementation. v1.0 ships with ephemeral-per-session identity, no long-term keys. |
| N2 | IP-level anonymity of peers | Achieved out-of-band by running the transport over Tor or i2p. The protocol is agnostic and contains no IP inference. |
| N3 | General-purpose pub/sub or messaging | Three frame types, hardcoded. No extension range, no plugin system. |
| N4 | Marketplace, service discovery, or peer directory | Same as N3. |
| N5 | Cover traffic, traffic-shape obfuscation, mixnet behaviour | Producing decoy traffic at a layer above TLS reliably leaks more than it hides; if you need this, run over Tor. |
| N6 | Forward secrecy across multiple sessions | Each session has its own ephemeral X25519 key. There is no long-term key whose compromise could decrypt past sessions, because there is no long-term key. |
| N7 | Cross-session reputation | Identities are ephemeral per session. Bans are local and IP-based, capped at 1 h. Nothing persists beyond this. |
| N8 | In-band kill-switch, security advisory, or governance signal | Security updates are distributed through the same channels as any LGPL library (GitHub releases, npm, security advisory). The protocol carries no out-of-protocol authority. |

---

## 2. Threat model summary

A full red-team catalogue is in §6 and tracked in `RED-TEAM-LOG.md`. Here is
the high-level framing.

### 2.1 What this protocol defends against

- A peer that injects malformed or oversized frames to exhaust receiver
  resources.
- A peer that signs no valid mining-bound proof yet attempts to participate.
- A peer that equivocates (signs two contradictory PREVHASH for the same
  block height) within a short window.
- A peer that replays captured frames after their freshness window has
  elapsed.
- A peer that opens many half-handshake connections to exhaust slots.
- An on-path observer that attempts to read frame contents (defended by
  AEAD), to alter frames (defended by AEAD authentication tag and Ed25519
  signature inside the AAD), or to substitute frames (defended by both).

### 2.2 What this protocol does NOT defend against

- **Long-lived correlation across many sessions of the same operator.** A
  determined observer who logs every connection from a given IP over weeks
  can correlate behaviour patterns. Mitigation = run over Tor (out-of-band).
- **IP-level deanonymisation of a peer.** The transport is IP-agnostic;
  the operator is not. Mitigation = Tor.
- **Compromise of code execution inside the proxy itself.** If an attacker
  achieves RCE on the proxy, the protocol does nothing for you. Out of
  scope.
- **Pool collusion to coordinate selfish mining at the network layer.** This
  is the problem `xmrigger` exists to *detect*; the federation merely shares
  the observations. The detection logic is in `PrevhashMonitor`.
- **A Sybil set of mining-bound identities exceeding 50 % of fresh peers.**
  Mitigation requires K-anonymity ring signatures (v1.1 roadmap) or active
  attestation (out of scope). v1.0 limits the surface via hardcoded peer
  caps and rate limits but cannot prevent an adversary willing to spend
  many real mining proxies.

---

## 3. Wire format

### 3.1 Frame layout — fixed 192 bytes for all three types

Every frame on the wire is exactly 192 bytes of plaintext, then encrypted
with ChaCha20-Poly1305 AEAD producing 12 (nonce) + 192 (ciphertext) + 16
(tag) = **220 bytes per frame on the wire**. There is no length prefix and
no version negotiation: a wrong-size frame is dropped silently.

```
plaintext frame = x⁰ ‖ x¹ ‖ x² ‖ x³

x⁰  header     16 B   proto_v | type | timestamp | reserved
x¹  identity   32 B   Ed25519 public key of the sender (this session)
x²  payload    80 B   schema-locked, depends on type
x³  signature  64 B   Ed25519(id_priv, x⁰ ‖ x¹ ‖ x²)
              ────
              192 B
```

### 3.2 Header (x⁰) — 16 bytes

| Offset | Size | Field          | Constraint |
|-------:|-----:|----------------|------------|
| 0      | 1 B  | `proto_v`      | MUST equal `0x02` |
| 1      | 1 B  | `type`         | MUST be 1 (HELLO), 2 (PREVHASH), or 3 (GUARD) |
| 2      | 8 B  | `timestamp_ms` | uint64 BE, sender wall clock at frame creation |
| 10     | 6 B  | `reserved`     | MUST be `0x00 × 6` |

Any byte in `reserved` ≠ 0 → drop + strike. `proto_v` ≠ 2 → close session
without strike (wire-incompat, not adversarial). `type` ∉ {1, 2, 3} → drop
+ strike. `|now − timestamp_ms| > 300_000` → drop + strike.

### 3.3 Identity (x¹) — 32 bytes

Raw Ed25519 public key (32 B), generated fresh at session start by the
sender. Identity is **ephemeral per session** (see §4). The `from` field
delivered to consumer code is the hex encoding of these 32 bytes.

### 3.4 Payload (x²) — 80 bytes, schema-locked

The 80-byte slot is interpreted according to `type`. Reserved sub-fields
MUST be zero — non-zero → drop + strike.

#### 3.4.1 TYPE = 1 (HELLO)

| Offset | Size  | Field                | Notes |
|-------:|------:|----------------------|-------|
| 0      | 32 B  | `eph_pub_x25519`     | X25519 ephemeral pubkey for AEAD session key derivation |
| 32     | 32 B  | `recent_prevhash`    | Hex-derived 32 B; a Monero block hash recently observed by sender's upstream pool |
| 64     | 16 B  | `nonce`              | Random, anti-replay within the timestamp window |

The HELLO is the only frame that establishes a session and is the only one
that contains the X25519 ephemeral key. Subsequent PREVHASH/GUARD frames
travel under the AEAD session key derived from the HELLO exchange.

#### 3.4.2 TYPE = 2 (PREVHASH)

| Offset | Size  | Field                | Notes |
|-------:|------:|----------------------|-------|
| 0      | 8 B   | `pool_id`            | uint64 BE, truncated SHA-256 of the upstream pool endpoint |
| 8      | 32 B  | `prevhash`           | Monero block prev-hash observed |
| 40     | 8 B   | `block_height`       | uint64 BE, height of the block whose prev-hash this is |
| 48     | 32 B  | reserved             | MUST be zero |

`pool_id` lets a receiver disambiguate when one peer watches multiple
pools (out of scope today but the field is there). `block_height` is the
canonical key for equivocation detection (§5.4).

#### 3.4.3 TYPE = 3 (GUARD)

| Offset | Size  | Field                  | Notes |
|-------:|------:|------------------------|-------|
| 0      | 4 B   | `concentration_ppm`    | uint32 BE, parts-per-million (0–1_000_000), pool/network ratio |
| 4      | 1 B   | `observed_peers`       | uint8, number of peers the sender observed when computing |
| 5      | 8 B   | `window_start_ms`      | uint64 BE, start of measurement window |
| 13     | 67 B  | reserved               | MUST be zero |

GUARD is a hint, not a command. Receivers MUST NOT evacuate purely on a
peer GUARD; they MUST trigger an independent local poll
(`HashrateMonitor.pollNow()`) and act only on their own measurement
(see SPEC.md §"Federation Alert Protocol").

### 3.5 Signature (x³) — 64 bytes

```
x³ = Ed25519_sign(id_priv, x⁰ ‖ x¹ ‖ x²)
```

The signature covers the first 128 bytes (header + identity + payload).
Verifier MUST reconstruct the byte-exact prefix and reject any signature
that does not verify against `id_pub = x¹`. Strict RFC 8032: small-subgroup
checks on the public key, canonical scalar `s` enforced.

### 3.6 AEAD wrapping

```
session_key = HKDF-SHA256(X25519(my_eph_priv, peer_eph_pub),
                          "xmrigger-federation-v1")

nonce = 12 random bytes per frame
ad    = (empty)                  -- see ERRATUM E-AEAD-AAD below
ct    = ChaCha20-Poly1305_Encrypt(session_key, nonce, ad, frame)
wire  = nonce ‖ ct ‖ tag         -- 12 + 192 + 16 = 220 bytes
```

End-to-end frame integrity is provided by the **Ed25519 signature embedded
in the last 64 bytes of the plaintext** (`x³`), which signs the first 128
bytes (signed region). AEAD here provides confidentiality and per-hop
authentication of the ciphertext.

#### ERRATUM E-AEAD-AAD (resolved 2026-05-13)

An earlier draft of this section specified `ad = x⁰ ‖ x¹ ‖ x²` (the signed
region) under D8. This is **structurally impossible** with ChaCha20-Poly1305
as standardly implemented: AAD is bound into the auth tag at encryption
time, so the receiver must know the AAD value BEFORE running decrypt — but
the receiver does not have the plaintext yet, and AAD = "first 128 bytes
of plaintext" is a chicken-and-egg circular dependency.

Two resolutions were considered:

1. Ship AAD on the wire separately (+ 128 B per frame overhead, breaks
   wire-uniformity).
2. Use AAD = empty and rely on the inner Ed25519 signature for integrity.

Resolution: **option 2**. The Ed25519 signature inside the plaintext is
the binding end-to-end integrity check. AEAD provides confidentiality and
protects the channel against on-path mutation that would corrupt the
ciphertext before reaching the legitimate peer. The two mechanisms are
complementary; the original D8 wording was an authoring mistake, not a
load-bearing protocol decision.

The implementation in `src/federation/crypto.js` calls
`crypto.createCipheriv('chacha20-poly1305', ...)` and `createDecipheriv`
without `setAAD()`. This is the canonical wire encoding for v1.0.

#### Replay protection

Replay is handled at two layers, both **per-process** (not per-session):

- **HELLO nonces**: every HELLO carries a 16-byte random nonce in its
  payload. The receiver maintains a process-wide LRU set
  (4096 entries, evicted by age beyond 2 × ts-skew tolerance) and rejects
  any HELLO whose nonce was already seen. This stops cross-session replay
  attacks (red-team finding #14) where captured HELLO bytes are re-played
  on a fresh WS connection.
- **PREVHASH / GUARD frames**: post-handshake, the receiver maintains a
  per-peer LRU (1024 entries per peer-id) keyed on a compact digest of
  (timestamp, payload prefix, signature prefix). Duplicate frames within
  the freshness window are dropped without strike (the peer is allowed
  one mistake — this is data-frame deduplication, not a punitive signal).

The `nonce` for AEAD itself is generated by `crypto.randomBytes(12)` per
frame and is never reused under the same session key.

---

## 4. Identity and session lifecycle

### 4.1 Ephemeral identity

At process start, the federation module generates **a single Ed25519
keypair** for this session. The private half is held in memory only and is
discarded on process exit. The public half is `x¹` in every frame this
process sends.

Across restarts, identity changes. Across sessions to different peers,
identity is shared (one identity per running process, not per peer connection).
This is intentional: rotation per-process is enough to prevent long-term
correlation, while keeping per-process operations consistent (a peer that
sees the process as `id_pub_X` consistently within a single process lifetime
can apply local trust scoring).

### 4.2 No `deriveIdentity` from a wallet seed

Earlier drafts explored HKDF-from-seed for persistent identity. v1.0
**rejects** persistent identity. Reasons:

- A long-term key is an attractive compromise target for deanonymisation.
- Reputation across sessions has no use case in this protocol: PrevhashMonitor
  is height-paced (votes per block), not actor-paced.
- Removing persistence simplifies the threat model: there is nothing to
  leak from disk, nothing to back up, nothing to migrate.

### 4.3 Mining-bound HELLO

A peer attempting to join MUST prove, at HELLO, that it currently observes
the Monero chain (i.e., it is a real mining proxy, not a free-rider).
Proof = signing a `recent_prevhash` that the receiver can reconcile with
the chain it sees.

Validation by the receiver:

1. `|now − timestamp_ms| ≤ 300_000` (5 minutes).
2. Ed25519 signature `x³` verifies against `x¹`.
3. `recent_prevhash` is one of:
   - the receiver's own `_ownPrevhash`,
   - a prevhash announced by a fresh peer in the receiver's `_peers` map
     within the last 30 seconds,
   - any 32-byte value if `process.env.TNZX_FEDERATION_BOOTSTRAP === "1"`
     (D5: explicit bootstrap mode for cold-start of the network).

Failure of any of these → close session without ban (the peer may simply
be on a different chain or freshly started).

### 4.4 Cold-start (D5)

The bootstrap problem: the very first node of a new federation has no
peers and therefore cannot validate any incoming HELLO via §4.3 step 3.
Resolution: operator sets `TNZX_FEDERATION_BOOTSTRAP=1` for that single
process. While this is set, the `recent_prevhash` field is accepted
without chain reconciliation (only the timestamp window applies). The
operator is expected to disable this env var once the federation has at
least 2 active peers.

The env var is a soft-policy concession to operations and is documented in
README.md and SECURITY.md as a temporary measure. It does not bypass
signature verification, frame validation, or rate limits.

### 4.5 Session termination

Sessions terminate on:

- TCP close.
- Handshake timeout (10 s without HELLO completion).
- Peer signature failure on any frame.
- Local ban triggered (§5).
- Local administrative shutdown.

There is no graceful BYE frame. TCP close is sufficient. (One frame type
saved; one fewer attack surface.)

---

## 5. Defensive runtime behaviour

### 5.1 Per-peer rate limiting

Token bucket per peer (identified by `id_pub`), hardcoded values:

| Rate | Sustained | Burst |
|------|-----------|-------|
| Frames per second per peer | 5 | 20 |
| Bytes per second per peer | 5 KB | 20 KB |

PREVHASH and GUARD frames count against the bucket. HELLO is one-time and
exempt within the same session (it cannot be repeated under the same
ephemeral key without a new session). Excess frames → drop + strike.

### 5.2 Per-IP rate limiting (D6 + D7)

These bound the cost of opening sessions, before any identity is
established:

| Rate | Limit | Window |
|------|-------|--------|
| New handshake attempts per IP | 3 | 60 s |
| Concurrent half-open handshakes per IP | 5 | — |

Excess connection attempts → TCP close immediately, IP soft-banned for the
remainder of the window (no entry in the persistent ban list). This is
defence against slowloris (E19) and boot-loop (E18) without locking out an
honest operator who reconnects after a transient network failure.

### 5.3 Per-peer strike escalation (inherited from `limits.js`)

Hardcoded values, no profile, no env override:

| Threshold | Action |
|-----------|--------|
| 3 strikes within 60 s | Soft quarantine: drop further frames for 5 min, session stays open |
| 6 strikes within 60 s | Hard quarantine: terminate session, IP ban for 1 h |
| 3 hard quarantines per IP within 24 h | Persistent IP ban for 30 days |

Strikes are emitted by every drop reason in §3 and §4 except the bootstrap
soft-policy cases. The strike counter is per-`id_pub` for soft escalation
and per-IP for hard escalation, so an attacker rotating identities behind
a single IP cannot reset the hard counter.

### 5.4 Equivocation detection

For each `id_pub` × `block_height` key, the receiver maintains a 60-second
LRU cache of `(prevhash, ts)`. If a second PREVHASH frame arrives with the
same key but a different `prevhash` value, that is **equivocation**. The
receiver:

1. Bans the source IP for 1 h.
2. Drops the second frame.
3. Emits `federation.on('peer-banned', { ip, reason: 'equivocation' })`.

The cache is bounded: max 10_000 entries total, LRU eviction.

D4: **No evidence is forwarded to other peers.** Each receiver detects
equivocation independently from its own observations. This is slower to
propagate but is also resistant to evidence-injection amplification attacks.

### 5.5 Memory caps (defence-in-depth)

Hardcoded:

| Structure | Cap | Eviction |
|-----------|-----|----------|
| Connected peer sessions | 1000 | reject new connections beyond cap |
| Equivocation cache entries | 10_000 | LRU |
| Ban list entries | 10_000 | LRU + TTL |
| Per-peer seen-nonce set | 1024 | LRU within timestamp window |
| WebSocket maxPayload | 256 B | reject pre-decrypt |
| In-flight handshake state per peer | 1 KB | timeout 10 s |

Excess input is dropped at the earliest possible point. There are no
unbounded data structures in the federation module.

### 5.6 No diagnostic feedback to the wire

A peer whose frame is dropped gets no acknowledgement, no error code, no
log message visible to it. Silence. This denies an active prober (E15)
the differential signal needed to fingerprint the implementation or
discover ban thresholds.

Local logs (operator-visible) are detailed, structured, and include the
reason; the wire does not.

### 5.7 No environment-tunable security parameters

All limits in §5.1–§5.5 are hardcoded `const` values in the source. There
is no env var to relax them, no config file. The single allowed env var
is `TNZX_FEDERATION_BOOTSTRAP` (§4.4), which controls only cold-start
HELLO acceptance and does not relax any other check.

This is a deliberate constraint: tunable security parameters become
attack surfaces (operator misconfiguration, supply chain manipulation of
defaults). The price is rigidity; the benefit is uniformity.

---

## 6. Threat catalogue (red-team)

The full catalogue with attack scenarios, defenses, and tests lives in
`RED-TEAM-LOG.md`. Summary table mapping attacks to defense layer:

| # | Attack | Defense layer | Status |
|---|--------|---------------|--------|
| E1 | Long-lived correlation across sessions | Out-of-band (Tor) | Documented limit |
| E2 | Mining-bound HELLO replay | Per-peer nonce LRU + ts window | Structural |
| E3 | Equivocation as ban-injection | No evidence forwarding (D4) | Structural |
| E4 | Slow-prevhash injection | block_height vs canonical chain check in PrevhashMonitor | Runtime |
| E5 | Identity recycling racing | Per-IP handshake rate cap (D6) | Structural |
| E6 | Parser path confusion | 3 hardcoded type branches, fixed schema | Structural |
| E7 | Length-prefix abuse | No length prefix, fixed 192 B | Structural |
| E8 | Signature malleability | Strict Ed25519 (RFC 8032 enforced) | Structural |
| E9 | AAD ≠ signed region confusion | AAD = signed region byte-exact (D8) | Structural |
| E10 | Zero-byte tolerance | Bytewise == 0 reserved-zero check | Structural |
| E11 | Frame size leak | All frames 192 B fixed | Structural |
| E12 | Session opening timing | Inevitable | Documented limit |
| E13 | IP correlation via reconnect | Out-of-band (Tor) | Documented limit |
| E14 | Cross-session linkage by patterns | Out-of-band | Documented limit |
| E15 | Active probing | Silent drop, no diagnostic | Structural |
| E16 | Clock skew | ±5 min ts tolerance | Runtime |
| E17 | Multi-pool peer claim flooding | Equivocation cache bounded | Structural |
| E18 | Boot-loop | Per-IP handshake rate cap | Structural |
| E19 | Half-open slowloris | Per-IP half-open cap (D7), 10 s timeout | Structural |
| E20 | Ban list spam | LRU cap 10 000 | Structural |
| E21 | parse(serialize(x)) ≠ x | Property test in conformance suite | Test |
| E22 | Sign/verify mutation tolerance | Property test mutating each byte | Test |
| E24 | Endianness disagreement | All multi-byte = big-endian, pinned in §3 | Structural |
| E25 | Memory pressure indeterminism | LRU policy, deterministic order | Structural |

---

## 7. Reference test vectors

Byte-exact test vectors live in `TEST-VECTORS.md`. Every conforming
implementation MUST reproduce them bit-for-bit:

- TV-1: HELLO with deterministic seed, expected x⁰‖x¹‖x²‖x³ as hex.
- TV-2: PREVHASH with deterministic seed and block_height = 1234567.
- TV-3: GUARD with concentration_ppm = 320_000.
- TV-4: Sign/verify round-trip on TV-1, TV-2, TV-3.
- TV-5: Mutate-and-fail on every byte of TV-1.
- TV-6: AEAD encrypt/decrypt of TV-1 with deterministic nonce.
- TV-7: HKDF derivation of session_key from two test ECDH inputs.

CI requirement: `npm run test:conformance` runs all TVs.

---

## 8. Live test plan

`test/federation-e2e.js` plus a separate manual script set in
`test/live/` cover:

| L# | Scenario | Automatable in CI |
|----|----------|---|
| L1 | Bootstrap mining-bound against a real stagenet pool | Yes (slow, ~30 s) |
| L2 | Reconnect after ban (variations of IP/identity) | Yes |
| L3 | Equivocation live multi-node | Yes |
| L4 | Slowloris on handshake | Yes |
| L5 | Frame oversize via raw WebSocket | Yes |
| L6 | Sign/verify property test (10k mutations) | Yes |
| L7 | Clock skew tolerance | Yes |
| L8 | Network partition + recovery | No (requires container or netns) — manual |
| L9 | Cold start of the network (TNZX_FEDERATION_BOOTSTRAP) | Yes |
| L10 | Live stagenet pool, 1-hour stability | No (manual operator run) |

---

## 9. Open issues / future work

| # | Issue | Resolution path |
|---|-------|-----------------|
| O1 | Ring signatures (CLSAG) for K-anonymity | v1.1, contingent on independent crypto review. Will require wire bump to proto_v=3. |
| O2 | HashrateMonitor clock injection (audit F7) | Independent refactor task, parity with PrevhashMonitor. Not blocking federation. |
| O3 | DNS rebinding hardening in `_fetchJson` (audit F10) | Optional v1.x. Requires hostname → IP resolution + re-check; adds DNS round-trip. |
| O4 | TLS pinning on default network endpoints (audit F14) | Significant operational cost; not v1.0. Document. |
| O5 | Forward equivocation evidence between peers (D4 alternative) | Rejected for v1.0; revisit if amplification-attack mitigation can be proven. |

---

## 10. Compatibility statement

v1.0 is **wire-incompatible** with the JSON-based "Federation Alert
Protocol" defined in `SPEC.md` v0.1 §"Federation Alert Protocol". That
protocol was optional and is hereby deprecated. SPEC.md will be updated
in the same change set that introduces this document.

A node implementing only v0.1 JSON cannot connect to a node implementing
v1.0. This is intentional: v0.1 had no signing, no replay protection, no
identity attestation, and no rate limits.

There is no v1.0 fallback to v0.1.

---

*End of SPEC-FEDERATION-v1.md draft.*
