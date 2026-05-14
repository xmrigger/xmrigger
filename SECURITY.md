# Security policy — xmrigger

xmrigger is a Monero mining defense library. The two guards
(`HashrateMonitor`, `PrevhashMonitor`) plus the federation transport
defined in [SPEC-FEDERATION-v1.md](SPEC-FEDERATION-v1.md) take
adversarial input by design — a hostile pool, a malicious peer, an
on-path observer. The protocol's threat model is documented; this file
covers everything outside that document.

## Reporting a vulnerability

If you believe you have found a security issue:

- **Email** `tnzx@proton.me` with the prefix `[security]` in the subject.
- If you would like the report end-to-end encrypted, request a PGP key
  in your first message and one will be sent in reply.
- Please include reproduction steps, an estimate of severity, and your
  preferred disclosure timeline.

### What we treat as in-scope

- Anything that contradicts a claim in `SPEC-FEDERATION-v1.md` §6 (threat
  catalogue) or §2 (threat model summary).
- Anything that lets a peer with no mining-bound proof connect to the
  federation.
- Anything that lets an on-path observer recover frame contents or
  forge frames that are accepted as valid.
- Memory-safety issues, unhandled exceptions that crash the host
  process, or unbounded data structures that grow without LRU eviction.
- Bypasses of the per-IP / per-peer rate caps or strike escalation.
- Differential signal on the wire that distinguishes which defense fired
  (violates §5.6 "no diagnostic feedback").

### What we treat as out of scope

- Long-lived correlation of an operator across many sessions from the
  same IP. The protocol is IP-agnostic; use Tor or i2p if you need
  IP-level anonymity.
- Compromise of a node's code execution (RCE, supply-chain). Out of
  scope of the protocol; report to the upstream Node.js/`ws` projects
  if relevant.
- Pool collusion to coordinate selfish mining. That's the problem the
  detection guards exist to surface, not the federation transport.
- Issues in xmrigger ≤ 0.1 (before the federation transport landed) —
  the network layer there was JSON-based and has been superseded.

## Disclosure timeline

Default coordinated-disclosure window:

| T+ | Step |
|----|------|
| 0 | Report received. Acknowledgement within 72 h. |
| ≤ 7 d | Triage complete, severity assigned, fix planned. |
| ≤ 30 d | Fix in master, scenario added to `test/red-team/scenarios/`, entry added to `RED-TEAM-LOG.md`. |
| 90 d (or earlier by agreement) | Public disclosure with reporter credit. |

If the issue is being actively exploited or the fix is trivial, we will
shorten the window. If the issue is deeply structural, we may extend it
by mutual agreement.

We don't run a bug-bounty program. Findings of merit are listed in
`RED-TEAM-LOG.md` and acknowledged in release notes; if you would
prefer not to be named, say so in your report.

## Already-known limitations

These are documented in SPEC and not security issues per se, but
they're listed here so reporters can save time:

- **Sybil set ≥ 50 % of fresh peers** can force the prevhash majority
  vote. v1.0 raises the cost from "free" to "one running mining-bound
  proxy per identity"; v1.1 ring-signatures roadmap would raise it
  further but ships only after independent crypto review.
- **DNS rebinding** on `HashrateMonitor` network endpoints (`*.local`
  resolving to private IPs is blocked, but a public hostname that
  resolves to a private IP at fetch time is not re-checked at the IP
  layer). Mitigated by endpoint plurality.
- **TLS pinning** is not enforced on the default network-info
  endpoints (`xmrchain.net` et al.). A compromised CA could MITM the
  difficulty fetch. Mitigated by endpoint plurality.
- **Two-peer reorg disambiguation:** with only two nodes in the
  federation (receiver + suspect), the honest-reorg heuristic cannot
  corroborate via a third party and will treat reorgs as equivocation.
  Workaround: run with three or more peers.

## Independent red-team work

We welcome independent adversarial review. Drop scenarios in
`test/red-team/scenarios/` (numbered ≥ 21), run
`npm run test:redteam:real`, and open a PR or an issue with the
result. Past findings are catalogued in `RED-TEAM-LOG.md`.

Thank you.
