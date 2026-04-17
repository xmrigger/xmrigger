# xmr-hashguard Protocol Specification v0.1

## Problem

A Monero mining pool that accumulates more than ~30% of total network hashrate
poses a risk to the 51%-attack security boundary. Miners individually have no
automatic mechanism to detect this and switch pools. A pool can simply refuse
to report its own share of network hashrate, making opt-in monitoring
ineffective.

## Goal

Define a minimal protocol that any miner, wrapper, or proxy can implement to:
1. Independently measure pool hashrate concentration
2. Warn the operator as the pool approaches a threshold
3. Disconnect automatically after a grace period if the threshold is sustained
4. Optionally broadcast an alert to peer nodes (federation)

## Definitions

- **Pool hashrate** (H_pool): total hashrate contributed to the target pool
- **Network hashrate** (H_net): total Monero network hashrate = `difficulty / 120`
- **Concentration ratio** (R): `R = H_pool / H_net`
- **Threshold** (T): configurable fraction, recommended default **0.30** (30%)
- **Warn level** (W): `W = T × 0.85`

## Data Sources

### Network hashrate

Network hashrate MUST be obtained from a source independent of the pool being
monitored. Implementations SHOULD query multiple sources concurrently and use
the first valid response.

Reference sources (Monero mainnet):

| URL | Response field |
|-----|---------------|
| `https://xmrchain.net/api/networkinfo` | `difficulty` |
| `https://community.xmr.to/api/v1/networkinfo` | `data.difficulty` |
| `https://moneroblocks.info/api/get_stats` | `difficulty` |
| `https://localmonero.co/blocks/api/get_stats` | `last_difficulty` |
| `https://p2pool.io/api/pool_info` | `mainchain.difficulty` |

`H_net = floor(difficulty / 120)`

### Pool hashrate

Preferred (highest trust, pool cannot suppress):
1. **Local measurement**: count accepted shares × current difficulty / time window
2. **Independent third-party**: miningpoolstats.stream or equivalent

Fallback (lowest trust — pool controls this data):
3. **Pool self-report**: `GET /pool/health` → `{ hashratePct: 0.0–1.0 }`

If the pool refuses to expose stats and no independent source is available,
the implementation MUST NOT treat this as "safe". It SHOULD log a warning and
optionally trigger evacuation after a configurable timeout.

## State Machine

```
         R < W                R >= W               R >= T
SAFE ──────────────▶ SAFE   SAFE ──────────▶ WARN   WARN/SAFE ──────▶ CRIT
                             WARN ──────────▶ WARN                          │
                             WARN ──────────▶ SAFE (R drops)                │ grace period starts
                                                                             ▼
                                                                          GRACE
                                                                             │ countdown (default 60s)
                                                              R drops?       │
                                                      SAFE ◀──────────────  │
                                                                             │ countdown expires
                                                                             ▼
                                                                         EVACUATE
```

Fork detection overrides all states → immediate EVACUATE (no grace period).

## Grace Period

When R >= T:
- Grace period begins (default 60s, operator-configurable)
- Emit one `grace-tick` event per second with `secsLeft`
- If R drops below W before countdown expires: cancel grace, return to SAFE
- If countdown expires: EVACUATE

Rationale: a brief spike (e.g. difficulty adjustment, burst of new miners
joining) should not cause unnecessary disconnections. The grace period
absorbs transient fluctuations.

## Evacuation

On EVACUATE:
1. Stop the current miner connection
2. Cycle to the next fallback pool (round-robin)
3. Restart the miner pointed at the fallback
4. Resume monitoring (possibly with a new pool health URL)

If no fallback is configured: stop mining, wait a configurable backoff
(default 5 minutes), then retry the primary pool.

## Federation Alert Protocol (optional)

Nodes participating in a proxy federation MAY broadcast guard alerts to peers
when they detect a threshold condition. This allows peers that share the same
upstream pool to react faster.

### Wire format

```json
{
  "type": "guard-alert",
  "reason": "threshold" | "fork",
  "hashratePct": 0.32,
  "origin": "proxy-name.xmr",
  "ts": 1713400000000
}
```

### Receiving behavior (IMPORTANT)

A node that receives a `guard-alert` from a peer MUST NOT evacuate
automatically. It MUST:

1. Apply a per-peer rate limit (ignore duplicate alerts within 60s from same peer)
2. Trigger an immediate independent poll (`pollNow()`)
3. Evacuate only if its own poll confirms threshold exceeded by its own threshold

Rationale: a peer with a low threshold (10%) or a misconfigured/malicious peer
must not be able to cause mass disconnections across the federation. Each node
is sovereign — it acts only on its own independent measurement.

## Pool Health Endpoint (for pools)

Pools implementing this spec SHOULD expose:

```
GET /pool/health
```

```json
{
  "hashratePct":       0.18,
  "avgBlockTimeMs":    122000,
  "orphanRate":        0.02,
  "forkDetected":      false,
  "federationAlerted": false,
  "gracePeriodEndsAt": null
}
```

This endpoint is informational only. Miners SHOULD cross-check it against
independent measurements rather than trusting it unconditionally.

## Security Considerations

- A pool controlling this endpoint can report `hashratePct: 0.0` to hide
  concentration. Implementations should prefer independent sources.
- Federation alerts are hints, not commands. Do not act on peer alerts without
  local verification.
- Rate-limit outbound alerts to avoid amplifying instability during incidents.

---

## Prevhash Divergence Detection (selfish mining guard)

### Motivation

A pool engaged in selfish mining must distribute Stratum jobs that reference
its private chain tip via the `prevhash` field. It cannot hide this: every
miner it employs must receive a job message, and that job message leaks the
tip of the private branch.

A proxy sitting between miners and a pool sees every `prevhash` in every
`mining.notify` (Stratum v1) or `SetNewPrevHash` (Stratum v2) message.
By sharing these values across a federation of proxies — each watching a
different pool — divergence becomes observable without any protocol changes.

### Detection logic

```
Proxy-A watches Pool-X:  prevhash = 0xAAAA  (public chain tip)
Proxy-B watches Pool-Y:  prevhash = 0xAAAA  (same — all honest)

                          ↓  Pool-Y mines privately  ↓

Proxy-A watches Pool-X:  prevhash = 0xAAAA
Proxy-B watches Pool-Y:  prevhash = 0xBBBB  ← DIVERGENCE
```

1. Each proxy broadcasts its upstream `prevhash` to federation peers:

```json
{
  "type":     "prevhash-announce",
  "prevhash": "0xBBBB...",
  "pool":     "pool-y.xmr:3333",
  "origin":   "proxy-b.xmr",
  "ts":       1713400000000
}
```

2. Each proxy compares received prevhash values against its own.
3. If disagreement **persists for `divergenceMs`** (default 20 s): emit `divergence`.
4. Operator can evacuate miners from the suspect pool.

### Why persistence matters

A brief prevhash mismatch is normal: pools may receive new blocks at different
times (propagation latency ~1–2 s). Requiring the divergence to persist for
several poll cycles eliminates false positives from network jitter.

### What this detects

| Scenario | Detected? |
|----------|-----------|
| Pool withholds block and mines privately (selfish mining) | ✓ Yes — prevhash differs from peers |
| Pool briefly ahead due to propagation delay | ✗ No — resolves within 1–2 polls |
| Pool runs on a stale tip (stuck node) | ✓ Yes — prevhash stops advancing |
| Unknown dark pool (no external miners) | ✗ No — no Stratum leakage |

### Sovereignty rule (same as hashrate guard)

A proxy that receives a `prevhash-announce` from a peer **MUST NOT evacuate
automatically**. It:
1. Updates its local peer table with the received prevhash.
2. Compares against its own upstream prevhash.
3. Evacuates only if **its own upstream** diverges from peers for `divergenceMs`.

A misconfigured peer cannot force evacuation on honest proxies.

### PrevhashMonitor API

```js
const { PrevhashMonitor } = require('xmr-hashguard');

const mon = new PrevhashMonitor({
  poolId:        'pool.hashvault.pro:3333',
  getPrevhash:   () => proxy.lastPrevhash,  // updated from Stratum stream
  pollIntervalMs: 5_000,
  divergenceMs:   20_000,
});

// Wire to federation
mon.on('announce',   ({ prevhash }) => federation.broadcastPrevhash({ prevhash }));
mon.on('divergence', ({ ownPrevhash, divergentPeers }) => {
  console.error('selfish mining suspected — evacuating');
  // evacuate miners
});
mon.on('resolved',   ({ prevhash }) => console.log('chains in sync'));

// Receive from federation
federation.on('prevhash-announce', ({ from, prevhash }) =>
  mon.onPeerAnnounce(from, prevhash));

mon.start();
```

### Compatibility with augmented proxies

Proxies that carry additional payloads within the Stratum stream are fully
compatible with this guard. Those payloads travel miner → proxy and are
intercepted there. Prevhash extraction happens on the pool → proxy path;
the two mechanisms are orthogonal and do not interfere.

Implication: during the divergence window (before evacuation triggers), miners
are unknowingly contributing hashrate to the private fork. This is unavoidable
for any miner at that pool. The guard minimises the exposure window to
`divergenceMs` and then evacuates automatically.

### Network effect and open deployment

Detection requires a federation of **≥ 2 proxies watching different pools**.
A single isolated proxy has no peers to compare against and cannot detect
divergence.

The collective protection scales with deployment:

- Each new proxy added to the federation increases the surface area of
  observation across pools.
- A pool attempting selfish mining must keep its private chain undetected
  across all federated proxies simultaneously.
- Sustained private-chain mining against a large federation is only possible
  using 100% in-house hashrate — which is both operationally difficult and
  detectable via the hashrate concentration guard.

**This is a passive, protocol-transparent answer to the selfish mining problem
described in Monero research-lab issues #136–#146.** It requires zero
modifications to the Monero protocol, zero changes to miners, and zero
additional configuration for miners who already use a compatible proxy.
Any miner pointing at such a proxy participates in the detection network
automatically.

### Relationship to hashrate guard

The two guards are **complementary**:

| Guard | Detects | Trigger |
|-------|---------|---------|
| HashrateMonitor | Pool exceeds concentration threshold (e.g. 30%) | Pool ratio ≥ T |
| PrevhashMonitor | Pool withholds blocks (selfish mining) | prevhash diverges from peers |

A pool can be dangerous with only 25% hashrate if it mines selfishly.
A pool at 35% may be honest. Both guards should run together.
