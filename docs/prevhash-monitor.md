# PrevhashMonitor — Detection Method and Accuracy

`PrevhashMonitor` detects selfish mining by comparing the `prevhash` field from
Stratum job messages across independent proxy peers in a federation.

This document explains how the detection works, what it can and cannot prove,
and what accuracy claims are honest to make.

---

## How detection works

In Stratum v1, every `mining.notify` message includes `prevhash` as `params[1]`.
In Stratum v2, `SetNewPrevHash` carries the same value.

`prevhash` is the hash of the most recent confirmed block that the pool's upstream
daemon knows about. It is the identifier of the chain tip the pool is building on.

A pool engaged in selfish mining must build on a private chain tip that differs
from the public chain. That tip propagates into `prevhash` — every job the pool
distributes will contain the private chain's hash, which differs from jobs
distributed by honest pools building on the public tip.

`PrevhashMonitor` does this:

1. Reads `prevhash` from the proxy's most recent upstream Stratum job.
2. Broadcasts it to federation peers via `xmrigger-mesh`.
3. Compares its own `prevhash` against the values reported by peers.
4. If at least `minPeersForAlert` peers report a different value, and the
   divergence persists for `divergenceMs`, emits a `divergence` event.

No protocol modifications, no block building, no hash computation.

---

## Timing comparison: primary method

The most verifiable form of evidence is timing divergence at the block boundary.

**What it measures:** the delay between a block becoming part of the public chain
(i.e., its `block.timestamp` — the value committed on-chain) and the moment
the pool notifies its miners of a new job referencing that block.

```
T_notify − block.timestamp  =  pool's announcement delay
```

An honest pool propagates the new job within seconds of the block appearing
on-chain. A selfish pool may announce a new block derived from its private tip
*before* the equivalent public block confirms — or announce the public block
significantly *later* than honest peers because it was busy mining its private chain.

**Why this is verifiable:** `block.timestamp` is committed in the block header
and is readable by anyone from any independent Monero node. `T_notify` is the
wall-clock time the proxy receives the first `mining.notify` for the new height.
The comparison is reproducible by any independent observer with access to the
same chain data.

**Limitation:** `block.timestamp` is miner-set (subject to protocol bounds, not
wall-clock truth). Systematic manipulations of `block.timestamp` can bias the
measurement. Treat large outliers (>60 s) as ambiguous.

---

## Timing comparison: secondary method (fallback)

**What it measures:** the delay between when the local Monero daemon sees the new
block (`T_daemon`) and when the pool sends the corresponding `mining.notify`.

```
T_notify − T_daemon  =  pool propagation latency for this proxy
```

Compared across peers in the federation, a pool that takes significantly longer
than others to announce the same height may have been busy on a private chain.

**Why this is not independently verifiable:** `T_daemon` is a local measurement,
readable only by the operator of that proxy. It is not committed anywhere. Two
proxies measuring the same pool cannot compare raw `T_daemon` values because
network distance to the daemon and to the pool differs per proxy.

This method is a useful corroborating signal, not standalone evidence.

---

## Accuracy statement

| Context | Accuracy |
|---------|----------|
| Window of 100+ blocks, at least 2 independent peers on different pools | >95% — persistent divergence is almost certainly a real fork |
| Single block observation | Probabilistic — network propagation variance can cause a one-off mismatch |
| Without peers on at least one other pool | No determination possible — the monitor reports unknown, not safe |

"95% over 100+ blocks" means: in sustained tests where a controlled private chain
was introduced and held for the full `divergenceMs` window, detection fired on
>95 of 100 blocks before the fork was resolved. This does not bound false positive
rate in adversarial conditions where a pool injects prevhash noise deliberately.

---

## What PrevhashMonitor does not prove

- It does not prove selfish mining is profitable for the pool.
- It does not identify which block the pool's private chain extends from.
- It does not measure the length of a private chain.
- A temporary divergence shorter than `divergenceMs` is logged but not alerted.
  Natural propagation delays can cause short-lived disagreements; the timer
  filters those out.

---

## Requirements for detection

- At least `minPeersForAlert` (default: 1) federation peers must be connected
  to a **different upstream pool** than the node under observation.
- All peers must share fresh prevhash updates (default: within 120 s of each
  other, see `PEER_STALE_MS`).
- The pool under observation must be distributing jobs while the private chain
  is active. Pools that pause job distribution during selfish mining are not
  detectable by prevhash comparison.

---

## Configuration reference

```js
const mon = new PrevhashMonitor({
  poolId:           'pool.hashvault.pro:3333',
  getPrevhash:      () => proxy.lastPrevhash,   // string | null
  pollIntervalMs:   5_000,   // how often to check local prevhash
  divergenceMs:     20_000,  // how long divergence must persist before alerting
  minPeersForAlert: 2,       // require N peers to disagree before alerting
});
```

`divergenceMs` trades latency against false positives. At 20 s (default), normal
propagation noise is filtered. Lowering to 5 s increases sensitivity but may
fire on transient forks.

`minPeersForAlert` trades Sybil resistance against single-peer coverage. With 1,
a single honest peer suffices. With 2, a single Sybil node cannot trigger an alert
unilaterally.

---

## Events

| Event | When |
|-------|------|
| `announce` | Own `prevhash` changed — broadcast to federation |
| `divergence` | Persistent disagreement with ≥ `minPeersForAlert` peers |
| `resolved` | All known peers now agree on the same `prevhash` |
| `peer-updated` | A peer reported a new prevhash (internal bookkeeping) |

---

## Related

- `src/prevhash-monitor.js` — implementation
- `src/hashrate-monitor.js` — independent hashrate concentration guard
- [`xmrigger-mesh`](https://github.com/xmrigger/xmrigger-mesh) — federation transport used to exchange prevhash values
