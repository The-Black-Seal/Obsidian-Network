# 04 — Time and timestamps

## Protocol time

**Protocol time** is the chain's own clock: the timestamp of the head block. It
advances only by producing blocks, never by wall-clock time passing. Every
consensus decision about "now" uses protocol time:

* whether a claim's interval has passed,
* how many claims an account has made in a protocol day,
* which slot a block belongs to,
* what weight a block contributes.

A browser timer is *informational only*. The interface shows the counts down, and
says explicitly that the chain's clock is what decides. If a device's clock is
two hours fast or slow, nothing changes about what the chain accepts.

Genesis starts at `GENESIS_TIMESTAMP = 1,767,225,600` (2026-01-01T00:00:00Z) on
every network; the first real block must be strictly later than its median time
past, which includes that value.

## The three timestamp rules

### Rule 1 — median time past

A block's timestamp must be **strictly greater** than the median time past of the
previous `MTP_WINDOW = 11` blocks (or fewer, at the start of the chain).

```
MTP(chain)   = median of the last min(11, height) timestamps, sorted, taking
               the ((n − 1) / 2)-th smallest
valid(t)  ⇔  t > MTP
```

Test vectors:

| chain timestamps (oldest → newest) | MTP | accepted `t` | refused `t` |
|---|---|---|---|
| `1,2,3,4,5,6,7,8,9,10,11` | `6` | `7` | `6` |
| `1..20` (window uses the newest 11) | `15` | `16` | `15` |
| `100` (single block) | `100` | `101` | `100` |

The median is used rather than the mean because it cannot be moved much by one
dishonest timestamp: at least six of the eleven would have to lie.

### Rule 2 — the parent bound

```
MIN_BLOCK_SPACING_SECS = 1     t ≥ parent.timestamp + 1
MAX_BLOCK_DRIFT_SECS   = 60    t ≤ parent.timestamp + 60
```

A child may be one second to one minute ahead of its parent. A node that stamps a
block an hour in the future produces a block the whole network rejects; a node
that stamps one in the past produces a block that never gets to the future.

`LOCAL_FUTURE_SANITY_SECS = 120` is **not** a consensus rule: it is the bound
beyond which a node declines to *gossip* a block whose timestamp is far ahead of
its own wall clock. A block that breaks rule 2 is invalid whatever any local
clock says.

### Rule 3 — the claim's declared protocol time

```
claim.timestamp == block.timestamp
```

A mining claim declares the protocol time of the block that will carry it. The
chain accepts it in that block and no other. This is what stops a claim being
mined "early" or "late": the value the claim was signed over must be exactly the
value the block carries, and the block's value is itself constrained by rules 1
and 2.

Read together:

* Rule 1 stops timestamps sliding backwards into history.
* Rule 2 stops them jumping forwards into the future.
* Rule 3 binds a claim to the block that carries it, which is the only clock a
  miner is allowed to obey.

## Clock discipline in a node

Because protocol time is not wall-clock time, a node's local clock only decides
what it is willing to relay. A node with a wrong clock still validates every
block correctly; it may simply be reluctant to gossip blocks that look far ahead,
which is why operators are told to run NTP on their hosts and why the local
bound is deliberately wide (120 s) compared with the consensus bound (60 s).

## What the interface shows

The interface reads `protocol_time` from the node's status and renders it as
absolute time and as remaining durations ("next in 3.5 hours"). Those strings are
formatted from the chain's own integers; the page's `Date` is used for
*displaying* the timestamp, never for deciding eligibility. The Mining view says
so in words: "Eligibility is protocol time, never a browser timer."
