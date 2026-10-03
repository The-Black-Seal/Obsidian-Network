# 03 — Proof of Time

## What PoT is

Proof of Time measures **protocol time** and **verified participation**. The
scarce resource is time itself, not computation.

* Blocks are produced at most once per slot, and a slot is
  `SLOT_DURATION_SECS = 30` protocol seconds.
* The proposer of a slot is chosen **deterministically** from the active
  validator set, from a seed that commits to the chain id, the parent hash and
  the slot number. Every node computes the same proposer with no communication
  and no race.
* A block's weight comes from the protocol time it advances plus the fraction of
  the validator set that attested it — both of which are integer arithmetic
  on values that are checked by everyone.
* Difficulty is a **bounded cadence multiplier** (0.6666× to 1.5×) on that
  weight. It is not a threshold, and nothing is ever rejected because a hash is
  above or below it.

## What PoT is not

There is no proof-of-work anywhere in this codebase, and there must never be:

| Not present | Why it matters |
|-------------|----------------|
| No hash puzzle | No block is accepted because a hash has leading zeros |
| No nonce search | Nobody iterates a counter to find a valid block |
| No hash target | Difficulty never defines an acceptance threshold |
| No hash-rate competition | More hardware buys no advantage; "Time-Rate" replaced "hash rate" |
| No mining pools by hash share | Rewards are per-claim, fixed by the protocol |

The word "mining" survives for a different thing: an account **claims** a fixed
protocol reward once every four hours. A claim is a signed statement that a
registered account's interval has passed — it is judged against the block's
protocol time, and it cannot be improved by buying hardware.

## Time-Rate

**Time-Rate** is the number of PoT weight atoms the chain accumulated per
protocol second, over a measurement window of `TIME_RATE_WINDOW_SLOTS = 2,880`
slots (24 hours). It is a *reported* figure: the Explorer and the APIs show it,
operators compare it against the target cadence, and it never changes a rule.

Target cadence is one block per slot: `10,000` difficulty basis points at
30-second slots.

## Slots, epochs and bootstrap

| Constant | Value | Meaning |
|----------|-------|---------|
| `SLOT_DURATION_SECS` | 30 | One PoT slot |
| `EPOCH_SLOTS` | 128 | Slots per difficulty epoch |
| `DIFFICULTY_WINDOW_BLOCKS` | 32 | Recent blocks used to measure cadence |
| `MAX_SLOT_GAP` | 8 | Most slots one block may advance, for weight purposes |
| `BOOTSTRAP_SLOTS` | 2,880 | 24 hours during which the bootstrap proposer rule applies |
| `MIN_VALIDATORS_FOR_SCHEDULED_PROPOSAL` | 1 | Below this, the network falls back rather than halting |

**Bootstrap is a liveness fallback, never a consensus bypass.** On an empty
network the first block may be proposed by an account that block itself
registers; past the bootstrap window, if there is **no** active validator the
network falls back to the bootstrap rule rather than stopping. In that state
there is no validator set to capture, and no rule, reward, fee or supply
parameter changes. The moment validators exist, proposer selection is
deterministic over the validator set.

## Why this is hard to capture

* **Time cannot be bought.** A proposer cannot produce the next slot early: the
  timestamp rules (see [04](04-time-and-timestamps.md)) bound every timestamp
  relative to its parent and to the median time past.
* **Scheduling is public.** Everyone can compute who should propose, so an
  unexpected proposer is visible evidence.
* **Attestations are signatures.** Weight from participation comes from
  signatures over the block, checked by the state machine. No node can inflate
  participation without those private keys.
* **Difficulty is re-derived.** A proposer that writes a favourable
  `difficulty_bp` produces an invalid block: every other node recomputes it from
  the same window.

This is a high-assurance, defence-in-depth design. It is **not** claimed to be
mathematically unhackable, and no such claim is made anywhere in this
documentation.
