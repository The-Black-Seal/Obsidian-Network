# 06 — PoT difficulty

## It is not a hash threshold

PoT difficulty is a **bounded multiplier on block weight**. It compensates for a
chain that is running faster or slower than the 30-second slot target by
adjusting how much each block weighs. No block is ever accepted or rejected
because of it, and there is no target to solve.

* `DIFFICULTY_INITIAL_BP = 10,000` — exactly on target.
* `DIFFICULTY_MIN_BP = 6,666` — 0.6666× base weight.
* `DIFFICULTY_MAX_BP = 15,000` — 1.5× base weight.
* `DIFFICULTY_WINDOW_BLOCKS = 32` — the measurement window.
* `EPOCH_SLOTS = 128` — how often it is updated.
* `DIFFICULTY_EMA_DEN = 8` — `next = (7 × previous + raw) / 8`.

## The formula

```
expected_span = window_slots × SLOT_DURATION_SECS
observed_span = newest_timestamp − oldest_timestamp        # of the window
raw_bp        = clamp(10,000 × expected_span / observed_span, 6,666, 15,000)
```

and, once per epoch:

```
next_bp = clamp((7 × previous_bp + raw_bp) / 8, 6,666, 15,000)      # integers only
```

Properties that make it safe:

* **Bounded.** The result can never leave `[6,666, 15,000]`, so no sequence of
  measurements can make the chain trivially heavy or nearly weightless.
* **Slow.** The EMA moves at most one eighth of the way toward the raw value, so
  one anomalous window cannot swing the multiplier.
* **Deterministic.** Every node derives it from block timestamps in a window that
  is part of the chain. A proposer cannot choose it; writing a wrong value makes
  the block invalid.
* **Conservative when the measurement is degenerate.** `observed_span == 0`
  returns the maximum, which can never make the chain easier to advance.

`expected_span` uses the *slot* count of the window, not the block count: skipped
slots are real time, and a chain that skips slots is a chain that took longer, so
its measured cadence is honestly slower.

## Where difficulty appears

| Where | What it does |
|-------|--------------|
| Block header | `difficulty_bp` — the value used for that block's weight, recomputed by every validator |
| Node status API | `pot_difficulty_bp` — the value the next block should use |
| Explorer | Displayed next to weight, so an operator can see cadence corrections |
| Consensus | Scaling factor inside `weight_of_block` — the only place it changes anything |

## Relationship to Time-Rate

Difficulty is the *input*; Time-Rate is the *output*. Difficulty says how much a
block weighs per slot of elapsed time; Time-Rate reports how much weight the
chain actually accumulated per protocol second over the last 24 hours. A healthy
mainnet runs near one block per slot with Time-Rate close to
`SLOT_WEIGHT_ATOMS / SLOT_DURATION_SECS` per second, scaled by participation
above the floor.
