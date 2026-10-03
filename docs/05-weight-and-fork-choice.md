# 05 — Weight and fork choice

## PoT weight

Weight is the measure of protocol time a chain has *verifiably accumulated*. It
is an integer count of atoms; one atom is one thousandth of one fully
participating slot-second. The units are arbitrary but fixed, and every node
computes the same value.

Weight contributed by one block:

```
slot_gap          = block.slot − parent.slot
gap               = clamp(slot_gap, 1, MAX_SLOT_GAP)          # 1 ≤ gap ≤ 8
time_atoms        = gap × SLOT_WEIGHT_ATOMS                   # 1,000 per slot

participation_bp  = active_validators == 0 ? 10,000
                    : attesting_validators × 10,000 / active_validators
participation_bp  = clamp(participation_bp, 2,500, 10,000)    # floor 25 %
participation_atoms = BLOCK_WEIGHT_ATOMS × participation_bp / 10,000  # 1,000,000 max

weight            = (time_atoms + participation_atoms) × difficulty_bp / 10,000
```

Reading the formula:

* **Time dominates.** Every block carries at least one slot of weight, and each
  extra elapsed slot adds the same again, up to eight. A chain's weight is first
  and last a count of protocol time.
* **Participation is evidence, not a claim.** The attested fraction of the
  active validator set can add at most `1,000,000` atoms (1,000 slots' worth) and
  never less than the 25 % floor, so liveness always accrues weight and a
  validator cannot inflate it without signatures.
* **Difficulty scales within hard bounds.** `difficulty_bp` is clamped to
  `6,666..=15,000`, so the factor is always between 0.6666 and 1.5. A proposer
  that writes a favourable value produces an invalid block, because every other
  node recomputes it.

Worked example — a single block, 30-second slot, 2 of 4 validators attesting,
difficulty `10,000`:

```
gap                = 1
time_atoms         = 1 × 1,000              = 1,000
participation_bp   = 2 × 10,000 / 4         = 5,000
participation_atoms= 1,000,000 × 5,000/10,000 = 500,000
weight             = (1,000 + 500,000) × 10,000/10,000 = 501,000 atoms
```

## Fork choice

`fork_choice_better(a, b)` applies three rules in order. They are total, so every
honest node agrees on which of two heads wins:

1. **Higher accumulated PoT weight wins.** Compared as `u128` atoms. A long chain
   of lightly-attested blocks does not beat a shorter, well-attested one.
2. **Lower block height wins** when weights are exactly equal. A shorter chain
   that accumulated the same weight did so with older, less re-organisable
   history.
3. **Lexicographically smaller head hash wins** when both weight and height are
   equal. This is objective and unpredictable when the block is built: it cannot
   be steered by a proposer without grinding a hash, which the protocol does not
   reward — and the deterministic proposer schedule makes grinding pointless
   anyway, because a proposer cannot choose its slot.

There is no "longest chain" rule and no rule that counts blocks. Height is only a
tie-breaker.

## Reorganisation and finality

* When a competing branch wins by the rules above, the node re-organises:
  transactions from the orphaned branch that are still valid return to the pool.
* `FINALITY_DEPTH_SLOTS = 128` slots behind the head is the reported finality
  horizon, and a block is considered final once the attested weight past it
  satisfies the 2/3 quorum of the active validator set:
  `ceil(2n/3)` attestations (3 validators need 2, 4 need 3, 1 needs 1 —
  computed with integers, never decimal fractions).
* The Explorer reports both: the head height, the finalised height, and the
  difference, so an operator can see a chain that is not finalising.

## Why weight, and not height or work

* Height alone is trivially cheap to inflate with empty blocks.
* Work (hash-rate) is what this network deliberately does not use.
* Weight couples *time elapsed* to *verified participation*, both of which every
  node can check from the block itself and its parent. A branch cannot buy
  weight without spending protocol time and gathering real signatures.
