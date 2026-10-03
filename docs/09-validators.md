# 09 — Validators

## Becoming one

| Rule | Value |
|------|-------|
| Bond | `VALIDATOR_BOND = 50 OBS` |
| Node identity | A distinct Ed25519 key from the account's wallet key |
| Enrolment | `RegisterValidator` transaction, signed by the wallet key |
| Deregistration | `DeregisterValidator`, then `UNBONDING_PERIOD_SECS = 48 h` before the bond returns |
| Uptime for reward | `MIN_UPTIME_BP = 5,000` (50 %) of expected attestations in an epoch |
| Reward epoch | `VALIDATOR_REWARD_EPOCH_SLOTS = 2,880` slots (24 hours) |

The node identity is deliberately separate from the wallet key. An operator can
run a node, expose its key to a hosting provider, and lose it without losing the
account: the wallet key — the one that holds the bond and the balance — never
goes on the validator host unless the operator chooses to put it there.

## Evidence, not self-reporting

There is no uptime field anywhere in the protocol. A validator's uptime is
**derived from attestations** it actually signed, which are carried in blocks and
verified by every node:

* an `Attest` transaction is a signature over the block it attests,
* the state machine counts attestations per validator per epoch,
* uptime is the ratio of signed attestations to expected ones,
* the reward pool is divided according to the score below, and a validator below
  the 50 % floor receives no share for that epoch.

A node that claims to be online but does not attest is simply not counted.

## Reward scoring

Each validator's share of the epoch's validator pool uses four components:

| Component | Weight |
|-----------|--------|
| Uptime (attestations signed / expected) | 40 |
| Participation (weight contributed) | 30 |
| Efficiency (blocks proposed well) | 20 |
| Reliability (no missed slots, no invalid proposals) | 10 |

Weights sum to 100 and are applied to integer values with integer arithmetic; the
split of the pool is exact, and any rounding remainder stays in the pool rather
than being invented.

## The bond

* 50 OBS moves out of the account's balance when the validator registers; it is
  held in protocol state, not by any key.
* Deregistration starts a 48-hour clock. The bond returns to the account when the
  clock expires, by a state transition, not by an operator action.
* A validator that is deregistered stops being scheduled and stops earning
  immediately; the cooldown exists so that the network has 48 hours of certainty
  about the set.

## Proposer scheduling

The proposer for a slot is chosen deterministically:

```
seed   = tagged_hash(PROPOSER_SEED, chain_id ‖ parent_hash ‖ slot)
index  = LE_u64(seed[..8]) mod validator_count
proposer = active_validators[index]        # ordered canonically
```

Every node computes the same answer with no communication and no race. The seed
binds selection to the parent hash, so nobody can bias a slot without changing
the chain.

On an empty network, or past the bootstrap window with **no** active validator,
the bootstrap rule applies (see [03](03-proof-of-time.md)); it is a liveness
fallback, and it changes no rule, reward, fee or supply parameter.

## Attestations and finality

Blocks carry up to `MAX_ATTESTATIONS_PER_BLOCK = 1,024` attestations. Finality is
reached when the attested weight past a block satisfies a two-thirds quorum of
the active validator set — `ceil(2n/3)`, computed with integers. The node reports
the finalised height, and the Explorer shows the gap between head and finality so
a stalled chain is visible to anyone.
