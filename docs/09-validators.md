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

### Inclusion rules

An attestation is evidence about a *moment*, so the protocol bounds when it may
be used. Three rules apply, all deterministic and all checked by the state
machine when a block is applied:

* an attestation must reference a block **below** the block that carries it —
  you cannot attest a block that does not exist yet;
* it must lie inside `ATTESTATION_WINDOW_BLOCKS = 4` of the carrying block (two
  minutes of protocol time at the 30-second slot), so a signature cannot be
  stockpiled and spent later by a validator that has since gone offline;
* a validator's attestations must reference **strictly increasing** heights, and
  each height may be attested once.

The node's queue follows from the last rule: it holds at most one attestation
per validator — always the newest — and a block built from that queue is
applicable by construction. Attestations that a block actually included are
dropped from the queue; the node's own attestation for the new head is queued as
the block is accepted, which is what makes the evidence chain continuous. A
proposer that instead tried to include an older attestation beside a newer one
from the same validator would produce an invalid block, so the rule is enforced
where it matters: in the state machine, not in the node's bookkeeping.

A node also verifies every attestation's signature **before** it queues it, even
though the state machine will verify it again. A queued attestation is one the
node will put in a block it proposes, so a peer able to push a forged one could
otherwise make the node build a block every node must reject. What a peer sends
decides nothing; it only decides what the node is willing to relay.

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

Blocks carry up to `MAX_ATTESTATIONS_PER_BLOCK = 1,024` attestations, each one
counted into the block's PoT weight ([05](05-weight-and-fork-choice.md)).
Validator accounting is written only from block content: the block that names a
validator as proposer credits it with a proposed block, and a block that does not
carry a validator's attestation charges it one missed opportunity. A block's
proposer is whoever signed the header, which is the validator's **node identity**
in scheduled mode and may be its **wallet key** inside the bootstrap window; a
validator is credited when either of its keys proposed, because the bond belongs
to the wallet and the attestations to the node identity and the protocol
requires those two keys to differ. Both numbers
and the uptime ratio above are what the node reports for `/api/v1/validators`,
which is exactly how the Explorer's validator table is produced. Finality is
reached when the attested weight past a block satisfies a two-thirds quorum of
the active validator set — `ceil(2n/3)`, computed with integers. The node reports
the finalised height, and the Explorer shows the gap between head and finality so
a stalled chain is visible to anyone.
