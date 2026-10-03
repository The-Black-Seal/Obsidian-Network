# 02 — Protocol

## Networks

| Network | Chain id | Address namespace | Purpose |
|---------|----------|-------------------|---------|
| mainnet | 1 | `obs1…` | Real value. Genesis invite, single use, never published |
| testnet | 2 | `tobs1…` | Public testing with worthless value |
| devnet | 3 | `dobs1…` | Development; `obs-cli devnet init` bootstraps an entire network |
| staging | 4 | `sobs1…` | Production rehearsal |

Each network has its own chain id, genesis, databases, secrets and invitation
codes. A transaction signed for one chain id cannot be replayed on another: the
chain id is inside the signed preimage of every transaction. A node refuses a
block or transaction from a different network outright.

## Addresses

An address is a bech32-style string with a network-specific human-readable part
(`obs`, `tobs`, `sobs`, `dobs`), a payload derived from the Ed25519 public key,
and a checksum. Checksums are verified on parse, so a mistyped character is
refused rather than treated as a different address.

The protocol **masks** addresses to third parties as `obs1q9x7…4k8m`. Masking is
applied by the APIs, not by the chain: inside the state machine the full address
is the account key.

## Accounts

An account is:

* `address` — derived from `wallet_key`
* `wallet_key`, `node_key` (validator identity), `recovery_key` — three distinct
  Ed25519 public keys, derived from one phrase at three derivation paths
* `balance`, `lifetime_rewards` — `Amount`, integer grains
* `next_nonce`, `last_claim_at`, `last_claim_sequence`, `claims_today`,
  `claims_day` — claim bookkeeping
* `genesis_claimed` — whether this account took the one-time genesis allocation
* `invites_issued` — invitations this account has spent (max 5)

A wallet registration **creates the account with a balance of exactly zero**.
Nothing in the protocol gives a newly registered account any value.

## Transactions

A transaction is a chain-id-bound, nonce-ordered, signed statement. Kinds:

| Kind | Effect |
|------|--------|
| `Register` | Creates an account from a signed invitation authorization |
| `Transfer` | Moves an amount, charging a gas fee |
| `Claim` | The mining claim (interval, cap and protocol-time rules apply) |
| `RegisterValidator` | Bonds 50 OBS and enrols a node identity |
| `DeregisterValidator` | Starts the 48-hour unbonding clock |
| `Attest` | A validator attests a block (participation evidence) |

Every transaction carries: chain id, sender address, nonce, kind, payload,
signature. The nonce must be exactly the account's next nonce, which is what
makes a transaction idempotent-proof and replay-proof within a chain. A
transaction's identifier is the hash of its canonical encoding — **never** an
address.

## Blocks

```
header
  protocol_version, chain_id, height, parent hash
  timestamp          = protocol time of this block
  proposer           = validator key that signed it
  weight_atoms       = PoT weight contributed by this block
  difficulty_bp      = PoT difficulty used for that weight
  state_root         = commitment over the whole state after the block
  tx_root            = deterministic root over the ordered transactions
  attestation_root   = deterministic root over the ordered attestations
  issued_supply      = total issued after this block
body
  transactions[≤4096], attestations[≤1024]
```

* `state_root` is recomputed by every node; a block whose root does not match the
  state it produces is rejected.
* Transactions inside a block are **canonically ordered** (by sender, then
  nonce), so two honest nodes building the same block produce byte-identical
  roots.
* The header is canonically encoded; the block hash is a tagged hash of that
  encoding.

## State commitment and history

State retains the last `STATE_HISTORY_BLOCKS = 1,024` blocks' worth of
consensus-relevant history: median-time-past window, difficulty window,
attestation records for finality, and fork-choice weight. Finality is tracked to
`FINALITY_DEPTH_SLOTS = 128` slots behind the head.

## Fail-closed

Unknown transaction kinds, unknown fields where the encoding is strict, malformed
addresses, bad checksums, bad signatures, wrong chain ids, oversized payloads and
numbers that do not fit the protocol's integer ranges are all **refused**. There
is no "best effort" path and no permissive mode. A node that cannot validate
something does not accept it.
