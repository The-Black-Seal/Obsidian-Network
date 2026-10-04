<img src="../web/assets/logo-official.svg" alt="Obsidian Network" width="88">

# Obsidian Network — documentation

Obsidian Seal Coin (**OBS**) is a chain whose scarce resource is *protocol time*,
not computation. Consensus is **Proof of Time (PoT)**: validators are scheduled
deterministically, weight accrues from elapsed protocol time plus verified
attestations, and there is no puzzle, no nonce search, no hash target and no
hash-rate competition anywhere in the protocol.

This directory is the protocol's written record. Every number in it is a constant
in `crates/obs-chain/src/params.rs`; every rule is enforced by the Rust code that
the tests exercise. Where this prose and the code disagree, the code is right and
this file is a bug.

## Read in this order

| # | Document | What it answers |
|---|----------|-----------------|
| 01 | [Architecture](01-architecture.md) | Which component is the authority, and what the others are allowed to do |
| 02 | [Protocol](02-protocol.md) | Blocks, transactions, state, addresses, encoding, chain ids |
| 03 | [Proof of Time](03-proof-of-time.md) | What PoT is, what it is not, and why time is the scarce resource |
| 04 | [Time and timestamps](04-time-and-timestamps.md) | Protocol time, MTP, and the three timestamp rules with test vectors |
| 05 | [Weight and fork choice](05-weight-and-fork-choice.md) | How weight is computed and how a fork is decided |
| 06 | [PoT difficulty](06-pot-difficulty.md) | The bounded cadence multiplier (not a hash threshold) |
| 07 | [Mining](07-mining.md) | Claims, intervals, rewards, halving, the floor, the genesis claim |
| 08 | [Genesis and treasury](08-genesis-and-treasury.md) | The one-time 100,000 OBS allocation |
| 09 | [Validators](09-validators.md) | Bond, node identity, attestations, uptime, unbonding |
| 10 | [Gas and fees](10-gas-and-fees.md) | 0.02%, the cap, and the 40/60 split, in integers |
| 11 | [Wallet](11-wallet.md) | Keys, derivation, the keystore, what never leaves the device |
| 12 | [Registration and recovery](12-registration-and-recovery.md) | The six steps, canonical Gmail, one account, invitations, MFA |
| 13 | [Explorer and privacy](13-explorer-and-privacy.md) | Partial addresses, no balances, and how that is enforced |
| 14 | [APIs](14-apis.md) | Every route, scope, limit and refusal |
| 15 | [Security](15-security.md) | The threat model, and what this system does not claim |
| 16 | [Networks and deployment](16-networks-and-deployment.md) | mainnet, testnet, devnet, staging and how to run them |
| 17 | [Operations](17-operations.md) | Running the four services |
| 18 | [Troubleshooting](18-troubleshooting.md) | The failures you will actually meet |
| 19 | [Testing](19-testing.md) | What is tested, how, and what the tests refuse to assume |
| 20 | [Parameters](20-parameters.md) | Every consensus constant in one table |
| 21 | [Acceptance](21-acceptance.md) | The 109-step acceptance run, the defects it found, and the adversarial pass |
| 22 | [The launch kit](22-launch-kit.md) | Rehearse, deploy, watch, back up, and the checklist for mainnet |
| 23 | [The audit brief](23-audit-brief.md) | Scope, what to attack, what is already known, and launch readiness |

## The four products

* **Mining** — one account, one claim every four hours, six a day. The reward is
  fixed by the protocol, and eligibility is judged against protocol time.
* **Native Wallet** — non-custodial. Keys are generated and used inside Rust
  compiled to WebAssembly, in the browser. Nothing is sent anywhere except a
  signed transaction.
* **Explorer** — an index of a node. It follows the chain; it never decides
  anything, and it publishes partial addresses and no balances.
* **Developer Portal** — API keys with scopes, rate limits, rotation and
  revocation, and an OpenAPI description generated from the service's own route
  table.

## The one sentence version

The consensus and blockchain state are Rust and are the only authority; the node
serves them, APIs index them, and the interface displays them — and the interface
can ask, and can sign with a key it holds, but cannot mint, cannot move value and
cannot change a rule.
