# Obsidian Network

**Obsidian Seal Coin (OBS)** — a blockchain whose scarce resource is **protocol
time**, not computation.

Consensus is **Proof of Time (PoT)**: validators are scheduled deterministically
from the previous block, blocks are produced at most once per 30-second slot,
weight accrues from elapsed protocol time plus verified attestations, and
difficulty is a bounded cadence multiplier — never a hash threshold. There is no
puzzle, no nonce search, no hash target and no hash-rate competition anywhere in
this repository. Mining is a fixed, protocol-set claim: one per account every
four hours, six a day.

```
Maximum supply      21,000,000 OBS        hard cap, enforced in the state machine
Smallest unit       1 grain = 10^-12 OBS  integers only, everywhere
Claim interval      4 hours of protocol time
Claim reward        0.000166666666 OBS    halving -0.5 % per 100,000 active miners
Reward floor        0.000033333333 OBS    per claim
Genesis claim       100,000 OBS           once, in block 1, to the treasury
Validator bond      50 OBS                returned after a 48-hour unbonding
Gas fee             0.02 % of a transfer  capped at 0.01 OBS, split 40/60
```

## The four products

| Product | What it is |
|---------|------------|
| **Mining** | Claim the protocol's fixed reward. Eligibility comes from protocol time; a browser timer is informational only |
| **Native Wallet** | Non-custodial. Keys are generated and used inside Rust compiled to WebAssembly, in the browser. The phrase crosses to JavaScript exactly once, when a wallet is created |
| **Explorer** | An index of a node. Partial addresses, no balances, and it says so when it is behind |
| **Developer Portal** | API keys with scopes, rate limits, rotation and revocation, and an OpenAPI document generated from the service's own route table |

## Authority, in one picture

```
consensus  →  blockchain state  →  verified node data  →  APIs and indexes  →  interface
 (Rust)         (Rust)                (Rust)                 (Rust)            (web)
```

The interface can ask questions, and can sign with a key the person created in
it. It cannot mint, cannot change a balance, cannot approve a claim, cannot alter
a fee, a reward, a timing rule or the supply, and cannot bypass validation —
there is no route, flag or code path anywhere that does.

## Quick start

```sh
export PATH=/opt/rust/bin:$PATH CARGO_HOME=/opt/cargo CARGO_NET_OFFLINE=true

cargo build --workspace --release     # node, gateway, app, cli
bash scripts/build-web.sh             # the wallet module into web/wasm/

# a whole devnet, from nothing
./target/release/obs-cli devnet init --data-dir /tmp/dev2 --password-file /tmp/dev2/pw
./target/release/obs-node --network devnet --data-dir /tmp/dev2/node --genesis-timestamp now \
    --authority-key <64 hex> --keystore /tmp/dev2/founder.keystore.json \
    --keystore-password-file /tmp/dev2/pw --mine --validator &
./target/release/obs-app --network devnet --node-url http://127.0.0.1:7200 --port 8081 \
    --static-dir web --accounts --accounts-store /tmp/dev2/accounts.json \
    --authority-key /tmp/dev2/authority.key &

open http://127.0.0.1:8081            # Mining · Wallet · Explorer · Developers
```

## Verifying it

```sh
cargo test --workspace                        # 330 Rust tests
bash scripts/build-web.sh --check             # the wasm artifact matches the source
node --test web/tests/format.test.mjs \
             web/tests/wallet-module.test.mjs \
             web/tests/smoke.test.mjs          # 15 JavaScript tests, incl. the browser path
bash scripts/acceptance.sh                    # 100 checks, end to end
```

The browser test boots the real interface against a live chain, drives the real
WebAssembly wallet through create → seal → reload → unlock, and asserts that an
account the chain does not know cannot claim. It skips — loudly — when no
deployment is running, and never passes silently.

## Repository layout

```
crates/
  obs-primitives  money, addresses, hashes, encoding, networks, Gmail canonicalisation
  obs-crypto      Ed25519, hashes, HKDF, Argon2id, ChaCha20-Poly1305, TOTP
  obs-chain       blocks, transactions, state machine, PoT, mining, parameters
  obs-consensus   fork choice, reorganisation, finality, the block store
  obs-wallet      derivation, signing, the sealed keystore
  obs-mempool     the pool: ordering, nonces, limits
  obs-node        ingest, mining, the node API, events
  obs-p2p         handshake, gossip, block and transaction relay
  obs-rpc         HTTP server and client, canonical errors, CLI parsing
  obs-wasm        the browser wallet, behind an opaque handle
  obs-gateway     registration, sign-in, invitations, MFA, recovery
  obs-app         explorer API, indexer, portal, privacy contract, the interface
  obs-cli         operator and developer tooling
web/              the interface: Mining, Wallet, Explorer, Developers
  wasm/           the compiled wallet module and its provenance record
docs/             the protocol, in 21 documents (start at docs/README.md)
scripts/          toolchain install, wallet build, and the acceptance run
```

## Documentation

`docs/README.md` indexes all 21 documents. The ones that answer the questions
people ask first:

* [Proof of Time](docs/03-proof-of-time.md) — what it is, and what it deliberately is not
* [Time and timestamps](docs/04-time-and-timestamps.md) — protocol time, MTP and the three rules, with test vectors
* [Mining](docs/07-mining.md) — the reward schedule, worked out
* [Wallet](docs/11-wallet.md) — what never leaves the device
* [Explorer and privacy](docs/13-explorer-and-privacy.md) — partial addresses and no balances, enforced three ways
* [Security](docs/15-security.md) — the threat model, and what this system does not claim
* [Acceptance](docs/21-acceptance.md) — the 100-step run and its results

## What this project does not claim

Obsidian is built for defence in depth and it fails closed, but it does not claim
to be mathematically unhackable: no system is, and saying so would be a
disservice. It claims that the consensus rules are implemented once in Rust and
shared by every component, that the interface cannot mint or move value, that
money is integer arithmetic with no floating point anywhere, and that every one
of those statements is checked by a test that refuses to be a mock.

## Licence and contributing

See the repository for licence terms. Before opening a pull request, run the
three commands under "Verifying it" — the acceptance run is the same gate the
maintainers use.
