# 01 — Architecture

## The authority hierarchy

```
  consensus rules            crates/obs-chain, crates/obs-consensus
        ↓                    (Rust; the only thing that decides what is true)
  blockchain state           crates/obs-chain::state, obs-consensus::store
        ↓
  verified node data         crates/obs-node   (accepts, validates, mines, rpc)
        ↓
  APIs and indexes           crates/obs-rpc, obs-p2p, obs-app, obs-gateway
        ↓
  interface                  web/  (asks; signs only with a key it holds)
```

Every layer may *narrow* what is visible. None may widen what is true:

* A **node** accepts a block or a transaction only by applying the consensus
  rules. It has no path that writes state without validation.
* The **explorer index** reads a node and follows it. If the index is behind, it
  says so; it never serves a number it did not read.
* The **interface** renders what the services answer, including refusals. It
  cannot submit anything except a transaction that is already signed, and it
  holds no key that the person did not create in it.

## Crates

| Crate | Responsibility |
|-------|----------------|
| `obs-primitives` | Money (`Amount`, grains), addresses (`obs1…`), hashes, tagged hashing, canonical codec, JSON, network identities, Gmail canonicalisation |
| `obs-crypto` | Ed25519, SHA-256, BLAKE-style tagged hashes, HKDF, Argon2id, ChaCha20-Poly1305, TOTP, constant-time helpers |
| `obs-chain` | Blocks, transactions, state machine, validation, PoT weight/difficulty/scheduling, mining economics, parameters |
| `obs-consensus` | Fork choice, reorganisation, finality tracking, the block store |
| `obs-wallet` | Key derivation, addresses, transaction signing, the sealed keystore |
| `obs-mempool` | Transaction and claiming pool: ordering, nonce discipline, pool limits |
| `obs-node` | The node: ingest, mining, the API, events |
| `obs-p2p` | Peer protocol: handshake, gossip, block and transaction relay |
| `obs-rpc` | The HTTP server and client, request parsing, canonical error shapes, CLI parsing |
| `obs-wasm` | The browser wallet: the Rust wallet behind a handle-based ABI |
| `obs-gateway` | Registration, sign-in, invitations, MFA, recovery, account sessions |
| `obs-app` | The public application: explorer API, indexer, portal, privacy contract, static interface, node read-through |
| `obs-cli` | Operator and developer tooling, including devnet bootstrap |

## Where the money lives

`obs-primitives::money::Amount` is an integer number of **grains**, with
`1 OBS = 10^12 grains`. There is no floating-point type anywhere in the monetary
path: not in the consensus rules, not in fees, not in rewards, not in issuance,
not in the wallet, not in the interface's formatting (which does string
arithmetic on decimal strings it received from the chain).

## Data flow for one claim

1. The wallet reads the chain: the account's own state (proved by a signature)
   and the chain's protocol time.
2. It stamps the claim with that protocol time and signs it inside the wallet
   core.
3. The signed bytes go to a node.
4. The node validates the claim against the rules — registration, interval,
   daily cap, protocol time — and pools it or refuses it.
5. A scheduled proposer includes the claim in a block stamped with exactly the
   protocol time the claim declared.
6. Every other node re-validates the block, including the claim's declared time.
7. The reward is issued from the mining pool, and the treasury and supply
   accounting move by exactly that integer.

A front end is involved at step 1 and step 3 only, and it cannot do anything the
person's own key cannot.
