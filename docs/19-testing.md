# 19 — Testing

## The shape of the suite

| Layer | Where | What it proves |
|-------|-------|----------------|
| Unit | `cargo test --workspace` | Every consensus rule, every formula, every refusal |
| Integration | crate `tests/` directories | Multi-crate behaviour on real sockets and real state |
| End-to-end | `crates/obs-gateway/tests/registration.rs`, `crates/obs-app/tests/explorer.rs` | A whole service, from HTTP request to chain state |
| Property | in `obs-chain`, `obs-primitives` | Invariants over many generated inputs |
| Adversarial | `obs-consensus`, `obs-mempool`, node tests | Reorgs, double-spends, nonce gaps, invalid roots, bad signatures |
| Browser-path | `web/tests/*.test.mjs` | The real interface, booted against a live chain, driving the real wasm wallet |
| Acceptance | `scripts/acceptance.sh` | 100 numbered checks over the whole system, end to end |

Current counts: **345 Rust tests**, **15 JavaScript tests**, **100 acceptance
checks**.

## What the tests specifically refuse to assume

* **No floating point anywhere.** Monetary and consensus tests use integer
  grains and compare exact values; a test that had to use a float to state its
  expectation would be a bug in the test.
* **Protocol time is moved, never slept through.** Tests advance protocol time
  with `set_clock_offset` before mining, so a four-hour interval is tested in
  milliseconds and the chain's own clock stays authoritative.
* **A test that needs a service starts one.** Integration tests bind real
  sockets on ephemeral ports; nothing is mocked into agreeing.
* **A skip is a skip.** The browser test skips when no deployment is running and
  says so; it never reports a silent pass.

## Invariants with dedicated tests

| Invariant | Test |
|-----------|------|
| Supply can never exceed 21,000,000 OBS | `obs-chain` issuance tests |
| The genesis allocation happens exactly once, at height 1, to the treasury | `obs-chain`, `obs-node` |
| A new account has balance zero, `claims_today == 0`, `last_claim_at == 0` | gateway and node tests |
| One canonical Gmail identity = one account, atomically | `obs-gateway` registration tests |
| Claim intervals and the 6-per-day cap | `obs-chain` mining tests |
| The gas cap and the 40/60 split | `obs-chain` params tests, node tests |
| The 50 OBS bond and the 48-hour cooldown | `obs-chain` validator tests |
| Addresses are masked and balances never published | `obs-app` privacy tests |
| Invalid blocks, roots and signatures are rejected | `obs-consensus`, `obs-node` adversarial tests |
| The wasm module never returns key material | `web/tests/wallet-module.test.mjs` |
| The official mark is served from this origin, and its source is unprintable | `obs-app` `logo.rs` unit tests, `tests/explorer.rs` |
| A logo source that answers HTML is refused rather than served | `obs-app` `logo.rs` unit tests |
| Nothing that must stay private is in the tree | `scripts/leak-check.sh`, acceptance check 100 |

## Running everything

```sh
export PATH=/opt/rust/bin:$PATH CARGO_HOME=/opt/cargo CARGO_NET_OFFLINE=true
cargo test --workspace                                   # 345 tests
bash scripts/build-web.sh --check                        # artifact matches source
node --test web/tests/format.test.mjs \
             web/tests/wallet-module.test.mjs \
             web/tests/smoke.test.mjs                    # 15 tests (smoke needs a live chain)
bash scripts/acceptance.sh                               # 100 checks
```

`node --test web/tests/` on the bare directory does not work on every Node
version; name the files.

## The browser test in detail

`web/tests/smoke.test.mjs` is the test that catches what unit tests cannot: a
page that throws while loading and leaves a person looking at an empty screen. It
provides a small DOM (`web/tests/dom.mjs`, deliberately not a browser engine),
loads the real `js/app.js` as a module, dispatches `DOMContentLoaded` the way a
browser does, and then:

1. reads the network badge and the footer, which come from the node;
2. visits all four views and asserts each renders a heading, substantial content,
   no error toast, and no proof-of-work language;
3. asserts the Explorer and portal views show no whole address and no balance;
4. creates a wallet through the real WebAssembly module and asserts 24 words and
   no 64-hex key on screen;
5. seals it with a password (Argon2id, deliberately slow) and asserts the stored
   text is sealed base64url with no raw key;
6. reloads the page, asserts the wallet is shown **locked** with its public
   address, unlocks it with the same password, and asserts the wallet opens;
7. asserts an account the chain does not know is reported as such, never as a
   balance of zero;
8. clicks "Mine a claim" and asserts the interface reports a failure rather than a
   claim — the page cannot mint.

## Fuzzing and hostile input

Every decoder in the codebase takes `&[u8]` and returns `Option`/`Result`; the
tests feed truncated, extended and bit-flipped encodings and assert a refusal
rather than a panic. The HTTP servers refuse oversized bodies, unknown methods and
malformed JSON with canonical errors. Malformed peer messages are dropped, not
propagated.
