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
| Acceptance | `scripts/acceptance.sh` | 104 numbered checks over the whole system, end to end |

Current counts: **374 Rust tests**, **19 JavaScript tests**, **104 acceptance
checks**.

## A test may not assert a property of a random value's spelling

The suite generates fresh keys, wallets and addresses on purpose — a fixed vector
cannot catch a mistake that only appears for some inputs. But that means an
assertion about *how a generated value happens to be spelled* is not a property,
it is a coin flip with a very long odds ratio, and it will fail in production
runs and pass in front of you.

The concrete case: a test asserted that no word of a recovery phrase appears in a
wallet's `Debug` output. Two of the three words it checked were inside the *field
names* — "main" is in "mainnet", "over" is in "recovery_key" — and an address is
bech32 text that can contain a dictionary word by chance. Measured over 5,000
generated wallets, 127 of them tripped it: a 2.5 % flake that failed the
acceptance run and had nothing to do with a leak. The replacement asserts the
exact debug form (public fields and three redactions, nothing else) and that the
phrase and the keys are absent — deterministic, and strictly stronger.

The rule: assert structure, counts, round trips and inequalities. If an
assertion's truth depends on a value it does not control, either fix the value or
assert something that is true for every value. The same rule bans discarding a
failing check's output — a check that cannot say why it failed costs more than no
check at all.

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

## Tests must not assume an idle machine

The suite binds real sockets, runs real threads and is expected to pass on a
machine that is busy with something else — a laptop running the developer's
editor, or CI running four jobs at once. That expectation is not a hope: it is a
rule the harnesses are built to satisfy, and it was learned the hard way.

* **A wait has a generator, not just a deadline.** A test that waits for the node
  to observe something drives the node's own loop from the test's thread
  (`settle`, a non-blocking `try_lock` poll) instead of assuming a background
  thread will be scheduled. A test about a peer being dropped once missed the
  peer's entire two-second lifetime — because the poller thread held the manager
  mutex in a hot loop and the test thread could not get it — and reported a
  network that never connected.
* **A hot loop yields.** The p2p harness's poller sleeps a millisecond after an
  idle poll. Holding a mutex for the length of a poll timeout and immediately
  re-acquiring it starves every other waiter: Rust's `Mutex` makes no fairness
  promise. With the yield, the p2p file went from 130–600 seconds to about four.
* **Deadlines are named for what they are.** `HANDSHAKE_TIMEOUT` (5 s) is a rule
  under test; `HANDSHAKE_DEADLINE` (120 s) is the test's own patience. Conflating
  them either makes the suite slow or turns a rule into a coin toss.
* **Heartbeats do not decide application assertions.** A node probes idle peers
  on its own timer, so a ping or a pong can arrive between any two messages. The
  waits that assert on application traffic skip them rather than assume the next
  message is theirs.
* **A retry is for a busy machine, not for a broken one.** Where a test must
  complete a handshake before it can test anything, it retries; the protocol
  rules it is checking are still checked exactly once, on a connection that was
  established.

* **A check that fails while reporting no failing assertion is the machine.**
  Acceptance check 55 (`node --test` over the wallet module) failed once during a
  full run with TAP output that contained only `ok 1` and no failing subtest, and
  passed standalone immediately after; the same shape was seen once on check 56.
  Confirm a check like that on its own before changing anything — and do not
  discard a check's stderr, which is where the difference lives.

Three consecutive full-workspace runs under ten CPU spinners pass — the suite,
which now stands at 374 tests, with no failures — and they are the gate for any
change to a harness.

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
cargo test --workspace                                   # 374 tests
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
