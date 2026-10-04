# 23 — The independent audit brief

This document is for the people who will audit Obsidian, and for the operator
who has to decide whether to spend money on them. It says what to review, what
to attack, what the project already knows about itself, and what "done" looks
like. It is deliberately written so that a reader who does not trust this
project can check every claim.

**No third party has audited this code.** The project's own adversarial pass is
in [21](21-acceptance.md#the-security-audit); it found and fixed real defects,
and it is still the authors checking their own homework.

## Scope

In priority order, by how much damage a bug would do:

| Order | Crate | Why it is first |
|-------|-------|-----------------|
| 1 | `obs-primitives` (`money`, `address`, `identity`, `hash`, `json`, `network`) | every amount, address, commitment and parser in the system |
| 2 | `obs-chain` (`state`, `validate`, `tx`, `block`, `params`, `mining`, `pot`) | consensus: supply, genesis, claims, fees, bonds, timestamps, weights |
| 3 | `obs-crypto` (`ed25519`, `argon2`, `chacha`, `totp`, `mnemonic`, `rand`) | the primitives every signature and secret depends on |
| 4 | `obs-wallet` (`seed`, `keystore`, `recovery`, `sign`) | key generation, sealing, derivation, non-custody |
| 5 | `obs-p2p` (`handshake`, `protocol`, `manager`, `peer`) | hostile peers, replay, resource limits, reconnection |
| 6 | `obs-rpc` (`server`, `http`, `cli`) | the transport: parsing, traversal, limits, smuggling |
| 7 | `obs-app` (`api`, `portal`, `privacy`, `indexer`, `logo`) | the public surface: masking, scopes, rate limits, sessions |
| 8 | `obs-gateway` (`authority`, registration, sessions, invites) | registration, MFA, invite atomicity |
| 9 | `scripts/*.sh`, `deploy/systemd/*` | the operator path: backup, restore, monitoring, units |

Out of scope: the drawing of the interface, the wording of the documentation,
and anything that only affects presentation. The front end cannot change state
in any case — that is [01](01-architecture.md)'s authority hierarchy, and
verifying it is in scope: the browser wallet must be *unable* to do more than
sign.

## What to attack

Each of these has a test in the suite; the interesting question is what the
tests do not cover.

* **Supply.** Can any sequence of transactions, blocks or reorganisations cause
  `issued_supply` to exceed `MAX_SUPPLY`, create value from nothing, or pay the
  genesis allocation twice? Is every arithmetic path checked, saturated or
  provably bounded — including amounts that arrive from the wire?
* **Consensus.** Can a proposer, a validator, or a set of them, break any of the
  three timestamp rules, shift MTP, inflate PoT weight, choose a fork that the
  documented rule would not, or make two nodes with the same state disagree
  about a block?
* **Keys.** Can a phrase, seed, private key or keystore password reach a log, a
  crash dump, an error message, an API response, or a second process? Is the
  browser wallet's interface to the WASM module free of any path by which a key
  could be returned to JavaScript?
* **The public API.** Is there any input — a path, a header, a body, a very deep
  document, a very large number, a duplicate field, a negative length — that
  makes a service panic, hang, allocate without bound, or answer with a balance
  it should not have?
* **Registration and invitations.** Can one Gmail identity hold two accounts?
  Can an invitation be spent twice, spent by another identity, replayed onto
  another chain, or minted by someone who does not hold the authority key? Is
  the recovery path separate from the wallet path, and can either be used to
  take an account over?
* **The operator path.** Can a backup be restored to a node that then agrees
  with the network? Can a monitor be fooled into reporting health for a node
  that is not serving the deployment's chain — or into staying quiet when the
  chain has stopped? Does an interrupted backup leave something that looks
  valid?

## What is already known, and written down

An auditor should start from these, because they are the project's own findings
and the places where a mistake would be most understandable:

* [21 — the security audit](21-acceptance.md#the-security-audit): the probes that
  were run against a live deployment, and the four defects they found.
* [15 — security](15-security.md): what is claimed, what is deliberately absent,
  and the arithmetic discipline.
* [19 — testing](19-testing.md): the suites, the invariants, and the rules a
  test must obey (including two flaky-test defects that were fixed).
* The `docs/21` "What the run found" section: sixteen further defects, each with
  what it was and what it cost.

## Deliverable

A report that names, for every finding: the file and line, a reproduction, what
an attacker gains, and whether the fix changes consensus. Findings that require
code changes should be filed as issues with the reproduction attached; the
project's rule is that a fix lands with a test that failed first.

For the operator deciding whether to spend the money: the useful question is not
"is it perfect" but "would you run the treasury on it". Ask for that sentence
explicitly, in writing.

## Launch readiness

The list the operator should be able to tick before founding mainnet. Everything
here is checkable by the operator alone, without trusting the authors.

| # | Item | How to check |
|---|------|--------------|
| 1 | The suite is green on the release commit | `cargo test --workspace` (376), `node --test web/tests/*.test.mjs` (19), `bash scripts/acceptance.sh` (108) |
| 2 | No secret is in the tree | `bash scripts/leak-check.sh` |
| 3 | The one-machine rehearsal passes | `bash scripts/rehearse.sh` — 6 of 6 |
| 4 | A two-host network runs for two weeks | deploy the testnet on two hosts; watch `height`, `finalized_height`, `peers` |
| 5 | A peer restart does not partition | restart one host; the other must reconnect by itself (this was a real defect) |
| 6 | A reboot survives | reboot a host; the units come back, the chain resumes |
| 7 | A backup restores | `scripts/restore.sh --archive … --start …` on a scratch directory |
| 8 | The monitor alerts | stop the node; the timer's `--alert-cmd` must fire within the interval |
| 9 | An upgrade is boring | deploy a new commit, restart, confirm the head |
| 10 | An independent audit is done | this document |
| 11 | The mainnet invitation exists and is offline | `obs-cli invite mint --genesis …` on a machine that is not the public host; the code in a `0600` file, nowhere else |
| 12 | The founder's phrase is offline | paper or metal, not on the mining host |
| 13 | TLS terminates in front of the interface | `curl -sI https://your.domain/` |
| 14 | Nothing else runs on the mainnet host | a validator that also serves a web shop is a validator with a second job |

Items 1–3 are true today. Items 4–9 are the testnet's job, and they are the
reason to run it for weeks rather than hours. Items 10–14 are yours.
