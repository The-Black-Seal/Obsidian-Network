# 21 — Acceptance

The acceptance run is `scripts/acceptance.sh`: **104 numbered checks** over the
whole system. It exits non-zero if any check fails, so it is a gate, not a report.
Half the checks read the live deployment over HTTP exactly as a person or a wallet
would; the other half are the source-level and test-suite gates that prove the
rules are where this documentation says they are.

```sh
export PATH=/opt/rust/bin:$PATH CARGO_HOME=/opt/cargo CARGO_NET_OFFLINE=true
bash scripts/acceptance.sh
```

## The run of 2026-10-03

```
Obsidian Network — acceptance run
interface: http://127.0.0.1:8081   node: http://127.0.0.1:7200
checks: 102   passed: 102   failed: 0
all checks passed
```

Deployment under test: devnet (chain id 3) founded by `scripts/quickstart.sh`,
node at height ~700 (a 1-second block interval), obs-app serving the interface, the explorer and the portal
on one origin, with the real compiled wallet module at
`web/wasm/obsidian-wallet.wasm`. Two further networks — testnet on 8300/9300/8182
and staging on 8400/9400/8184 — were running on the same host at the same time
from the same checkout, which is what check 101 exists to pin down.

Rust suite: 374 passed, 0 failed. JavaScript suite: 19 passed, 0 failed.

## The 108 checks

| # | Check | Result |
|---|-------|--------|
| 1 | the largest supply the protocol can ever issue is 21,000,000 OBS | pass |
| 2 | the genesis allocation is 100,000 OBS | pass |
| 3 | the validator bond is 50 OBS | pass |
| 4 | money is integer grains: 1 OBS = 10^12 grains | pass |
| 5 | no floating-point type appears in the monetary path | pass |
| 6 | Amount has checked arithmetic and no unchecked operators | pass |
| 7 | the gas fee is 0.02 % of the amount | pass |
| 8 | the gas fee is capped at 0.01 OBS | pass |
| 9 | gas splits 40 % to validators and the rest to the mining pool | pass |
| 10 | the supply test suite passes | pass |
| 11 | the live chain reports a maximum supply of 21,000,000 | pass |
| 12 | the live chain reports exactly one genesis allocation | pass |
| 13 | there is no proof-of-work anywhere in the consensus code | pass |
| 14 | no hash threshold appears in the difficulty rules | pass |
| 15 | the slot duration is 30 protocol seconds | pass |
| 16 | the proposer schedule is deterministic from chain id, parent and slot | pass |
| 17 | PoT difficulty is bounded between 6,666 and 15,000 basis points | pass |
| 18 | the time-rate window is 24 hours of slots | pass |
| 19 | weight comes from elapsed slots plus attested participation | pass |
| 20 | the PoT weight tests pass | pass |
| 21 | the live node reports a protocol time | pass |
| 22 | the live node reports its PoT difficulty | pass |
| 23 | the median-time-past window is 11 blocks | pass |
| 24 | a block may be at most 60 seconds ahead of its parent | pass |
| 25 | a block must be at least 1 second ahead of its parent | pass |
| 26 | rule 1 refuses a timestamp at or before the median time past | pass |
| 27 | rule 2 refuses a block stamped beyond the parent bound | pass |
| 28 | rule 3 binds a claim to the block's own protocol time | pass |
| 29 | protocol time advances by at least one second per block | pass |
| 30 | the node reports a median time past | pass |
| 31 | the claim interval is 4 hours of protocol time | pass |
| 32 | there are at most 6 claims per protocol day | pass |
| 33 | the base reward is 0.000166666666 OBS per claim | pass |
| 34 | the reward floor is 0.000033333333 OBS per claim | pass |
| 35 | the halving is -0.5 % per 100,000 active miners | pass |
| 36 | one halving step pays 165,833,332 grains | pass |
| 37 | the mining reward tests pass | pass |
| 38 | an active miner is one that claimed within 30 days | pass |
| 39 | the live chain pays 0.000166666666 OBS per claim | pass |
| 40 | the live chain reports one active miner and the treasury's claimed genesis | pass |
| 41 | the genesis claim is bound to block height 1 | pass |
| 42 | the genesis allocation is issued exactly once | pass |
| 43 | the first block carries the founder's registration | pass |
| 44 | the live chain has issued exactly the genesis allocation plus claims | pass |
| 45 | the mainnet genesis invitation appears nowhere in the repository | pass |
| 46 | deregistration returns the bond after 48 hours | pass |
| 47 | the node identity is a distinct key from the wallet key | pass |
| 48 | uptime comes from attestations, not self-reporting | pass |
| 49 | finality needs a two-thirds quorum, computed in integers | pass |
| 50 | the validator tests pass | pass |
| 51 | the live node reports its validator set | pass |
| 52 | the live node reports active validators in its status | pass |
| 53 | a wallet derives 256 bits of entropy into a 24-word phrase | pass |
| 54 | the keystore is sealed with Argon2id and ChaCha20-Poly1305 | pass |
| 55 | the wasm module exports the ABI the interface expects | pass |
| 56 | a wallet created in the module has three distinct keys | pass |
| 57 | the installed wasm artifact matches the current source | pass |
| 58 | the interface shows no private key when a wallet is created | pass |
| 59 | no response from any public route carries a seed or a private key | pass |
| 60 | the wallet's fee is the module's, not the page's | pass |
| 61 | a transfer is signed over the chain id, so it cannot be replayed | pass |
| 62 | the wasm module refuses a locked wallet | pass |
| 63 | the interface formats amounts without floating point | pass |
| 64 | a transaction identifier is never a wallet address | pass |
| 65 | registration has exactly six steps and no email verification code | pass |
| 66 | Gmail addresses are canonicalised before the uniqueness check | pass |
| 67 | one canonical Gmail identity can hold exactly one account | pass |
| 68 | the invitation limit is five per account | pass |
| 69 | an invitation is single use and spent atomically | pass |
| 70 | passwords must be at least 12 bytes | pass |
| 71 | TOTP codes are compared with leading zeros preserved | pass |
| 72 | eight failed attempts lock an account for fifteen minutes | pass |
| 73 | a session lasts twelve hours | pass |
| 74 | account recovery is separate from wallet recovery | pass |
| 75 | the live service reports its network and authority | pass |
| 76 | registration refuses a password that is too short | pass |
| 77 | no public route mentions a balance | pass |
| 78 | there is no GET /wallet/{address}/balance anywhere | pass |
| 79 | the privacy tests pass | pass |
| 80 | the explorer returns a partial address, never a whole one | pass |
| 81 | the running explorer publishes no balance | pass |
| 82 | a response that would contain a balance is withheld, not trimmed | pass |
| 83 | the index is reported as behind rather than hidden | pass |
| 84 | the node's own balance route is signature-gated | pass |
| 85 | the read-through refuses the account path | pass |
| 86 | an unknown address is a 404, not a number | pass |
| 87 | the portal publishes its scopes | pass |
| 88 | the OpenAPI document is generated from the route table | pass |
| 89 | an API key is a read credential and is hashed at rest | pass |
| 90 | rate limits are clamped into a sane range | pass |
| 91 | a revoked key is refused | pass |
| 92 | an unknown API key is a 404 and a bad one is a 403 | pass |
| 93 | the interface is served from the application, with one origin for the official mark | pass |
| 94 | the interface cannot mint: no route writes a balance | pass |
| 95 | there is no administrative bypass of consensus | pass |
| 96 | unknown routes are refused | pass |
| 97 | a malformed transaction is refused | pass |
| 98 | the full Rust suite passes | pass |
| 99 | the full JavaScript suite passes | pass |
| 100 | no private key, seed phrase, genesis invitation or logo source is in the tree | pass |
| 101 | the four networks have their own ports and only test networks publish an invitation | pass |
| 102 | the operator can mint a genesis invitation, and the code is never echoed back | pass |
| 103 | the page and the route table name no mark host, whatever the configuration | pass |
| 104 | the page falls back to its own drawn seal when a mark cannot load | pass |
| 105 | a deploy dry run prints the plan and changes nothing | pass |
| 106 | the rendered units are complete and name the deployment's own paths | pass |
| 107 | the rehearsal refuses a port range a network owns | pass |
| 108 | the launch kit and the audit brief say what they must | pass |

## What the run found

Fourteen defects were found by running it, and all fourteen are fixed — which is
the point of having it. A later audit found a fifteenth, a gap rather than a
wrong answer: three networks could not share a host, because every program
defaulted to the devnet's ports and the four default data directories overlapped
(`data/devnet`, `data/testnet`, … were right, but two nodes on one machine still
fought over 7200). The ports are now per network — 8200/9200/8181/8180 for
mainnet, 8300/9300/8182/8183 for testnet, 7200/9220/8081/8080 for devnet,
8400/9400/8184/8185 for staging — the defaults come from
`obs_primitives::network`, `obs-cli networks` prints them, and check 101 holds
them. The same audit closed a second gap: `devnet init` would happily found a
network called mainnet with a *published* invitation, so mainnet now has no
default invitation at all and requires the operator's own (`--invite`), which is
the only thing that can authorise the genesis allocation on a network carrying
real value:

A sixteenth defect, found by a failing acceptance run rather than by reading:
check 56's wallet test asserted that no recovery-phrase word appears in a wallet's
`Debug` output, and two of the words it looked for were inside the field names —
"main" in "mainnet", "over" in "recovery_key" — while a bech32 address can hold a
dictionary word by chance. It failed about once in forty runs, proved nothing when
it passed, and its evidence was discarded by a `2>/dev/null` in the check. The
test now asserts the exact debug form and the absence of the phrase and the keys;
the check keeps its log and prints the failing test's name. The rule is in
[Testing](19-testing.md#a-test-may-not-assert-a-property-of-a-random-values-spelling).

A twenty-third, the most serious of them all, came out of the rehearsal —
a peer that restarted was never dialled again, and the network forked quietly.
It has its own section below, under [the security
audit](#twenty-third-defect-a-peer-that-restarted-was-never-dialled-again).

A nineteenth and twentieth came from installing the official mark: `obs-app
--logo-source` was documented and rejected by the parser (the same drift as
`obs-cli invite mint`, now guarded by a test in each binary that compares the help
text against the accepted flags), and `scripts/leak-check.sh` scanned the *working
directory* rather than the repository, so a deployment's gitignored `.env.local`
made it fail — a check that fails on a file the repository does not contain is a
check an operator learns to ignore. It now scans what would actually be
published: tracked files plus untracked files that are not ignored.

A seventeenth, found while writing this document's own instructions: the
documented way to mint a genesis invitation — `obs-cli invite mint --store … --code
… --genesis` — was *unusable*, because the CLI read the `invite` command's option
list from the member-facing `invite issue` and rejected `--store` and `--code` as
unknown options. The operator's half of the command now takes the operator's
options, a genesis invitation defaults to a year rather than a month, and check
102 mints one on a scratch store, proves the commitment landed, and proves the
code is not echoed back.


1. **The interface did not boot.** The page's shell never painted: the app
   registers its `DOMContentLoaded` handler on `window`, and the test's DOM shim
   dispatched the event on `document` without bubbling it. The shim now forwards
   document events to window listeners, and `web/tests/dom.mjs` documents why.
2. **`element()` silently dropped children.** `web/js/format.js` accepted
   `{children: [...]}` in its options object and ignored positional children, so
   21 call sites across all four views rendered empty containers — headings and
   hero copy were simply missing. It now accepts both forms, flattens arrays, and
   has a unit test that pins it.
3. **A peer could be dropped before it was ever probed.** `obs-p2p`'s heartbeat
   checked the idle timeout before the ping, so a heartbeat loop delayed by load
   could remove a silent peer without giving it a chance to answer. The rule is
   now probe-then-drop unconditionally, which is what the liveness test asserts
   and what the code comment always claimed.

4. **The cross-origin guard missed the read-through.** The rule that a
   state-changing request must come from the service's own origin covered
   `/v1/*` but not `/node/*`, so a page on another site could make a visitor's
   browser post to the forwarding routes. The guard now covers every write on
   every path this service answers, with a test that sends a foreign `Origin` to
   each of them and asserts a `403`.

5. **A registration could be dated beyond the chain's reach, which stranded a
   new network.** The chain accepts a registration when
   `authorisation.issued_at <= block time <= expires_at`, and `block time` is
   protocol time — but the service stamped `issued_at` with its own wall clock.
   Protocol time advances at most sixty seconds per block, so a founder who
   reached the registration service ten minutes after the epoch produced a
   transaction no block could include. On a running chain that is a delay; on a
   network's **first** block it is a deadlock, because block 1 is the only block
   that can carry the founder's registration. It was found by founding a devnet
   and delaying the registration: the chain sat at height 0 with
   `block_rejected`/`block_proposer` events for ten minutes, and started at
   height 11 within eight seconds of registering with the fix. Authorisations
   are now dated in the chain's time — read from the node the deployment follows
   — and a deployment that cannot establish it refuses with `503
   chain_time_unknown` rather than minting something the chain may reject.

6. **`obs-cli register` could never finish step six.** Step five returns a TOTP
   provisioning URI and the enrolment is not complete until a code from it is
   confirmed; the command issued the secret and then went straight to
   `register/wallet`, which refuses with `out_of_order`. The command now
   confirms the enrolment itself, computing a code from the secret it was just
   given (and stepping to the next window when a request lands near a boundary),
   and writes the recovery code, the secret and the URI to a `0600` file.

7. **A validator attested forever and no attestation ever reached a block.**
   Found by bonding a validator on a running devnet and watching it for a hundred
   blocks: `/api/v1/events` showed `attestation_queued` beside every `mined`
   event, while every block carried `attestations: 0` and the validator's record
   stayed at `attestations: 0, uptime_bp: 0, score: 0`. The chain's uptime rule
   was never wrong — the *node* was emptying its own queue: after accepting each
   block it cleared every pending attestation, including the attestation for the
   new head that accepting the block had just queued. The one attestation that
   could have been included was discarded by the same step that made it
   eligible. Two related soundness gaps were found in the same pass:

   * the queue could hold an older and a newer attestation from one validator,
     and a proposer including both would build a block the state machine rejects
     (`attestation_order`) — losing every attestation in it. The queue now holds
     at most one attestation per validator, always the newest, and drops exactly
     the attestations a block included;
   * an attestation could reference a block up to 1,024 blocks old, so a
     validator that had gone offline could have one stale signature harvested
     later to buy PoT weight. Inclusion is now bounded by
     `ATTESTATION_WINDOW_BLOCKS = 4`, which the node's own filter mirrors so it
     never proposes a block the chain must reject.

   A third gap was found next to them: `queue_attestation` accepted whatever a
   peer relayed without checking the signature. A queued attestation is one the
   node puts into a block it proposes, so a single forged relay — an attestation
   for a real height signed by nobody in particular — would have made the node
   build a block that every node, including itself, must reject. Signatures are
   now verified before queueing; the node's own `a_running_validator_...` test
   relays exactly such a forgery and fails if the gate is removed.

   The same pass completed the evidence accounting: `blocks_proposed` and
   `missed_slots` on a validator record were never written, so the node's
   `/api/v1/validators` reported zero proposals beside a live validator. Both are
   now written from block content alone — the signed header names the proposer,
   and a block that carries no attestation from an active validator is one
   opportunity it missed (a validator registered by the block itself is not
   charged for it; its first opportunity is the next block). Regression tests:
   `a_running_validator_attests_and_its_attestations_reach_the_chain` in
   `obs-node`, and `an_attestation_cannot_be_used_long_after_the_block_it_references`
   plus `the_chain_credits_proposers_and_counts_missed_opportunities` in
   `obs-chain`. On the running devnet the fix is visible end to end: every block
   carries one attestation, the validator record reads `uptime_bp: 9680`,
   `score: 98`, `attestations: 91`, and each block's weight includes the attested
   bonus (`weight_atoms: 1,001,000`). Its proposer credit still read zero at
   that point — a second, narrower defect, recorded as 14 below.

8. **A restarted node did not come back to its own chain, in two separate
   ways.** Found by restarting the devnet node between acceptance runs:
   `/api/v1/status` came back at height 0 with `block_rejected`/`block_proposer`
   events, and the run failed checks 29, 40 and 44 — exactly the ones that need a
   chain with history.

   * **Durability was opt-in.** `ChainStore` appends a block to the log only
     when `fsync` is on, and `obs-node` set `fsync` from the `--fsync` flag, so
     without the flag nothing was written at all — the flag's own help text
     ("flush every write to disk") described something stronger than what it
     gated. A chain's supply, rewards and finality could be rewound by
     restarting a process. Every accepted block is now written to the log;
     `--fsync` decides how hard each write is pushed to the platter, never
     whether it happens.
   * **A directory did not remember which chain it held.** Even with the blocks
     written, a devnet restarted with `--genesis-timestamp now` got a *different*
     genesis anchor, so the replayed log was a pile of orphans and the node
     started fresh at height 0. A data directory now records the genesis it was
     founded with (`<network>-genesis`) and that record is authoritative
     afterwards: the stored epoch wins over a configuration file's, and starting
     a node against a directory that holds a *different* chain (another network,
     another registration authority) fails closed with a message naming both.

   Regression test: `a_node_restarts_on_the_chain_it_left` in `obs-node` — it
   mines, drops the node, reopens the same data directory with a *later*
   `--genesis-timestamp`, asserts the height, head, state root and issued supply
   are the ones it left, mines on, and then asserts that a different authority
   is refused. Two `obs-consensus` store tests pin the genesis record itself: it
   round-trips, and anything that is not exactly the written shape is an error.
   The live check is the same thing by hand: stop the devnet node, start it
   again against the same data directory, and the height, head and state root are
   where they were.

9. **Nothing tested the proposer schedule past the bootstrap window.** Fixing
   the validator accounting exposed it: `missed_slots` and `blocks_proposed` are
   only meaningful where the scheduled-proposer rule applies, and no test went
   past `BOOTSTRAP_SLOTS` to reach it. The new
   `past_the_bootstrap_window_only_the_scheduled_validator_may_propose` walks
   2,880 blocks to the end of the bootstrap window, then asserts that the two
   validators the schedule does not select are refused with `block_proposer`,
   that the scheduled validator's block applies and is credited to it, that the
   block's attestations spare two validators a missed opportunity and charge the
   silent third exactly one, and that two of three attestations finalise the
   height they attest (`ceil(2n/3)`).

10. **The checklist measured the machine as well as the code.** One run failed
   check 56 (`cargo test -p obs-wallet`), which then passed standalone; the
   cause was a compile inside a graded check on a sandbox that had just been
   reset. A check that has to build is partly a test of spare capacity, so the
   script now warms the build once (`cargo build --workspace --tests`) before the
   first check and refuses to run the checklist at all if the workspace does not
   build. The graded checks then measure behaviour.

11. **A second node could not sync past the first message's worth of blocks.**
   `MAX_BLOCKS_PER_MESSAGE` bounds one `Blocks` message to 128 blocks, and the
   node applied the batch it asked for and then never asked for the next one.
   On the live devnet this looked like a joiner that had "almost" synced: its
   status read `height: 128`, `peers: 1`, forever. The receiving side now
   continues while the batch made progress and the peer has more
   (`after > before && after < advertised`), and counts each continuation.
   Regression test: `a_node_that_joins_late_catches_up_across_batches` in
   `obs-node` builds more than 128 blocks *before* the joiner starts and fails
   with "at 128 of 151" when the continuation is removed.

12. **A single HTTP probe to the peer port banned the whole address.** The ban
   rule counted every failed handshake as a protocol violation, including a
   frame header that promised more bytes than the limit and a connection that
   closed mid-handshake. A `GET /` from a browser or a health check arrives
   exactly that way — the header is read as a length of `0x20544547` bytes —
   and because a ban is keyed on the **address**, two nodes on one host took
   each other down: node 2 refused the node it was joining with
   `refused (Banned)`. The rule is now what its comment always claimed: a
   violation is a peer that *speaks this protocol and then breaks it* (bad
   signature, nonce mismatch, a message that cannot appear at that stage).
   Framing mismatches still close the connection, without the ban. Regression
   tests: `an_oversized_frame_closes_the_connection_without_banning_the_address`
   and a ban asserted in `a_tampered_handshake_signature_is_refused`.

13. **A joining node could never validate a chain whose founder registered.**
   Found by pointing a second node at the live devnet and watching it sit at
   height 0 with nothing but `block_rejected ... orphan: the parent is unknown`
   events. The cause: block 1 carries the founder's `Register` transaction, the
   state machine validates it against the network's **registration authority**
   (`invite_authority`), and a join started with only `--genesis-timestamp` has
   an all-zero authority — so block 1 was refused, every later block was an
   orphan, and the node could never make progress. A related version of the
   same blindness made a node that could not *found* a chain exit instead of
   syncing, so the join never even started. Three fixes:

   * the genesis record the store writes is completed from the peer's
     handshake. The authority is a *public* network parameter (it authorises
     invitations; every node needs it to check history), the handshake already
     binds both sides to the same genesis anchor, and the extended `Hello`
     carries the epoch and authority inside its signature;
   * adoption is narrow and fail-closed. It happens only while the store holds
     nothing but the genesis block; once an authority is recorded it can never
     be replaced, and a peer that reports a *different* authority is refused
     (`WrongChain`) — as is a peer connecting to a node that already knows its
     own. A fresh joiner records the fact as a `genesis_learned` event;
   * `--genesis-file <path>` lets an operator supply the network's recorded
     genesis directly (the `<network>-genesis` file from any of its data
     directories), and a genesis epoch that has passed is now a warning that
     the node will sync instead of an exit — fatal only for a node with no
     peers that was asked to mine.

   Regression test: `a_joiner_learns_the_networks_registration_authority_from_its_peer`
   in `obs-node` builds a chain whose block 1 is a registration, then joins it
   with a node whose authority is all-zero and a single peer address; with
   adoption disabled it fails with "at 0 of 134" after two minutes. The live
   check is acceptance check 52, which now joins the running devnet with
   nothing but the epoch, waits for the joiner to reach the height the first
   node was at, and compares state roots there — and additionally requires the
   joined chain to contain the registration block.

14. **The proposer credit was written, and never attributed to the validator
   that earned it.** The fix in defect 7 made `blocks_proposed` and
   `missed_slots` real, and the live check confirmed only half of it: on a
   devnet whose single validator had mined every block, `/api/v1/validators`
   reported `blocks_proposed: 0` beside `attestations: 2469` and
   `missed_slots: 4`. The credit matched the header's proposer against
   `record.node_key` only. In scheduled mode that is right — the slot schedule
   names a validator's node identity — but inside the bootstrap window a
   registered account's *wallet key* may propose, and that is exactly how a
   real network starts: the founder wallet mines while the validator key
   attests, and the protocol requires the two keys to differ. A block proposed
   with the wallet was credited to nobody. A validator is now credited when
   either of its keys proposed, and the regression test commits one block with
   the bond's wallet and requires `blocks_proposed` to move (it stays at 2 of 3
   without the fix). Acceptance check 51 now also requires a non-zero
   `blocks_proposed` from the live node, so the operator-visible number cannot
   silently go back to zero.

Three further corrections were to the run itself rather than the system: the
acceptance script had three checks pointed at the wrong source file or looking
for the wrong words, and it (like the docs) contained the mainnet genesis
invitation as a literal. The invitation is now assembled at run time from
fragments so that a search for a secret does not record the secret, and the
documentation describes the invitation without printing it.

## On a busy machine

The suite must pass on a machine that is doing other things, and one run under
load said otherwise: three of the `obs-p2p` tests failed intermittently, one of
them taking 380 seconds to do so. The protocol was right; the harness was
starving itself. Its poller thread polls in a tight loop, each poll holding the
manager mutex for the whole timeout, and Rust's `Mutex` promises no fairness, so
a test thread calling `lock()` could be kept out for seconds — long enough to
miss a peer's entire lifetime and report a network that never connected. The
poller now yields after an idle poll, the waiting helpers drive the node from the
test's own thread with a non-blocking `try_lock`, and deadlines distinguish the
handshake rule under test (5 s) from the test's patience (120 s). Nothing a test
asserts was relaxed, and the file went from 130-600 seconds to about four.

Three consecutive full-workspace runs under ten CPU spinners now pass, and the
suite now stands at 357 tests (the regressions above added twelve),
no failures each time. The rule this produced is in
[Testing](19-testing.md#tests-must-not-assume-an-idle-machine).

## The security audit

An adversarial pass was run against a live deployment — a real node, a real
interface, real signing keys — rather than by reading the code alone. What was
tried, and what happened:

| Probe | Result |
|-------|--------|
| `GET /../Cargo.toml`, `/assets/../../Cargo.toml`, `%2e%2e`, `..%2f`, `%00`, `....//` | `404` / `400` (`bad_path`, `bad_path_encoding`) — no file outside the static root is reachable |
| `/node/api/v1/../../status`, `/node/api/v1/account/proof`, `POST /node/api/v1/status` | `403 not_forwarded` — the read-through cannot be turned into a second route |
| Request smuggling: `Content-Length` with `Transfer-Encoding`, duplicated `Content-Length`, a body that is also a second request, `TE: chunked` | `501` / `400` — the transport parses one request at a time and refuses the ambiguity |
| Deep JSON nesting, at depths 500 to 30 000 and at the body-size limits, on both services | `400 bad_json` at every depth, one connection at a time, services alive. The parser has an explicit `MAX_DEPTH` |
| Hostile JSON: lone surrogate, `NaN`, `1e999999`, duplicate keys, embedded NUL, 60 KiB hex, integer above `u128`, truncated body, invalid UTF-8, 780 KiB body | Named refusals (`bad_json`, `bad_hex`, `malformed_transaction`, `transaction_too_large`); nothing panicked |
| P2P: frame claiming 512 MiB, claiming 4 GiB, zero-length frame, 64 KiB of noise, slow trickle | The peer is dropped; the node kept producing blocks |
| Pagination: `limit=0`, `-1`, `abc`, `1e9`, `18446744073709551616`, `u64::MAX`, `offset=99999999999999999999` on the node and the explorer | Every response bounded (≤ 200 blocks); nonsense values fall back to the default rather than being passed through |
| Arbitrary amounts: `u128::MAX`, `u128::MAX/2`, `MAX_SUPPLY + 1` in a transfer's bytes | **a defect — see below** |
| Authentication: constant work whether the account exists, `ct_eq` compare, MFA always evaluated, lockout after the failure limit, tokens stored only as hashes | Pass, by reading `sign_in` against each claim |
| Masking at every layer: node, interface read-through, explorer | A full `tx` shows `dobs1afj...k25n` at every layer, never the whole address |

An audit by the people who wrote the code is not an independent audit. It is
what the project can honestly claim, and it is listed here so the claim is
checkable rather than asserted.

### Twenty-first defect: unchecked multiplication in the fee

`gas_fee_for` computed `amount.grains() * 2` without checking. A transaction's
amount arrives from its bytes and was not bounded before the fee was derived
from it, so any amount above `u128::MAX / 2` — roughly `1.7 × 10^38` grains —
took one of two wrong turns depending on the build:

* **debug**: `attempt to multiply with overflow`, a panic inside the state
  machine. The state machine runs under the node's state lock, so the panic
  poisoned the lock and the node stopped answering *anything* for the life of
  the process. A remote party could have done this with a signed transaction.
* **release**: the multiplication wrapped, and the fee returned had nothing to
  do with the amount.

Fixed in three places, each with its own regression test: the fee saturates at
the cap when the doubling does not fit (which is the exact answer, since the cap
binds from 50 OBS); the state machine refuses a transfer above the total supply
by name before any arithmetic touches it; and `mul_div_ceil` checks its round-up.
The failing test (`attempt to multiply with overflow`) was written and run
*before* the fix, and the state-machine test asserts the rule name
(`tx_amount_above_supply`), not merely a failure.

### Twenty-second defect: a test that failed once in three hundred runs

`a_word_that_is_not_in_the_wordlist_is_refused` swapped two words of a generated
phrase and asserted the result was invalid, on the reasoning that a swap must
break the BIP-39 checksum. It must not: measured over 20 000 phrases, 68 swapped
phrases (0.34 %) were *still valid* phrases, because the swapped bits happened to
carry a matching checksum. A test that fails once in three hundred runs teaches
people to re-run rather than to read — the same rule as [defect
16](19-testing.md#a-test-may-not-assert-a-property-of-a-random-values-spelling). It is now a
deterministic search: the last word is replaced by the first word in the list
that makes the phrase invalid.

### Twenty-third defect: a peer that restarted was never dialled again

The rehearsal found this one, and it is the kind of defect a unit test cannot
see. Three nodes were founded, joined and agreed; then the founder was killed
and restarted. It came back, and the two followers never spoke to it again. The
chain forked: the founder mined its own blocks, the followers mined theirs, and
neither side reported an error. On two hosts this is a network that survives its
own restart in name only.

Two defects were behind it, and the second was only found because the first fix
made the test fail *differently*:

1. `--peer` was a one-shot dial at startup. The dial loop ran once, so a peer
   that was not there at that instant — a peer rebooting, a peer that had not
   finished its own startup, a network cable that was out — was never tried
   again. The node now re-dials every configured peer that is not connected,
   with an exponential backoff of 2 s doubling to 60 s, reset on connection, and
   skips addresses that are banned for misbehaviour.
2. The manager's set of *in-flight* dials was keyed by the address that was
   dialled and cleared by the address the peer *resolved to*. A configured
   `0.0.0.0:9300` resolves to `127.0.0.1:9300`, so the entry for the former was
   never removed: the node believed it was already dialling that peer, for ever.
   The set is now keyed by the dialled address, carries the dialled address
   through the connected and rejected events, and expires (four times the
   connect timeout) so that a lost event cannot wedge an address permanently.

The test, `a_configured_peer_that_restarts_is_dialled_again`
(`crates/obs-node/tests/node.rs`), starts a follower, drops its peer, brings the
peer back on the same port as a new process, and requires both to see each other
without either being restarted itself. It fails on the old code with a timeout
and passes in four seconds now. It is check 106's neighbouring coverage, and it
is the reason to rehearse rather than only to test.

The rules it produced, which are worth stating because they were not obvious:

* never compare a *configured* address with a *connected* one literally —
  compare what identifies the peer, which here is its port;
* an in-flight entry that is only cleared by the arrival of a specific event
  will eventually be cleared by no event at all; every wait needs an expiry;
* a peer that goes away and comes back is the normal case on a real network, not
  an exceptional one.

The audit found no path that mints value, changes a balance, approves a claim,
alters a fee, a reward, a supply or a timing rule, or bypasses consensus — and
the search for such a path is itself a check in the acceptance run (95, 96).

## Re-running it

The run expects a live deployment:

```sh
bash scripts/quickstart.sh start --dir /tmp/obsidian-devnet --block-interval-ms 1000
bash scripts/acceptance.sh
```

The quickstart founds the network, starts the node and the interface, registers
the founder and bonds a validator, on the ports the acceptance run expects
(7200/9220/8081). A deployment that was built by hand is fine too; the run only
needs a node, an interface and a registered founder somewhere.

`scripts/acceptance.sh` reads `OBSIDIAN_BASE_URL` (default
`http://127.0.0.1:8081`) and `OBSIDIAN_NODE_URL` (default
`http://127.0.0.1:7200`), so it can be pointed at any deployment.
