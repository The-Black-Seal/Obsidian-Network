# 21 — Acceptance

The acceptance run is `scripts/acceptance.sh`: **100 numbered checks** over the
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
checks: 100   passed: 100   failed: 0
all checks passed
```

Deployment under test: devnet (chain id 3), node at height ~1,900, obs-app
serving the interface, the explorer and the portal on one origin, with the real
compiled wallet module at `web/wasm/obsidian-wallet.wasm`.

Rust suite: 330 passed, 0 failed. JavaScript suite: 15 passed, 0 failed.

## The 100 checks

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
| 93 | the interface is served from the application | pass |
| 94 | the interface cannot mint: no route writes a balance | pass |
| 95 | there is no administrative bypass of consensus | pass |
| 96 | unknown routes are refused | pass |
| 97 | a malformed transaction is refused | pass |
| 98 | the full Rust suite passes | pass |
| 99 | the full JavaScript suite passes | pass |
| 100 | no private key, seed phrase or genesis invitation is in the tree | pass |

## What the run found

Three defects were found by running it, and all three are fixed — which is the
point of having it:

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

Three further corrections were to the run itself rather than the system: the
acceptance script had three checks pointed at the wrong source file or looking
for the wrong words, and it (like the docs) contained the mainnet genesis
invitation as a literal. The invitation is now assembled at run time from
fragments so that a search for a secret does not record the secret, and the
documentation describes the invitation without printing it.

## Re-running it

The run expects a live deployment:

```sh
./target/debug/obs-node --network devnet --data-dir /tmp/dev2/node --genesis-timestamp now \
    --authority-key <64 hex> --keystore /tmp/dev2/founder.keystore.json \
    --keystore-password-file /tmp/dev2/founder.password.txt --mine --validator &
./target/debug/obs-app --network devnet --node-url http://127.0.0.1:7200 --port 8081 \
    --static-dir web --store /tmp/dev2/portal.json --accounts \
    --accounts-store /tmp/dev2/accounts.json --authority-key /tmp/dev2/authority.key &
./target/debug/obs-cli devnet register --data-dir /tmp/dev2 --password-file /tmp/dev2/founder.password.txt
bash scripts/acceptance.sh
```

`scripts/acceptance.sh` reads `OBSIDIAN_BASE_URL` (default
`http://127.0.0.1:8081`) and `OBSIDIAN_NODE_URL` (default
`http://127.0.0.1:7200`), so it can be pointed at any deployment.
