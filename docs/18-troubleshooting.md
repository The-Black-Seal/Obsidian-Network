# 18 — Troubleshooting

## The interface says "The node is not answering"

The page reads a node and never invents chain data; with no node it says so
instead of showing stale numbers.

1. Is the node up? `curl -s localhost:7200/api/v1/status`
2. Is `obs-app` pointed at it? `obs-app --node-url …`; the start-up log prints
   the node URL it is indexing.
3. Is the page reading the right base? It defaults to `/node` on its own origin
   (the app's read-through). A page served from static hosting needs
   `<meta name="obsidian-node-api" content="https://node.example.com">`.

A `503` from `/node/...` means the app is up and the node is not — the app
reports that rather than papering over it.

## "the interface did not reach the expected state in time" (browser test)

The smoke test needs a live deployment. Start the node and `obs-app`, then:

```sh
OBSIDIAN_BASE_URL=http://127.0.0.1:8081 node --test web/tests/smoke.test.mjs
```

If the services are not running the test *skips*; it never passes silently.

## A claim is refused

In order of likelihood:

| Refusal | Cause |
|---------|-------|
| `not_registered` | The account is not on chain yet — registration must be mined first |
| `interval_not_elapsed` | Fewer than 14,400 protocol seconds since the last claim |
| `daily_cap` | Six claims already in this protocol day |
| `timestamp_protocol_claim` | The claim was stamped with a protocol time other than the block's |
| `bad_nonce` | The transaction used a nonce other than the chain's next one |

The wallet reads the chain's own `next_nonce`, `last_claim_at` and protocol time,
so the last two happen only when a hand-built transaction bypasses it.

## A transaction is refused with `nonce_gap`

The node orders per-account transactions strictly: the next transaction must use
the account's current nonce. Submit the missing nonce first, or resend the same
transaction (resubmitting is idempotent — the pool recognises it).

## Registration fails at step 1

* `invalid_gmail` — canonicalisation rejected the address: it must contain an
  `@` and a dot in the domain.
* `identity_taken` — one canonical Gmail identity holds one account. A `+tag`,
  a dot, or `googlemail.com` does not make a new identity.

## Registration fails at step 3

* `invite_invalid` — the code is unknown for this network (codes are per-network.
* `invite_spent` — single use, already used.
* `invite_expired` — invitations live 7 days.
* `invite_mismatch` — the authorization is bound to a different Gmail commitment.

## The authenticator code is rejected

Codes are six digits, `30`-second steps, with one step of skew either side.
Check the device clock — TOTP is wall-clock based even though mining is not. After
`8` failures within the lockout window the account is locked for `900` seconds.

## `Connection refused (os error 111)` from `obs-cli devnet init`

Expected when the node is not running yet: the wallet and authority are still
written, and the command is re-runnable. Start the node and run
`obs-cli devnet register`.

## `--authority-key expects 32 bytes of hex`

The flag takes the **public key**, 64 hex characters, not a path to the key file.
Read it with `obs-cli keys` or from the operator output at init time.

## The wallet says "This wallet is not on chain yet"

Correct, and not an error. A newly created wallet has keys but no account until
its registration is mined. The interface refuses to show a balance the chain did
not send.

## A keystore will not open

* Wrong password — the failure is reported as a decryption failure, and the
  keystore is then re-locked.
* Wrong network — a keystore sealed for one network is refused by another.
* Truncated text — the sealed form is base64url; a copy that lost characters
  fails to parse rather than opening to a different wallet.

## `obs-wasm` aborts with `RuntimeError: unreachable` when a call returns

The result buffer is allocated as a 4-byte length header plus the payload, so it
must be freed with the same size it was allocated with:
`obs_free(pointer, length + 4)`. Freeing with `4` aborts in the allocator. Input
buffers are allocated as `length || 1`.

## The wasm module does not change after a rebuild

`cargo build` alone does not install it. Run `bash scripts/build-web.sh`, and
`bash scripts/build-web.sh --check` to confirm the installed artifact matches
the current source. Browsers cache aggressively: a hard reload may be needed.

## A gate fails after a sandbox reset

The toolchain lives outside the repository and can be lost:

```sh
sudo mkdir -p /opt/rust /opt/cargo && sudo chown -R user:user /opt/rust /opt/cargo
bash scripts/install-toolchain.sh
```

`scripts/build-web.sh` needs the `wasm32-unknown-unknown` target, which the
installer provides.
