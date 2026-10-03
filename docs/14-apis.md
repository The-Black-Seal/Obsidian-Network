# 14 — APIs

Four surfaces, deliberately different in what they can do. Every one of them is
read-only except for the three writes marked below, and none of them can sign.

## Node API (`obs-node`; 7200 on devnet, 8200 on mainnet — see [Networks](16-networks-and-deployment.md#the-four-networks))

| Method | Route | Returns |
|--------|-------|---------|
| GET | `/api/v1/status` | network, chain id, height, head, state root, protocol time, weight, difficulty, issued supply, validators, miners |
| GET | `/api/v1/supply` | max supply, issued supply, genesis allocation, pool balances |
| GET | `/api/v1/params` | the protocol parameters the chain is running |
| GET | `/api/v1/mining` | reward per claim, daily rate, active miners, halving position, interval, cap |
| GET | `/api/v1/blocks` | recent blocks, newest first (`limit`, `offset`) |
| GET | `/api/v1/blocks/{height-or-hash}` | one block |
| GET | `/api/v1/transactions/{id}` | one transaction by id |
| GET | `/api/v1/validators` | the validator set: bond, uptime, attestations, status |
| GET | `/api/v1/mempool` | pooled transaction count and summaries |
| GET | `/api/v1/peers` | connected peers |
| GET | `/api/v1/events` | recent node events |
| **POST** | `/api/v1/transactions` | submits `{"transaction":"<hex>"}`; the node validates it and answers `{accepted,id,status}` |
| **POST** | `/api/v1/account/proof` | `{"address","nonce","signature"}`; answers that account's own state **only** if the signature proves the key |

The last two are the only writes on the whole node, and both carry their own
authentication. There is no key material anywhere in the API: nothing accepts a
private key, a seed phrase or a password.

`account/proof` is the **only** route that can answer a balance, and it answers
only the holder of the key. An unknown address gets `404 account_not_found`.

## Registration API (`obs-gateway`)

| Method | Route | Purpose |
|--------|-------|---------|
| POST | `/v1/register/begin` | canonicalise and reserve the Gmail identity |
| POST | `/v1/register/password` | set the account password |
| POST | `/v1/register/invite` | spend an invitation |
| POST | `/v1/register/recovery-code` | issue the account recovery code (shown once) |
| POST | `/v1/register/mfa` | enrol TOTP |
| POST | `/v1/register/mfa/confirm` | confirm TOTP with a code |
| POST | `/v1/register/wallet` | submit the three public keys; produces the activation |
| POST | `/v1/auth/sign-in` | Gmail + password + TOTP → session token |
| GET | `/v1/account` | the caller's own account summary |
| POST/GET | `/v1/invites` | mint (authority key) / list the caller's invitations |
| POST | `/v1/recovery/verify` | account recovery, step 1 |
| POST | `/v1/recovery/mfa` | account recovery, step 2 |
| GET | `/v1/network`, `/v1/authority` | network identity and the authority public key |
| GET | `/healthz` | liveness |

Every step answers the same envelope so a client can walk the flow without
inventing state:

```json
{ "stage": "invite", "next": "/v1/register/invite", "value": {...}, "notice": "..." }
```

Refusals are canonical: `{"ok": false, "error": {"code": "...", "message": "..."}}`.

## Application API (`obs-app`; 8081 on devnet, 8181 on mainnet)

The Explorer and the Developer Portal, plus the node read-through.

| Method | Route | Scope | Notes |
|--------|-------|-------|-------|
| GET | `/v1/explorer/status` | — | heights, times, supply, participation |
| GET | `/v1/explorer/blocks` | `read:blocks` | newest first |
| GET | `/v1/explorer/blocks/{selector}` | `read:blocks` | by height or hash |
| GET | `/v1/explorer/transactions/{id}` | `read:transactions` | sender masked |
| GET | `/v1/explorer/address/{address}` | `read:blocks` | activity only; partial address, no balance |
| GET | `/v1/explorer/validators` | `read:validators` | bond, uptime, attestations |
| GET | `/v1/explorer/supply` | — | issuance, protocol level |
| GET | `/v1/explorer/mining` | — | rate, halving position, active miners |
| GET | `/v1/explorer/search` | — | find a block, transaction or address |
| GET | `/v1/portal/scopes` | — | the scopes an API key can hold |
| GET | `/v1/portal/keys` | session | list the caller's keys |
| POST | `/v1/portal/keys` | session | create a key; the secret is shown **once** |
| DELETE | `/v1/portal/keys/{id}` | session | revoke |
| POST | `/v1/portal/keys/{id}/rotate` | session | rotate; the old secret stops working immediately |
| GET | `/v1/portal/usage` | session | request counts and rate-limit refusals |
| GET | `/v1/portal/openapi.json` | — | the OpenAPI description, generated from the route table |
| GET | `/v1/routes` | — | the public route list |
| GET | `/node/api/v1/{read-path}` | — | read-through to the node (see below) |
| POST | `/node/api/v1/transactions` | — | forwards an already-signed transaction |
| POST | `/node/api/v1/account/proof` | — | forwards an account's signed proof of its own state |
| GET | `/assets/logo-official.png` | — | the deployment's official mark, from this origin |
| GET | `/assets/mark.json` | — | which mark the front end should show (no URL unless the operator published one) |
| GET | `/healthz` | — | liveness |

### The official mark

`GET /assets/logo-official.png` returns the project's official logo from the
service's own origin. The interface and the favicon point at that single path, so
nothing else in a page has to know where a mark comes from.

A deployment may take the image from either of two places:

* a file, `web/assets/logo-official.<png|svg|webp|jpg>` — installed with
  `bash scripts/sync-logo.sh <url>` (or `<file>`) on a machine that can reach the
  source, and committed; the provenance file next to it records where the bytes
  came from — an operator-supplied link or file, or that the image was drawn in
  this repository — plus the hash, media type, size and date. The candidates are
  tried in order, PNG first: installing `logo-official.png` replaces a drawing
  named `logo-official.svg` with no other change, and the route's name stays
  `/assets/logo-official.png` either way, so no page ever has to be edited;
* a source URL, `obs-app --logo-source <url>` or `OBSIDIAN_LOGO_URL` — which the
  service fetches **server-side**, caches for an hour and serves to visitors.

The second exists so that an operator can keep the mark's origin private: the URL
is read from configuration, never written into the repository, and never sent to a
browser, which always talks to this service's own origin. `LogoSource`'s `Debug`
implementation prints `LogoSource(<configured by the operator>)`, so no log line,
error or panic can leak the link by accident.

Only `image/*` answers are accepted (a source that returns an HTML login page is
refused, not served as a logo), only images up to 2 MiB, and a local file always
wins over the network. When neither is available the route answers `404` and the
page uses its drawn seal — a missing logo costs branding, never the page.

### When the service cannot reach the mark, but the browser can

A deployment in a sandbox, behind an egress allowlist, or on a node whose only
route out is through a proxy the mark's host does not allow may be unable to fetch
the image even though the people visiting the page can. For that case an operator
may name a **third** source:

```sh
obs-app --mark-url <url>            # or OBSIDIAN_MARK_URL
```

The service publishes that URL at `GET /assets/mark.json` and `web/js/mark.js`
loads it in the browser; the drawn seal remains the fallback if the browser cannot
reach the host either. The document is two fields and is not cached:

```json
{"configured":true,"url":"<the operator's URL>"}
```

This is the one arrangement in which the mark's URL becomes **public**: anyone who
loads the page and reads this configuration learns it, and the page's visitors
contact that host directly. It is therefore off by default, a file in `web/assets/`
and `--logo-source` both take precedence over it, and an operator who wants the
origin private should use those instead. An unconfigured deployment publishes
`{"configured":false,"url":null}` and no host at all, which check 103 verifies.

### API keys

* A key is a **read credential**. It never grants custody, never signs, and never
  reaches a private key. The non-custodial wallet API is non-custodial precisely
  because a key cannot do anything a reader can do.
* The secret is shown once and stored only as a tagged hash.
* Scopes: `read:blocks`, `read:transactions`, `read:validators` (and the
  unscoped public routes).
* Rate limits are per key, clamped to `[10, 6000]` requests/minute. Refusals are
  `429` with a `Retry-After` header.
* `404` for an unknown key, `403` for a bad, revoked or insufficiently scoped key.

### OpenAPI

`GET /v1/portal/openapi.json` is generated from the same route table the service
routes with, so documentation cannot drift from behaviour. The Developer Portal
renders call examples in JavaScript, TypeScript, Rust and cURL from that
document.

## Wallet module ABI (`obs-wasm`)

The Rust wallet core, compiled to WebAssembly, exposes three functions:

```
obs_alloc(length) -> pointer
obs_free(pointer, length)          # the size the allocator was given
obs_call(operation_ptr, operation_len, request_ptr, request_len) -> pointer
```

`obs_call` returns a 4-byte little-endian length followed by UTF-8 JSON, and the
result must be freed as `length + 4`. Operations:
`phrase_new`, `phrase_validate`, `wallet_generate`, `wallet_from_phrase`,
`keystore_seal`, `keystore_open`, `wallet_lock`, `wallet_list`,
`account_proof`, `sign_transfer`, `sign_claim`, `sign_registration`,
`sign_validator_register`, `sign_validator_deregister`, `protocol_facts`.

An unlocked wallet lives behind an opaque `u64` handle. Handle discipline is
enforced by the module: an unknown handle is refused, and a locked handle cannot
sign.
