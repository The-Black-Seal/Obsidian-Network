# 13 — Explorer and privacy

## The contract

The public Explorer and the Explorer API publish:

* **Partial addresses.** `obs1q9x7…4k8m` — a prefix and a suffix with the middle
  removed. An address is never shown whole to a third party.
* **No balances.** Not for accounts, not for validators, not in aggregate per
  address. There is no route that answers "how much does this address hold".
* **No endpoint shaped like one.** `GET /wallet/{address}/balance`,
  `GET /address/{address}/balance` and every similar shape are absent from the
  route table, and the acceptance run asserts that no public route's path
  contains `balance`.

## How the contract is enforced

Three independent mechanisms, so a mistake in one is caught by another:

1. **The route table.** `crates/obs-app/src/privacy.rs` lists every public route
   with its method, summary and required scope. Tests assert that no route path
   contains `balance`, that no route mentions a per-address wallet, and that the
   scope table and the route table agree.
2. **The response scrubber.** Every JSON body produced by the app passes through
   `scrub()`, which walks the whole value and **refuses** the response if any key
   is on the forbidden list (`balance`, `balances`, `balance_grains`,
   `lifetime_rewards`, `spendable`, `available`, …). This is fail-closed: a field
   that should not exist turns into an error, not into a leak. The refusal does
   not name the offending field, because the field list is a design document and
   a public error should not teach an attacker which internal names exist.
3. **The index does not hold balances.** The indexer records heights, hashes,
   times, claim counts, block appearances and validator participation. It never
   keeps an account's balance, because it never reads one.

## What an address page shows

`GET /v1/explorer/address/{address}` returns:

```json
{
  "address": "dobs1aelka…ot7bto",
  "claims": 2,
  "blocks_proposed": 0,
  "first_seen": 1791009327,
  "last_seen": 1791016527,
  "recent_heights": [6, 12],
  "note": "activity only: the network does not publish balances or whole addresses"
}
```

Activity, not value. Anyone who wants their own balance asks the node with a
signature proving they hold the key — see [14](14-apis.md).

## The index is not an authority

* The index reads a node and follows it. If it is behind, `indexed_height` and
  `node_height` differ and the difference is shown in the interface rather than
  hidden.
* A search that finds nothing says so; the index never guesses.
* Every figure the Explorer shows traces to a block the node served. There is no
  computed value that is not also derivable from the chain.

## The node read-through

A browser gets one origin. `obs-app` serves `GET /node/api/v1/…` as a
**read-through** to the node it indexes, restricted to an allowlist:

```
status, supply, params, mining, blocks, blocks/*, transactions/*,
validators, mempool, peers, events
```

Two writes are forwarded, and only these:

* `POST /node/api/v1/transactions` — a transaction that is already signed. The
  service holds no key and cannot alter a byte without invalidating the
  signature.
* `POST /node/api/v1/account/proof` — an account proving its own ownership with a
  signature over a fresh nonce, to read **its own** state. The node answers only
  when the signature proves the key; an unknown account is a `404`, not a number.
  `GET` on this path is refused, so no third party can name an address and
  receive a balance.

Everything off the list is refused (`403 not_forwarded`), including
`/node/api/v1/account` and any path that tries to reach it by traversal or
encoding. Responses are still scrubbed on the way out, and an unreachable node is
reported as `503` rather than papered over.

## What the Explorer API cannot do

* It cannot write. Every route is `GET`.
* It cannot approve anything: there is no claim approval, no invitation minting,
  no parameter change.
* It cannot widen what a node said. If the node refuses, the API refuses.
