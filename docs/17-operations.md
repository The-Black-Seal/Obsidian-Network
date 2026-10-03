# 17 — Operations

## Day two of a node

```sh
# status: height, head, protocol time, difficulty, participation
curl -s localhost:7200/api/v1/status | head -c 400

# what the chain pays right now
curl -s localhost:7200/api/v1/mining

# is anything pooled, and is anyone connected
curl -s localhost:7200/api/v1/mempool; curl -s localhost:7200/api/v1/peers

# recent events (heads, reorgs, refusals)
curl -s 'localhost:7200/api/v1/events?limit=20'
```

A healthy node shows: `height` increasing, `protocol_time` moving with it,
`active_validators` ≥ 1 (unless the network is still bootstrapping),
`pooled_transactions` draining, and `pot_difficulty_bp` near `10,000`.

## Reading the numbers

| Field | Healthy | What it means when it is not |
|-------|---------|------------------------------|
| `protocol_time` | moves ≥ 1 s per block | If it stalls, no blocks are being produced |
| `pot_difficulty_bp` | near 10,000 | Below: blocks are slower than the 30 s target. Above: faster |
| `total_weight_atoms` | strictly increasing | A decrease means a reorg to a lighter branch, which the rules forbid |
| `finalized_height` | within ~128 slots of `height` | A wide gap means validators are not attesting |
| `issued_supply` | increases by the claim reward per claim | Any other movement is a bug and the block would have been rejected |
| `active_miners` | rises with participation | Used for the halving position; derived, never reported |

## Backups

* **Chain state and blocks**: the `--data-dir`. A node can re-sync from peers, so
  this is a convenience rather than a necessity.
* **Authority and service keys**: irreplaceable. A missing authority key stops the
  registration service and prevents minting invitations; losing it means no new
  invitations can be minted for that network.
* **The account registry** (`--accounts-store`): accounts and their commitments.
  Back it up; a lost registry means every account has to recover.
* **The portal store**: API keys and usage. Back it up, or accept that keys must
  be reissued.

A wallet is the person's own responsibility: the phrase or the sealed keystore.
No service holds a copy, and no operator can produce one.

## Upgrades

* A node binary can be replaced and restarted; it re-reads its data directory.
* Changing a **consensus parameter** is not an upgrade, it is a new network. The
  parameters are compiled in, committed to by the genesis hash, and published in
  every block header. There is no flag that changes them and no governance
  shortcut that bypasses a version bump.
* The wallet module is rebuilt by `scripts/build-web.sh`; `--check` proves the
  installed artifact matches the source before a deployment.

## Monitoring

Watch, in this order:

1. **Height and protocol time** — is the chain alive?
2. **`finalized_height`** — are validators attesting?
3. **`issued_supply`** versus `max_supply` — is issuance consistent with claims?
4. **`peers`** — is the node connected?
5. **The app's `indexed_height` versus the node's `height`** — is the explorer
   behind? (It is reported, not hidden, when it is.)

## Invitations

Minting requires the network's authority key:

```sh
obs-gateway --network mainnet --store /var/lib/obsidian/registry.json \
    --authority-key /etc/obsidian/authority.key --mint-invite --expires-in 7d
```

The operator CLI never prints the code it mints in the clear to a log; the code
goes to the caller. The mainnet **genesis** invitation is not minted by tooling
in normal operation and is never published — if it is lost, the network needs a
new genesis, not a reprint.

## Registering an account from the command line

```sh
obs-cli register --gmail someone@gmail.com --invite <code> \
                --keystore ./someone.keystore.json \
                --gateway-url http://127.0.0.1:8081 --node-url http://127.0.0.1:7200
```

Six steps, no email verification code, and the wallet is created on this machine
before the account exists. The authenticator secret is confirmed from the same
machine (a code is computed from the secret the service just issued), and the
secrets are written to a `0600` file next to the keystore: the account recovery
code, the authenticator secret and the provisioning URI, shown once and never
again.

The invitation authorisation the service returns is dated in the chain's time, so
the registration transaction is includable in the next block whenever the chain
is ready for it — including on a brand-new network, whose first block is the only
one that can carry the founder's registration.
