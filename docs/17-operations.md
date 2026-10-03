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

## Durability: what a restart keeps

A node writes every accepted block to `<data-dir>/<network>-blocks.log` as it
accepts it, and rebuilds its state from that log on start — the log is the chain
as far as the node itself is concerned. On restart a node therefore returns to
the head it left, with the same state root recomputed by replaying the same
blocks through the same rules, and issues nothing again along the way.

`--fsync` chooses **how hard** each write is pushed to disk, not whether the
block is written: with it, every append calls `sync_data` before the block is
reported stored; without it the write is handed to the operating system, which
survives a process crash but not a machine losing power. Run a mainnet node with
`--fsync`; a devnet that is recreated on every start does not need it.

**A data directory holds one chain.** The genesis it was founded with is
written beside the log as `<network>-genesis` (one field per line, readable with
`cat`) and is authoritative from then on: the stored epoch wins over the
`--genesis-timestamp` a process was started with, so a restart resumes the chain
it has instead of founding a new one. Starting a node against a directory that
holds a different chain — another network, or another registration authority —
fails closed and names both. To re-found a chain, use a new data directory
(`obs-cli devnet init` does this), not a new flag on an old one.

The log is self-checking. Each record carries its own length and CRC32, and a
torn or partial trailing record found at open is dropped and truncated away
rather than trusted; a log that contains a block the protocol rejects is an
error, not something to skip. The parallel `<network>-head` file is the head
pointer, written atomically through a rename.

## Backups

* **Chain state and blocks**: the `--data-dir`, which holds the block log. A node
  can re-sync from peers instead, so this is a convenience rather than a
  necessity — but a node with no peers has only its log.
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
