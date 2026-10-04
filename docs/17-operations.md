# 17 — Operations

## The index catching up after a restart

An explorer restarted against a running chain starts where it starts: level with
the node's head and holding no history. It reads its way back to the genesis block
in slices of 64 blocks per sync, and until it gets there its status says so —
`indexed_from` is the oldest block it holds and `history_complete` is `false`.

What to watch:

* `indexed_from` falling towards 1 and `history_complete` turning `true`: normal,
  and quick on a young chain.
* `indexed_from` not moving while the node is up: the index is not being synced
  (`--sync-ms`), or the node is refusing the listing.
* `index_behind` growing: the node is producing blocks faster than the index
  reads them — a sign the machine is too small for the chain, not a bug.
* `backfill_stalls` above zero with `history_complete` still `false`: the node
  answered a request for history below the cursor with nothing, so the index
  cannot read further back. It keeps the cursor where it is and says so rather
  than reporting a complete chain it never read. In practice this means the node
  is an older build without the `before` cursor on its block listing, or it is
  refusing the request.

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

## Joining a network you did not found

A node that joins an existing chain needs three things: the network name, the
chain's **epoch**, and a peer address. The epoch is in any node's status
(`GET /api/v1/status` → `genesis_timestamp`); without it a node has its own
genesis anchor and the handshake refuses every peer as a different chain.

```sh
./target/release/obs-node --network devnet --data-dir /var/lib/obsidian/join \
    --api-port 7201 --listen-port 9221 \
    --genesis-timestamp 1791033668 --peer 127.0.0.1:9220
```

The chain's **registration authority** is the fourth thing a node needs in
practice: it is the public key that authorises invitations, and the state
machine checks it against every `Register` transaction in the chain's history,
including the founder's — which is normally in block 1. A joining node does not
have to be told it. The handshake carries the epoch and the authority inside the
signed `Hello`, both sides already compare the genesis anchor, and a joiner
whose record has no authority adopts the one its peer reports, before it has
validated any block. An operator who would rather not take the first peer's word
can supply the record directly, out of band:

```sh
./target/release/obs-node --network devnet --data-dir /var/lib/obsidian/join \
    --genesis-timestamp 1791033668 --peer 127.0.0.1:9220 \
    --genesis-file /tmp/dev2/node/devnet-genesis
```

`--genesis-file` reads a `<network>-genesis` record (from any of the network's
data directories) and refuses anything that is not one, or belongs to another
network. `--authority-key <64 hex>` states the same thing as a key. Adoption is
deliberately narrow: it happens only while the data directory holds nothing but
the genesis block, the recorded authority can never be replaced afterwards, and
a peer that reports a different authority than the one a node already knows is
refused at the handshake. A node that learns the network's genesis records a
`genesis_learned` event naming the peer it learned it from.

## Banning, and what is not a ban

A peer is banned by address for a while when it *speaks the protocol and then
breaks it*: a handshake signature that does not verify, a nonce that does not
come back, or a message that cannot appear at that stage of the connection.
Everything else — a frame header that promises more bytes than the limit, a
connection that closes mid-handshake, a self-connect — closes the connection
without banning anyone, because that is also what a health check, a port
scanner, a browser tab and a peer that is still starting up look like from the
other side. The distinction matters on a host running several nodes: an address
ban takes every peer on that address with it, and a stray `GET /` to the peer
port must not take the deployment down. A peer on another chain, or with a
different genesis or registration authority, is refused with a reason
(`WrongChain`) and is not banned either: it is misconfigured, not hostile.

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
