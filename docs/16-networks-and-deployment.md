# 16 — Networks and deployment

## The four networks

| Network | Chain id | Namespace | Genesis invite | Purpose |
|---------|----------|-----------|----------------|---------|
| mainnet | 1 | `obs1…` | one, single use, never published | real value |
| testnet | 2 | `tobs1…` | disposable | public testing |
| devnet | 3 | `dobs1…` | disposable, created by tooling | development |
| staging | 4 | `sobs1…` | disposable | production rehearsal |

Each network has its own chain id, genesis timestamp, database directory,
authority key and service key. A transaction signed for one chain id is invalid
on every other network, and a node refuses a block from a different chain
outright — so a testnet transaction can never be replayed on mainnet.

## What to run

| Service | Binary | Typical port | Job |
|---------|--------|--------------|-----|
| Node | `obs-node` | 7200 API / 9200 peers | consensus, state, mining, the node API |
| Registration | `obs-gateway` | 7300 | accounts, invitations, MFA, sessions |
| Application | `obs-app` | 8081 | Explorer API, indexer, portal, static interface, node read-through |
| Tooling | `obs-cli` | — | keys, wallets, devnet bootstrap, operator tasks |

A node needs an authority key (to recognise invitations), and either a keystore
or a wallet password to propose. `obs-app` needs the authority key only if it
mounts the registration service in-process (`--accounts`).

## Building

```sh
export PATH=/opt/rust/bin:$PATH CARGO_HOME=/opt/cargo CARGO_NET_OFFLINE=true
cargo build --workspace --release          # the four services
bash scripts/build-web.sh                  # the wallet module into web/wasm/
bash scripts/build-web.sh --check          # verify the installed module matches the build
cargo test --workspace                     # the Rust suite
node --test web/tests/*.test.mjs           # the JavaScript suite
```

`scripts/build-web.sh` builds `obs-wasm` for `wasm32-unknown-unknown`, installs
the artifact at `web/wasm/obsidian-wallet.wasm`, and writes
`web/wasm/PROVENANCE.txt` recording the toolchain, target, profile and hash. The
`--check` form rebuilds and compares byte-for-byte, so the module in the tree is
provably the one the source produces.

## Devnet in one command

```sh
./target/release/obs-cli devnet init --data-dir /var/lib/obsidian/devnet \
    --password-file /etc/obsidian/founder.password
./target/release/obs-node --network devnet --data-dir /var/lib/obsidian/devnet/node \
    --genesis-timestamp now --authority-key <authority public key, 64 hex> \
    --keystore /var/lib/obsidian/devnet/founder.keystore.json \
    --keystore-password-file /etc/obsidian/founder.password --mine --validator
./target/release/obs-cli devnet register --data-dir /var/lib/obsidian/devnet \
    --password-file /etc/obsidian/founder.password
```

`devnet init` writes the authority key, the founder's wallet, its phrase and its
password (all `0600` except the phrase, which is `0600` too). It needs no running
node; `devnet register` submits the founding registration and is safe to re-run.
The first block carries that registration and the founder's first claim — the
genesis claim.

## Deployment topology

A minimal production-shaped deployment:

```
        ┌────────────┐        ┌──────────────┐
        │  obs-node  │◀──────▶│   obs-node   │   peers over the peer port
        └─────┬──────┘        └──────────────┘
              │ node API (private)
        ┌─────▼──────┐        ┌──────────────┐
        │  obs-app   │◀──────▶│ obs-gateway  │   registration, sessions
        └─────┬──────┘        └──────────────┘
              │ HTTPS
        ┌─────▼──────┐
        │  browser   │  the interface, the wallet module
        └────────────┘
```

* The node's API is **not** exposed to the internet in this shape; the app serves
  the node read-through and the explorer, and it holds the node on a private
  network.
* The gateway is behind the app (or beside it on its own origin) and holds the
  authority and service keys on `0600` files it owns.
* The interface is static files served by `obs-app --static-dir web`. It can also
  be served from any static host, in which case its node API base is set with
  `<meta name="obsidian-node-api" content="https://node.example.com">` and the
  node must allow the page's origin.
* The official mark is served at `/assets/logo-official.png` from whichever of
  these the deployment has (see [APIs](14-apis.md#the-official-mark)):
  `web/assets/logo-official.*`, installed by `bash scripts/sync-logo.sh <url>`;
  or a source the app fetches server-side with `--logo-source <url>` /
  `OBSIDIAN_LOGO_URL`. Either way the page references one relative path, the
  browser never contacts the mark's origin, and the repository never records it.

## Configuration that matters

| Where | Setting | Why |
|-------|---------|-----|
| node | `--data-dir` | chain state and blocks; one directory per network |
| node | `--authority-key` | which invitation authorities this chain trusts |
| node | `--keystore` / `OBS_WALLET_PASSWORD` | the key that proposes and claims |
| node | `--mine`, `--validator` | whether this node proposes and attests |
| app | `--node-url` | which node it follows |
| app | `--require-key` | refuse anonymous readers on the explorer routes |
| app | `--store`, `--accounts-store` | the portal's keys and the account registry |
| app | `--logo-source` / `OBSIDIAN_LOGO_URL` | where to fetch the official mark, when it is not a file in `web/assets/` |
| gateway | `--store`, `--authority-key`, `--service-key` | accounts, invitations, sealed TOTP secrets |
