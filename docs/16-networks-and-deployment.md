# 16 — Networks and deployment

## The four networks

| Network | Chain id | Namespace | Genesis invite | Purpose |
|---------|----------|-----------|----------------|---------|
| mainnet | 1 | `obs1…` | one, single use, never published | real value |
| testnet | 2 | `tobs1…` | disposable | public testing |
| devnet | 3 | `dobs1…` | disposable, created by tooling | development |
| staging | 4 | `sobs1…` | disposable | production rehearsal |

Each network has its own chain id, genesis timestamp, database directory,
authority key and service key. The genesis parameters are public — a joiner
learns the registration authority from a peer's signed handshake, or is given
the network's recorded genesis with `--genesis-file` — while the authority's
*private* half, which mints invitations, never leaves the registration service. A transaction signed for one chain id is invalid
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

## Termux: a node on a phone

A full node, a validator and the interface run on an Android phone under
[Termux](https://termux.dev). Nothing here needs a service the phone lacks: the
workspace builds with **zero third-party crates**, the store is a single
append-only file, and the only network traffic is peers the operator names. It is
a useful way to carry a devnet in a pocket, and — because a phone is a machine
someone actually leaves running — a reasonable way to keep a small testnet
validator online.

```sh
pkg update -y && pkg upgrade -y
pkg install -y rust git curl binutils     # clang too, if the linker complains
git clone -b arena/01a0fe6f-obsidian-network \
    https://github.com/The-Black-Seal/Obsidian-Network.git
cd Obsidian-Network
termux-wake-lock                          # keep it alive while you test
bash scripts/devnet-quickstart.sh         # build (minutes), start, verify
```

Then open the printed URL (`http://127.0.0.1:8081`) in the phone's browser. The
first build is the long part — a few minutes of CPU on a phone; every start
after that is seconds.

* **Storage.** Keep the data directory under `$HOME`
  (`~/obsidian-devnet` is the default). `/sdcard` is FUSE-mounted and is a bad
  place for a block log.
* **Staying alive.** Android kills background processes; `termux-wake-lock` is
  what stops it, and `termux-wake-unlock` releases it. The lock also survives
  the screen going off, which is what makes a phone a usable validator.
* **Ports.** Everything binds above 1024, so no root and no `sudo` is involved.
  `obs-node` and `obs-app` bind `0.0.0.0`, so another device on the same Wi-Fi can
  reach the interface at `http://<phone-ip>:8081` — convenient for testing a
  wallet on a laptop against a phone's chain, and *not* something to leave open on
  an untrusted network: a devnet peer port accepts connections from anyone who can
  reach it.
* **A devnet's keys are development secrets on plain files** (`authority.key`,
  `founder.keystore.json`, `founder.password.txt`, `founder.phrase.txt`). That is
  fine for a disposable chain and is never how a real network is run — mainnet
  keys belong on `0600` files the operator owns, and a real account is created
  through the registration service with a real invitation.
* **Updating.** `git pull` and re-run `scripts/devnet-quickstart.sh`: the build is
  incremental, and a running devnet resumes the chain it has (its genesis record
  wins over any flag, so a restart cannot silently re-found it).

## Configuration that matters

| Where | Setting | Why |
|-------|---------|-----|
| node | `--data-dir` | chain state and blocks; one directory per network |
| node | `--authority-key` | which invitation authorities this chain trusts |
| node | `--genesis-file` | a recorded `<network>-genesis`, for joining a network this node did not found |
| node | `--genesis-timestamp` | the network's epoch — `now` when founding, the value from `/api/v1/status` when joining |
| node | `--keystore` / `OBS_WALLET_PASSWORD` | the key that proposes and claims |
| node | `--mine`, `--validator` | whether this node proposes and attests |
| app | `--node-url` | which node it follows |
| app | `--require-key` | refuse anonymous readers on the explorer routes |
| app | `--store`, `--accounts-store` | the portal's keys and the account registry |
| app | `--logo-source` / `OBSIDIAN_LOGO_URL` | where to fetch the official mark, when it is not a file in `web/assets/` |
| gateway | `--store`, `--authority-key`, `--service-key` | accounts, invitations, sealed TOTP secrets |
