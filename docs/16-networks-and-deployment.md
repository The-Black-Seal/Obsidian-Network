# 16 — Networks and deployment

## The four networks

| Network | Chain id | Namespace | Node API | Peers | Interface | Service | Genesis invite | Purpose |
|---------|----------|-----------|----------|-------|-----------|---------|----------------|---------|
| mainnet | 1 | `obs1…` | 8200 | 9200 | 8181 | 8180 | one, single use, never published | real value |
| testnet | 2 | `tobs1…` | 8300 | 9300 | 8182 | 8183 | disposable | public testing |
| devnet | 3 | `dobs1…` | 7200 | 9220 | 8081 | 8080 | disposable, created by tooling | development |
| staging | 4 | `sobs1…` | 8400 | 9400 | 8184 | 8185 | disposable | production rehearsal |

The ports are constants in `obs_primitives::network` and are the default each
binary takes when the flag is absent, so four networks can run on one machine
without a port being passed by hand and without a wallet pointed at `127.0.0.1`
reading the wrong chain's node. `obs-cli networks` prints the table from the
binaries themselves. Everything binds above 1024: no root is needed anywhere.

Each network has its own chain id, genesis timestamp, database directory,
authority key and service key. The genesis parameters are public — a joiner
learns the registration authority from a peer's signed handshake, or is given
the network's recorded genesis with `--genesis-file` — while the authority's
*private* half, which mints invitations, never leaves the registration service. A transaction signed for one chain id is invalid
on every other network, and a node refuses a block from a different chain
outright — so a testnet transaction can never be replayed on mainnet.

## What to run

| Service | Binary | Port (devnet defaults) | Job |
|---------|--------|------------------------|-----|
| Node | `obs-node` | 7200 API / 9220 peers | consensus, state, mining, the node API |
| Registration | `obs-gateway` | 8080 | accounts, invitations, MFA, sessions |
| Application | `obs-app` | 8081 | Explorer API, indexer, portal, static interface, node read-through |
| Tooling | `obs-cli` | — | keys, wallets, network bootstrap, operator tasks |

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

## A network in one command

```sh
bash scripts/quickstart.sh start --network devnet   # or testnet, staging, mainnet
```

`devnet init` — which the quickstart calls for you — writes the authority key,
the founder's wallet, its phrase and its password, all `0600`. It needs no
running node; `devnet register` submits the founding registration and is safe to
re-run. The first block carries that registration and the founder's first claim:
the genesis claim, which is the one-time 100,000 OBS allocation to the treasury
wallet.

### `--node-url` decides which chain is founded

A machine can serve several networks, and "the node on this network's default
port" is not always the node you mean. So the rule is explicit:

* `devnet init --node-url <url>` founds *and* registers: the registration goes to
  the node you named, which is the node that will carry block 1;
* `devnet init` **without** `--node-url` founds and stops there. It prints
  `the founder is not registered yet: no --node-url was given, so init did not
  guess at a chain`, and tells you to run
  `obs-cli devnet register --node-url <url> --data-dir <dir>` once the node is up;
* `devnet register --node-url <url>` is the second half, and is safe to re-run.

Before that was the rule, `init` posted the founder's registration to whatever
answered on the default port. On a machine already serving one deployment that
is a different deployment's chain, and the symptom later is
[`gmail_duplicate`](18-troubleshooting.md#gmail_duplicate-this-gmail-identity-already-has-an-account)
— the founder is "already registered", on a chain that is not the one being
deployed. A node with `--mine` and no founder registration mines **nothing**:
height stays 0, because block 1 is the registration.

`scripts/deploy.sh` always does this correctly, in this order: founding keys,
units, node started, founder registered, validator bonded, verified.

### Being the wallet that takes the genesis allocation

The 100,000 OBS genesis allocation goes to the account whose claim is in **block
1**, and block 1 can only be proposed by the wallet that registers in it. So on a
chain you found, the founder wallet *is* the treasury, and there is no way for a
person who registers later — however early — to take that allocation: a claim in
block 2 is an ordinary 0.000166666666 OBS claim like any other. This is the
protocol, not a policy; [Genesis and treasury](08-genesis-and-treasury.md) has the mechanism.

Therefore, if the treasury should be yours rather than a wallet a tool generated,
found the chain with a wallet you already hold:

```sh
# words you created — in the wallet screen, or wherever you keep them, in a 0600
# file: the phrase is read, validated by BIP-39, used, and copied nowhere else
bash scripts/quickstart.sh start --network devnet --phrase-file ~/my-words.txt

# or by hand, for any network
obs-cli devnet init --network testnet --data-dir <DIR> \
    --password-file <DIR>/password.txt --phrase-file ~/my-words.txt
```

The founder address printed at the end is then derivable from your words, and the
treasury is yours. `--phrase-file` refuses a phrase with a wrong word or a broken
checksum, refuses to overwrite an existing keystore, and does **not** write
`founder.phrase.txt`: a phrase in two places is a phrase in two places to lose.

### The invitation a test network publishes, and the one the service knows

There are two doors an invitation can be used at, and they are not the same door:

| Door | Which invitation it checks |
|------|----------------------------|
| `obs-cli devnet init` / `devnet register` (founding) | the published code, offline, with the authority key on this machine |
| the interface's registration steps (`/v1/register/*`) | the codes minted into the **registration service's own store** |

A test network's published founder invitation is minted into that store by
`scripts/quickstart.sh` on a fresh deployment, so the code
`obs-cli networks` advertises also works at the interface — otherwise a person
typing it would be told `invite_invalid` about an invitation the network
publishes. `scripts/invite-check.sh` proves the whole path against a scratch
service, spending nothing real:

```sh
bash scripts/invite-check.sh --network devnet
```

On a deployment made by `scripts/deploy.sh` — a testnet, a staging network, or
mainnet — nothing is minted for you. Mint the invitation you intend to hand out,
then restart the service so it loads the store:

```sh
obs-cli invite mint --network testnet --store <DIR>/accounts.json \
    --code "$(cat ~/my-invitation.txt)" --genesis
sudo systemctl restart obs-app
```

Mainnet's genesis invitation is the operator's and is minted exactly once, into
the store of the host that will accept the first registration, from a machine
that is not the public host.

### Resetting a test network

```sh
bash scripts/quickstart.sh reset --network devnet --yes            # keep the old chain aside
bash scripts/quickstart.sh reset --network devnet --yes --purge    # delete it
bash scripts/quickstart.sh reset --network mainnet --yes           # refused
```

A reset stops the deployment's processes, refuses to run while anything still
holds its ports (a node that cannot bind its peer port still answers its API from
the chain in its data directory, so "the API answered" is not evidence that this
deployment is the one running), and — by default — **moves** the old directory to
`<dir>.before-reset-<stamp>` rather than deleting it. The next `start` founds a
new chain with a new founder wallet, a fresh account store, and the published
invitation working again.

Mainnet is refused outright, and not only for safety: a mainnet directory holds
the network's authority key and the founder's wallet, while the chain itself
lives on in every peer — so "reset" there would destroy the keys without
resetting anything. That refusal is check 110.

## Each network, by hand

The quickstart wraps these; running them by hand is what a service unit, a
container or a supervisor does. Only the network name and the ports change
between them — the shape is identical, which is the point of the port table
above. `<DIR>` is one directory per network (`/var/lib/obsidian/<network>` on a
server, `$HOME/obsidian-<network>` on a phone).

Found the network once, from the operator's account. A test network takes its
disposable invitation (printed by `obs-cli networks`); mainnet takes
`--invite <the operator's own code>`, which is written in no file of this
repository and belongs in a `0600` one of the operator's:

```sh
obs-cli networks                                          # the four networks and their ports
obs-cli devnet init --network devnet  --data-dir <DIR> --password-file <DIR>/password.txt
obs-cli devnet init --network testnet --data-dir <DIR> --password-file <DIR>/password.txt
obs-cli devnet init --network staging --data-dir <DIR> --password-file <DIR>/password.txt
obs-cli devnet init --network mainnet --data-dir <DIR> --password-file <DIR>/password.txt \
    --invite "$(cat <DIR>/genesis-invite.txt)"            # the operator's, never published
```

Then the node — mining and attesting, which is what advances protocol time:

```sh
# mainnet: node API 8200, peers 9200, interface 8181, service 8180
obs-node --network mainnet  --data-dir <DIR>/node --genesis-timestamp now --fsync \
    --authority-key <64 hex> --keystore <DIR>/founder.keystore.json \
    --keystore-password-file <DIR>/password.txt --mine --validator
obs-node --network testnet  --data-dir <DIR>/node --genesis-timestamp now --fsync \
    --authority-key <64 hex> --keystore <DIR>/founder.keystore.json \
    --keystore-password-file <DIR>/password.txt --mine --validator
obs-node --network staging  --data-dir <DIR>/node --genesis-timestamp now --fsync \
    --authority-key <64 hex> --keystore <DIR>/founder.keystore.json \
    --keystore-password-file <DIR>/password.txt --mine --validator
obs-node --network devnet   --data-dir <DIR>/node --genesis-timestamp now --fsync \
    --authority-key <64 hex> --keystore <DIR>/founder.keystore.json \
    --keystore-password-file <DIR>/password.txt --mine --validator
```

and the interface, which serves the Explorer, the wallet and the developer
portal from the same origin:

```sh
obs-app --network mainnet --port 8181 --node-url http://127.0.0.1:8200 \
    --static-dir web --store <DIR>/index.json
obs-app --network testnet --port 8182 --node-url http://127.0.0.1:8300 \
    --static-dir web --store <DIR>/index.json
obs-app --network staging --port 8184 --node-url http://127.0.0.1:8400 \
    --static-dir web --store <DIR>/index.json
obs-app --network devnet  --port 8081 --node-url http://127.0.0.1:7200 \
    --static-dir web --store <DIR>/index.json
```

Registration — `--accounts` on the application, or the service on its own port —
is required for anyone but the founder to exist, and on mainnet it is how real
accounts are created:

```sh
obs-gateway --network mainnet --port 8180 --authority-key <DIR>/authority.key \
    --store <DIR>/accounts.json --node-url http://127.0.0.1:8200
```

`--genesis-timestamp now` founds a chain in a directory that has none; a
directory that already holds a chain keeps it, so a restart can never silently
re-found a network. A node joining a network it did not found takes the epoch
from the operator and names a peer instead:

```sh
obs-node --network mainnet --data-dir <DIR>/node \
    --genesis-timestamp <the epoch from the operator's /api/v1/status> \
    --peer <host>:9200 --fsync
```

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
bash scripts/quickstart.sh                # build (minutes), start, verify
```

That is a devnet. `--network testnet` or `--network staging` does the same for
those, on their own ports, beside the devnet rather than instead of it; the
compatibility name `scripts/devnet-quickstart.sh` is the same script pinned to
`--network devnet`.

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
* **Updating.** `git pull` and re-run `scripts/quickstart.sh`: the build is
  incremental, and a running devnet resumes the chain it has (its genesis record
  wins over any flag, so a restart cannot silently re-found it).

## The official mark on a deployment

Three arrangements, in precedence order, and only the first keeps the mark's
origin private:

1. **A file.** `bash scripts/sync-logo.sh <url|file>` on a machine that can reach
   the source installs `web/assets/logo-official.<ext>` and records its hash in
   `web/assets/logo-official.provenance`. Commit it and every deployment serves
   the image from its own origin with no network at all. This is the arrangement
   the repository itself uses.
2. **A server-side source.** `obs-app --logo-source <url>` (or
   `OBSIDIAN_LOGO_URL`) fetches the image and serves it from the service's origin:
   the URL is configuration, never source, and never reaches a browser or a log
   line.
3. **A browser source.** `obs-app --mark-url <url>` (or `OBSIDIAN_MARK_URL`) is for
   the deployment whose *visitors* can reach the host but whose *server* cannot —
   a sandbox, an egress allowlist, a proxy the host does not accept. The URL is
   published at `/assets/mark.json` and `web/js/mark.js` loads it in the page,
   falling back to the drawn seal if the browser cannot reach it either. **That
   URL is public**: anyone reading the page's configuration sees it, and the
   visitors' browsers contact the host directly.

A deployment's local configuration belongs in a gitignored file — `.env.local` is
ignored by this repository's `.gitignore` — so the URL is present on the machine
and absent from the tree:

```sh
# .env.local, mode 0600, never committed
OBSIDIAN_MARK_URL=<the mark's url>
```

```sh
set -a; . ./.env.local; set +a
obs-app --network mainnet --port 8181 --node-url http://127.0.0.1:8200 --static-dir web
```

Whatever the arrangement, the page, its scripts, its stylesheet and the route
table name no host — acceptance check 103 asserts exactly that — so the served
interface is identical on every deployment.

## Oracle Cloud: a public node in the free tier

Oracle's Always Free tier is the cheapest way to put the network on a public IP,
and it is a good fit for a PoT node: proof of time is not hash-rate competition,
so a small ARM instance is not "too slow to mine" — it is a full node, a
validator and an interface on 2 cores that would be idle under any proof of work.

**What the free tier actually is** (Oracle's *Always Free Resources* page, which
is the authority for this and the one to re-read when it changes):

| Resource | Always Free |
|----------|-------------|
| `VM.Standard.A1.Flex` (Ampere, Arm) | 2 OCPUs and 12 GB RAM, splittable across up to two instances |
| AMD micro instances | 2 × `VM.Standard.E2.1.Micro` (1/8 OCPU, 1 GB each) |
| Block storage | 200 GB total (boot volumes count; 47 GB minimum each) |
| Outbound transfer | 10 TB per month |
| Load balancer | 1 flexible, 10 Mbps |
| Signup | a card for identity verification; Always Free resources are not charged |

Paid, on-demand prices for the same shape are around **$0.01 per OCPU-hour plus
$0.0015 per GB-hour** — roughly $14/month for 1 OCPU and 6 GB, $28/month for 2
and 12, $56/month for 4 and 24. The console's own estimate, in your region and
currency, is the number to trust; the free allowance is a tenancy-wide monthly
pool (about 3,000 OCPU-hours and 18,000 GB-hours), so a 4-OCPU instance that runs
all month consumes more than the Always Free entitlement and starts to bill.

**The reclaim rule people trip over.** Oracle may reclaim an idle Always Free
instance when, over a 7-day window, the 95th-percentile CPU use is under 20 %,
network use is under 20 %, and (on A1) memory use is under 20 %. A quiet chain is
exactly that: consensus work here is time, not hashing, so an idle validator can
look idle to Oracle. If the node is meant to be permanent, either run the
interface on the same instance and poll it (the indexer and the interface keep
the box visibly busy), or pay for a small instance and stop worrying about it.
The free tier is best for a testnet or staging node; mainnet validators should be
paid, monitored, and more than one.

### 1. The instance

Create an Ubuntu 24.04 (Arm) instance, shape `VM.Standard.A1.Flex`, 2 OCPU /
12 GB, 100 GB boot volume, with your SSH public key. Note the public IP.

### 2. Two firewalls, not one

Oracle has a network-level security list and the image has its own `iptables`
rules, and **both must allow a port** before a packet arrives. The image also
disables `ufw` and ships a `REJECT` rule, so opening the console alone changes
nothing — this is the single most common "the port is open but it is not open".

In the console: *Networking → Virtual Cloud Networks → your VCN → Security Lists
→ Default Security List → Add Ingress Rules*. Open 80 and 443 from `0.0.0.0/0`
for the interface, and 9200 **only from the other nodes' addresses** — a peer
port is not a public API, it is a consensus connection.

On the instance, insert the same rules above the reject rule and persist them:

```sh
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
sudo iptables -L INPUT --line-numbers        # the ACCEPTs sit above the REJECT
sudo netfilter-persistent save               # or: sudo iptables-save > /etc/iptables/rules.v4
```

### 3. Build from source

There is one build system and it is `cargo`; the workspace has no third-party
crates, so the build needs no package registry.

```sh
sudo apt update && sudo apt install -y build-essential curl git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"
cd "$HOME" && git clone https://github.com/The-Black-Seal/Obsidian-Network.git
cd Obsidian-Network && git checkout arena/01a0fe6f-obsidian-network
cargo build --workspace --release       # a couple of minutes on 2 Arm cores
bash scripts/build-web.sh               # the wallet module for the interface
```

The checkout pins Rust 1.88.0 in `rust-toolchain.toml`, so `rustup` fetches the
toolchain the release was built and tested with rather than whatever is newest.

### 4. Run it under systemd

Everything the quickstart prints by hand belongs in a unit file on a server. One
account, one directory, two services:

```sh
sudo useradd --system --home /var/lib/obsidian --create-home obsidian
sudo -u obsidian bash scripts/quickstart.sh start --network testnet --dir /var/lib/obsidian/testnet
```

```ini
# /etc/systemd/system/obs-node.service
[Unit]
Description=Obsidian Network node (testnet)
After=network-online.target

[Service]
User=obsidian
WorkingDirectory=/opt/obsidian
ExecStart=/opt/obsidian/target/release/obs-node --network testnet \
    --data-dir /var/lib/obsidian/testnet/node --bind 127.0.0.1 \
    --api-port 8300 --listen-port 9300 --fsync --mine --validator \
    --authority-key <64 hex from: obs-cli authority print --authority-key <file>> \
    --keystore /var/lib/obsidian/testnet/founder.keystore.json \
    --keystore-password-file /var/lib/obsidian/testnet/founder.password.txt
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/var/lib/obsidian/testnet
[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/obs-app.service
[Unit]
Description=Obsidian Network interface (testnet)
After=obs-node.service

[Service]
User=obsidian
WorkingDirectory=/opt/obsidian
ExecStart=/opt/obsidian/target/release/obs-app --network testnet --bind 127.0.0.1 \
    --port 8182 --node-url http://127.0.0.1:8300 --static-dir /opt/obsidian/web \
    --store /var/lib/obsidian/testnet/index.json --accounts \
    --accounts-store /var/lib/obsidian/testnet/accounts.json \
    --authority-key /var/lib/obsidian/testnet/authority.key
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/var/lib/obsidian/testnet
[Install]
WantedBy=multi-user.target
```

`--bind 127.0.0.1` is the reason the units above do not simply expose 8300 and
8182 to the internet: the only port the world should reach is the one a TLS
proxy owns. `--bind` refuses an address it cannot parse, so a typo cannot
silently become "listen everywhere".

### 5. TLS in front of it

The interface and the gateway are plain HTTP on purpose: they are behind a
terminator that owns the certificate and the domain. Caddy is the shortest path
(one file, automatic certificates, automatic renewal):

```
obsidian.example.org {
    reverse_proxy 127.0.0.1:8182
}
```

```sh
sudo systemctl reload caddy     # after the Caddyfile change
curl -s https://obsidian.example.org/api/v1/status
```

nginx with `certbot --nginx` is the same arrangement. Keep the interface port on
loopback, keep 80/443 open in **both** firewalls from step 2, and let the proxy
do the TLS.

### 6. Running a node worth trusting

* **Peers.** `--peer <host>:9300` for each known node, one flag each time. A node
  with no peers still mines; it just has no one to compare notes with.
* **Joining, not founding.** A node that did not found the network takes the
  epoch from the operator and names a peer — `--genesis-timestamp <epoch>` with
  no `--mine` or `--validator` for a follower. A data directory that already
  holds a chain keeps it, so a restart can never re-found a network.
* **Backups.** The data directory plus the keystore, the authority key and the
  invitation file are the node. The recovery phrase belongs offline, on paper or
  metal, not on the machine that mines.
* **Monitoring.** `obs-cli status --network testnet --node-url http://127.0.0.1:8300`,
  `journalctl -u obs-node -f`, and the supply endpoint for issuance drift. A node
  whose height stops moving while `protocol_time` moves is a node that is not
  being selected — check `peers`, then `validators`.
* **Secrets.** `bash scripts/leak-check.sh` before every push; it fails on a
  private key, a genesis invitation or a logo origin in the tree. A server that
  has ever held the mainnet invitation and a public repository do not mix.

## Configuration that matters

| Where | Setting | Why |
|-------|---------|-----|
| node | `--bind` | which address the API answers on: `0.0.0.0` (default) or `127.0.0.1` behind a proxy |
| node | `--data-dir` | chain state and blocks; one directory per network |
| node | `--authority-key` | which invitation authorities this chain trusts |
| node | `--genesis-file` | a recorded `<network>-genesis`, for joining a network this node did not found |
| node | `--genesis-timestamp` | the network's epoch — `now` when founding, the value from `/api/v1/status` when joining |
| node | `--keystore` / `OBS_WALLET_PASSWORD` | the key that proposes and claims |
| node | `--mine`, `--validator` | whether this node proposes and attests |
| app | `--bind` | `127.0.0.1` when a TLS terminator is in front, `0.0.0.0` when it is not |
| app | `--logo-source` / `OBSIDIAN_LOGO_URL` | the service fetches the official mark server-side; the URL never reaches a browser |
| app | `--mark-url` / `OBSIDIAN_MARK_URL` | the *front end* loads the mark, for a deployment whose visitors reach a host the service cannot. That URL is public by design; a file and `--logo-source` both win over it |
| app | `--node-url` | which node it follows |
| app | `--require-key` | refuse anonymous readers on the explorer routes |
| app | `--store`, `--accounts-store` | the portal's keys and the account registry |
| app | `--logo-source` / `OBSIDIAN_LOGO_URL` | where to fetch the official mark, when it is not a file in `web/assets/` |
| gateway | `--store`, `--authority-key`, `--service-key` | accounts, invitations, sealed TOTP secrets |
