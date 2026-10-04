# 22 — The launch kit

Everything in this document is a command you can run. It exists so that going
from "the repository is green" to "a network is running on a server, watched and
backed up" is one command and an hour, rather than a weekend of improvisation.

The order is deliberate and it is not a suggestion:

1. **Rehearse on one machine** (`scripts/rehearse.sh`) — three nodes, a restart,
   a live backup and a proven restore. Ten minutes, no server needed.
2. **Deploy the testnet** (`scripts/deploy.sh --network testnet`) — found it for
   real, on the machine that will host it, with systemd, the monitor timer and a
   backup.
3. **Run it for a while** — two hosts if you have them, with a reboot, an
   upgrade and a restore drill in the middle. The testnet exists to find the
   things no test suite can.
4. **Then mainnet**, with your own invitation, and nothing else running on that
   host.

## The pieces

| File | What it is for |
|------|----------------|
| `scripts/rehearse.sh` | Three nodes on one machine: founded, joined, one killed and restarted, backed up live, restored and proved. Exit 0 only if every step passed. |
| `scripts/deploy.sh` | Found a network, render the systemd units, register the founder, bond a validator, verify it. `--dry-run` changes nothing; `--units-out` renders without touching systemd. |
| `scripts/monitor.sh` | The five questions of [17](17-operations.md) plus disk and clock, as exit 0/1/2, with `--alert-cmd` and `--webhook`. Installed as a timer by the deploy. |
| `scripts/backup.sh` | An archive plus a manifest that lists every file and its hash. Refuses to take a live snapshot by accident, and refuses a directory that holds no chain. |
| `scripts/restore.sh` | Verifies every hash before it trusts the archive, then optionally boots the restored node and compares the block the manifest recorded with the restored chain. |
| `deploy/systemd/*.in` | The units the deploy renders: node, interface, monitor service and timer. |
| `scripts/common.sh` | What the four scripts share, including the port table (read from `obs-cli networks`, never copied) and the chain-identity check. |

## 1. Rehearse

```sh
bash scripts/rehearse.sh
```

Runs on the default rehearsal ports (`17000`-`17009`), in
`/tmp/obsidian-rehearsal`, and refuses to start if those ports are already
listening — a rehearsal that half-starts is worse than one that refuses, because
a node that cannot bind its peer port still answers its API from a chain it is
not syncing, and every later check then lies about what it saw.

What it does, and what each step is for:

1. **Founds a network.** Authority key, founder wallet, invitation authorisation,
   the founder's registration, the genesis claim and a validator bond.
2. **Joins it from two more nodes.** They must reach the same head hash as the
   founder, not merely the same height: equal hashes at a height mean equal
   state there.
3. **Kills the founder and brings it back.** The remaining nodes must see it
   leave and, when it returns, everyone must agree again. This is the step that
   found the defect described in [21](21-acceptance.md#the-security-audit): a
   peer that restarted was never dialled again, so a two-host network could sit
   partitioned until somebody restarted a node by hand.
4. **Backs up the founder while it runs, restores that archive into a fresh
   directory, boots the restored node and compares the block the manifest
   recorded with the restored chain.** A backup you have never restored is a
   hope, not a backup.

If a step fails, the report says which one, and the logs are in
`<dir>/logs`. `--keep` leaves the nodes running so you can poke at them.

### Resetting a test network

```sh
bash scripts/quickstart.sh reset --network devnet --yes            # keep the old chain aside
bash scripts/quickstart.sh reset --network devnet --yes --purge    # delete it
bash scripts/quickstart.sh reset --network mainnet --yes           # refused, always
```

A reset stops the deployment, refuses while anything still holds its ports (a
node that cannot bind its peer port still answers its API from a chain it is not
syncing, so a listener is the only honest evidence), and moves the old directory
to `<dir>.before-reset-<stamp>` instead of deleting it. The next `start` founds
a new chain: new founder wallet, empty account store, and the published founder
invitation working again — at `obs-cli devnet init` *and* at the interface's
registration steps, because a fresh deployment mints it into the registration
service's store.

Mainnet is refused by name. Its directory holds the authority key and the
founder's wallet, and the chain is in every peer's hands: a "reset" there would
destroy the keys and reset nothing.

### Being the wallet that takes the genesis allocation

The 100,000 OBS goes to block 1's claimant, and block 1 is proposed by the wallet
that registers in it. So the founder wallet is the treasury, and no later
registration can take it. To be that wallet, found the chain with words you hold:

```sh
bash scripts/quickstart.sh start --network devnet --phrase-file ~/my-words.txt
```

The phrase is validated (BIP-39), used to derive the founder wallet, and copied
nowhere. Everything else about the deployment is unchanged.

### Proving the invitation path before inviting anybody

```sh
bash scripts/invite-check.sh --network devnet
```

Starts a scratch registration service with its own store, mints the network's
published invitation into it, and walks the gmail → password → invitation steps
exactly as a person would — on loopback, with a throwaway identity, spending
nothing real. It is acceptance check 112, and it is the answer to "the code the
network advertises is refused by the service that is supposed to accept it".

## 2. Deploy the testnet

On the server, as a user that can `sudo`:

```sh
git clone https://github.com/The-Black-Seal/Obsidian-Network.git
cd Obsidian-Network
bash scripts/deploy.sh --network testnet --dir /var/lib/obsidian/testnet
```

That command, in order:

* checks what it can check before it creates anything (network name, ports,
  binaries, the browser-wallet module, `curl`, `tar`, `sha256sum`);
* creates the deployment directory, the founder's password and the keys — all
  `0600`, none of them printed;
* renders the units from `deploy/systemd/` and installs them into
  `/etc/systemd/system`, then `daemon-reload` and `enable --now`;
* when the node answers, registers the founder (block 1 carries the
  registration and the 100,000 OBS genesis allocation) and bonds a validator;
* verifies: the chain is advancing, a validator is bonded, the interface
  answers, and `monitor.sh` says the deployment is healthy.

Useful variations:

```sh
bash scripts/deploy.sh --network testnet --dry-run          # print everything, change nothing
bash scripts/deploy.sh --network testnet --units-out /tmp/u # render the units, install nothing
bash scripts/deploy.sh --network testnet --stage verify     # just check an existing deployment
bash scripts/deploy.sh --network testnet --min-peers 1      # expect at least one peer (default 0 on a test network)
bash scripts/deploy.sh --network testnet --no-mine          # a follower: no blocks, no attestations
```

A test network of one node is legitimate, so `--min-peers` defaults to 0 there
and the monitor will not warn about the silence of a network that was only ever
meant to have one member. Mainnet defaults to 1.

### A second host

The second node must not mine until it has synced, and it must learn the chain's
identity from the operator rather than invent one:

```sh
# on the first host
curl -s http://127.0.0.1:8300/api/v1/status | grep -o '"genesis_timestamp":[0-9]*'

# on the second host: keys and units, but no founding
bash scripts/deploy.sh --network testnet --dir /var/lib/obsidian/testnet \
    --no-mine --no-validator --genesis-timestamp <the epoch you read above> \
    --units-out /tmp/units
# add the peer to the node unit before installing it:
#     --peer <first host>:9300
sudo install -m 644 /tmp/units/obs-node.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now obs-node obs-app obs-monitor.timer
```

The second host then needs its own account — a human registers with an
invitation from the first host's account (`obs-cli invite issue`), and bonds its
own validator with `obs-cli validator register`. A validator's node identity is
never its wallet key; the protocol enforces that.

## 3. Watch it

```sh
bash scripts/monitor.sh --network testnet --node-url http://127.0.0.1:8300 \
    --data-dir /var/lib/obsidian/testnet --alert-cmd 'mail -s obsidian you@example.org'
```

The timer runs it every five minutes. Alerts are sent on a state change and then
at most once every `--remind` seconds (default 30 minutes), so a flapping check
cannot become a mail storm. Exit codes: `0` healthy, `1` warning, `2` critical —
usable directly as a check in whatever you already run.

What it will tell you, and what each one means:

| Finding | Level | What it usually is |
|---------|-------|--------------------|
| `node_down` | critical | the node is not running, or the port is wrong |
| `height_stalled` | critical | the node is up but not advancing: no selected proposer, or a partition |
| `height_went_back` | critical | a restored or replaced chain — stop and look |
| `no_finality` | critical | blocks are produced but not attested: one proposer, no majority |
| `finality_behind` | warning | validators are attesting slowly |
| `supply_exceeded` | critical | issuance crossed the cap — stop and investigate |
| `no_validators` | warning | no bond is active: finality cannot advance |
| `no_peers` | warning | fewer peers than `--min-peers`: cannot tell disagreement from silence |
| `wrong_chain` | critical | the node at that URL is serving a *different* chain from that directory |
| `index_behind` | warning | the Explorer's index is catching up (it reports the distance) |
| `disk_full` / `disk_filling` | critical / warning | 95 % / 85 % used on the deployment's filesystem |
| `clock_skew` | warning | protocol time is far from this host's clock: check NTP |

`wrong_chain` deserves its own sentence. A genesis timestamp *is* the chain's
identity, and the deployment keeps its own genesis record in
`<dir>/node/<network>-genesis`. Every script in the kit compares the two before
it believes a node: a backup taken from a node on a different chain writes a
manifest about a chain the archive does not hold, which is a lie that only
surfaces the day it is restored.

## 4. Back it up, and prove it

```sh
# a consistent snapshot: stop the node, or ask for a live one
sudo systemctl stop obs-node
bash scripts/backup.sh --dir /var/lib/obsidian/testnet
sudo systemctl start obs-node

# or, without stopping anything
bash scripts/backup.sh --dir /var/lib/obsidian/testnet --live

# prove it, monthly and after every upgrade: restore into a scratch directory
bash scripts/restore.sh --archive /var/lib/obsidian/backups/testnet-<stamp>.tar.gz \
    --dir /tmp/restore-check --start 19300
```

The archive holds the chain, the keys and the founder's phrase: that is what
makes it a restore rather than a resync. It is written `0600`. Keep a copy off
the machine — a backup on the same disk as the thing it backs up is a copy, not
a backup.

The `--start` form is the drill: the restored node boots, and the kit asks it for
the block the manifest recorded and compares the hash. If those two hashes agree,
the archive is the chain.

## 5. Mainnet, last

```sh
# on a host that has never held a testnet key, with the invitation in a 0600
# file, and nothing else running:
bash scripts/deploy.sh --network mainnet \
    --invite-file ~/obsidian-mainnet/invite.txt --confirm-mainnet \
    --dir /var/lib/obsidian/mainnet --min-peers 1
```

Mainnet is founded once, by you, with the invitation that is in no file of this
repository. The deploy refuses without `--invite-file` and `--confirm-mainnet`.

After it is up:

* move `founder.phrase.txt` to offline storage (paper or metal) and delete it
  from the host;
* keep `authority.key`, the founder keystore and the invitation file `0600`,
  backed up, and on a host that does not run a public service;
* put TLS in front of the interface ([16](16-networks-and-deployment.md),
  section 5) and open **no** port except 443/80 and the peer port for the other
  validators;
* only then invite people.

## What the kit deliberately does not do

* **It does not install a TLS certificate.** Certificates belong to a domain,
  and the domain belongs to the operator. Caddy needs one config file
  ([16](16-networks-and-deployment.md), section 5); doing it for you would mean
  guessing.
* **It does not touch your firewall.** Two firewalls on Oracle Cloud (security
  list *and* iptables) is a documented trap
  ([16](16-networks-and-deployment.md), section 2) and it stays a manual step
  because nothing here can see your cloud console.
* **It does not rotate secrets.** The authority key and the founder's wallet are
  the network's identity; rotating them is a decision about the network, not a
  maintenance task.
* **It does not prove the network is worth trusting.** That is what
  [23](23-audit-brief.md) is for, and it is not something this project can do for
  itself.

## Where to go next

* [23 — the audit brief and launch readiness checklist](23-audit-brief.md)
* [16 — networks and deployment](16-networks-and-deployment.md), for TLS, the
  cloud firewall and the by-hand commands the deploy wraps
* [17 — operations](17-operations.md), for what the numbers mean on day two
