#!/usr/bin/env bash
#
# Brings a local Obsidian Network up from a checkout — on a phone, in Termux, or
# on any Linux box — and prints what to open in a browser.
#
#   bash scripts/quickstart.sh                          # a devnet: build if needed, start, verify
#   bash scripts/quickstart.sh status                   # what is running now
#   bash scripts/quickstart.sh stop                     # stop the node and the interface
#   bash scripts/quickstart.sh reset --yes              # put the chain aside and found a fresh one
#   bash scripts/quickstart.sh reset --yes --purge      # delete it instead of keeping it
#   bash scripts/quickstart.sh start --phrase-file ~/words.txt   # found it with YOUR wallet
#   bash scripts/quickstart.sh start --network testnet  # any of the four networks
#   bash scripts/quickstart.sh start --dir ~/obsidian-testnet --ui-port 8182
#
# The network decides the ports (see `obs-cli networks`) and the data directory,
# so a devnet, a testnet and a staging node can all run on one machine at once:
#
#   network   node API   peers   interface   service
#   mainnet     8200      9200      8181       8180
#   testnet     8300      9300      8182       8183
#   devnet      7200      9220      8081       8080
#   staging     8400      9400      8184       8185
#
# Mainnet is different in one way that matters: it is founded with the
# operator's own invitation, which is never a default here and is read from a
# file (`--invite-file`), and it is the only network whose founder holds real
# value.  Read the last section of the header before pointing this at mainnet.
#
# A deployment's own configuration — the mark URL, anything else an operator
# would rather not commit — lives in a file outside this checkout, sourced before
# the services start:
#
#   --env-file <path>        default: $HOME/.config/obsidian/env, when it exists
#
# The file is a plain `KEY=value` list, sourced by the shell, so the URL is on the
# machine and never in the repository.
#
# What "up" means, in order, because the order matters:
#
#   1. the binaries (a release build; `--no-build` to require them already)
#   2. a data directory holding the network's authority key, a founder wallet and
#      the password that seals it — all of them development secrets, all of them
#      in files under `--dir`, none of them printed
#   3. the node (`obs-node`), which mines and attests, so the chain advances
#   4. the founder's registration, which only a running node can accept, and
#      which must be in block 1 for the chain to have its genesis allocation
#   5. a validator bond, so the network has the attestations finality needs
#   6. the interface (`obs-app`), which serves the Explorer and the wallet
#
# Everything is idempotent: running it again resumes the devnet it finds instead
# of founding a second one, and a second founder registration is refused by the
# chain anyway (the CLI checks first, so it is quiet about it).
#
# Two ways to be the person who holds the treasury on a chain you found.  The
# genesis allocation goes to the account whose claim is in block 1, and block 1
# is proposed by the wallet that registers in it, so the founder *is* the
# claimant: whatever wallet this script gives the node to mine with is the wallet
# that takes the 100,000 OBS.  By default that wallet is generated here (and its
# phrase is written under `--dir`); with `--phrase-file` it is derived from words
# you already hold, so the treasury is yours and this script never sees a phrase
# it invented.  `reset` puts a chain aside (archived, not deleted, unless you say
# --purge) and refuses to touch mainnet at all.
#
# A test network's published founder invitation is also minted into the
# registration service's store on a *fresh* deployment, so the same code that
# founds the chain with the CLI also works at the interface's registration steps
# — otherwise a person typing the code the network advertises would be told it is
# unknown.  Mainnet's invitation is never minted by this script.
#
# On devnet, testnet and staging nothing here is real money: the authority key,
# the founder's phrase and its password are written to plain files because those
# networks are disposable, and their founder invitations are published constants
# one can read with `obs-cli networks`.  Mainnet does not work that way — its
# invitation is the operator's, its founder wallet is a real account holding the
# treasury, and its phrase file is a secret that belongs on an offline backup, not
# on the machine that mines.  This script refuses to found mainnet without
# `--invite-file`, and says so in the lines it prints.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ACTION="start"
NETWORK="${OBSIDIAN_NETWORK:-devnet}"
BLOCK_INTERVAL_MS=5000
BUILD=1
ASSUME_YES=0
PURGE=0
INVITE_FILE=""
PHRASE_FILE=""
ENV_FILE="${OBSIDIAN_ENV_FILE:-$HOME/.config/obsidian/env}"

# The ports each network listens on, from `obs_primitives::network::Network`.
# Written out rather than read from a built binary: this runs before the build.
case "$NETWORK" in
    mainnet) DEFAULT_API=8200; DEFAULT_PEER=9200; DEFAULT_UI=8181; ADDR_PREFIX=obs1 ;;
    testnet) DEFAULT_API=8300; DEFAULT_PEER=9300; DEFAULT_UI=8182; ADDR_PREFIX=tobs1 ;;
    staging) DEFAULT_API=8400; DEFAULT_PEER=9400; DEFAULT_UI=8184; ADDR_PREFIX=sobs1 ;;
    devnet)  DEFAULT_API=7200; DEFAULT_PEER=9220; DEFAULT_UI=8081; ADDR_PREFIX=dobs1 ;;
    *)
        echo "quickstart: --network $NETWORK is not a network; use devnet, testnet, staging or mainnet" >&2
        exit 2
        ;;
esac
API_PORT="$DEFAULT_API"
PEER_PORT="$DEFAULT_PEER"
UI_PORT="$DEFAULT_UI"
DIR="${OBSIDIAN_NETWORK_DIR:-${OBSIDIAN_DEVNET_DIR:-$HOME/obsidian-$NETWORK}}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        start|stop|status|reset) ACTION="$1" ;;
        --network) NETWORK="${2:?--network needs a name}" ; shift ;;
        --invite-file) INVITE_FILE="${2:?--invite-file needs a path}" ; shift ;;
        --env-file) ENV_FILE="${2:?--env-file needs a path}" ; shift ;;
        --dir) DIR="${2:?--dir needs a path}" ; shift ;;
        --ui-port) UI_PORT="${2:?--ui-port needs a number}" ; shift ;;
        --api-port) API_PORT="${2:?--api-port needs a number}" ; shift ;;
        --peer-port) PEER_PORT="${2:?--peer-port needs a number}" ; shift ;;
        --block-interval-ms) BLOCK_INTERVAL_MS="${2:?--block-interval-ms needs a number}" ; shift ;;
        --phrase-file) PHRASE_FILE="${2:?--phrase-file needs a path}" ; shift ;;
        --no-build) BUILD=0 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --purge) PURGE=1 ;;
        -h|--help)
            sed -n '3,35p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "quickstart: unknown argument $1" >&2
            exit 2
            ;;
    esac
    shift
done

# `--network` may have arrived after the case above, so settle the per-network
# values once more, now that every argument has been read.
case "$NETWORK" in
    mainnet) [[ "$API_PORT" == "$DEFAULT_API" ]] && API_PORT=8200
             [[ "$PEER_PORT" == "$DEFAULT_PEER" ]] && PEER_PORT=9200
             [[ "$UI_PORT" == "$DEFAULT_UI" ]] && UI_PORT=8181
             ADDR_PREFIX=obs1 ;;
    testnet) [[ "$API_PORT" == "$DEFAULT_API" ]] && API_PORT=8300
             [[ "$PEER_PORT" == "$DEFAULT_PEER" ]] && PEER_PORT=9300
             [[ "$UI_PORT" == "$DEFAULT_UI" ]] && UI_PORT=8182
             ADDR_PREFIX=tobs1 ;;
    staging) [[ "$API_PORT" == "$DEFAULT_API" ]] && API_PORT=8400
             [[ "$PEER_PORT" == "$DEFAULT_PEER" ]] && PEER_PORT=9400
             [[ "$UI_PORT" == "$DEFAULT_UI" ]] && UI_PORT=8184
             ADDR_PREFIX=sobs1 ;;
    devnet)  [[ "$API_PORT" == "$DEFAULT_API" ]] && API_PORT=7200
             [[ "$PEER_PORT" == "$DEFAULT_PEER" ]] && PEER_PORT=9220
             [[ "$UI_PORT" == "$DEFAULT_UI" ]] && UI_PORT=8081
             ADDR_PREFIX=dobs1 ;;
esac

DIR="${DIR/#\~/$HOME}"
BIN="$ROOT/target/release"
NODE_URL="http://127.0.0.1:$API_PORT"
UI_URL="http://127.0.0.1:$UI_PORT"
PASSWORD_FILE="$DIR/founder.password.txt"
KEYSTORE="$DIR/founder.keystore.json"
AUTHORITY_KEY="$DIR/authority.key"
NODE_PID="$DIR/node.pid"
APP_PID="$DIR/app.pid"

SELF="bash scripts/quickstart.sh"
# The deployment's own configuration, if the operator keeps one.  Sourced in a
# subshell first so a mistake in the file is reported here rather than half way
# through a start-up; the values are then exported for the processes below.
if [ -f "$ENV_FILE" ]; then
    if ! ( set -a; . "$ENV_FILE" ) >/dev/null 2>&1; then
        echo "quickstart: $ENV_FILE could not be read as a list of KEY=value lines" >&2
        exit 2
    fi
    set -a
    . "$ENV_FILE"
    set +a
fi

say() { printf '%s: %s\n' "$NETWORK" "$1"; }
die() { printf '%s: %s\n' "$NETWORK" "$1" >&2; exit 1; }

# The invitation that founds this network.  A test network has a published,
# disposable one and needs no flag; mainnet's is the operator's and is read from
# a file, never from the command line (a command line is visible to `ps`).
invite_argument() {
    if [ -n "$INVITE_FILE" ]; then
        [ -r "$INVITE_FILE" ] || die "--invite-file $INVITE_FILE is not readable"
        INVITE="$(tr -d '\r\n' < "$INVITE_FILE")"
        [ -n "$INVITE" ] || die "--invite-file $INVITE_FILE is empty"
    fi
}

# The script talks to the node over HTTP to know when it is up, so it needs a
# client.  Saying which one is missing here is friendlier than an empty answer
# from a `curl: command not found` three steps later.
require_curl() {
    command -v curl >/dev/null 2>&1 || die "curl is required to check that the node is up: pkg install curl"
}

# ---------------------------------------------------------------- helpers ----

running() { # running <pid-file>  → the pid, if that process is alive
    [ -f "$1" ] || return 1
    local pid
    pid="$(cat "$1" 2>/dev/null || true)"
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    printf '%s' "$pid"
}

stop_pidfile() { # stop_pidfile <pid-file> <name>
    local pid
    if pid="$(running "$1")"; then
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$pid" 2>/dev/null || true
        say "stopped $2 (pid $pid)"
    else
        say "$2 was not running"
    fi
    rm -f "$1"
}

http_ok() { # http_ok <url>  → the body, or failure
    curl -sf --max-time 5 "$1"
}

wait_for_http() { # wait_for_http <url> <seconds> <what>
    local url="$1" seconds="$2" what="$3"
    local deadline=$((SECONDS + seconds))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if http_ok "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    say "$what did not answer within ${seconds}s"
    return 1
}

# The node's JSON is compact and single-line.  These read the *first* occurrence
# of a key, which is what a top-level field is: `active` also appears inside each
# validator object, so a greedy match would answer with the wrong one.
json_number() { # json_number <json> <key>  → the first number for that key
    printf '%s' "$1" | grep -o "\"$2\":[-0-9]*" | head -n 1 | cut -d: -f2
}

json_string() { # json_string <json> <key>  → the first string for that key
    printf '%s' "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -n 1 | cut -d'"' -f4
}

listening() { # listening <port>  → is anything bound to that port on this host
    # A node that cannot bind its peer port still answers its API from the chain
    # in its data directory, so "the API answered" is not evidence that this
    # deployment is the one running.  A listener on its ports is.
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -q ":$port " && return 0
        ss -ltun 2>/dev/null | grep -q ":$port " && return 0
        return 1
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | grep -q ":$port " && return 0
        return 1
    fi
    # No way to look: say so once rather than pretend the check passed.
    return 2
}

stamp() { date -u +%Y%m%dT%H%M%SZ; }

# The invitation that founds this network as the *service* advertises it: the
# published, disposable code of a test network.  Mainnet has none, by design.
published_invite() {
    "$BIN/obs-cli" networks 2>/dev/null \
        | awk -v n="$NETWORK" '$1 == n && $2 == "disposable" { print $NF; exit }'
}

lan_address() {
    # The address another device on the same network can reach, if there is one.
    # Best effort: Termux does not always have `ip` or `ifconfig`, and a wrong
    # guess is worse than none — a link-local (169.254.x.x) or loopback answer is
    # printed as no answer at all rather than as an address that cannot work.
    local addr=""
    if command -v ip >/dev/null 2>&1; then
        addr="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -n 1)"
    fi
    if [ -z "$addr" ] && command -v ifconfig >/dev/null 2>&1; then
        addr="$(ifconfig 2>/dev/null | sed -n 's/.*inet addr:\([0-9.]*\).*/\1/p' | head -n 1)"
    fi
    case "$addr" in
        "" | 127.* | 169.254.*) return 0 ;;
    esac
    printf '%s' "$addr"
    return 0
}

# --------------------------------------------------------------- actions ----

action_status() {
    require_curl
    say "data directory  $DIR"
    local status
    if status="$(http_ok "$NODE_URL/api/v1/status")"; then
        say "node            running on $NODE_URL"
        say "  height        $(json_number "$status" height)"
        say "  peers         $(json_number "$status" peers)"
        say "  protocol time $(json_number "$status" protocol_time)"
        say "  supply        $(json_string "$status" issued_supply)"
        say "  validators    active $(json_number "$status" active_validators)"
        local validators
        if validators="$(http_ok "$NODE_URL/api/v1/validators")"; then
            say "  proposals     $(json_number "$validators" blocks_proposed) blocks, $(json_number "$validators" attestations) attestations"
        fi
    else
        say "node            not answering on $NODE_URL"
    fi
    if http_ok "$UI_URL/" >/dev/null 2>&1; then
        say "interface       running on $UI_URL"
    else
        say "interface       not answering on $UI_URL"
    fi
}

action_stop() {
    stop_pidfile "$APP_PID" "the interface"
    stop_pidfile "$NODE_PID" "the node"
    say "data is kept in $DIR; start again with: $SELF start --network $NETWORK"
}

action_reset() {
    # Mainnet is refused outright, and not because of the flag: a mainnet
    # deployment's directory holds the authority key, the founder's wallet and
    # the treasury's password.  "Reset the chain" on mainnet is not a maintenance
    # action, it is the loss of the network's identities — and the chain itself
    # lives on in every peer, so a fresh directory would not even reset anything.
    if [ "$NETWORK" = mainnet ]; then
        printf 'quickstart: refusing to reset mainnet.\n' >&2
        printf 'quickstart: %s holds the network authority key, the founder wallet and the password\n' "$DIR" >&2
        printf 'quickstart: that seals them; a fresh directory would not reset the chain, it would destroy\n' >&2
        printf 'quickstart: the keys.  If you meant to start a new chain, do it on another network.\n' >&2
        exit 2
    fi
    if [ ! -e "$DIR" ]; then
        say "there is nothing at $DIR; the next start founds a new chain"
        return 0
    fi
    if [ "$ASSUME_YES" != 1 ]; then
        if [ "$PURGE" = 1 ]; then
            printf 'quickstart: this DELETES %s (chain, keys, password) and everything in it.\n' "$DIR" >&2
        else
            printf 'quickstart: this stops the %s in %s and moves the directory aside\n' "$NETWORK" "$DIR" >&2
            printf 'quickstart: (chain, keys, password are kept in %s.before-reset-<stamp>).\n' "$DIR" >&2
        fi
        printf 'quickstart: the next start founds a NEW chain with a new founder wallet.  Re-run with --yes.\n' >&2
        exit 2
    fi

    # Stopped by hand rather than through `action_stop`, whose message about
    # keeping the data would be a lie one line before moving it.
    stop_pidfile "$APP_PID" "the interface"
    stop_pidfile "$NODE_PID" "the node"

    # A process still holding these ports is still writing the files this is
    # about to move or delete — very often a node started by hand from the same
    # directory, whose pidfile this script therefore does not know.  Refuse
    # rather than produce a half-reset deployment.
    local port check
    for port in "$API_PORT" "$PEER_PORT" "$UI_PORT"; do
        check=0
        listening "$port" || check=$?
        case "$check" in
            0)
                die "port $port is still listening: stop that process first (reset would move files something is still writing)"
                ;;
            2)
                say "note: no ss or netstat here, so "nothing is still running on this deployment" was not checked"
                break
                ;;
        esac
    done

    if [ "$PURGE" = 1 ]; then
        rm -rf "$DIR"
        say "deleted $DIR (--purge)"
    else
        local aside="$DIR.before-reset-$(stamp)"
        mv "$DIR" "$aside"
        say "moved the old chain aside to $aside"
        say "  its keys and its founder phrase are still there; delete it when you are sure"
    fi
    say "the next start founds a new chain with a new founder wallet:"
    say "    $SELF start --network $NETWORK${PHRASE_FILE:+ --phrase-file $PHRASE_FILE}"
    if [ "$NETWORK" != mainnet ]; then
        local published
        published="$("$BIN/obs-cli" networks 2>/dev/null | awk -v n="$NETWORK" '$1 == n && $2 == "disposable" { print $NF; exit }')"
        if [ -n "$published" ]; then
            say "  the founder invitation: $(printf '%s' "$published" | sed 's/....$/****/') (printed in full by \`obs-cli networks\`)"
        fi
    fi
    say "  to found it with a wallet you already hold, add:  --phrase-file <your 24 words>"
}

action_start() {
    require_curl
    invite_argument

    # Mainnet is founded by its operator, with an invitation that is not in this
    # checkout.  Refusing here — before a keystore exists, before a chain exists —
    # is the only moment at which a slip is still free.
    if [ "$NETWORK" = mainnet ] && [ -z "${INVITE:-}" ]; then
        cat >&2 <<'EOF'
mainnet: refusing to found mainnet without --invite-file.
    Mainnet's first invitation authorises the genesis allocation of 100,000 OBS on
    the network that carries real value.  It is held by the operator, minted into
    the registration service's own store with

        obs-cli invite mint --genesis --store <store.json>

    and written on no page, in no log and in no file of this checkout.  Put it in
    a 0600 file and pass the path:   --invite-file ~/obsidian-mainnet/invite.txt
    A test network needs no flag: its disposable invitation is published in
    `obs-cli networks` on purpose.
EOF
        exit 2
    fi

    # --- 1. the binaries ---------------------------------------------------
    if [ ! -x "$BIN/obs-node" ] || [ ! -x "$BIN/obs-app" ] || [ ! -x "$BIN/obs-cli" ]; then
        if [ "$BUILD" != 1 ]; then
            die "target/release is missing the binaries; run without --no-build"
        fi
        if ! command -v cargo >/dev/null 2>&1; then
            cat >&2 <<'EOF'
devnet: cargo is not installed.
    Termux:  pkg install rust git
    Debian:  sudo apt install rustc cargo
Rust 1.88 or newer is needed.  There are no third-party crates, so the build
needs no network: it compiles exactly the Rust in this checkout.
EOF
            exit 1
        fi
        say "building the workspace in release mode (this is the slow part: minutes on a phone)"
        cargo build --workspace --release
    fi

    # --- 2. the devnet's keys ---------------------------------------------
    mkdir -p "$DIR"
    if [ ! -f "$PASSWORD_FILE" ]; then
        # A password for the founder's keystore, generated here and stored
        # `0600`: the node reads it to unlock the wallet it mines with, and it
        # opens the same wallet from the command line.
        (umask 077 && head -c 32 /dev/urandom | sha256sum | cut -c1-48 > "$PASSWORD_FILE")
        say "generated a founder password at $PASSWORD_FILE"
    fi
    chmod 600 "$PASSWORD_FILE" 2>/dev/null || true

    if [ ! -f "$KEYSTORE" ] || [ ! -f "$AUTHORITY_KEY" ]; then
        if [ -n "${PHRASE_FILE:-}" ]; then
            [ -r "$PHRASE_FILE" ] || die "--phrase-file $PHRASE_FILE is not readable"
            say "founding the network with the wallet your phrase describes (the treasury will be yours)"
        else
            say "founding the network (authority key, founder wallet, invitation authorisation)"
        fi
        # The command comes first: `obs-cli` reads argv[0] as the command, so a
        # global flag in front of it is an unknown command, not an option.
        local founding=()
        # Mainnet: the operator's own invitation, read from a file.  A test
        # network: no flag, and the CLI uses the published disposable code.
        if [ -n "${INVITE:-}" ]; then
            founding+=(--invite "$INVITE")
        fi
        # An operator who brought their own words holds the founder wallet, and
        # therefore the account that block 1's genesis claim pays.
        if [ -n "${PHRASE_FILE:-}" ]; then
            founding+=(--phrase-file "$PHRASE_FILE")
        fi
        "$BIN/obs-cli" devnet init --network "$NETWORK" \
            --data-dir "$DIR" --password-file "$PASSWORD_FILE" "${founding[@]}"
    fi
    # The node needs the authority's *public* key as hex; the CLI reads it out of
    # the key file, so the private half never has to be handled here.
    local authority
    authority="$("$BIN/obs-cli" authority print --network "$NETWORK" --authority-key "$AUTHORITY_KEY")"
    [ -n "$authority" ] || die "could not read the authority public key from $AUTHORITY_KEY"

    # --- 3. the node -------------------------------------------------------
    if running "$NODE_PID" >/dev/null; then
        say "the node is already running (pid $(running "$NODE_PID"))"
    else
        say "starting the node (mining and attesting; protocol time advances through blocks)"
        # `--genesis-timestamp now` only applies to a directory with no chain:
        # the genesis record a data directory already holds wins, so this is
        # safe to run against a devnet that is being resumed.
        nohup "$BIN/obs-node" --network "$NETWORK" --data-dir "$DIR/node" \
            --api-port "$API_PORT" --listen-port "$PEER_PORT" \
            --genesis-timestamp now --authority-key "$authority" \
            --keystore "$KEYSTORE" --keystore-password-file "$PASSWORD_FILE" \
            --mine --validator --fsync --block-interval-ms "$BLOCK_INTERVAL_MS" \
            >"$DIR/node.log" 2>&1 &
        printf '%s' "$!" > "$NODE_PID"
        if ! wait_for_http "$NODE_URL/api/v1/status" 60 "the node"; then
            tail -n 20 "$DIR/node.log" >&2 || true
            die "the node did not start; its log is $DIR/node.log"
        fi
        say "node up on $NODE_URL (peer port $PEER_PORT, log $DIR/node.log)"
    fi

    # --- 4. the founder's registration ------------------------------------
    # Idempotent: the CLI asks the chain whether the account exists first, and
    # the chain refuses a second registration for one Gmail identity anyway.
    local registration
    local register_invite=()
    # `set -e` is on: a bare `test && assignment` returns non-zero when the test
    # is false and would end the script here.
    if [ -n "${INVITE:-}" ]; then
        register_invite=(--invite "$INVITE")
    fi
    registration="$("$BIN/obs-cli" devnet register --network "$NETWORK" --node-url "$NODE_URL" \
        --data-dir "$DIR" --password-file "$PASSWORD_FILE" "${register_invite[@]}" 2>&1)"
    if printf '%s' "$registration" | grep -q "already on chain"; then
        say "the founder is already registered on this chain"
    else
        say "founder registered; block 1 carries the registration and the 100,000 OBS genesis allocation"
    fi

    # --- 5. the validator bond --------------------------------------------
    local active
    active="$(json_number "$(http_ok "$NODE_URL/api/v1/status")" active_validators)"
    if [ "${active:-0}" = "0" ]; then
        say "bonding 50 OBS and registering the validator node identity"
        "$BIN/obs-cli" validator register --network "$NETWORK" --node-url "$NODE_URL" \
            --keystore "$KEYSTORE" --password-file "$PASSWORD_FILE" \
            --endpoint "http://127.0.0.1:$PEER_PORT" >/dev/null
    fi

    # --- 5b. the invitation the interface's registration steps accept -------
    # `devnet init` used the published code to found the chain, which is one
    # door; a person typing that code at the interface is at another, and the
    # registration service only knows the invitations in its own store.  Minting
    # it once, on a fresh store, is what makes the code the network advertises
    # actually work everywhere it is advertised.  Mainnet is excluded: its
    # invitation is the operator's, minted deliberately with `invite mint`.
    if [ "$NETWORK" != mainnet ] && [ ! -f "$DIR/accounts.json" ]; then
        local published
        published="$(published_invite)"
        if [ -n "$published" ]; then
            say "minting the published founder invitation into the registration service's store"
            "$BIN/obs-cli" invite mint --network "$NETWORK" --store "$DIR/accounts.json" \
                --code "$published" --genesis >/dev/null
            say "  a person can now register through the interface with the code \`obs-cli networks\` prints"
        fi
    fi

    # --- 6. the interface --------------------------------------------------
    if running "$APP_PID" >/dev/null; then
        say "the interface is already running (pid $(running "$APP_PID"))"
    else
        say "starting the interface (Explorer, wallet, developer portal)"
        nohup "$BIN/obs-app" --network "$NETWORK" --port "$UI_PORT" --node-url "$NODE_URL" \
            --static-dir "$ROOT/web" \
            --accounts --accounts-store "$DIR/accounts.json" \
            --store "$DIR/index.json" --authority-key "$AUTHORITY_KEY" \
            --sync-ms 2000 \
            >"$DIR/app.log" 2>&1 &
        printf '%s' "$!" > "$APP_PID"
        if ! wait_for_http "$UI_URL/" 30 "the interface"; then
            tail -n 20 "$DIR/app.log" >&2 || true
            die "the interface did not start; its log is $DIR/app.log"
        fi
    fi

    # --- what to do next ---------------------------------------------------
    local status height lan founder
    status="$(http_ok "$NODE_URL/api/v1/status")"
    height="$(json_number "$status" height)"
    lan="$(lan_address)"
    founder="$("$BIN/obs-cli" wallet address --network "$NETWORK" \
        --keystore "$KEYSTORE" --password-file "$PASSWORD_FILE" 2>/dev/null \
        | grep -o "$ADDR_PREFIX[a-z0-9]*" | head -n 1 || true)"

    echo
    say "the $NETWORK is live."
    say "  open            $UI_URL"
    if [ -n "$lan" ]; then
        say "  from another device on the same network:  http://$lan:$UI_PORT"
    fi
    say "  node API        $NODE_URL/api/v1/status"
    say "  height          ${height:-?} and climbing; blocks every ${BLOCK_INTERVAL_MS}ms of protocol time"
    say "  founder wallet  ${founder:-see $KEYSTORE}"
    say "  data            $DIR   (chain, keys, logs; node.log and app.log)"
    echo
    say "  stop it         $SELF stop --network $NETWORK"
    say "  its state       $SELF status --network $NETWORK"
    say "  a fresh chain   $SELF reset --network $NETWORK --yes"
    echo
    # The two commands this script ran, so they can be run by hand, wrapped in a
    # service unit, or handed to a supervisor: the flags are the deployment.
    say "  the node process:"
    say "    $BIN/obs-node --network $NETWORK --data-dir $DIR/node \\"
    say "        --api-port $API_PORT --listen-port $PEER_PORT --genesis-timestamp now \\"
    say "        --authority-key $AUTHORITY_KEY --keystore $KEYSTORE \\"
    say "        --keystore-password-file $PASSWORD_FILE --mine --validator --fsync"
    say "  the interface process:"
    say "    $BIN/obs-app --network $NETWORK --port $UI_PORT --node-url $NODE_URL \\"
    say "        --static-dir $ROOT/web --accounts --accounts-store $DIR/accounts.json \\"
    say "        --store $DIR/index.json --authority-key $AUTHORITY_KEY"
    echo
    if [ -f "$ENV_FILE" ]; then
        say "  deployment config $ENV_FILE (sourced; not part of the checkout)"
    fi
    say "  claim mining rewards with the founder wallet:"
    say "    $BIN/obs-cli claim --node-url $NODE_URL \\"
    say "        --keystore $KEYSTORE --password-file $PASSWORD_FILE"
    say "  read the chain from the command line:"
    say "    $BIN/obs-cli status --node-url $NODE_URL"
    if [ -n "${PREFIX:-}" ] && [ "${PREFIX#/data/data/com.termux}" != "$PREFIX" ]; then
        echo
        say "  Termux: keep it alive while you test with   termux-wake-lock"
        say "          (and run  termux-wake-unlock  when you are done)"
    fi
    if [ "$NETWORK" = mainnet ]; then
        say "  mainnet: the founder wallet holds real value.  Move"
        say "  $DIR/founder.phrase.txt to an offline backup, delete the copy here,"
        say "  and keep $KEYSTORE and $PASSWORD_FILE readable only by this account."
    else
        say "  a test network's authority key, founder phrase and password are"
        say "  development secrets on plain files — never reuse any of them on mainnet."
    fi
}

case "$ACTION" in
    start) action_start ;;
    stop) action_stop ;;
    status) action_status ;;
    reset) action_reset ;;
esac
