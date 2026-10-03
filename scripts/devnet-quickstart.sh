#!/usr/bin/env bash
#
# Brings a local Obsidian Network devnet up from a checkout — on a phone, in
# Termux, or on any Linux box — and prints what to open in a browser.
#
#   bash scripts/devnet-quickstart.sh                 # build if needed, start, verify
#   bash scripts/devnet-quickstart.sh status          # what is running now
#   bash scripts/devnet-quickstart.sh stop            # stop the node and the interface
#   bash scripts/devnet-quickstart.sh start --dir ~/obsidian-devnet --ui-port 8081
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
# Nothing here is real money and nothing here is a mainnet procedure: the
# authority key, the founder's phrase and its password are written to plain files
# because a devnet is disposable.  A mainnet deployment registers a real person
# through the registration service with a real invitation, and keeps every key on
# a `0600` file it owns.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ACTION="start"
DIR="${OBSIDIAN_DEVNET_DIR:-$HOME/obsidian-devnet}"
UI_PORT=8081
API_PORT=7200
PEER_PORT=9220
BLOCK_INTERVAL_MS=5000
BUILD=1
ASSUME_YES=0
NETWORK=devnet

while [ "$#" -gt 0 ]; do
    case "$1" in
        start|stop|status|reset) ACTION="$1" ;;
        --dir) DIR="${2:?--dir needs a path}" ; shift ;;
        --ui-port) UI_PORT="${2:?--ui-port needs a number}" ; shift ;;
        --api-port) API_PORT="${2:?--api-port needs a number}" ; shift ;;
        --peer-port) PEER_PORT="${2:?--peer-port needs a number}" ; shift ;;
        --block-interval-ms) BLOCK_INTERVAL_MS="${2:?--block-interval-ms needs a number}" ; shift ;;
        --no-build) BUILD=0 ;;
        --yes|-y) ASSUME_YES=1 ;;
        -h|--help)
            sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "devnet-quickstart: unknown argument $1" >&2
            exit 2
            ;;
    esac
    shift
done

DIR="${DIR/#\~/$HOME}"
BIN="$ROOT/target/release"
NODE_URL="http://127.0.0.1:$API_PORT"
UI_URL="http://127.0.0.1:$UI_PORT"
PASSWORD_FILE="$DIR/founder.password.txt"
KEYSTORE="$DIR/founder.keystore.json"
AUTHORITY_KEY="$DIR/authority.key"
NODE_PID="$DIR/node.pid"
APP_PID="$DIR/app.pid"

say() { printf 'devnet: %s\n' "$1"; }
die() { printf 'devnet: %s\n' "$1" >&2; exit 1; }

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
    say "data is kept in $DIR; start again with: bash scripts/devnet-quickstart.sh start"
}

action_reset() {
    if [ "$ASSUME_YES" != 1 ]; then
        printf 'devnet: this deletes the devnet in %s (chain, keys, password).  Re-run with --yes.\n' "$DIR" >&2
        exit 2
    fi
    # Stopped by hand rather than through `action_stop`, whose message about
    # keeping the data would be a lie one line before deleting it.
    stop_pidfile "$APP_PID" "the interface"
    stop_pidfile "$NODE_PID" "the node"
    rm -rf "$DIR"
    say "deleted $DIR; the next start founds a new chain"
}

action_start() {
    require_curl
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
        say "founding the devnet (authority key, founder wallet, invitation authorisation)"
        # The command comes first: `obs-cli` reads argv[0] as the command, so a
        # global flag in front of it is an unknown command, not an option.
        "$BIN/obs-cli" devnet init --network "$NETWORK" \
            --data-dir "$DIR" --password-file "$PASSWORD_FILE"
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
    registration="$("$BIN/obs-cli" devnet register --network "$NETWORK" --node-url "$NODE_URL" \
        --data-dir "$DIR" --password-file "$PASSWORD_FILE" 2>&1)"
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
        | grep -o 'dobs1[a-z0-9]*' | head -n 1 || true)"

    echo
    say "the devnet is live."
    say "  open            $UI_URL"
    if [ -n "$lan" ]; then
        say "  from another device on the same network:  http://$lan:$UI_PORT"
    fi
    say "  node API        $NODE_URL/api/v1/status"
    say "  height          ${height:-?} and climbing; blocks every ${BLOCK_INTERVAL_MS}ms of protocol time"
    say "  founder wallet  ${founder:-see $KEYSTORE}"
    say "  data            $DIR   (chain, keys, logs; node.log and app.log)"
    echo
    say "  stop it         bash scripts/devnet-quickstart.sh stop"
    say "  its state       bash scripts/devnet-quickstart.sh status"
    say "  a fresh chain   bash scripts/devnet-quickstart.sh reset --yes"
    echo
    say "  claim mining rewards with the founder wallet:"
    say "    ./target/release/obs-cli claim --node-url $NODE_URL \\"
    say "        --keystore $KEYSTORE --password-file $PASSWORD_FILE"
    say "  read the chain from the command line:"
    say "    ./target/release/obs-cli status --node-url $NODE_URL"
    if [ -n "${PREFIX:-}" ] && [ "${PREFIX#/data/data/com.termux}" != "$PREFIX" ]; then
        echo
        say "  Termux: keep it alive while you test with   termux-wake-lock"
        say "          (and run  termux-wake-unlock  when you are done)"
    fi
    say "  a devnet's authority key, founder phrase and password are development"
    say "  secrets on plain files — never reuse any of them on a real network."
}

case "$ACTION" in
    start) action_start ;;
    stop) action_stop ;;
    status) action_status ;;
    reset) action_reset ;;
esac
