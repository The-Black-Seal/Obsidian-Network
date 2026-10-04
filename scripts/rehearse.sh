#!/usr/bin/env bash
#
# A rehearsal of the things that actually break a network, run on one machine:
#
#   1. a network is founded and produces blocks
#   2. two nodes join it and agree on the same head, block for block
#   3. the node that founded it dies and comes back, and catches up
#   4. a live backup is taken, restored into a fresh directory, and the restored
#      chain is proved to hold the same block at the same height
#
#   bash scripts/rehearse.sh                      # devnet ports +17000, throwaway dirs
#   bash scripts/rehearse.sh --base-port 27000 --interval 500
#   bash scripts/rehearse.sh --keep               # leave the nodes running to look at
#
# It refuses to use a port range that a network already owns, so it can be run
# on a machine that is already serving a testnet.  Exit status is 0 only when
# every step passed; the report it writes names the step that failed, the log
# that shows it and the command that reproduces it.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

OBS_TAG=rehearse

NETWORK="devnet"
DIR="${TMPDIR:-/tmp}/obsidian-rehearsal"
BASE_PORT=17000
INTERVAL=500
KEEP=0
TIMEOUT=90

while [ $# -gt 0 ]; do
    case "$1" in
        --network) NETWORK="${2:?}"; shift ;;
        --dir) DIR="${2:?}"; shift ;;
        --base-port) BASE_PORT="${2:?}"; shift ;;
        --interval) INTERVAL="${2:?}"; shift ;;
        --timeout) TIMEOUT="${2:?}"; shift ;;
        --keep) KEEP=1 ;;
        -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done

# The four networks own 7200-9400 and 8080-8185.  A rehearsal that took one of
# those ports would either fail to bind or, worse on a machine serving a real
# network, interfere with it.
for reserved in $(seq 7200 9400) $(seq 8080 8185); do
    for used in $(seq "$BASE_PORT" $((BASE_PORT + 9))); do
        [ "$used" = "$reserved" ] && die "--base-port $BASE_PORT would collide with port $reserved, which a network owns"
    done
done

FOUNDER="$DIR/founder"
RESTORED="$DIR/restored"
LOGS="$DIR/logs"
REPORT="$DIR/REPORT.txt"
PORTS=()
for i in $(seq 0 9); do PORTS+=("$((BASE_PORT + i))"); done

PASS=0
FAIL=0
STEPS=()
step() { # step <name> <ok|fail> <detail>
    STEPS+=("$2|$1|$3")
    if [ "$2" = ok ]; then PASS=$((PASS + 1)); say "  $1: ok — $3"
    else FAIL=$((FAIL + 1)); warn "  $1: FAILED — $3"; fi
}

stop_all() {
    # Every node the rehearsal starts writes its pid next to its data directory;
    # the globs must match exactly that, or a finished rehearsal leaves nodes
    # behind holding the ports for the next one (which is how this line came to
    # be written with follower-*/node.pid rather than follower-*.pid).
    for pidfile in "$FOUNDER/node.pid" "$DIR"/follower-*/node.pid "$RESTORED/node.pid"; do
        [ -f "$pidfile" ] || continue
        local pid; pid="$(cat "$pidfile" 2>/dev/null || true)"
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
        rm -f "$pidfile"
    done
}

cleanup() {
    if [ "$KEEP" != 1 ]; then stop_all; fi
}
trap cleanup EXIT

say "rehearsal: $NETWORK on ports $BASE_PORT-$((BASE_PORT + 9)), in $DIR"

# Ports first, because a rehearsal that half-starts is worse than one that
# refuses: a node that cannot bind its peer port still answers its API from a
# chain it is not syncing, and every later check then lies about what it saw.
busy=""
for port in "${PORTS[@]}"; do
    if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | awk '{ print $4 }' | grep -q "[:.]$port\$"; then
        busy="$busy $port"
    fi
done
if [ -n "$busy" ]; then
    warn "these ports are already listening:$busy"
    warn "another rehearsal or a deployment is using them.  Stop it first, or pick"
    warn "another range:  bash scripts/rehearse.sh --base-port $((BASE_PORT + 100))"
    warn "a rehearsal that leaves nodes behind:  pkill -f 'obs-node .*data-dir $DIR'"
    exit 2
fi

# A previous rehearsal that was interrupted can still be running even when its
# ports were free a moment ago; stop what this directory remembers before
# deleting it, so a re-run never inherits half a network.
if [ -d "$DIR" ]; then
    for pidfile in "$DIR"/*.pid "$DIR"/node.pid; do
        [ -f "$pidfile" ] || continue
        kill "$(cat "$pidfile" 2>/dev/null || true)" 2>/dev/null || true
    done
fi
rm -rf "$DIR"
mkdir -p "$FOUNDER" "$LOGS"
if [ ! -x "$OBS_BIN/obs-node" ] || [ ! -x "$OBS_BIN/obs-cli" ]; then
    die "$OBS_BIN is missing the binaries; run: cargo build --workspace --release"
fi

# ---------------------------------------------------------------------------
# 1. found a network
# ---------------------------------------------------------------------------
say "1. founding a network"
AUTHORITY=""
# `devnet init` seals the founder's wallet with this password, so it has to exist
# first — the same order the quickstart uses, and the same reason: a missing
# password file must not be discovered by a half-initialised directory.
( umask 077 && random_password > "$FOUNDER/founder.password.txt" )
chmod 600 "$FOUNDER/founder.password.txt"
if ! "$OBS_BIN/obs-cli" devnet init --network "$NETWORK" --data-dir "$FOUNDER" \
        --password-file "$FOUNDER/founder.password.txt" >"$LOGS/init.log" 2>&1; then
    step "founding" fail "obs-cli devnet init failed; see $LOGS/init.log"
    cat "$LOGS/init.log" >&2
    exit 1
fi
AUTHORITY="$("$OBS_BIN/obs-cli" authority print --network "$NETWORK" --authority-key "$FOUNDER/authority.key" 2>/dev/null || true)"
if [ -z "$AUTHORITY" ]; then
    step "founding" fail "the authority public key could not be read"
    exit 1
fi
step "founding" ok "authority key, founder wallet and invitation authorisation written to $FOUNDER"

start_node() { # start_node <name> <dir> <api> <peer> <extra flags...>
    local name="$1" dir="$2" api="$3" peer="$4"; shift 4
    mkdir -p "$dir"
    nohup "$OBS_BIN/obs-node" --network "$NETWORK" --data-dir "$dir/node" --bind 127.0.0.1 \
        --api-port "$api" --listen-port "$peer" --fsync --authority-key "$AUTHORITY" "$@" \
        >"$LOGS/$name.log" 2>&1 &
    printf '%s' "$!" > "$dir/node.pid"
    # A node that refuses to start (a taken port, a locked data directory) must
    # be reported as that, not as a chain that never converged: the two demand
    # completely different responses from whoever reads the report.
    sleep 1
    if grep -q "could not start" "$LOGS/$name.log" 2>/dev/null; then
        warn "$name did not start: $(grep -m1 'could not start' "$LOGS/$name.log")"
        return 1
    fi
    return 0
}

founder_api="${PORTS[0]}"; founder_peer="${PORTS[1]}"
start_node founder "$FOUNDER" "$founder_api" "$founder_peer" \
    --genesis-timestamp now --mine --validator \
    --keystore "$FOUNDER/founder.keystore.json" \
    --keystore-password-file "$FOUNDER/founder.password.txt" \
    --block-interval-ms "$INTERVAL"
founder_url="http://127.0.0.1:$founder_api"

if ! wait_for_http "$founder_url/api/v1/status" 30 "the founder node"; then
    step "the founder produces blocks" fail "the node did not answer; see $LOGS/founder.log"
    exit 1
fi
"$OBS_BIN/obs-cli" devnet register --network "$NETWORK" --node-url "$founder_url" \
    --data-dir "$FOUNDER" --password-file "$FOUNDER/founder.password.txt" >>"$LOGS/init.log" 2>&1 || true
"$OBS_BIN/obs-cli" validator register --network "$NETWORK" --node-url "$founder_url" \
    --keystore "$FOUNDER/founder.keystore.json" --password-file "$FOUNDER/founder.password.txt" \
    --endpoint "http://127.0.0.1:$founder_peer" >>"$LOGS/init.log" 2>&1 || true

if wait_for_height "$founder_url" 8 "$TIMEOUT"; then
    step "the founder produces blocks" ok "height reached $(json_number "$(http_ok "$founder_url/api/v1/status")" height)"
else
    step "the founder produces blocks" fail "height did not reach 8 in ${TIMEOUT}s; see $LOGS/founder.log"
fi

genesis_epoch="$(json_number "$(http_ok "$founder_url/api/v1/status")" genesis_timestamp)"
# ---------------------------------------------------------------------------
# 2. two nodes join and agree
# ---------------------------------------------------------------------------
say "2. joining the network from two more nodes"
follower_apis=()
for index in 1 2; do
    api="${PORTS[$((index * 2))]}"
    peer="${PORTS[$((index * 2 + 1))]}"
    follower_dir="$DIR/follower-$index"
    if ! start_node "follower-$index" "$follower_dir" "$api" "$peer" \
            --genesis-timestamp "$genesis_epoch" --peer "127.0.0.1:$founder_peer"; then
        step "three nodes agree on one head" fail "follower $index did not start; see $LOGS/follower-$index.log"
        exit 1
    fi
    follower_apis+=("http://127.0.0.1:$api")
done

all_urls=("$founder_url" "${follower_apis[@]}")

# What each node says right now, for the report: "they did not converge" is a
# useless thing to be told without the heights that say who is behind.
describe_nodes() {
    local url status height head peers
    for url in "${all_urls[@]}"; do
        status="$(http_ok "$url/api/v1/status" 2>/dev/null || true)"
        if [ -z "$status" ]; then
            say "    $url  (no answer)"
            continue
        fi
        height="$(json_number "$status" height)"
        head="$(json_string "$status" head)"
        peers="$(json_number "$status" peers)"
        say "    $url  height $height  head ${head:0:12}…  peers $peers"
    done
}
if wait_for_http "${follower_apis[0]}/api/v1/status" 20 "follower 1" && \
   wait_for_http "${follower_apis[1]}/api/v1/status" 20 "follower 2"; then
    if wait_for_agreement "$TIMEOUT" "${all_urls[@]}"; then
        head="$(json_string "$(http_ok "$founder_url/api/v1/status")" head)"
        step "three nodes agree on one head" ok "all three report ${head:0:16}… at height $(json_number "$(http_ok "$founder_url/api/v1/status")" height)"
    else
        step "three nodes agree on one head" fail "they did not converge in ${TIMEOUT}s; see $LOGS/*.log"
        describe_nodes
    fi
else
    step "three nodes agree on one head" fail "a follower did not start; see $LOGS/follower-*.log"
fi

# ---------------------------------------------------------------------------
# 3. the founder dies and comes back
# ---------------------------------------------------------------------------
say "3. killing the founder and bringing it back"
height_before="$(json_number "$(http_ok "$founder_url/api/v1/status" || true)" height)"
founder_pid="$(cat "$FOUNDER/node.pid" 2>/dev/null || true)"
if [ -n "$founder_pid" ]; then
    kill "$founder_pid" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$founder_pid" 2>/dev/null || break; sleep 0.5; done
    rm -f "$FOUNDER/node.pid"
fi
if kill -0 "$founder_pid" 2>/dev/null; then
    step "the founder restarts and catches up" fail "the founder would not stop"
else
    sleep 2
    start_node founder "$FOUNDER" "$founder_api" "$founder_peer" \
        --genesis-timestamp "$genesis_epoch" --mine --validator \
        --keystore "$FOUNDER/founder.keystore.json" \
        --keystore-password-file "$FOUNDER/founder.password.txt" \
        --block-interval-ms "$INTERVAL"
    if ! wait_for_http "$founder_url/api/v1/status" 30 "the restarted founder"; then
        step "the founder restarts and catches up" fail "the restarted node did not answer on $founder_url; see $LOGS/founder.log"
    elif ! wait_for_height "$founder_url" "$((height_before + 3))" "$TIMEOUT"; then
        step "the founder restarts and catches up" fail "the restarted node stopped answering, or stayed below height $((height_before + 3)) for ${TIMEOUT}s"
    elif ! wait_for_agreement "$TIMEOUT" "${all_urls[@]}"; then
        step "the founder restarts and catches up" fail "the nodes did not agree again within ${TIMEOUT}s"
        describe_nodes
    else
        step "the founder restarts and catches up" ok "it stopped at height $height_before and is at $(json_number "$(http_ok "$founder_url/api/v1/status")" height) with the others"
    fi
fi

# ---------------------------------------------------------------------------
# 4. a live backup, restored and proved
# ---------------------------------------------------------------------------
say "4. backing up the founder while it runs, and restoring it"
archive="$DIR/backup.tar.gz"
if bash "$OBS_ROOT/scripts/backup.sh" --network "$NETWORK" --dir "$FOUNDER" --live \
        --node-url "$founder_url" --out "$archive" --keep 0 >"$LOGS/backup.log" 2>&1; then
    step "a live backup is taken" ok "$(grep -o 'MANIFEST\|files' "$LOGS/backup.log" >/dev/null && echo "$archive")"
else
    step "a live backup is taken" fail "backup.sh refused or failed; see $LOGS/backup.log"
fi

if [ -f "$archive" ]; then
    if bash "$OBS_ROOT/scripts/restore.sh" --archive "$archive" --dir "$RESTORED" \
            --start "${PORTS[8]}" --listen "${PORTS[9]}" >"$LOGS/restore.log" 2>&1; then
        line="$(grep -o 'restore drill: PASS.*' "$LOGS/restore.log" | head -1)"
        step "the restored chain matches the backup" ok "${line:-restored and verified}"
    else
        step "the restored chain matches the backup" fail "the drill failed; see $LOGS/restore.log"
    fi
fi

# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
{
    printf 'obsidian rehearsal report\n'
    printf 'when %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'network %s   ports %s-%s   interval %sms\n' "$NETWORK" "$BASE_PORT" "$((BASE_PORT + 9))" "$INTERVAL"
    printf 'passed %s   failed %s\n' "$PASS" "$FAIL"
    for entry in "${STEPS[@]}"; do
        printf '%s  %s  %s\n' "${entry%%|*}" "$(printf '%s' "$entry" | cut -d'|' -f2)" "$(printf '%s' "$entry" | cut -d'|' -f3)"
    done
} > "$REPORT"

echo
say "passed $PASS, failed $FAIL; report at $REPORT"
if [ "$FAIL" -gt 0 ]; then
    say "logs: $LOGS"
    exit 1
fi
if [ "$KEEP" = 1 ]; then
    say "the nodes are still running (--keep): ports $BASE_PORT-$((BASE_PORT + 9)), logs in $LOGS"
else
    say "all nodes stopped; the directories are in $DIR"
fi
exit 0
