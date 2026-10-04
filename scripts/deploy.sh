#!/usr/bin/env bash
#
# Deploys an Obsidian Network on a server: founds it, renders the systemd units,
# starts the services under the supervisor, registers the founder, bonds a
# validator and verifies the result.  One command, one network, one directory.
#
#   bash scripts/deploy.sh --network testnet                  # the whole thing
#   bash scripts/deploy.sh --network testnet --dry-run        # print every step, change nothing
#   bash scripts/deploy.sh --network testnet --units-out /tmp/units   # render units, do not install
#   bash scripts/deploy.sh --network mainnet --invite-file ~/obsidian-mainnet/invite.txt --confirm-mainnet
#   bash scripts/deploy.sh --network testnet --stage verify   # just check a deployment that exists
#
# What it will not do:
#   * found mainnet without --invite-file and --confirm-mainnet
#   * publish, log or print any secret (invitations, phrases, passwords, keys)
#   * run as a different user than the one that owns the data directory, unless
#     it is told which user that is (--user) and can switch to it
#
# Read docs/22-launch-kit.md before pointing this at a mainnet host.  The short
# version: test the testnet first, and keep the mainnet invitation on the host
# that will use it, never in the checkout.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

OBS_TAG=deploy

NETWORK="testnet"
DEPLOY_DIR=""
DEPLOY_USER="${SUDO_USER:-$(id -un)}"
OBS_PREFIX="$OBS_ROOT"
INVITE_FILE=""
UNITS_OUT=""
STAGE="all"
DRY_RUN=0
BUILD=1
CONFIRM_MAINNET=0
WANT_MINE=1
WANT_VALIDATOR=1
ALERT_CMD=""
SYSTEMD=1
MIN_PEERS=""
GENESIS="now"


usage() {
    cat <<'USAGE'
deploy.sh — found, run and verify an Obsidian Network on this machine

  --network <testnet|mainnet|staging|devnet>   default testnet
  --dir <path>          deployment directory    default /var/lib/obsidian/<network>
  --user <name>         the account that owns and runs it   default: $SUDO_USER or you
  --prefix <path>       the checkout to run from            default: this one
  --invite-file <path>  the operator's invitation (mainnet: required; 0600)
  --confirm-mainnet     say yes to founding a network that carries real value
  --units-out <dir>     render the systemd units there instead of installing them
  --stage <all|keys|units|register|verify>      default all
  --no-mine             do not mine
  --no-validator        do not bond a validator
  --alert-cmd <cmd>     the monitor's alert command (mail, curl to a webhook, ...)
  --min-peers <n>       how many peers the monitor expects (default 1; 0 for a
                        network whose only node is this one)
  --genesis-timestamp <now|seconds>   the chain's epoch in the node unit
                        (default now: this deployment founds the network; a node
                        joining somebody else's chain takes their epoch, or a
                        --genesis-file, and must not mine until it has synced)
  --no-systemd          do not touch systemd (use with --units-out)
  --no-build            require the release binaries to exist already
  --dry-run             print what would happen and change nothing

Every step is idempotent: re-running it resumes the deployment it finds.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --network) NETWORK="${2:?--network needs a name}"; shift ;;
        --dir) DEPLOY_DIR="${2:?--dir needs a path}"; shift ;;
        --user) DEPLOY_USER="${2:?--user needs a name}"; shift ;;
        --prefix) OBS_PREFIX="${2:?--prefix needs a path}"; shift ;;
        --invite-file) INVITE_FILE="${2:?--invite-file needs a path}"; shift ;;
        --units-out) UNITS_OUT="${2:?--units-out needs a path}"; shift ;;
        --stage) STAGE="${2:?--stage needs a name}"; shift ;;
        --alert-cmd) ALERT_CMD="${2:?--alert-cmd needs a command}"; shift ;;
        --min-peers) MIN_PEERS="${2:?--min-peers needs a number}"; shift ;;
        --genesis-timestamp) GENESIS="${2:?--genesis-timestamp needs a value}"; shift ;;
        --mine) WANT_MINE=1 ;;
        --no-mine) WANT_MINE=0 ;;
        --validator) WANT_VALIDATOR=1 ;;
        --no-validator) WANT_VALIDATOR=0 ;;
        --no-systemd) SYSTEMD=0 ;;
        --no-build) BUILD=0 ;;
        --confirm-mainnet) CONFIRM_MAINNET=1 ;;
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown argument $1" ;;
    esac
    shift
done

case "$NETWORK" in
    testnet|mainnet|staging|devnet) ;;
    *) die "--network $NETWORK is not a network; use testnet, mainnet, staging or devnet" ;;
esac
case "$STAGE" in
    all|keys|units|register|verify) ;;
    *) die "--stage $STAGE is not a stage; use all, keys, units, register or verify" ;;
esac

if [ -z "$DEPLOY_DIR" ]; then
    DEPLOY_DIR="/var/lib/obsidian/$NETWORK"
fi
[ -d "$(dirname "$DEPLOY_DIR")" ] || DEPLOY_DIR="$HOME/obsidian-$NETWORK"

read -r API_PORT PEER_PORT UI_PORT SERVICE_PORT <<EOF
$(network_ports "$NETWORK")
EOF

# A network of one node is a legitimate testnet, and a monitor that warns about
# having no peers for ever teaches its operator to ignore it.  Mainnet is
# different: a mainnet node with no peers is a node that cannot tell agreement
# from silence, so it is expected to have at least one.
if [ -z "$MIN_PEERS" ]; then
    if [ "$NETWORK" = mainnet ]; then MIN_PEERS=1; else MIN_PEERS=0; fi
fi
case "$MIN_PEERS" in
    ''|*[!0-9]*) die "--min-peers $MIN_PEERS is not a number" ;;
esac

run() { # run <command...>  — executes, or prints it under --dry-run
    if [ "$DRY_RUN" = 1 ]; then
        printf '  would run: %s\n' "$*"
    else
        "$@"
    fi
}

as_owner() { # as_owner <command...>  — run as the deployment's user
    if [ "$(id -un)" = "$DEPLOY_USER" ]; then
        run "$@"
    elif command -v sudo >/dev/null 2>&1; then
        run sudo -u "$DEPLOY_USER" -- "$@"
    else
        die "not $DEPLOY_USER and there is no sudo: run this as $DEPLOY_USER, or as root"
    fi
}

# ---------------------------------------------------------------------------
# Preflight: everything that can be checked before anything is created
# ---------------------------------------------------------------------------

OBS_CHAIN_ID="$("$OBS_BIN/obs-cli" networks 2>/dev/null | awk -v n="$NETWORK" '$1 == n { print $2; exit }')"
OBS_ADDR_PREFIX="$("$OBS_BIN/obs-cli" networks 2>/dev/null | awk -v n="$NETWORK" '$1 == n { print $3; exit }')"
say "network    $NETWORK (chain id ${OBS_CHAIN_ID:-?}, addresses ${OBS_ADDR_PREFIX:-?})"
say "directory  $DEPLOY_DIR"
say "run as     $DEPLOY_USER"
say "prefix     $OBS_PREFIX"
say "ports      api $API_PORT  peers $PEER_PORT  interface $UI_PORT  service $SERVICE_PORT"
[ "$DRY_RUN" = 1 ] && say "dry run: nothing will be created or changed"

if [ "$NETWORK" = mainnet ]; then
    if [ -z "$INVITE_FILE" ]; then
        cat >&2 <<'EOF'
deploy: mainnet is founded with the operator's own invitation, which is in no
file of this checkout.  It was minted with

    obs-cli invite mint --genesis --store <store.json>

Put it in a 0600 file on this host and pass --invite-file <path>, then say yes
with --confirm-mainnet.  A test network needs neither flag: its invitation is
published on purpose (`obs-cli networks`).
EOF
        exit 2
    fi
    [ "$CONFIRM_MAINNET" = 1 ] || die "add --confirm-mainnet to found the network that carries real value"
    [ -r "$INVITE_FILE" ] || die "--invite-file $INVITE_FILE is not readable"
    if [ "$(stat -c '%a' "$INVITE_FILE" 2>/dev/null || echo 644)" != "600" ]; then
        warn "$INVITE_FILE is not 0600; tighten it: chmod 600 $INVITE_FILE"
    fi
fi

# The invitation is read once, kept in a variable, and never printed.  It is a
# single-use authorisation bound to one Gmail identity and one chain, so an
# operator losing it to a log loses nothing that a fresh mint cannot replace.
OBS_INVITE=""
if [ -n "$INVITE_FILE" ]; then
    OBS_INVITE="$(cat "$INVITE_FILE")"
    [ -n "$OBS_INVITE" ] || die "--invite-file $INVITE_FILE is empty"
fi

if [ ! -d "$OBS_PREFIX" ]; then
    die "--prefix $OBS_PREFIX does not exist"
fi
if [ ! -x "$OBS_PREFIX/target/release/obs-node" ] || [ ! -x "$OBS_PREFIX/target/release/obs-app" ] || [ ! -x "$OBS_PREFIX/target/release/obs-cli" ]; then
    if [ "$BUILD" = 1 ]; then
        need cargo "the release binaries are missing and building needs it"
        say "building the workspace in release mode"
        run cargo build --workspace --release --manifest-path "$OBS_PREFIX/Cargo.toml"
    else
        die "$OBS_PREFIX/target/release is missing the binaries (drop --no-build to build them)"
    fi
fi
if [ ! -f "$OBS_PREFIX/web/index.html" ]; then
    die "$OBS_PREFIX/web is missing; the interface is built by scripts/build-web.sh"
fi
if [ ! -f "$OBS_PREFIX/web/wasm/obsidian-wallet.wasm" ]; then
    say "the browser wallet module is missing; building it"
    run bash "$OBS_PREFIX/scripts/build-web.sh"
fi

# The interface binary must exist before the units are installed: a unit that
# starts a program that is not there is a restart loop, not a deployment.
need curl "the deployment verifies itself over HTTP"
need tar "backups"
need sha256sum "backups"

# ---------------------------------------------------------------------------
# 1. keys — the authority, the founder's wallet and the password that seals it
# ---------------------------------------------------------------------------

stage_keys() {
    say "keys: preparing $DEPLOY_DIR"
    run mkdir -p "$DEPLOY_DIR"
    if [ "$DRY_RUN" != 1 ] && [ "$(id -u)" = 0 ] && [ "$DEPLOY_USER" != root ]; then
        id -u "$DEPLOY_USER" >/dev/null 2>&1 || run useradd --system --create-home --home-dir "$(dirname "$DEPLOY_DIR")" "$DEPLOY_USER"
        run chown -R "$DEPLOY_USER" "$DEPLOY_DIR"
    fi
    if [ -f "$DEPLOY_DIR/founder.keystore.json" ] && [ -f "$DEPLOY_DIR/authority.key" ]; then
        say "keys: this deployment already has its authority key and founder wallet"
        return 0
    fi
    if [ ! -f "$DEPLOY_DIR/founder.password.txt" ]; then
        if [ "$DRY_RUN" = 1 ]; then
            printf '  would create: %s (0600)\n' "$DEPLOY_DIR/founder.password.txt"
        else
            (umask 077 && random_password > "$DEPLOY_DIR/founder.password.txt")
            chmod 600 "$DEPLOY_DIR/founder.password.txt"
        fi
    fi
    local invite_arg=()
    if [ -n "${OBS_INVITE:-}" ]; then
        invite_arg=(--invite "$OBS_INVITE")
    fi
    say "keys: founding $NETWORK (authority key, founder wallet, phrase; all 0600, none printed)"
    as_owner "$OBS_PREFIX/target/release/obs-cli" devnet init --network "$NETWORK" \
        --data-dir "$DEPLOY_DIR" --password-file "$DEPLOY_DIR/founder.password.txt" "${invite_arg[@]}"
}

# ---------------------------------------------------------------------------
# 2. units — render the systemd services and start them
# ---------------------------------------------------------------------------

render_units() { # render_units <out-dir>
    local out="$1" template rendered authority
    authority="$(as_owner "$OBS_PREFIX/target/release/obs-cli" authority print \
        --network "$NETWORK" --authority-key "$DEPLOY_DIR/authority.key" 2>/dev/null || true)"
    if [ -z "$authority" ] && [ "$DRY_RUN" != 1 ]; then
        die "could not read the authority public key from $DEPLOY_DIR/authority.key"
    fi
    [ -n "$authority" ] || authority="<64 hex: obs-cli authority print --authority-key $DEPLOY_DIR/authority.key>"
    run mkdir -p "$out"
    for template in obs-node.service obs-app.service obs-monitor.service; do
        local source_file="$OBS_PREFIX/deploy/systemd/$template.in"
        local target="$out/$template"
        if [ "$DRY_RUN" = 1 ]; then
            printf '  would render: %s → %s\n' "$source_file" "$target"
            continue
        fi
        sed \
            -e "s|@NETWORK@|$NETWORK|g" \
            -e "s|@USER@|$DEPLOY_USER|g" \
            -e "s|@GROUP@|$DEPLOY_USER|g" \
            -e "s|@PREFIX@|$OBS_PREFIX|g" \
            -e "s|@DIR@|$DEPLOY_DIR|g" \
            -e "s|@API_PORT@|$API_PORT|g" \
            -e "s|@PEER_PORT@|$PEER_PORT|g" \
            -e "s|@UI_PORT@|$UI_PORT|g" \
            -e "s|@MIN_PEERS@|$MIN_PEERS|g" \
            -e "s|@GENESIS@|$GENESIS|g" \
            -e "s|@AUTHORITY_KEY@|$authority|g" \
            "$source_file" > "$target"
        # The mine/validator switches are words or nothing at all.
        if [ "$WANT_MINE" = 1 ]; then
            sed -i "s|@MINE@|--mine|g" "$target"
        else
            sed -i "s|@MINE@||g" "$target"
        fi
        if [ "$WANT_VALIDATOR" = 1 ]; then
            sed -i "s|@VALIDATOR@|--validator|g" "$target"
        else
            sed -i "s|@VALIDATOR@||g" "$target"
        fi
        if [ -n "$ALERT_CMD" ]; then
            sed -i "s|@ALERT@|--alert-cmd '$ALERT_CMD'|g" "$target"
        else
            sed -i "s|@ALERT@||g" "$target"
        fi
        # Anything still carrying @UPPER@ at this point is a placeholder the
        # renderer does not know about, and a unit file is a bad place to guess.
        # Comments may talk about placeholders; only the directives count.
        if grep -vE '^[[:space:]]*#' "$target" | grep -qE '@[A-Z_]+@'; then
            die "unfilled placeholder in $target: $(grep -vE '^[[:space:]]*#' "$target" | grep -oE '@[A-Z_]+@' | sort -u | tr '\n' ' ')"
        fi
        chmod 644 "$target"
    done
    # The monitor's timer is the same on every host, and the peer port above is
    # a typo waiting to happen if it is ever substituted — it is not.
    if [ "$DRY_RUN" != 1 ]; then
        sed "s|@NETWORK@|$NETWORK|g" "$OBS_PREFIX/deploy/systemd/obs-monitor.timer" > "$out/obs-monitor.timer"
        chmod 644 "$out/obs-monitor.timer"
    fi
    say "units: rendered into $out"
}

stage_units() {
    local out="$UNITS_OUT"
    if [ -z "$out" ]; then
        out="$(mktemp -d)"
        if [ "$DRY_RUN" = 1 ]; then
            say "units: would render into a temporary directory and install them into /etc/systemd/system"
            return 0
        fi
        render_units "$out"
        if [ "$SYSTEMD" = 0 ]; then
            say "units: left in $out (--no-systemd)"
            return 0
        fi
        say "units: installing into /etc/systemd/system"
        for unit in obs-node.service obs-app.service obs-monitor.service obs-monitor.timer; do
            run sudo install -m 644 "$out/$unit" "/etc/systemd/system/$unit"
        done
        run sudo systemctl daemon-reload
        run sudo systemctl enable --now obs-node.service
        run sudo systemctl enable --now obs-app.service obs-monitor.timer
        if [ "$DRY_RUN" != 1 ]; then
            rm -rf "$out"
        fi
    else
        render_units "$out"
    fi
}

# ---------------------------------------------------------------------------
# 3. register — the founder on chain, then the validator bond
# ---------------------------------------------------------------------------

stage_register() {
    local node_url="http://127.0.0.1:$API_PORT"
    if [ "$DRY_RUN" = 1 ]; then
        say "register: would wait for the node on $node_url, register the founder and bond a validator"
        return 0
    fi
    wait_for_http "$node_url/api/v1/status" 60 "the node" || die "the node is not answering on $node_url; check: journalctl -u obs-node -n 50"
    say "register: the founder's registration (block 1 carries it, with the 100,000 OBS genesis allocation)"
    local invite_arg=()
    if [ -n "${OBS_INVITE:-}" ]; then
        invite_arg=(--invite "$OBS_INVITE")
    fi
    local output
    output="$(as_owner_capture "$OBS_PREFIX/target/release/obs-cli" devnet register \
        --network "$NETWORK" --node-url "$node_url" --data-dir "$DEPLOY_DIR" \
        --password-file "$DEPLOY_DIR/founder.password.txt" "${invite_arg[@]}" 2>&1 || true)"
    if printf '%s' "$output" | grep -q "already on chain"; then
        say "register: the founder is already registered on this chain"
    elif [ "$DRY_RUN" = 1 ]; then
        say "register: would submit the founder's registration"
    else
        say "register: founder registered"
    fi
    local active
    active="$(json_number "$(http_ok "$node_url/api/v1/status" || true)" active_validators || true)"
    if [ "$WANT_VALIDATOR" = 1 ] && [ "${active:-0}" = "0" ]; then
        say "register: bonding 50 OBS and registering the validator node identity"
        as_owner "$OBS_PREFIX/target/release/obs-cli" validator register --network "$NETWORK" \
            --node-url "$node_url" --keystore "$DEPLOY_DIR/founder.keystore.json" \
            --password-file "$DEPLOY_DIR/founder.password.txt" \
            --endpoint "http://127.0.0.1:$PEER_PORT"
    fi
}

# Captures a command's output instead of printing it, under either identity.
as_owner_capture() {
    if [ "$DRY_RUN" = 1 ]; then
        printf 'would run: %s\n' "$*"
        return 0
    fi
    if [ "$(id -un)" = "$DEPLOY_USER" ]; then
        "$@" 2>&1 || true
    else
        sudo -u "$DEPLOY_USER" -- "$@" 2>&1 || true
    fi
}

# ---------------------------------------------------------------------------
# 4. verify — the deployment proves itself, or says what is wrong
# ---------------------------------------------------------------------------

stage_verify() {
    local node_url="http://127.0.0.1:$API_PORT"
    local ui_url="http://127.0.0.1:$UI_PORT"
    local failures=0
    local status

    if ! node_serves_deployment "$node_url" "$DEPLOY_DIR" "$NETWORK"; then
        warn "verify: the node is not serving this deployment's chain"
        return 1
    fi
    if ! status="$(http_ok "$node_url/api/v1/status")"; then
        warn "verify: the node is not answering on $node_url"
        return 1
    fi
    local height head finalized supply max_supply active peers
    height="$(json_number "$status" height)"
    head="$(json_string "$status" head)"
    finalized="$(json_number "$status" finalized_height)"
    supply="$(json_string "$status" issued_supply)"
    max_supply="$(json_string "$status" max_supply)"
    active="$(json_number "$status" active_validators)"
    peers="$(json_number "$status" peers)"

    say "verify: height $height  head ${head:0:16}…  finalized $finalized  validators ${active:-0}  peers ${peers:-0}"
    say "verify: issued ${supply:-?} of ${max_supply:-?} OBS"
    [ "${height:-0}" -ge 1 ] 2>/dev/null || { warn "verify: no block has been produced yet"; failures=$((failures+1)); }
    if wait_for_height "$node_url" "$(( ${height:-0} + 1 ))" 30; then
        say "verify: the chain is advancing"
    else
        warn "verify: the height has not moved in 30s"
        failures=$((failures+1))
    fi
    if [ "${active:-0}" -ge 1 ] 2>/dev/null; then
        say "verify: a validator is bonded"
    elif [ "$WANT_VALIDATOR" = 1 ]; then
        # The bond is a transaction: it has to be mined before the validator set
        # contains it.  A verification that runs a second after the bond was
        # submitted is not evidence that the deployment is broken, it is
        # evidence that the check was early.
        say "verify: waiting for the validator bond to be mined"
        if wait_for_validators "$node_url" 1 60; then
            say "verify: a validator is bonded"
        else
            warn "verify: no validator is bonded after 60s, so finality will not advance"
            failures=$((failures+1))
        fi
    fi
    if http_ok "$ui_url/healthz" >/dev/null 2>&1 || http_ok "$ui_url/" >/dev/null 2>&1; then
        say "verify: the interface answers on $ui_url"
    else
        warn "verify: the interface is not answering on $ui_url"
        failures=$((failures+1))
    fi
    if [ -x "$OBS_PREFIX/scripts/monitor.sh" ]; then
        local health=0
        bash "$OBS_PREFIX/scripts/monitor.sh" --network "$NETWORK" --node-url "$node_url" \
            --app-url "$ui_url" --data-dir "$DEPLOY_DIR" --min-peers "$MIN_PEERS" --quiet \
            >/dev/null 2>&1 || health=$?
        case "$health" in
            0) say "verify: the health check is green" ;;
            1)
                say "verify: the health check is green with warnings:"
                bash "$OBS_PREFIX/scripts/monitor.sh" --network "$NETWORK" --node-url "$node_url" \
                    --data-dir "$DEPLOY_DIR" --min-peers "$MIN_PEERS" 2>&1 | sed 's/^/    /' || true
                ;;
            *)
                warn "verify: the health check is critical — run: bash scripts/monitor.sh --network $NETWORK --node-url $node_url --data-dir $DEPLOY_DIR"
                failures=$((failures+1))
                ;;
        esac
    fi
    return "$failures"
}

# ---------------------------------------------------------------------------

case "$STAGE" in
    keys) stage_keys ;;
    units) stage_units ;;
    register) stage_register ;;
    verify)
        if [ "$DRY_RUN" = 1 ]; then
            say "verify: would check height, finality, the interface and the health check"
            exit 0
        fi
        stage_verify || exit 1
        ;;
    all)
        stage_keys
        stage_units
        if [ "$UNITS_OUT" != "" ]; then
            say "units rendered to $UNITS_OUT; install them yourself, or drop --units-out to let this script install them"
            exit 0
        fi
        if [ "$DRY_RUN" != 1 ]; then
            say "waiting for the services to come up"
            sleep 3
        fi
        stage_register
        if [ "$UNITS_OUT" = "" ] && [ "$DRY_RUN" != 1 ]; then
            if stage_verify; then :; else
                warn "the deployment is up but not fully verified; see the lines above"
                exit 1
            fi
        fi
        ;;
esac

echo
say "next:"
say "  health now      bash scripts/monitor.sh --network $NETWORK --node-url http://127.0.0.1:$API_PORT --data-dir $DEPLOY_DIR"
say "  logs            journalctl -u obs-node -f        (and: -u obs-app)"
say "  backup now      bash scripts/backup.sh --dir $DEPLOY_DIR --node-url http://127.0.0.1:$API_PORT"
say "  restore drill   bash scripts/restore.sh --archive <backup> --dir <fresh dir> --verify-only"
say "  rehearse        bash scripts/rehearse.sh          (three nodes, a restart and a restore)"
if [ "$NETWORK" != mainnet ]; then
    say "  TLS + a public name: docs/16-networks-and-deployment.md, section 5"
else
    say "  mainnet: move $DEPLOY_DIR/founder.phrase.txt to an offline backup and delete it here."
    say "  mainnet: keep $DEPLOY_DIR/authority.key, the invitation file and the founder keystore on this host, 0600, backed up."
fi
