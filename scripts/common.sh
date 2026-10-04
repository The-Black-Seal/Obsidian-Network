#!/usr/bin/env bash
#
# Shared helpers for the operator scripts (deploy, monitor, backup, restore,
# rehearse).  Sourced, never run: `source scripts/common.sh`.
#
# Everything here is deliberately dependency-free — curl, tar, sha256sum and the
# shell — because these scripts run on a server whose whole job is to keep a
# chain alive, and a deployment should not need a package manager to be
# monitored or backed up.

set -euo pipefail

# The checkout this script lives in.
OBS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBS_BIN="$OBS_ROOT/target/release"

say()  { printf '%s: %s\n' "${OBS_TAG:-obsidian}" "$*"; }
warn() { printf '%s: %s\n' "${OBS_TAG:-obsidian}" "$*" >&2; }
die()  { printf '%s: %s\n' "${OBS_TAG:-obsidian}" "$*" >&2; exit 2; }

need() { # need <command> <why>
    command -v "$1" >/dev/null 2>&1 || die "$1 is not installed ($2)"
}

# The ports of a network, from the CLI that owns the table.
#
# `obs-cli networks` prints   network  chain id  address prefix  node API  peers
# interface  service  — this reads the row for one network rather than keeping a
# second copy of the numbers here, where it could drift from the chain's own
# definition.
network_ports() { # network_ports <network>  → "api peer interface service"
    local network="$1" row
    row="$("$OBS_BIN/obs-cli" networks 2>/dev/null | awk -v n="$network" '$1 == n { print $4, $5, $6, $7; exit }')"
    [ -n "$row" ] || row="$(awk -v n="$network" '$1 == n { print $4, $5, $6, $7 }' "$OBS_ROOT/scripts/ports.txt" 2>/dev/null || true)"
    [ -n "$row" ] || die "unknown network $network (run: $OBS_BIN/obs-cli networks)"
    printf '%s' "$row"
}

network_prefix() { # network_prefix <network>  → the address prefix
    # `obs-cli networks` has a second section that also starts a line with the
    # network's name (the founder invitations), so every reader takes the first
    # match: the table row.
    "$OBS_BIN/obs-cli" networks 2>/dev/null | awk -v n="$1" '$1 == n { print $3; exit }'
}

http_ok() { curl -sf --max-time "${OBS_HTTP_TIMEOUT:-5}" "$1"; }

json_number() { printf '%s' "$1" | grep -o "\"$2\":[-0-9]*" | head -n 1 | cut -d: -f2; }
json_string() { printf '%s' "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -n 1 | cut -d'"' -f4; }

wait_for_http() { # wait_for_http <url> <seconds> <what>
    local url="$1" seconds="$2" what="$3" deadline=$((SECONDS + $2))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if http_ok "$url" >/dev/null 2>&1; then return 0; fi
        sleep 0.5
    done
    warn "$what did not answer within ${seconds}s"
    return 1
}

# Waits until a node reports height >= the given height.
wait_for_height() { # wait_for_height <node-url> <height> <seconds>
    local url="$1" want="$2" seconds="$3" deadline=$((SECONDS + $3)) status height
    while [ "$SECONDS" -lt "$deadline" ]; do
        if status="$(http_ok "$url/api/v1/status" 2>/dev/null)"; then
            height="$(json_number "$status" height)"
            if [ -n "$height" ] && [ "$height" -ge "$want" ] 2>/dev/null; then return 0; fi
        fi
        sleep 0.5
    done
    return 1
}

# Waits until a node reports at least this many bonded validators.
wait_for_validators() { # wait_for_validators <node-url> <count> <seconds>
    local url="$1" want="$2" deadline=$((SECONDS + $3)) active
    while [ "$SECONDS" -lt "$deadline" ]; do
        active="$(json_number "$(http_ok "$url/api/v1/status" 2>/dev/null || true)" active_validators || true)"
        if [ -n "$active" ] && [ "$active" -ge "$want" ] 2>/dev/null; then return 0; fi
        sleep 1
    done
    return 1
}

# Waits until every node in the list reports the same head hash.
wait_for_agreement() { # wait_for_agreement <seconds> <node-url>...
    local seconds="$1"; shift
    local deadline=$((SECONDS + seconds)) urls=("$@") heads=() url head
    while [ "$SECONDS" -lt "$deadline" ]; do
        heads=()
        for url in "${urls[@]}"; do
            head="$(json_string "$(http_ok "$url/api/v1/status" 2>/dev/null || true)" head || true)"
            [ -n "$head" ] || { heads=(); break; }
            heads+=("$head")
        done
        if [ "${#heads[@]}" -eq "${#urls[@]}" ]; then
            local first="${heads[0]}" same=1 h
            for h in "${heads[@]}"; do [ "$h" = "$first" ] || same=0; done
            [ "$same" = 1 ] && return 0
        fi
        sleep 1
    done
    return 1
}

# The genesis record a node writes into its data directory: the chain's identity
# as this deployment knows it.  A node answering on a port is not evidence that
# it is *this* chain — on a machine with two deployments of the same network it
# is exactly the wrong evidence — so every script that reads a node on behalf of
# a directory checks this first.
deployment_genesis_timestamp() { # deployment_genesis_timestamp <deployment dir> <network>
    local file
    for file in "$1/node/$2-genesis" "$1/$2-genesis"; do
        if [ -f "$file" ]; then
            awk '$1 == "timestamp" { print $2; exit }' "$file"
            return 0
        fi
    done
    return 1
}

# Fail-closed check: the node at <url> must be running the chain that
# <deployment dir> holds.  Returns 0 when it is (or when the directory has no
# chain yet, which is a different situation and not this function's business),
# 1 when it is a different chain, having explained why.
node_serves_deployment() { # node_serves_deployment <node-url> <deployment dir> <network>
    local url="$1" dir="$2" network="$3" local_epoch remote_epoch status
    local_epoch="$(deployment_genesis_timestamp "$dir" "$network" 2>/dev/null || true)"
    [ -n "$local_epoch" ] || return 0
    status="$(http_ok "$url/api/v1/status" 2>/dev/null || true)"
    [ -n "$status" ] || return 0
    remote_epoch="$(json_number "$status" genesis_timestamp)"
    [ -n "$remote_epoch" ] || return 0
    if [ "$local_epoch" = "$remote_epoch" ]; then
        return 0
    fi
    printf '%s: the node at %s is a different chain\n' "${OBS_TAG:-obsidian}" "$url" >&2
    printf '  %s holds a chain with genesis %s\n' "$dir" "$local_epoch" >&2
    printf '  the node answers with genesis %s\n' "$remote_epoch" >&2
    printf '  a genesis timestamp is the chain identity: two networks, two chains.\n' >&2
    printf '  pass --node-url for the node attached to %s.\n' "$dir" >&2
    return 1
}

# Reads one KEY=value out of a deployment's env file, if it exists.
env_value() { # env_value <file> <key>
    [ -f "$1" ] || return 1
    grep -E "^$2=" "$1" | tail -n 1 | cut -d= -f2- || return 1
}

random_password() { head -c 32 /dev/urandom | sha256sum | cut -c1-48; }
