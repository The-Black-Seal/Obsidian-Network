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
    row="$("$OBS_BIN/obs-cli" networks 2>/dev/null | awk -v n="$network" '$1 == n { print $4, $5, $6, $7 }')"
    [ -n "$row" ] || row="$(awk -v n="$network" '$1 == n { print $4, $5, $6, $7 }' "$OBS_ROOT/scripts/ports.txt" 2>/dev/null || true)"
    [ -n "$row" ] || die "unknown network $network (run: $OBS_BIN/obs-cli networks)"
    printf '%s' "$row"
}

network_prefix() { # network_prefix <network>  → the address prefix
    "$OBS_BIN/obs-cli" networks 2>/dev/null | awk -v n="$1" '$1 == n { print $3 }'
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

# Reads one KEY=value out of a deployment's env file, if it exists.
env_value() { # env_value <file> <key>
    [ -f "$1" ] || return 1
    grep -E "^$2=" "$1" | tail -n 1 | cut -d= -f2- || return 1
}

random_password() { head -c 32 /dev/urandom | sha256sum | cut -c1-48; }
