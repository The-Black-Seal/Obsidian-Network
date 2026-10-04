#!/usr/bin/env bash
#
# Is this deployment healthy?  Answers the five questions of
# docs/17-operations.md, in order, and exits 0 (healthy), 1 (warning) or
# 2 (critical) so a timer, a dashboard or a person can all use it.
#
#   bash scripts/monitor.sh --network testnet --node-url http://127.0.0.1:8300
#   bash scripts/monitor.sh --json                       # machine-readable
#   bash scripts/monitor.sh --alert-cmd "mail -s obsidian ops@example.org"
#   bash scripts/monitor.sh --webhook https://example.org/hooks/obsidian
#
# What it watches, and why each one:
#
#   1. height and protocol time   — is the chain alive?  On PoT the height is a
#      function of time, so a stalled height while protocol time moves is the
#      signature of a node that is not being selected, not of a slow machine.
#   2. finalized_height           — are validators attesting?  A chain that
#      produces blocks but never finalizes has one proposer and no majority.
#   3. issued_supply vs max       — does issuance still match claims?  This is
#      the one number that must never cross its bound.
#   4. peers                      — a health check that cannot see the network
#      cannot tell "I am alone" from "everyone is down".
#   5. index behind head          — the Explorer is allowed to be behind; it is
#      not allowed to be silently wrong, so it reports its distance.
#
# Plus the two things that stop a node for reasons that have nothing to do with
# the chain: disk space, and the clock drifting away from protocol time.
#
# Alerts are sent at most once per state change, or once every --remind seconds
# while a problem persists, so a flapping check cannot turn into a mail storm.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

OBS_TAG=monitor

NETWORK="testnet"
NODE_URL=""
APP_URL=""
DATA_DIR=""
STATE_FILE=""
ALERT_CMD=""
WEBHOOK=""
JSON=0
QUIET=0
REMIND_SECS=1800
STALL_SECS=180
MIN_PEERS=1

while [ $# -gt 0 ]; do
    case "$1" in
        --network) NETWORK="${2:?}"; shift ;;
        --node-url) NODE_URL="${2:?}"; shift ;;
        --app-url) APP_URL="${2:?}"; shift ;;
        --data-dir) DATA_DIR="${2:?}"; shift ;;
        --state) STATE_FILE="${2:?}"; shift ;;
        --alert-cmd) ALERT_CMD="${2:?}"; shift ;;
        --webhook) WEBHOOK="${2:?}"; shift ;;
        --remind) REMIND_SECS="${2:?}"; shift ;;
        --stall) STALL_SECS="${2:?}"; shift ;;
        --min-peers) MIN_PEERS="${2:?}"; shift ;;
        --json) JSON=1 ;;
        --quiet) QUIET=1 ;;
        -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done

if [ -z "$NODE_URL" ]; then
    read -r API_PORT _ _ _ <<EOF
$(network_ports "$NETWORK")
EOF
    NODE_URL="http://127.0.0.1:$API_PORT"
fi
if [ -z "$APP_URL" ]; then
    read -r _ _ UI_PORT _ <<EOF
$(network_ports "$NETWORK")
EOF
    APP_URL="http://127.0.0.1:$UI_PORT"
fi
if [ -z "$STATE_FILE" ]; then
    STATE_FILE="${TMPDIR:-/tmp}/obsidian-monitor-$NETWORK.state"
fi

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

CRITICAL=0
WARNING=0
FINDINGS=()
VALUES=()

# A decimal amount as an integer number of grains, with no floating point
# anywhere: "1.25" becomes 1250000000000.  Used only for comparisons, so the
# shell cannot introduce the very rounding the protocol went out of its way to
# avoid.
to_grains() { # to_grains <decimal>  → grains
    local whole="${1%%.*}" frac=""
    case "$1" in *.*) frac="${1#*.}" ;; esac
    [ -n "$whole" ] || whole=0
    while [ "${#frac}" -lt 12 ]; do frac="${frac}0"; done
    frac="${frac:0:12}"
    printf '%s%s' "$whole" "$frac" | sed 's/^0*//'
}

# True when the first integer (a non-negative decimal string) is greater than
# the second.  Length first, then lexicographic — exact at any size.
decimal_gt() {
    local a="$1" b="$2"
    while [ "${#a}" -gt 1 ] && [ "${a#0}" != "$a" ]; do a="${a#0}"; done
    while [ "${#b}" -gt 1 ] && [ "${b#0}" != "$b" ]; do b="${b#0}"; done
    if [ "${#a}" -ne "${#b}" ]; then
        [ "${#a}" -gt "${#b}" ] && return 0
        return 1
    fi
    [ "$a" \> "$b" ]
}

# Escapes a string for a JSON document: a path with a quote in it must not be
# able to produce a broken document.
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

finding() { # finding <level> <key> <message>
    case "$1" in
        critical) CRITICAL=$((CRITICAL + 1)) ;;
        warning) WARNING=$((WARNING + 1)) ;;
    esac
    FINDINGS+=("$1|$2|$3")
}

value() { VALUES+=("$1|$2"); }

now="$(date +%s)"

if [ -n "$DATA_DIR" ] && ! node_serves_deployment "$NODE_URL" "$DATA_DIR" "$NETWORK" 2>/dev/null; then
    finding critical wrong_chain "the node on $NODE_URL is a different chain from $DATA_DIR; every number below is about the wrong network"
fi

status="$(http_ok "$NODE_URL/api/v1/status" || true)"
if [ -z "$status" ]; then
    finding critical node_down "the node does not answer on $NODE_URL"
else
    height="$(json_number "$status" height)"
    head="$(json_string "$status" head)"
    finalized="$(json_number "$status" finalized_height)"
    supply="$(json_string "$status" issued_supply)"
    max_supply="$(json_string "$status" max_supply)"
    protocol_time="$(json_number "$status" protocol_time)"
    active_validators="$(json_number "$status" active_validators)"
    peers="$(json_number "$status" peers)"
    pooled="$(json_number "$status" pooled_transactions)"
    value height "$height"
    value head "$head"
    value finalized_height "$finalized"
    value issued_supply "$supply"
    value protocol_time "$protocol_time"
    value active_validators "$active_validators"
    value peers "$peers"
    value pooled_transactions "$pooled"

    # --- 1. height, over time -------------------------------------------------
    last_height=""; last_time=""; last_state=""
    if [ -f "$STATE_FILE" ]; then
        last_height="$(awk -F'|' '$1 == "height" { print $2 }' "$STATE_FILE" 2>/dev/null || true)"
        last_time="$(awk -F'|' '$1 == "observed" { print $2 }' "$STATE_FILE" 2>/dev/null || true)"
    fi
    if [ -n "$last_height" ] && [ -n "$last_time" ]; then
        elapsed=$((now - last_time))
        if [ "$height" -le "$last_height" ] 2>/dev/null && [ "$elapsed" -ge "$STALL_SECS" ]; then
            finding critical height_stalled "height has not moved for ${elapsed}s (still $height)"
        fi
        if [ -n "$last_height" ] && [ "$height" -lt "$last_height" ] 2>/dev/null; then
            finding critical height_went_back "height went backwards: $last_height → $height"
        fi
    fi

    # --- 2. finality ---------------------------------------------------------
    if [ "${height:-0}" -gt 12 ] 2>/dev/null; then
        if [ "${finalized:-0}" -le 0 ] 2>/dev/null; then
            finding critical no_finality "the chain is producing blocks but nothing is finalized"
        elif [ $((height - finalized)) -gt 12 ] 2>/dev/null; then
            finding warning finality_behind "finality is $(($height - $finalized)) blocks behind the head"
        fi
    fi
    if [ "${active_validators:-0}" -le 0 ] 2>/dev/null; then
        finding warning no_validators "no validator is bonded, so finality cannot advance"
    fi

    # --- 3. supply -----------------------------------------------------------
    if [ -n "$supply" ] && [ -n "$max_supply" ]; then
        # Compare as integers in grains: the same arithmetic the chain uses.
        issued_grains="$(to_grains "$supply")"
        max_grains="$(to_grains "$max_supply")"
        value issued_grains "$issued_grains"
        value max_grains "$max_grains"
        if [ -n "$issued_grains" ] && [ -n "$max_grains" ] && decimal_gt "$issued_grains" "$max_grains"; then
            finding critical supply_exceeded "issued supply $supply exceeds the maximum $max_supply — stop and investigate"
        fi
    fi

    # --- 4. peers ------------------------------------------------------------
    if [ "${peers:-0}" -lt "$MIN_PEERS" ] 2>/dev/null; then
        finding warning no_peers "only ${peers:-0} peer(s) connected (--min-peers $MIN_PEERS): this node cannot tell disagreement from silence"
    fi

    # --- the clock -----------------------------------------------------------
    if [ -n "$protocol_time" ]; then
        skew=$((now - protocol_time))
        [ "$skew" -lt 0 ] && skew=$((-skew))
        value clock_skew_secs "$skew"
        if [ "$skew" -gt 900 ]; then
            finding warning clock_skew "protocol time is ${skew}s away from this host's clock; verify NTP"
        fi
    fi
fi

# --- 5. the index ------------------------------------------------------------
if [ -n "$APP_URL" ]; then
    explorer="$(http_ok "$APP_URL/v1/explorer/status" || true)"
    if [ -z "$explorer" ]; then
        finding critical interface_down "the interface does not answer on $APP_URL"
    else
        indexed="$(json_number "$explorer" indexed_height)"
        node_height="$(json_number "$explorer" node_height)"
        value indexed_height "$indexed"
        behind="$(json_number "$explorer" index_behind)"
        if [ -z "$indexed" ] || [ -z "$node_height" ]; then
            # The index is allowed to be behind; it is not allowed to be silent.
            finding warning index_unknown "the interface did not report its indexed height"
        else
            [ -n "$behind" ] || behind=$((node_height - indexed))
            value index_behind "$behind"
            if [ "$behind" -gt 32 ] 2>/dev/null; then
                finding warning index_behind "the index is $behind blocks behind the node"
            fi
        fi
        if http_ok "$APP_URL/assets/mark.json" >/dev/null 2>&1; then
            : # the mark route exists; whether it is configured is the operator's business
        fi
    fi
fi

# --- disk --------------------------------------------------------------------
if [ -n "$DATA_DIR" ] && [ -d "$DATA_DIR" ]; then
    read -r avail_pct _ <<EOF
$(df -P "$DATA_DIR" 2>/dev/null | awk 'NR == 2 { gsub("%", "", $5); print $5, $4 }')
EOF
    if [ -n "${avail_pct:-}" ]; then
        used_pct="$avail_pct"
        value disk_used_percent "$used_pct"
        if [ "$used_pct" -ge 95 ] 2>/dev/null; then
            finding critical disk_full "the filesystem holding $DATA_DIR is ${used_pct}% full"
        elif [ "$used_pct" -ge 85 ] 2>/dev/null; then
            finding warning disk_filling "the filesystem holding $DATA_DIR is ${used_pct}% full"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Report, and remember
# ---------------------------------------------------------------------------

if [ "$CRITICAL" -gt 0 ]; then STATE=critical
elif [ "$WARNING" -gt 0 ]; then STATE=warning
else STATE=healthy; fi

if [ "$JSON" = 1 ]; then
    printf '{'
    printf '"network":"%s","state":"%s","critical":%d,"warning":%d' "$NETWORK" "$STATE" "$CRITICAL" "$WARNING"
    printf ',"values":{'
    first=1
    for pair in "${VALUES[@]}"; do
        key="${pair%%|*}"; val="${pair#*|}"
        [ -n "$val" ] || continue
        if [ "$first" = 1 ]; then first=0; else printf ','; fi
        case "$val" in
            ''|*[!0-9]*) printf '"%s":"%s"' "$key" "$(json_escape "$val")" ;;
            *) printf '"%s":%s' "$key" "$val" ;;
        esac
    done
    printf '},"findings":['
    first=1
    for entry in "${FINDINGS[@]}"; do
        level="${entry%%|*}"; rest="${entry#*|}"; key="${rest%%|*}"; message="${rest#*|}"
        if [ "$first" = 1 ]; then first=0; else printf ','; fi
        printf '{"level":"%s","key":"%s","message":"%s"}' "$level" "$key" "$(json_escape "$message")"
    done
    printf ']}\n'
else
    if [ "$QUIET" != 1 ]; then
        if [ "$STATE" = healthy ]; then
            say "$NETWORK is healthy: height ${height:-?}, finalized ${finalized:-?}, validators ${active_validators:-0}, peers ${peers:-0}, issued ${supply:-?} OBS"
        else
            say "$NETWORK is $STATE"
        fi
        for entry in "${FINDINGS[@]}"; do
            level="${entry%%|*}"; rest="${entry#*|}"; message="${rest#*|}"
            printf '  %-8s %s\n' "$level" "$message" >&2
        done
    fi
fi

# The state file, written after the check so a crash mid-check does not look
# like a healthy observation of a lower height.
if [ "$JSON" != 1 ] || [ -n "${height:-}" ]; then
    {
        printf 'observed|%s\n' "$now"
        [ -n "${height:-}" ] && printf 'height|%s\n' "$height"
        printf 'state|%s\n' "$STATE"
    } > "$STATE_FILE" 2>/dev/null || true
fi

# --- alerts ------------------------------------------------------------------
# Sent when the state changes, or while it stays bad and --remind has passed.
previous=""
if [ -f "$STATE_FILE" ]; then
    previous="$(awk -F'|' '$1 == "state" { print $2 }' "$STATE_FILE.alerted" 2>/dev/null || true)"
fi
remind_due=1
if [ -f "$STATE_FILE.alerted" ]; then
    alerted_at="$(awk -F'|' '$1 == "at" { print $2 }' "$STATE_FILE.alerted" 2>/dev/null || true)"
    if [ -n "$alerted_at" ] && [ "$STATE" != healthy ] && [ $((now - alerted_at)) -lt "$REMIND_SECS" ]; then
        remind_due=0
    fi
fi
if [ "$STATE" != healthy ] && { [ "$STATE" != "$previous" ] || [ "$remind_due" = 1 ]; }; then
    message="obsidian $NETWORK: $STATE"
    for entry in "${FINDINGS[@]}"; do
        level="${entry%%|*}"; rest="${entry#*|}"; text="${rest#*|}"
        message="$message
  $level: $text"
    done
    if [ -n "$ALERT_CMD" ]; then
        printf '%s\n' "$message" | eval "$ALERT_CMD" || warn "the alert command failed"
    fi
    if [ -n "$WEBHOOK" ]; then
        payload="$(printf '%s' "$message" | awk '{ gsub(/"/, "\\\""); printf "%s\\n", $0 }')"
        curl -sf --max-time 10 -X POST "$WEBHOOK" -H 'content-type: application/json' \
            -d "{\"network\":\"$NETWORK\",\"state\":\"$STATE\",\"text\":\"$payload\"}" \
            >/dev/null || warn "the webhook failed"
    fi
    [ "$QUIET" != 1 ] && [ "$STATE" != healthy ] && warn "$message"
    { printf 'state|%s\nat|%s\n' "$STATE" "$now" > "$STATE_FILE.alerted"; } 2>/dev/null || true
elif [ "$STATE" = healthy ]; then
    if [ -n "$previous" ] && [ "$previous" != healthy ]; then
        say "recovered: $NETWORK is healthy again"
        if [ -n "$ALERT_CMD" ]; then printf 'obsidian %s: recovered\n' "$NETWORK" | eval "$ALERT_CMD" || true; fi
    fi
    { printf 'state|healthy\nat|%s\n' "$now" > "$STATE_FILE.alerted"; } 2>/dev/null || true
fi

if [ "$CRITICAL" -gt 0 ]; then exit 2; fi
if [ "$WARNING" -gt 0 ]; then exit 1; fi
exit 0
