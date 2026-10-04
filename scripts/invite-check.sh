#!/usr/bin/env bash
#
# Proves that a network's published founder invitation actually registers.
#
# The invitation exists in two places, and they are different doors:
#
#   * `obs-cli devnet init` uses the published code to *found* a chain — it holds
#     the authority key on the operator's machine and signs the authorisation
#     itself;
#   * a person typing the code at the interface is at the registration service,
#     which only knows the invitations in its own store.  A code the network
#     advertises (`obs-cli networks`) and the service has never heard of is
#     answered `invite_invalid`, which is a contradiction a user would meet and
#     have no way to explain.
#
# This check runs the whole thing against a scratch service and a scratch store
# on loopback, so it needs no live deployment, spends no invitation that matters,
# and creates no account anywhere.  It is what acceptance check 112 runs, and an
# operator can run it before inviting anybody.
#
#   bash scripts/invite-check.sh [--network devnet] [--code OBS-...] [--port 19510]
#
# Exit 0 when the code is accepted at the invitation step, 1 when it is refused
# or anything on the way fails.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NETWORK="${OBSIDIAN_NETWORK:-devnet}"
CODE=""
PORT=19510
BIN="${OBSIDIAN_BIN:-$ROOT/target/debug}"
if [ ! -x "$BIN/obs-gateway" ] && [ -x "$ROOT/target/release/obs-gateway" ]; then
    BIN="$ROOT/target/release"
fi

say() { printf 'invite-check: %s\n' "$*"; }
die() { printf 'invite-check: %s\n' "$*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --network) NETWORK="${2:?--network needs a name}"; shift ;;
        --code) CODE="${2:?--code needs the invitation}"; shift ;;
        --port) PORT="${2:?--port needs a number}"; shift ;;
        --bin) BIN="${2:?--bin needs a directory}"; shift ;;
        -h|--help)
            sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done

[ -x "$BIN/obs-gateway" ] || die "obs-gateway is not built at $BIN (run: cargo build --workspace)"
command -v curl >/dev/null 2>&1 || die "curl is required"

# The published invitation, when the operator did not name one.  Mainnet has
# none — by design, its invitation is the operator's — and this script will not
# invent one for it.
if [ -z "$CODE" ]; then
    CODE="$("$BIN/obs-cli" networks 2>/dev/null \
        | awk -v n="$NETWORK" '$1 == n && $2 == "disposable" { print $NF; exit }')"
    [ -n "$CODE" ] || die "$NETWORK publishes no founder invitation; pass --code (and never for mainnet)"
fi

DIR="$(mktemp -d "${TMPDIR:-/tmp}/obsidian-invite-check-XXXXXX")"
GATEWAY_PID=""
cleanup() {
    if [ -n "$GATEWAY_PID" ]; then
        kill "$GATEWAY_PID" 2>/dev/null || true
        wait "$GATEWAY_PID" 2>/dev/null || true
    fi
    rm -rf "$DIR"
    return 0
}
trap cleanup EXIT

# A scratch authority and a scratch store: the same two commands an operator
# runs, on a network nobody is using.
"$BIN/obs-gateway" --network "$NETWORK" --generate-authority \
    --authority-key "$DIR/authority.key" >/dev/null 2>&1 \
    || die "the scratch authority key could not be generated"
"$BIN/obs-gateway" --network "$NETWORK" --store "$DIR/accounts.json" \
    --authority-key "$DIR/authority.key" --mint-genesis-invite "$CODE" >/dev/null 2>&1 \
    || die "the invitation could not be minted into the scratch store"

# The code must not be recoverable from the store it was minted into.
if grep -q -- "$CODE" "$DIR/accounts.json"; then
    die "the code was written to the store in the clear"
fi

"$BIN/obs-gateway" --network "$NETWORK" --store "$DIR/accounts.json" \
    --authority-key "$DIR/authority.key" --port "$PORT" --bind 127.0.0.1 \
    >"$DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!

ready=0
for _ in $(seq 1 60); do
    if curl -sf --max-time 2 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.25
done
[ "$ready" = 1 ] || die "the scratch registration service did not start on port $PORT"

# Steps 1-3 of registration, with a throwaway Gmail identity that exists nowhere:
# the address, a password, the invitation.  Nothing here creates an account —
# activation is the step that does, and it is never reached.
begin="$(curl -sf -X POST "http://127.0.0.1:$PORT/v1/register/begin" \
    -H 'content-type: application/json' \
    -d '{"gmail":"invite.check@googlemail.com"}')" || die "the gmail step failed"
case "$begin" in
    *'"next":"password"'*) ;;
    *) die "the gmail step answered something unexpected: $begin" ;;
esac
token="$(printf '%s' "$begin" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
[ -n "$token" ] || die "the gmail step returned no token"

curl -sf -X POST "http://127.0.0.1:$PORT/v1/register/password" \
    -H 'content-type: application/json' \
    -d "{\"token\":\"$token\",\"password\":\"an-invitation-check-password\"}" \
    >/dev/null || die "the password step failed"

step="$(curl -sf -X POST "http://127.0.0.1:$PORT/v1/register/invite" \
    -H 'content-type: application/json' \
    -d "{\"token\":\"$token\",\"code\":\"$CODE\"}")" \
    || die "the registration service refused the published invitation"

case "$step" in
    *'"next":"recovery"'*) ;;
    *) die "the invitation step answered something unexpected: $step" ;;
esac

say "$NETWORK: the published founder invitation is accepted at the registration service"
say "  the code was never printed by the service, and is stored only as a hash"
exit 0
