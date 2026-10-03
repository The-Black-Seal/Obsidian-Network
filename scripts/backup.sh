#!/usr/bin/env bash
#
# Backs up a deployment: the chain, the keys, and a manifest that says exactly
# what was in the archive and what the chain looked like when it was taken.
#
#   bash scripts/backup.sh --dir /var/lib/obsidian/testnet
#   bash scripts/backup.sh --dir … --out /backup/obsidian-testnet.tar.gz --keep 30
#   bash scripts/backup.sh --dir … --live          # while the node runs
#
# The archive holds the founder's keystore, the authority key and (on a test
# network) the password file: that is the point of a backup — restore it and you
# have the node back.  It is written 0600, and it should leave this machine:
# a backup on the same disk as the thing it backs up is a copy, not a backup.
#
# A node writes its block log while it runs.  Taking a backup with the node
# running is allowed with --live and recorded in the manifest as such, because
# the honest thing to do with a live snapshot is to *verify* it: restore.sh
# boots the restored directory and compares its head against the manifest.  A
# backup you have never restored is a hope.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

OBS_TAG=backup

NETWORK="testnet"
DEPLOY_DIR=""
OUT=""
NODE_URL=""
KEEP=14
LIVE=0
INCLUDE_LOGS=0

while [ $# -gt 0 ]; do
    case "$1" in
        --network) NETWORK="${2:?}"; shift ;;
        --dir) DEPLOY_DIR="${2:?}"; shift ;;
        --out) OUT="${2:?}"; shift ;;
        --node-url) NODE_URL="${2:?}"; shift ;;
        --keep) KEEP="${2:?}"; shift ;;
        --live) LIVE=1 ;;
        --include-logs) INCLUDE_LOGS=1 ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done

[ -n "$DEPLOY_DIR" ] || DEPLOY_DIR="/var/lib/obsidian/$NETWORK"
[ -d "$DEPLOY_DIR" ] || die "$DEPLOY_DIR does not exist"
read -r API_PORT _ _ _ <<EOF
$(network_ports "$NETWORK")
EOF
if [ -z "$NODE_URL" ]; then
    NODE_URL="http://127.0.0.1:$API_PORT"
fi

# The node answers → it is running, and a live snapshot needs to be asked for.
running=0
if http_ok "$NODE_URL/api/v1/status" >/dev/null 2>&1; then running=1; fi
if [ "$running" = 1 ] && [ "$LIVE" != 1 ]; then
    cat >&2 <<EOF
backup: the node is answering on $NODE_URL, so its block log is being written.
    A copy taken now can include a half-written tail.  Either stop the node
    (systemctl stop obs-node), or take the snapshot deliberately:

        bash scripts/backup.sh --dir $DEPLOY_DIR --live

    --live is not a shortcut to be avoided: it is a promise to verify, and
    scripts/restore.sh is how.  A snapshot that has never been restored is a
    hope, not a backup.
EOF
    exit 2
fi

# Where the archive goes: beside the deployment, never inside it (a wiped data
# directory should not take the backups with it).
BACKUP_DIR="$(dirname "$DEPLOY_DIR")/backups"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -z "$OUT" ]; then
    mkdir -p "$BACKUP_DIR"
    OUT="$BACKUP_DIR/$NETWORK-$STAMP.tar.gz"
fi
mkdir -p "$(dirname "$OUT")"

# --- the manifest -----------------------------------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
MANIFEST="$WORK/MANIFEST.txt"
{
    printf 'obsidian-backup 1\n'
    printf 'network %s\n' "$NETWORK"
    printf 'created_at %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'host %s\n' "$(hostname 2>/dev/null || echo unknown)"
    printf 'source %s\n' "$DEPLOY_DIR"
    printf 'live %s\n' "$running"
    status="$(http_ok "$NODE_URL/api/v1/status" 2>/dev/null || true)"
    : "${status:=}"
    if [ -n "$status" ]; then
        printf 'head_height %s\n' "$(json_number "$status" height)"
        printf 'head_hash %s\n' "$(json_string "$status" head)"
        printf 'finalized_height %s\n' "$(json_number "$status" finalized_height)"
        printf 'issued_supply %s\n' "$(json_string "$status" issued_supply)"
        printf 'protocol_time %s\n' "$(json_number "$status" protocol_time)"
    else
        printf 'head_height unknown\nhead_hash unknown\n'
    fi
} > "$MANIFEST"

# --- what goes in -----------------------------------------------------------
# Everything the node needs to come back as itself; never a pid file, never a
# nested backup.
#
# Be careful with "log": the chain's own block log lives in `node/` and *is* the
# chain — a backup that excludes `*.log` excludes the history and restores a
# node that has forgotten everything.  The only logs left out by default are the
# two the services write for a human to read, and only when they are not asked
# for.
TAR_EXCLUDES=(--exclude='*.pid' --exclude='./backups' --exclude='monitor.state*' --exclude='*.tmp' --exclude='*.tar.gz' --exclude='./node.log' --exclude='./app.log')
FIND_EXCLUDES=(! -name '*.pid' ! -name 'monitor.state*' ! -name '*.tmp' ! -name '*.tar.gz' ! -path './backups/*' ! -name 'node.log' ! -name 'app.log')
if [ "$INCLUDE_LOGS" = 1 ]; then
    TAR_EXCLUDES=(--exclude='*.pid' --exclude='./backups' --exclude='monitor.state*' --exclude='*.tmp' --exclude='*.tar.gz')
    FIND_EXCLUDES=(! -name '*.pid' ! -name 'monitor.state*' ! -name '*.tmp' ! -name '*.tar.gz' ! -path './backups/*')
fi

# The manifest lists every file with its hash, and it is written *before* the
# archive, in one pass: a manifest that describes the file list is worth more
# than an archive that claims to describe itself.
LIST="$WORK/FILES.txt"
( cd "$DEPLOY_DIR" && find . -type f "${FIND_EXCLUDES[@]}" -print0 2>/dev/null | sort -z | xargs -0 sha256sum ) > "$LIST" 2>/dev/null || true
{
    printf 'files %s\n' "$(wc -l < "$LIST" | tr -d ' ')"
} >> "$MANIFEST"
cat "$LIST" >> "$MANIFEST"

# A deployment whose data directory holds no chain is a mistake worth refusing:
# the archive would restore a node that has forgotten everything, and it would
# look like a working backup until the day it was needed.
if ! find "$DEPLOY_DIR" -type f -name '*-blocks.log' -print -quit 2>/dev/null | grep -q .; then
    if find "$DEPLOY_DIR" -type f -name '*-genesis' -print -quit 2>/dev/null | grep -q .; then
        say "note: this deployment has a genesis record but no block log yet (a chain that has not produced a block)"
    else
        die "$DEPLOY_DIR holds no chain (no *-genesis and no *-blocks.log); is this the right --dir?"
    fi
fi

say "archiving $DEPLOY_DIR (live=$running)"
tar -czf "$OUT" "${TAR_EXCLUDES[@]}" -C "$DEPLOY_DIR" . -C "$WORK" MANIFEST.txt
chmod 600 "$OUT"

SIZE="$(du -h "$OUT" | cut -f1)"
say "wrote $OUT ($SIZE, 0600, $(wc -l < "$LIST" | tr -d ' ') files)"
say "  it holds the chain, the keys and the manifest; keep a copy off this machine"
if [ -n "${status:-}" ]; then
    say "  head when taken: height $(json_number "$status" height), $(json_string "$status" head | cut -c1-16)…"
fi
say "  prove it:  bash scripts/restore.sh --archive $OUT --dir /tmp/obsidian-restore --start $(( API_PORT + 2000 ))"

# --- retention --------------------------------------------------------------
if [ "$KEEP" -gt 0 ] 2>/dev/null; then
    mapfile -t old < <(ls -1t "$BACKUP_DIR"/"$NETWORK"-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)))
    for file in "${old[@]}"; do
        [ -n "$file" ] || continue
        rm -f "$file"
        say "  pruned $file (keeping $KEEP)"
    done
fi
