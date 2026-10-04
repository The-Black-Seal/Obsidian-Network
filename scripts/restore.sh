#!/usr/bin/env bash
#
# Restores a backup, verifying it before it is trusted, and optionally proves it
# by booting the restored node and comparing its head with the manifest.
#
#   bash scripts/restore.sh --archive backup.tar.gz --dir /tmp/check --verify-only
#   bash scripts/restore.sh --archive backup.tar.gz --dir /var/lib/obsidian/testnet --force
#   bash scripts/restore.sh --archive backup.tar.gz --dir /tmp/restored --start 9400
#
# The verification is the point.  Every file the manifest lists is hashed after
# extraction and compared; a single mismatch stops the restore with the file's
# name and leaves the extracted copy in place to be looked at.  A backup that
# silently restores a truncated block log produces a node that agrees with no
# one, three weeks later, on a night nobody wants it.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

OBS_TAG=restore

ARCHIVE=""
TARGET=""
NETWORK=""
FORCE=0
VERIFY_ONLY=0
START_PORT=""
PEER_PORT=""
LEAVE_RUNNING=0

while [ $# -gt 0 ]; do
    case "$1" in
        --archive) ARCHIVE="${2:?}"; shift ;;
        --dir) TARGET="${2:?}"; shift ;;
        --network) NETWORK="${2:?}"; shift ;;
        --listen) PEER_PORT="${2:?}"; shift ;;
        --start) START_PORT="${2:?}"; shift ;;
        --force) FORCE=1 ;;
        --verify-only) VERIFY_ONLY=1 ;;
        --leave-running) LEAVE_RUNNING=1 ;;
        -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done

[ -n "$ARCHIVE" ] || die "--archive <path> is required"
[ -f "$ARCHIVE" ] || die "$ARCHIVE does not exist"
[ -n "$TARGET" ] || die "--dir <path> is required"

# --- 1. read the manifest ----------------------------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
if ! tar -xzf "$ARCHIVE" -C "$WORK" MANIFEST.txt 2>/dev/null; then
    die "$ARCHIVE is not an Obsidian backup (no MANIFEST.txt inside)"
fi
MANIFEST="$WORK/MANIFEST.txt"
[ "$(sed -n 1p "$MANIFEST")" = "obsidian-backup 1" ] || die "the manifest is not in the expected format"
field() { sed -n "s/^$1 //p" "$MANIFEST" | head -n 1; }
[ -n "$NETWORK" ] || NETWORK="$(field network)"
[ -n "$NETWORK" ] || die "the manifest does not name a network"
manifest_height="$(field head_height)"
manifest_hash="$(field head_hash)"
manifest_files="$(field files)"
say "manifest: $NETWORK, taken $(field created_at) (live=$(field live)), head $(field head_height) $(field head_hash | cut -c1-16)…, $manifest_files files"

# --- 2. what the manifest says is inside ------------------------------------
# Every line after `files N` is "<sha256>  <path>".
sed -n "/^files $manifest_files\$/,\$p" "$MANIFEST" | tail -n +2 > "$WORK/FILES.txt"
listed="$(grep -c . "$WORK/FILES.txt" 2>/dev/null || echo 0)"
[ "$listed" = "$manifest_files" ] || die "the manifest lists $listed files but claims $manifest_files"
[ "$listed" -gt 0 ] || die "the manifest lists no files"

# --- 3. extract, then verify every file -------------------------------------
EXTRACT="$WORK/extract"
mkdir -p "$EXTRACT"
if [ "$VERIFY_ONLY" != 1 ]; then
    if [ -e "$TARGET" ] && [ -n "$(ls -A "$TARGET" 2>/dev/null || true)" ] && [ "$FORCE" != 1 ]; then
        die "$TARGET is not empty; restoring over it needs --force (nothing has been written)"
    fi
    mkdir -p "$TARGET"
fi
tar -xzf "$ARCHIVE" -C "$EXTRACT" --exclude='MANIFEST.txt' || die "the archive could not be extracted"

verified=0
while IFS= read -r line; do
    [ -n "$line" ] || continue
    hash="${line%% *}"
    path="${line#*  }"
    file="$EXTRACT/${path#./}"
    if [ ! -f "$file" ]; then
        printf '%s: %s is listed in the manifest but is not in the archive\n' "${OBS_TAG}" "$path" >&2
        exit 2
    fi
    actual="$(sha256sum "$file" | cut -d' ' -f1)"
    if [ "$actual" != "$hash" ]; then
        printf '%s: %s does not match the manifest\n' "${OBS_TAG}" "$path" >&2
        printf '  manifest %s\n  archive  %s\n' "$hash" "$actual" >&2
        exit 2
    fi
    verified=$((verified + 1))
done < "$WORK/FILES.txt"
say "verified $verified files against the manifest"

if [ "$VERIFY_ONLY" = 1 ]; then
    say "the archive is complete and every file matches; nothing was written to $TARGET"
    exit 0
fi

# --- 4. move it into place --------------------------------------------------
cp -a "$EXTRACT/." "$TARGET/"
say "restored into $TARGET"
if [ -f "$TARGET/founder.password.txt" ]; then chmod 600 "$TARGET/founder.password.txt" 2>/dev/null || true; fi
if [ -f "$TARGET/authority.key" ]; then chmod 600 "$TARGET/authority.key" 2>/dev/null || true; fi
for secret in "$TARGET"/*.json; do
    [ -f "$secret" ] && chmod 600 "$secret" 2>/dev/null || true
done
say "  start it:  obs-node --network $NETWORK --data-dir $TARGET/node --bind 127.0.0.1 \\"
say "                 --api-port <api> --listen-port <peer> --authority-key <hex from authority.key>"

# --- 5. prove it, by booting it --------------------------------------------
if [ -z "$START_PORT" ]; then
    say "nothing was started; pass --start <api-port> to boot the restored node and compare its head with the manifest"
    exit 0
fi

[ "$manifest_height" != "unknown" ] || die "this backup has no head height in its manifest, so a restore cannot be compared"
[ -n "$PEER_PORT" ] || PEER_PORT=$((START_PORT + 1))

authority=""
if [ -f "$TARGET/authority.key" ]; then
    authority="$("$OBS_BIN/obs-cli" authority print --network "$NETWORK" --authority-key "$TARGET/authority.key" 2>/dev/null || true)"
fi

LOG="$TARGET/restore-verify.log"
say "booting the restored node on api $START_PORT / peers $PEER_PORT (log $LOG)"
"$OBS_BIN/obs-node" --network "$NETWORK" --data-dir "$TARGET/node" --bind 127.0.0.1 \
    --api-port "$START_PORT" --listen-port "$PEER_PORT" \
    ${authority:+--authority-key "$authority"} \
    >"$LOG" 2>&1 &
node_pid=$!

cleanup_node() {
    if [ "$LEAVE_RUNNING" != 1 ] && kill -0 "$node_pid" 2>/dev/null; then
        kill "$node_pid" 2>/dev/null || true
        wait "$node_pid" 2>/dev/null || true
    fi
}
trap 'cleanup_node; rm -rf "$WORK"' EXIT

url="http://127.0.0.1:$START_PORT"
if ! wait_for_http "$url/api/v1/status" 30 "the restored node"; then
    tail -n 20 "$LOG" >&2 || true
    die "the restored node did not start; its log is $LOG"
fi

status="$(http_ok "$url/api/v1/status")"
height="$(json_number "$status" height)"
head="$(json_string "$status" head)"
say "restored node reports height $height, head $(printf '%s' "$head" | cut -c1-16)…"

# The proof: the block the manifest recorded must be *this chain's* block at
# that height, byte for byte.  If the restored node has moved on, asking for
# that height still answers with the same hash — which is what makes this check
# race-free.
block="$(http_ok "$url/api/v1/blocks/$manifest_height" || true)"
restored_hash="$(json_string "$block" hash)"
if [ "$restored_hash" = "$manifest_hash" ]; then
    say "restore drill: PASS — block $manifest_height in the restored chain is $manifest_hash"
    exit 0
fi
printf '%s: restore drill: FAIL\n  the manifest recorded block %s as %s\n  the restored chain says         %s\n' \
    "${OBS_TAG}" "$manifest_height" "$manifest_hash" "$restored_hash" >&2
exit 2
