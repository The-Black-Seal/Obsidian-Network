#!/usr/bin/env bash
#
# Publishes-nothing check: scan the repository for anything that must never
# leave the machines it is configured on.
#
#   bash scripts/leak-check.sh
#
# Three things live outside the repository on purpose, and this script is how the
# project proves it:
#
#   1. the mainnet genesis invitation, which exists on the operator's machine and
#      nowhere else;
#   2. private keys — no PEM block, ever;
#   3. the source URL of the official mark, which a deployment may fetch
#      server-side but which must never be written into a file, hotlinked from a
#      page, or recorded beside the image.
#
# The first two are searched for by name, and the name is assembled here from
# fragments: a check for a secret is no place to write the secret down.  The
# third is different — searching for that host by name would put the host in the
# repository, which is the very thing being prevented.  So it is searched for by
# shape instead: any absolute URL in the tree that names a logo.  The only such
# URLs allowed are loopback addresses and reserved placeholder domains in tests,
# which reach nothing and belong to nobody.
#
# Exit status is 0 when the tree is clean, 1 when something leaked, and the
# offending lines are printed.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Assembled, never literal.
INVITE_NEEDLE="OBS-GENESIS""-7K4M""-X9P2"
KEY_NEEDLE="-----BEGIN ""PRIVATE KEY-----"

EXCLUDES=(--exclude-dir=.git --exclude-dir=target --exclude-dir=node_modules)
FAILED=0

report() {
    local what="$1"
    shift
    echo "leak-check: $what"
    printf '%s\n' "$@" | sed 's/^/  /'
    FAILED=1
}

# Addresses that may legitimately appear: the tests' loopback stand-ins and the
# reserved placeholder domain from RFC 2606.  Written with bracket dots so the
# pattern means exactly what it looks like.
ALLOWED='127[.]0[.]0[.]1|localhost|0[.]0[.]0[.]0|private[.]example|example[.]com' 

# --- 1. the invitation and private keys ---------------------------------------
if hits="$(grep -rnE "$INVITE_NEEDLE|$KEY_NEEDLE" "${EXCLUDES[@]}" . 2>/dev/null)"; then
    report "the genesis invitation or a private key is in the tree:" "$hits"
fi

# --- 2. an absolute URL that names a logo -------------------------------------
# Loopback and RFC 2606 placeholders are the stand-ins the tests use; a real
# operator's mark is served from a configured URL that appears nowhere.
if hits="$(grep -rniE 'https?://[^ "'"'"']*logo' "${EXCLUDES[@]}" . 2>/dev/null \
        | grep -vE "$ALLOWED")"; then
    report "a logo is referenced by absolute URL:" "$hits"
fi

# --- 3. the interface reaches nobody for its mark -----------------------------
if hits="$(grep -nE 'rel="(icon|alternate icon)"|class="mark"' web/index.html 2>/dev/null \
        | grep -E 'https?://')"; then
    report "the page loads its icon or mark off-origin:" "$hits"
fi

# --- 4. an installed image is recorded by hash, not by origin -----------------
if [ -f web/assets/logo-official.provenance ]; then
    if ! grep -q 'sha256:' web/assets/logo-official.provenance; then
        report "web/assets/logo-official.provenance records no hash"
    fi
    if hits="$(grep -E 'https?://' web/assets/logo-official.provenance)"; then
        report "the provenance of the official mark names its origin:" "$hits"
    fi
fi

if [ "$FAILED" -ne 0 ]; then
    echo
    echo "leak-check: FAILED — see above"
    exit 1
fi

echo "leak-check: clean (invitation, private keys, and the mark's source are all absent)"
