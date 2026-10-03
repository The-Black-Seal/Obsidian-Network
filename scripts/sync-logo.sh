#!/usr/bin/env bash
#
# Installs the official logo as a file in this repository.
#
#   bash scripts/sync-logo.sh https://<the logo host>/<path>
#   bash scripts/sync-logo.sh ./some/local/image.png
#
# Run this on a machine that can reach the logo's source — a workstation, or a
# CI job with the URL in a secret.  It takes the image, checks that it really is
# one, and writes it to web/assets/logo-official.<ext>.  A local file is used as
# it is, which is the path to use when the image was handed over some way other
# than a link.
#
# The point of doing it this way is what is *not* written down.  The URL is an
# argument, never a file: after this runs, the repository contains the mark and
# nothing that says where it came from.  The provenance file records the hash,
# the media type, the size and the date, so the bytes in the tree can be checked
# against what was fetched — and the source stays wherever the operator keeps it.
#
# Once the image is in web/assets/, this deployment needs no network to show it:
# the page, the favicon and `obs-app` all read the file.  (`obs-app
# --logo-source <url>` is the alternative for a deployment that would rather
# fetch it at run time; either way the URL never reaches a browser.)
#
# The logo is committed to a public repository once this runs, so the *image*
# becomes public.  That is the point — it is the project's mark — but it is worth
# saying out loud: only the URL stays private.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SOURCE="${1:-${LOGO_URL:-}}"
if [ -z "$SOURCE" ]; then
    echo "usage: bash scripts/sync-logo.sh <url|file>" >&2
    echo "   or: LOGO_URL=<url> bash scripts/sync-logo.sh" >&2
    exit 2
fi

command -v python3 >/dev/null 2>&1 || { echo "sync-logo: python3 is required" >&2; exit 1; }

bytes_of() { wc -c < "$1" | tr -d ' '; }

mkdir -p web/assets
temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT

if [ -f "$SOURCE" ]; then
    # A file the operator already has: no network, no source to record at all.
    cp "$SOURCE" "$temporary"
    echo "sync-logo: using $(bytes_of "$temporary") bytes from the file $SOURCE"
else
    command -v curl >/dev/null 2>&1 || { echo "sync-logo: curl is required for a URL" >&2; exit 1; }
    echo "sync-logo: fetching the mark"
    # --fail so an error page is not saved as a logo; a browser-like Accept so
    # hosts that negotiate on it answer with an image.
    if ! curl --fail --silent --show-error --location --max-time 60 \
            --user-agent 'obsidian-logo-sync/1.0' \
            --header 'Accept: image/png,image/svg+xml,image/webp,image/jpeg,image/*;q=0.8' \
            --output "$temporary" \
            --write-out 'sync-logo: the host answered %{http_code} %{content_type}, %{size_download} bytes\n' \
            "$SOURCE"; then
        echo "sync-logo: the fetch failed; nothing was written" >&2
        exit 1
    fi
fi


# The file decides the extension, not the URL: a logo host may serve
# /logo.png as a JPEG, and the page must still get a correct content type.
read -r extension content_type <<EOF
$(python3 - "$temporary" <<'PY'
import pathlib, sys
blob = pathlib.Path(sys.argv[1]).read_bytes()
if blob[:8] == b"\x89PNG\r\n\x1a\n":
    print("png image/png")
elif blob[:3] == b"\xff\xd8\xff":
    print("jpg image/jpeg")
elif blob[:4] == b"RIFF" and blob[8:12] == b"WEBP":
    print("webp image/webp")
elif blob[:6] in (b"GIF87a", b"GIF89a"):
    print("gif image/gif")
elif blob.lstrip()[:5] in (b"<svg ", b"<?xml") and b"<svg" in blob[:4096]:
    print("svg image/svg+xml")
elif blob[:4] == b"\x00\x00\x01\x00":
    print("ico image/x-icon")
else:
    sys.exit("sync-logo: what was fetched is not an image")
PY
)
EOF

size="$(wc -c < "$temporary" | tr -d ' ')"
if [ "$size" -gt 2097152 ]; then
    echo "sync-logo: the image is $size bytes, above the 2 MiB this project serves" >&2
    exit 1
fi

destination="web/assets/logo-official.$extension"
cp "$temporary" "$destination"
chmod 644 "$destination"

hash="$(python3 - "$destination" <<'PY'
import hashlib, pathlib, sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"

{
    echo "# Provenance of the official mark carried in this repository."
    echo "#"
    echo "# The bytes below came from a source the operator supplied — a link or a"
    echo "# file, deliberately not both fetched and written down: the origin is"
    echo "# configuration, not source. What can be checked is the artifact itself."
    echo "file:        $(basename "$destination")"
    echo "sha256:      $hash"
    echo "bytes:       $size"
    echo "media_type:  $content_type"
    echo "fetched_utc: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "installed_by: scripts/sync-logo.sh"
} > web/assets/logo-official.provenance

# The mark also belongs at the top of the documentation, where a reader meets it
# first.  The banner is inserted once and replaced on later runs, so this script
# can be re-run whenever the image changes.  Relative paths only: the file is in
# the repository, so nothing points anywhere else.
banner() {
    path="$1"
    prefix="$2"
    [ -f "$path" ] || return 0
    line="<img src=\"${prefix}web/assets/logo-official.png\" alt=\"Obsidian Network\" width=\"88\">"
    temporary_banner="$(mktemp)"
    if head -n 1 "$path" | grep -q 'logo-official\.png'; then
        # Already bannered: replace the line, so a re-run cannot stack banners.
        {
            echo "$line"
            tail -n +2 "$path"
        } > "$temporary_banner"
    else
        {
            echo "$line"
            echo
            cat "$path"
        } > "$temporary_banner"
    fi
    mv "$temporary_banner" "$path"
}
banner README.md ""
banner docs/README.md "../"

# The page already asks for this path; the drawn seal stays as the fallback.
if ! grep -q 'assets/logo-official.png' web/index.html; then
    echo "sync-logo: web/index.html does not reference assets/logo-official.png" >&2
    exit 1
fi

echo "sync-logo: installed $destination ($content_type, $size bytes)"
echo "sync-logo: sha256 $hash"
echo
echo "The deployment now serves the mark from its own origin; no browser is sent"
echo "to the source, and the source URL is not in this repository."
echo "Commit web/assets/ and the interface will use it everywhere."
