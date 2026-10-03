#!/usr/bin/env bash
#
# Points the whole project at the official Obsidian logo.
#
#   bash scripts/set-logo.sh https://example.com/obsidian-logo.png
#   bash scripts/set-logo.sh ~/Downloads/logo.png           # copied into web/assets/
#
# The logo appears in exactly three places in what ships — the page's header
# image, the favicon, and the two READMEs — so this script sets all of them at
# once and prints what it changed.  It keeps the drawn seal at
# web/assets/logo.svg as a fallback that is still referenced if the configured
# source cannot be reached, so a typo in a URL degrades to a working page rather
# than a broken brand.
#
# A remote logo is loaded by the visitor's browser directly from that URL, so:
#   * prefer https;
#   * the host must allow hotlinking (a 403 or a redirect to a login page shows
#     as a broken image);
#   * a square mark reads best — the header renders it at 34x34.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ $# -ne 1 ]; then
    echo "usage: bash scripts/set-logo.sh <https-url-or-local-file>" >&2
    exit 2
fi

SOURCE="$1"
TARGET="$SOURCE"

case "$SOURCE" in
    http://*|https://*)
        ;;
    *)
        # A local file: copy it in, so the page keeps working offline and the
        # repository carries the mark it actually renders.
        if [ ! -f "$SOURCE" ]; then
            echo "set-logo: no such file: $SOURCE" >&2
            exit 1
        fi
        extension="${SOURCE##*.}"
        case "$extension" in
            png|svg|jpg|jpeg|webp) ;;
            *) echo "set-logo: unsupported image type: .$extension" >&2; exit 1 ;;
        esac
        mkdir -p web/assets
        cp "$SOURCE" "web/assets/logo-official.$extension"
        TARGET="assets/logo-official.$extension"
        echo "set-logo: copied $SOURCE to web/assets/logo-official.$extension"
        ;;
esac

python3 - "$TARGET" <<'PY'
import pathlib, sys, re

target = sys.argv[1]
changed = []

# --- the page: one img, one favicon, one meta the script's own tests read ------
page = pathlib.Path("web/index.html")
text = page.read_text()

def swap(pattern, replacement, text):
    new, count = re.subn(pattern, replacement, text, count=1)
    if count == 0:
        raise SystemExit("set-logo: could not find the logo reference in web/index.html")
    return new

# The favicon's declared type must match the file, or a browser may treat a PNG
# as an SVG and render nothing.
extension = target.rsplit(".", 1)[-1].lower()
mime = {
    "svg": "image/svg+xml",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
}[extension]
text = swap(r'<link rel="icon" href="[^"]*"( type="[^"]*")?',
            f'<link rel="icon" href="{target}" type="{mime}"', text)
text = swap(r'<img src="[^"]*" alt="" width="34" height="34">',
            f'<img src="{target}" alt="Obsidian Network" width="34" height="34" '
            f'decoding="async" referrerpolicy="no-referrer">', text)
if '<meta name="obsidian-logo"' in text:
    text = swap(r'<meta name="obsidian-logo" content="[^"]*">',
                f'<meta name="obsidian-logo" content="{target}">', text)
else:
    text = text.replace('<meta name="color-scheme" content="dark">',
                        f'<meta name="color-scheme" content="dark">\n'
                        f'<meta name="obsidian-logo" content="{target}">', 1)
page.write_text(text)
changed.append("web/index.html (header image, favicon, obsidian-logo meta)")

# --- the front doors, so the same mark appears in the documentation -----------
for path in ("README.md", "docs/README.md"):
    readme = pathlib.Path(path)
    text = readme.read_text()
    line = f'<img src="{target}" alt="Obsidian Network" width="96">\n\n'
    # only the first line of the file is the logo slot; everything else is prose
    if text.startswith('<img src='):
        text = re.sub(r'<img src="[^"]*"[^>]*>\n\n', line, text, count=1)
    else:
        text = line + text
    readme.write_text(text)
    changed.append(path)

print("set-logo: pointed at " + target)
for item in changed:
    print("set-logo:   " + item)
PY

echo "set-logo: the drawn seal at web/assets/logo.svg is still on disk as a fallback"
