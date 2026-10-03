#!/usr/bin/env bash
# Builds the browser wallet and installs it into the web interface.
#
# The interface is plain files — no bundler, no npm, no build step — with one
# exception: the wallet.  Key derivation, keystore sealing and signing are Rust,
# compiled to WebAssembly, so that the keys a browser holds are produced by the
# same code the command-line client runs.  This script builds that module and
# copies it where the interface loads it from.
#
# Usage: scripts/build-web.sh [--check]
#
#   --check   build to a temporary file and compare with the installed one,
#             exiting non-zero when they differ (used by the release checklist)
#
# Requirements: the workspace toolchain, including the wasm32-unknown-unknown
# target, and nothing else.  No third-party crates are used anywhere, so this
# needs no network access.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET="wasm32-unknown-unknown"
ARTIFACT="target/$TARGET/release/obs_wasm.wasm"
DESTINATION="web/wasm/obsidian-wallet.wasm"
CHECK=0

for argument in "$@"; do
  case "$argument" in
    --check) CHECK=1 ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "build-web: unknown argument $argument" >&2
      exit 2
      ;;
  esac
done

if ! command -v cargo >/dev/null 2>&1; then
  echo "build-web: cargo is not on PATH." >&2
  echo "build-web: export PATH=/opt/rust/bin:\$PATH (or install the toolchain with scripts/install-toolchain.sh)" >&2
  exit 1
fi

if ! rustc --print target-list 2>/dev/null | grep -qx "$TARGET"; then
  echo "build-web: rustc does not know the $TARGET target" >&2
  exit 1
fi

LIBDIR="$(rustc --print sysroot)/lib/rustlib/$TARGET/lib"
if [ ! -d "$LIBDIR" ]; then
  echo "build-web: the $TARGET standard library is not installed for this toolchain." >&2
  echo "build-web: install it with: rustup target add $TARGET   (the workspace's" >&2
  echo "build-web: toolchain file lists it, so a toolchain installed with rustup gets it for free)" >&2
  exit 1
fi

echo "build-web: compiling the wallet for $TARGET"
cargo build --offline -p obs-wasm --target "$TARGET" --release

if [ ! -f "$ARTIFACT" ]; then
  echo "build-web: the build produced no artifact at $ARTIFACT" >&2
  exit 1
fi

size="$(wc -c < "$ARTIFACT" | tr -d ' ')"
echo "build-web: module is $size bytes"

if [ "$CHECK" -eq 1 ]; then
  if [ ! -f "$DESTINATION" ]; then
    echo "build-web: $DESTINATION is missing; run scripts/build-web.sh" >&2
    exit 1
  fi
  if cmp -s "$ARTIFACT" "$DESTINATION"; then
    echo "build-web: $DESTINATION matches the build"
    exit 0
  fi
  echo "build-web: $DESTINATION does not match the current source" >&2
  echo "build-web: run scripts/build-web.sh to refresh it" >&2
  exit 1
fi

mkdir -p "$(dirname "$DESTINATION")"
install -m 0644 "$ARTIFACT" "$DESTINATION"

# The provenance file is written by the build, so the interface never claims an
# artifact came from somewhere it did not.
{
  echo "Built from crates/obs-wasm by scripts/build-web.sh."
  echo "Target: $TARGET"
  echo "Size:   $size bytes"
  echo "SHA-256: $(sha256sum "$DESTINATION" | cut -d' ' -f1)"
  echo
  echo "This is a compiled artifact committed so that the interface works on a"
  echo "checkout with no toolchain.  Rebuild it with scripts/build-web.sh; the"
  echo "source of truth is the Rust in crates/obs-wasm, crates/obs-wallet and"
  echo "crates/obs-crypto."
} > "$(dirname "$DESTINATION")/PROVENANCE.txt"

echo "build-web: installed $DESTINATION"
echo "build-web: provenance written to $(dirname "$DESTINATION")/PROVENANCE.txt"
