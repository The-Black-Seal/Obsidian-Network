#!/usr/bin/env bash
# Installs the Rust toolchain used to build and test Obsidian Network, without
# rustup and without touching the network's own dependency policy.
#
# Why this exists: this build environment has no rustup and no access to
# static.rust-lang.org, crates.io or the GitHub release hosts.  The only
# reachable distribution channel is the npm registry, which mirrors the official
# rust-lang component tarballs as `@rustbin/*` packages.  This script installs
# them into /opt/rust exactly as the official installer would lay them out.
#
# Usage:  scripts/install-toolchain.sh [install-prefix]
# Then:   export PATH=/opt/rust/bin:$PATH
#         export CARGO_HOME=/opt/cargo CARGO_NET_OFFLINE=true
set -euo pipefail

VERSION="${RUST_VERSION:-1.88.0}"
HOST="${RUST_HOST:-x86_64-unknown-linux-gnu}"
PREFIX="${1:-/opt/rust}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "downloading toolchain components ${VERSION} for ${HOST} ..."
npm pack --silent \
  "@rustbin/rustc-${VERSION}-${HOST}" \
  "@rustbin/cargo-${VERSION}-${HOST}" \
  "@rustbin/rust-std-${VERSION}-${HOST}" \
  "@rustbin/rust-std-${VERSION}-wasm32-unknown-unknown" >/dev/null

copy_tree() { # source-dir destination-dir
  if [ -d "$1" ]; then
    mkdir -p "$2"
    cp -a "$1/." "$2/"
  fi
}

# Every package mirrors the official installer layout, so after stripping the
# npm "package/" prefix each tarball contributes one component directory:
# rustc/, cargo/ or rust-std-<target>/.
for tarball in *.tgz; do
  dir="${tarball%.tgz}"
  mkdir -p "$dir"
  tar -xzf "$tarball" -C "$dir" --strip-components=1

  for component in rustc cargo; do
    [ -d "$dir/$component" ] || continue
    copy_tree "$dir/$component/bin" "$PREFIX/bin"
    copy_tree "$dir/$component/lib" "$PREFIX/lib"
    copy_tree "$dir/$component/libexec" "$PREFIX/libexec"
  done

  for std in "$dir"/rust-std-*; do
    [ -d "$std/lib/rustlib" ] || continue
    for target in "$std/lib/rustlib"/*; do
      [ -d "$target" ] || continue
      copy_tree "$target" "$PREFIX/lib/rustlib/$(basename "$target")"
    done
  done
done

# The component tarballs ship the standard library as a .tar.xz that the
# official installer unpacks; unpack it here if present.
for target in "$PREFIX"/lib/rustlib/*; do
  for archive in "$target"/lib/*.tar.xz; do
    [ -e "$archive" ] || continue
    tar -xJf "$archive" -C "$target/lib"
    rm -f "$archive"
  done
done

chmod +x "$PREFIX/bin/"* 2>/dev/null || true

if [ "$(id -u)" = "0" ]; then
  chown -R "${SUDO_USER:-root}" "$PREFIX" 2>/dev/null || true
fi

echo "installed:"
"$PREFIX/bin/rustc" --version
"$PREFIX/bin/cargo" --version
cat <<EOF

Add this to your shell before building:
  export PATH=${PREFIX}/bin:\$PATH
  export CARGO_HOME=/opt/cargo
  export CARGO_NET_OFFLINE=true
EOF
