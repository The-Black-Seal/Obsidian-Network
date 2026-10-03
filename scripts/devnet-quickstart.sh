#!/usr/bin/env bash
# Compatibility name for the devnet quickstart: see scripts/quickstart.sh.
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/quickstart.sh" --network devnet "$@"
