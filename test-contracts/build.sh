#!/usr/bin/env bash
# Build the test contracts reproducibly via `kontor build` (cargo build +
# brotli, pinned). This script only bootstraps the kontor binary
# (which can't build itself) and then delegates.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$SCRIPT_DIR/../core"

( cd "$CORE_DIR" && cargo build --release --bin kontor )
"$CORE_DIR/target/release/kontor" build "$SCRIPT_DIR"
