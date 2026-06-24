#!/usr/bin/env bash
# Build the native contracts reproducibly via `kontor build` (cargo build +
# brotli, pinned). This script only bootstraps the kontor binary
# (which can't build itself) and then delegates. Artifacts -> binaries/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$SCRIPT_DIR/../core"

( cd "$CORE_DIR" && cargo build --release --bin kontor )
"$CORE_DIR/target/release/kontor" build "$SCRIPT_DIR" --out-dir "$SCRIPT_DIR/binaries"
