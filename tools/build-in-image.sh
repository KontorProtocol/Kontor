#!/usr/bin/env bash
# The contract build itself — runs INSIDE the pinned image
# (tools/kontor-build.Dockerfile). For each contracts workspace passed as an
# argument it: compiles to wasm, optimizes (wasm-opt) and compresses (brotli)
# into <workspace>/binaries/, and records the build platform in
# <workspace>/binaries/build.json (CI reads it to pick a matching runner).
#
# Host tool versions (rustc/wasm-opt/brotli) would make the bytes
# non-reproducible, so this refuses to run outside the image — use
# tools/build-contracts.sh, which launches the image and calls this.
set -euo pipefail
shopt -s nullglob

if [ -z "${KONTOR_BUILD_IMAGE:-}" ]; then
  echo "error: run tools/build-contracts.sh (this must build inside the pinned image)" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64) platform=linux/amd64 ;;
  aarch64) platform=linux/arm64 ;;
  *) echo "error: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

# Provenance derived from the actual installed tools — truthful, and no lockstep
# edits when the image bumps. The image tag follows rustc, like the published one.
rustc_version="$(rustc --version | cut -d' ' -f2)"
binaryen_version="$(wasm-opt --version | grep -oE 'version_[0-9]+')"

for ws in "$@"; do
  echo "==> Building $ws"
  (
    cd "$ws"
    mkdir -p binaries
    # Start clean so removed/renamed contracts don't leave stale artifacts: drop
    # the committed .wasm.br and the previous top-level .wasm (including _opt),
    # then let cargo regenerate only the current workspace members.
    for stale in binaries/*.wasm.br target/wasm32-unknown-unknown/release/*.wasm; do
      rm -f "$stale"
    done
    cargo build --release
    for wasm in target/wasm32-unknown-unknown/release/*.wasm; do
      case "$wasm" in *_opt.wasm) continue ;; esac
      opt="${wasm%.wasm}_opt.wasm"
      wasm-opt -Oz --enable-bulk-memory --enable-sign-ext "$wasm" -o "$opt"
      brotli -Zf "$opt" -o "binaries/$(basename "$wasm").br"
    done
    cat >binaries/build.json <<EOF
{
  "platform": "$platform",
  "image": "kontorprotocol/kontor-build:$rustc_version",
  "rustc": "$rustc_version",
  "wasm_opt": "binaryen $binaryen_version"
}
EOF
  )
done

echo "==> Done"
