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

# Pin CARGO_HOME to a fixed in-repo path. cargo bakes dependency source paths into
# the wasm as panic locations (<CARGO_HOME>/registry/src/.../foo.rs), so the same
# source builds DIFFERENT bytes under different CARGO_HOME — e.g. the image default
# /usr/local/cargo when CI invokes this directly, vs a local cache. Fixing it here
# makes the build identical however this script runs. (trim-paths, the cargo flag
# that would remap these away, isn't stabilized in 1.96.) Under /build it also
# persists across local runs (the repo is mounted there), so rebuilds stay fast.
export CARGO_HOME=/build/.build-cache/cargo
mkdir -p "$CARGO_HOME"

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
    # Clean only the ephemeral target wasm (incl. _opt) up front, so a removed or
    # renamed contract's stale artifact can't be re-optimized. Committed binaries/
    # are left untouched until the build succeeds — a failed build must not nuke
    # the genesis/fixture bytes in the (bind-mounted) working tree.
    for w in target/wasm32-unknown-unknown/release/*.wasm; do rm -f "$w"; done
    cargo build --release
    for wasm in target/wasm32-unknown-unknown/release/*.wasm; do
      case "$wasm" in *_opt.wasm) continue ;; esac
      opt="${wasm%.wasm}_opt.wasm"
      wasm-opt -Oz --enable-bulk-memory --enable-sign-ext "$wasm" -o "$opt"
      brotli -Zf "$opt" -o "binaries/$(basename "$wasm").br"
    done
    # Build succeeded: now prune committed binaries for contracts that no longer
    # exist (no matching freshly-built wasm), so binaries/ reflects exactly the
    # current members. Doing it here, not before the build, keeps a failed build
    # from leaving the tree without its committed artifacts.
    for br in binaries/*.wasm.br; do
      base="$(basename "$br" .wasm.br)"
      [ -f "target/wasm32-unknown-unknown/release/$base.wasm" ] || rm -f "$br"
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
