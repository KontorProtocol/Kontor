#!/usr/bin/env bash
set -euo pipefail

# Workspace member: cargo writes outputs to the workspace target/ at
# core/target/, not the local crate's target/.
TARGET_DIR="$(cargo metadata --format-version=1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"

cargo build --release

# Size-optimize the core module before wrapping it as a Component.
# wasm-opt -Oz typically trims 10–30% off a Rust→WASM release build
# beyond what LLVM does on its own. Enable the WASM 2.0 features Rust
# emits by default (Rust edition 2024) so wasm-opt doesn't reject the
# input as invalid.
wasm-opt -Oz \
  --enable-bulk-memory \
  --enable-mutable-globals \
  --enable-nontrapping-float-to-int \
  --enable-sign-ext \
  --enable-reference-types \
  --enable-multivalue \
  "${TARGET_DIR}/wasm32-unknown-unknown/release/kontor_sdk.wasm" \
  -o "${TARGET_DIR}/wasm32-unknown-unknown/release/kontor_sdk.wasm"

wasm-tools component new \
  "${TARGET_DIR}/wasm32-unknown-unknown/release/kontor_sdk.wasm" \
  -o "${TARGET_DIR}/wasm32-unknown-unknown/release/kontor_sdk_component.wasm"

# jco lives in sdk/node_modules; invoke it from there so `npx` resolves
# the local install instead of fetching a placeholder from the registry.
# TARGET_DIR is absolute (resolved via cargo metadata above) so the
# component path survives the cd.
(cd ../../sdk && npx jco transpile \
  "${TARGET_DIR}/wasm32-unknown-unknown/release/kontor_sdk_component.wasm" \
  --name kontor-sdk \
  -o src/component)
