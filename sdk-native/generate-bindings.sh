#!/usr/bin/env bash
# Generate the TS/C++ JSI bindings for @kontor/sdk-native from the
# `core/kontor-sdk-native` uniffi crate.
#
# `ubrn generate all` reads the uniffi metadata out of a *compiled*
# library, so build kontor-sdk-native for the host first — a plain debug
# build; the metadata doesn't depend on target or profile.
set -euo pipefail
cd "$(dirname "$0")"

(cd ../core && cargo build -p kontor-sdk-native)

# Workspace member: cargo writes to the workspace target/ (core/target/).
TARGET_DIR="$(cd ../core && cargo metadata --format-version=1 --no-deps \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
LIB="$TARGET_DIR/debug/libkontor_sdk_native.dylib"
[ -f "$LIB" ] || LIB="$TARGET_DIR/debug/libkontor_sdk_native.so"

# `generate jsi bindings` (not `generate all`): only the TS/C++ bindings
# are generator-owned and drift-gated in CI. The TurboModule scaffold
# (src/index.ts, cpp/kontor-sdk-native.*, android/, ios/, the podspec) was
# scaffolded once by `generate all` and is hand-maintained since — `all`
# would clobber local fixes (e.g. build.gradle's kotlinVersion fallback)
# with the upstream templates.
#
# Run from the crate dir: the subcommand resolves the crate via `cargo
# metadata` in the cwd (it takes no ubrn.config.yaml).
# CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false: see "//ubrn-bug" in package.json.
# --no-format: prettier/clang-format availability varies by machine, and
# formatting would make the output non-deterministic — the CI drift gate
# (`git diff --exit-code` after regenerating) needs byte-identical output.
PKG_DIR="$(pwd)"
(cd ../core/kontor-sdk-native && CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false \
  "$PKG_DIR/node_modules/.bin/uniffi-bindgen-react-native" generate jsi bindings \
  --library "$LIB" --ts-dir "$PKG_DIR/src/generated" --cpp-dir "$PKG_DIR/cpp" \
  --no-format)
