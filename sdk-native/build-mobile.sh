#!/usr/bin/env bash
# Build the native mobile binaries for @kontor/sdk-native from the
# `core/kontor-mobile` uniffi crate. The JSI Turbo Module + TypeScript
# bindings are generated once up front by uniffi-bindgen-react-native
# (ubrn); the per-platform build steps only compile and link.
#
# Prerequisites (see README.md):
#   - Rust + `rustup target add` the iOS/Android triples (done below)
#   - `npm install` here — it pulls the `ubrn` CLI (an npm package,
#     NOT a cargo crate)
#   - iOS:     Xcode (macOS runner)
#   - Android: Android NDK (ANDROID_NDK_HOME) + `cargo install cargo-ndk`
#
# Usage: ./build-mobile.sh [ios|android|all]   (default: all)
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${1:-all}"

add_ios_targets() {
  rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
}
add_android_targets() {
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
}

build_ios() {
  add_ios_targets
  npm run ubrn:build:ios
}
build_android() {
  : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your Android NDK path}"
  add_android_targets
  # ubrn 0.29.x drives cargo-ndk with `--no-strip`, an option cargo-ndk
  # >= 4 removed. Build the three ABIs ourselves (same invocation works
  # on cargo-ndk 3 and 4; ABI list mirrors ubrn.config.yaml) and let
  # ubrn only assemble the jniLibs from the prebuilt libraries.
  (cd ../core && cargo ndk --platform 23 \
    -t arm64-v8a -t armeabi-v7a -t x86_64 \
    build -p kontor-mobile)
  npm run ubrn:build:android -- --no-cargo
}

case "$TARGET" in
  ios | android | all) ;;
  *)
    echo "usage: $0 [ios|android|all]" >&2
    exit 1
    ;;
esac

# Generate the bindings once; the builds below don't regenerate them.
npm run ubrn:generate

case "$TARGET" in
  ios) build_ios ;;
  android) build_android ;;
  all)
    build_ios
    build_android
    ;;
esac

echo "Done. Generated bindings in src/generated/, native artifacts under ios/ and android/."
