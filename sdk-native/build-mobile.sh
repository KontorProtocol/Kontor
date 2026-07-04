#!/usr/bin/env bash
# Build the native mobile binaries for @kontor/sdk-native from the
# `core/kontor-mobile` uniffi crate, and generate the JSI Turbo Module +
# TypeScript bindings via uniffi-bindgen-react-native (ubrn).
#
# Prerequisites (see README.md):
#   - Rust + `rustup target add` the iOS/Android triples (done below)
#   - uniffi-bindgen-react-native: `cargo install uniffi-bindgen-react-native`
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

case "$TARGET" in
  ios)
    add_ios_targets
    npm run ubrn:build:ios
    ;;
  android)
    : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your Android NDK path}"
    add_android_targets
    npm run ubrn:build:android
    ;;
  all)
    "$0" ios
    "$0" android
    ;;
  *)
    echo "usage: $0 [ios|android|all]" >&2
    exit 1
    ;;
esac

echo "Done. Generated bindings in src/generated/, native artifacts under ios/ and android/."
