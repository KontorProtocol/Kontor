#!/usr/bin/env bash
# Build the native mobile binaries for @kontor/sdk-native from the
# `core/kontor-mobile` uniffi crate. The JSI Turbo Module + TypeScript
# bindings are generated once up front by uniffi-bindgen-react-native
# (ubrn); the per-platform build steps only compile and link.
#
# Binaries are built with `--profile mobile` (core/Cargo.toml): a
# release-derived profile tuned for on-device size/perf (thin LTO,
# stripped symbols). The ubrn:build:* npm scripts pass the same profile
# so ubrn assembles from target/<triple>/mobile/.
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

# Single in-script source for the target lists. Must match
# ubrn.config.yaml (ios.targets / android.targets), which ubrn reads to
# assemble the xcframework/jniLibs; the completeness checks below fail
# the build if the two drift.
IOS_TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
ANDROID_TARGETS=(aarch64-linux-android armv7-linux-androideabi x86_64-linux-android)
ANDROID_ABIS=(arm64-v8a armeabi-v7a x86_64)
# Matches minSdkVersion in android/gradle.properties.
ANDROID_PLATFORM=24

build_ios() {
  rustup target add "${IOS_TARGETS[@]}"
  npm run ubrn:build:ios
  # ubrn writes the framework to the package root (the podspec's
  # vendored_frameworks path).
  [ -d KontorSdkNativeFramework.xcframework ] || {
    echo "ERROR: KontorSdkNativeFramework.xcframework was not produced" >&2
    exit 1
  }
}
build_android() {
  : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your Android NDK path}"
  rustup target add "${ANDROID_TARGETS[@]}"
  # ubrn 0.29.x drives cargo-ndk with `--no-strip`, an option cargo-ndk
  # >= 4 removed. Build the ABIs ourselves (same invocation works on
  # cargo-ndk 3 and 4) and let ubrn only assemble the jniLibs from the
  # prebuilt libraries.
  local ndk_targets=()
  local abi
  for abi in "${ANDROID_ABIS[@]}"; do ndk_targets+=(-t "$abi"); done
  (cd ../core && cargo ndk --platform "$ANDROID_PLATFORM" \
    "${ndk_targets[@]}" \
    build -p kontor-mobile --profile mobile)
  npm run ubrn:build:android -- --no-cargo
  # ubrn's --no-cargo path silently skips ABIs whose prebuilt library is
  # missing (it filters on file existence); assert every expected ABI
  # actually landed in jniLibs.
  for abi in "${ANDROID_ABIS[@]}"; do
    ls android/src/main/jniLibs/"$abi"/libkontor_mobile.* >/dev/null 2>&1 || {
      echo "ERROR: jniLibs/$abi is missing libkontor_mobile — ABI list drift?" >&2
      exit 1
    }
  done
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
