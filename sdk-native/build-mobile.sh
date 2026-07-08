#!/usr/bin/env bash
# Build the native mobile binaries for @kontor/sdk-native from the
# `core/kontor-sdk-native` uniffi crate. The JSI Turbo Module + TypeScript
# bindings are generated once up front by uniffi-bindgen-react-native
# (ubrn); the per-platform steps here only compile and assemble.
#
# SHARED, not static. We ship the pre-linked `cdylib` (a stripped .so /
# dynamic .framework), NOT the `staticlib` .a. A static archive carries
# every object of the crate + all deps (blst, serde_json, wit-parser, and
# even a whole TypeScript compiler dragged in transitively) with no
# dead-code elimination until the consumer's final link — ~80 MB per iOS
# slice, ~1.2 GB unpacked across all ABIs. The cdylib is already linked and
# DCE'd, so the same code is ~3 MB per slice (~20x smaller). The consumer
# links it dynamically: Android via CMake `SHARED IMPORTED` + the .so in
# jniLibs; iOS via a dynamic-framework xcframework that CocoaPods embeds.
# This is why we bypass `ubrn build` (which assembles the static archive)
# and assemble the artifacts here instead — same pattern as the cargo-ndk
# bypass below.
#
# Binaries are built with `--profile mobile` (core/Cargo.toml): a
# release-derived profile (thin LTO + codegen-units=1 + stripped symbols).
# Because we ship the linked cdylib, LTO optimizes the shipped artifact and
# leaves no embedded bitcode behind (unlike a staticlib, where it would).
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

# Single in-script source of truth for the target lists (binding generation
# reads the uniffi metadata from a host build, not these). Kept mirrored in
# ubrn.config.yaml as documentation. IOS_TARGETS / ANDROID_TARGETS are
# index-aligned with the xcframework slices / ANDROID_ABIS.
IOS_TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
ANDROID_TARGETS=(aarch64-linux-android armv7-linux-androideabi x86_64-linux-android)
ANDROID_ABIS=(arm64-v8a armeabi-v7a x86_64)
# Matches minSdkVersion in android/gradle.properties.
ANDROID_PLATFORM=24
# Matches min_ios_version_supported (podspec) / app.plugin.js floor. blst's
# C objects are built against the runner's iOS SDK; rustc's default iOS
# deployment target (10.0) lacks symbols like ___chkstk_darwin, so the
# cdylib link fails unless we pin it here.
IOS_MIN=15.1

# The uniffi cdylib basename produced by cargo for kontor-sdk-native.
LIB=libkontor_sdk_native
# The dynamic-framework name embedded in the xcframework.
FRAMEWORK=KontorSdkNative
XCFRAMEWORK=KontorSdkNativeFramework.xcframework

# Locate the cdylib cargo emitted for a target (it lives at the profile
# root, or under deps/ depending on cargo version).
find_cdylib() { # $1 = triple, $2 = extension (so|dylib)
  ls "../core/target/$1/mobile/$LIB.$2" \
     "../core/target/$1/mobile/deps/$LIB.$2" 2>/dev/null | head -1
}

# Wrap a dylib (or fat dylib) in a minimal dynamic .framework bundle with an
# @rpath install name, so CocoaPods embeds + re-signs it into the host app.
make_ios_framework() { # $1 = input dylib, $2 = output parent dir
  local dylib=$1 fwdir="$2/$FRAMEWORK.framework"
  mkdir -p "$fwdir"
  cp "$dylib" "$fwdir/$FRAMEWORK"
  install_name_tool -id "@rpath/$FRAMEWORK.framework/$FRAMEWORK" "$fwdir/$FRAMEWORK"
  cat > "$fwdir/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>$FRAMEWORK</string>
  <key>CFBundleIdentifier</key><string>com.kontor.sdknative.$FRAMEWORK</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>$FRAMEWORK</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>MinimumOSVersion</key><string>$IOS_MIN</string>
</dict></plist>
PLIST
}

build_ios() {
  rustup target add "${IOS_TARGETS[@]}"
  local t
  for t in "${IOS_TARGETS[@]}"; do
    (cd ../core && IPHONEOS_DEPLOYMENT_TARGET="$IOS_MIN" \
      cargo build -p kontor-sdk-native --profile mobile --target "$t")
  done

  # Assemble a dynamic-framework xcframework: one framework for the device
  # (arm64) slice, one for the simulator slice (arm64-sim + x86_64 fat).
  local work
  work="$(mktemp -d)"
  local dev sima simx
  dev=$(find_cdylib aarch64-apple-ios dylib)
  sima=$(find_cdylib aarch64-apple-ios-sim dylib)
  simx=$(find_cdylib x86_64-apple-ios dylib)
  [ -n "$dev" ] && [ -n "$sima" ] && [ -n "$simx" ] || {
    echo "ERROR: an iOS cdylib is missing (dev=$dev sim-arm64=$sima sim-x86=$simx)" >&2
    exit 1
  }
  make_ios_framework "$dev" "$work/device"
  lipo -create "$sima" "$simx" -output "$work/sim_fat.dylib"
  make_ios_framework "$work/sim_fat.dylib" "$work/sim"

  rm -rf "$XCFRAMEWORK"
  xcodebuild -create-xcframework \
    -framework "$work/device/$FRAMEWORK.framework" \
    -framework "$work/sim/$FRAMEWORK.framework" \
    -output "$XCFRAMEWORK"
  rm -rf "$work"
  [ -d "$XCFRAMEWORK" ] || {
    echo "ERROR: $XCFRAMEWORK was not produced" >&2
    exit 1
  }
}

build_android() {
  : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your Android NDK path}"
  rustup target add "${ANDROID_TARGETS[@]}"
  # cargo-ndk wires the NDK toolchain (CC/AR/linker per target). We invoke
  # it directly (not via `ubrn build`) because ubrn >= 0.29 passes cargo-ndk
  # the `--no-strip` flag that cargo-ndk >= 4 removed, and because ubrn's
  # assembly copies the static .a — we want the cdylib .so instead.
  local ndk_targets=() abi
  for abi in "${ANDROID_ABIS[@]}"; do ndk_targets+=(-t "$abi"); done
  (cd ../core && cargo ndk --platform "$ANDROID_PLATFORM" \
    "${ndk_targets[@]}" \
    build -p kontor-sdk-native --profile mobile)

  # Place each cdylib .so into jniLibs. The app's CMake links it as
  # SHARED IMPORTED and Gradle packages it into the APK's lib/<abi>/;
  # System.loadLibrary pulls it in at runtime (see KontorSdkNativeModule.kt).
  local i triple
  for i in "${!ANDROID_TARGETS[@]}"; do
    triple="${ANDROID_TARGETS[$i]}"
    abi="${ANDROID_ABIS[$i]}"
    local so
    so=$(find_cdylib "$triple" so)
    [ -n "$so" ] || {
      echo "ERROR: cdylib for $triple ($abi) not found — ABI list drift?" >&2
      exit 1
    }
    mkdir -p "android/src/main/jniLibs/$abi"
    cp "$so" "android/src/main/jniLibs/$abi/$LIB.so"
  done
  # Assert every expected ABI landed.
  for abi in "${ANDROID_ABIS[@]}"; do
    [ -f "android/src/main/jniLibs/$abi/$LIB.so" ] || {
      echo "ERROR: jniLibs/$abi is missing $LIB.so — ABI list drift?" >&2
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

echo "Done. Generated bindings in src/generated/; native artifacts:"
# Informational summary — never let a missing per-platform artifact (e.g. no
# jniLibs on an iOS-only build) set a non-zero exit for the whole script.
{ [ -d "$XCFRAMEWORK" ] && du -sh "$XCFRAMEWORK"; } || true
{ [ -d android/src/main/jniLibs ] && du -sh android/src/main/jniLibs; } || true
exit 0
