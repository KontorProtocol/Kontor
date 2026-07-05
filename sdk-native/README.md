# @kontor/sdk-native

React Native (JSI) backend for [`@kontor/sdk`](../sdk). Provides the exact
same `KontorBackend` surface as the WASM component — BLS signing, `Inst`
(de)serialization, the `Wit` WAVE codec, and `numerics` — but backed by a
**native library** built from the same Rust source (`core/kontor-mobile`,
a uniffi wrapper over `core/kontor-core`), because Hermes/JSC has no
`WebAssembly`.

Because it's the same Rust the indexer compiles, on-device bytes are
identical to the chain's verification path.

## How it fits together

```
core/kontor-core   (pure Rust: BLS, Inst codec, Wit, numerics)
     ├── core/kontor-sdk     → WASM component  → @kontor/sdk (web/Node)
     └── core/kontor-mobile  → uniffi          → @kontor/sdk-native (RN)
                                   │
                        uniffi-bindgen-react-native
                                   ↓
                   JSI Turbo Module + TS bindings (SYNC)
```

`@kontor/sdk` selects this module automatically on React Native via the
`react-native` conditional export in its `package.json` (which points at
`dist/index.native.js`, a bundle that swaps the WASM boundary for this
package). Consumers just `import { KontorSession, Decimal } from "@kontor/sdk"`.

The calls are **synchronous** (JSI), matching the web API — `Decimal.add`,
`wit.encodeCall`, `blsSign` do not become Promises on mobile.

## Status

The Rust crates (`kontor-core` + `kontor-mobile`), the SDK-side
`react-native` wiring, this package's binding layer, and the Expo
integration are done: `src/index.ts` installs the Rust crate into the JS
runtime (`installRustCrate()` + uniffi `initialize()`) and re-shapes the
generated bindings into the `KontorBackend` surface. The generated
bindings are committed (the published package ships them) and CI fails if
they drift from what `npm run ubrn:generate` emits. Both native targets
build under `--profile mobile`: the Android `.so`s and the iOS
`KontorSdkNativeFramework.xcframework` (device `arm64` + simulator
`arm64`/`x86_64`).

Still to do, in a mobile dev environment:

1. **On-device smoke test** — an example app exercising sign/verify and
   the numerics round-trip on Hermes.

### Expo integration

Consumer Expo apps get zero-config linking: `@kontor/sdk-native` ships an
`expo-module.config.json` (so Expo autolinking sees it) and an
`app.plugin.js` config plugin. Add the plugin to the app config —

```json
{ "expo": { "plugins": ["@kontor/sdk-native"] } }
```

— and `expo prebuild` raises the two floors the prebuilt binaries require:
iOS deployment target ≥ 15.1 and Android `minSdkVersion` ≥ 24 (it only ever
raises them, never lowers a higher app target). Bare React Native apps link
via the podspec / `build.gradle` through the usual community-CLI
autolinking; there the deployment target / minSdk are set by hand.

## Building

```bash
# One-time tooling
cargo install cargo-ndk                 # Android cross-linking
npm install                             # pulls the `ubrn` CLI (see version note)

# Generate TS/C++ bindings from core/kontor-mobile
npm run ubrn:generate

# Compile native libs (needs Xcode for iOS, ANDROID_NDK_HOME for Android)
npm run build:mobile            # or: ./build-mobile.sh ios | android
```

Binaries are built with `--profile mobile` (defined in `core/Cargo.toml`):
release + thin LTO + `codegen-units=1` + stripped symbols. We ship the
**pre-linked `cdylib`** — a dynamic `.so` (Android) / dynamic-framework
xcframework (iOS) — not the `staticlib` `.a`. A static archive carries
every object of the crate and all its deps (blst, serde_json, wit-parser,
and a whole TypeScript compiler pulled in transitively) with no dead-code
elimination until the consumer's link (~80 MB per iOS slice, ~1.2 GB
unpacked across all ABIs); the linked cdylib is DCE'd and stripped down to
~3 MB per slice, keeping the published package around ~20 MB. The published
npm package must contain the binaries — `prepack` refuses to pack if they
are missing.

### Gotchas learned during setup

- **`uniffi-bindgen-react-native` is an npm package, not a cargo crate.** It ships
  the `ubrn` CLI. `cargo install uniffi-bindgen-react-native` does NOT work.
- **Version must match the `uniffi` crate.** `core/kontor-mobile` pins
  `uniffi = "0.29"`, so this package pins `ubrn` `0.29.3-1`. If you bump one,
  bump the other in lockstep (all published `ubrn` versions are `-N` prereleases).
- **Run `ubrn` from an interactive terminal.** In a headless / non-TTY context
  (background job, some CI shells) the CLI can hang with no output on first run.
  Locally, run it directly in your shell; in CI, allocate a TTY if needed.
- **Node LTS.** Use Node 20 or 22 (`nvm use 22`), not bleeding-edge (25+).
- **clap debug_assert.** ubrn 0.29.3-1's cli.cjs runs `cargo run` (debug), and with
  clap 4.6 that panics on a `#[clap(long, default_value = "false")]`-on-bool arg
  (`Argument 'native_bindings' is positional ... but action is SetTrue`). The npm
  scripts prepend `CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false` to disable dev
  debug-assertions and neutralize it — no ubrn source patch needed.
- **Android NDK** was found at `~/Library/Android/sdk/ndk/<version>`; set
  `ANDROID_NDK_HOME` to it. **iOS** needs full **Xcode** (Command Line Tools
  alone lack the iphoneos SDK).
- **`build-mobile.sh` bypasses `ubrn build`.** ubrn's platform build
  assembles the *static* archive (and on cargo-ndk ≥ 4 also trips over the
  `--no-strip` flag ubrn 0.29.x passes). The script instead compiles the
  cdylib per target with `cargo` / `cargo ndk` directly and assembles the
  shared artifacts itself: the `.so`s into `jniLibs/`, and the iOS dylibs
  into dynamic `.framework` bundles wrapped in the xcframework.

`./build-mobile.sh ios` is verified locally: it produces
`KontorSdkNativeFramework.xcframework` (8.6 MB — device `arm64` + simulator
`arm64`/`x86_64`, `@rpath` install name, 133 uniffi FFI symbols exported).
The Android `.so` build and the full on-device link/load run in CI (which
also reports the shipped artifact sizes) — see
`.github/workflows/mobile.yml`.
