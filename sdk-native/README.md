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
`react-native` wiring, and this package's binding layer are done:
`src/index.ts` installs the Rust crate into the JS runtime
(`installRustCrate()` + uniffi `initialize()`) and re-shapes the generated
bindings into the `KontorBackend` surface. The generated bindings are
committed (the published package ships them) and CI fails if they drift
from what `npm run ubrn:generate` emits.

Still to do, in a mobile dev environment:

1. **Expo module glue** — `expo-module.config.json` (scaffold with
   `create-expo-module` + ubrn's generated Turbo Module spec).
2. **On-device smoke test** — an example app exercising sign/verify and
   the numerics round-trip on Hermes.

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

The Android path is verified working (`cargo ndk -t arm64-v8a build -p
kontor-mobile` produces `libkontor_mobile.so`). Full verification runs in CI —
see `.github/workflows/mobile.yml`.
