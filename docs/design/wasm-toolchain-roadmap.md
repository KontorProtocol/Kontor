# Wasm dependencies and shared builds

Agreed scope, 2026-09-14. The dependency upgrade merged in [PR #565](https://github.com/KontorProtocol/Kontor/pull/565), followed by the initialization-fuel fix in [PR #566](https://github.com/KontorProtocol/Kontor/pull/566). The shared build command below follows those changes.

## Completed: our WIT/WAVE and binding dependencies

- Upgrade our direct `wit-parser`, `wit-component`, and `wasm-wave` dependencies to 0.259 and `wit-bindgen`, `wit-bindgen-core`, and `wit-bindgen-rust` to 0.62.
- Leave Wasmtime's internal dependency versions under Wasmtime's control. Its internal 0.254 dependencies can coexist with our 0.259 dependencies.
- Remove duplicate WIT parsing where shared parser types allow it, including the second Resolve in `core/macros/src/import.rs`. Remove superseded code and comments about that version mismatch.
- Rebuild native contracts, test contracts, and the checked-in SDK component. Validate runtime loading/execution, macro behavior, WIT/WAVE conversion, SDK code generation, and SDK calls using the rebuilt outputs.
- Use the existing pinned contract container machinery for this PR. Do not mix in the build-command redesign.

The dependency upgrade starts from main and carries the Wasmtime 48.0.2 update without the intentionally failing diagnostic. PR #564 is closed without merging; its branch remains available for the upstream reproduction. The import macros now reuse one Resolve for validation, call shims, and binding generation. The separate `contract!` / `wit_bindgen::generate!` macro expansion stages retain their existing parsing and source-file tracking.

## Shared `kontor build`

- Add `kontor build` around the existing pinned container machinery, with the same build implementation used locally and in CI.
- Include contract compilation and SDK component/binding generation. Pin the SDK's currently unpinned Wasm tools and all other inputs needed for reproducible generated output.
- Extend reproducibility checks to the checked-in SDK output, including additions and deletions, as well as the native and test contract binaries.
- Remove superseded build scripts and migrate package scripts, CI workflows, documentation, and other callers to the shared command. Retain only necessary container/bootstrap internals, with one clear public build path.
- Run CI's Rust tests with `-- --nocapture`, retaining the existing macOS crash-report uploads. This preserves pre-abort diagnostics that Rust's normal test capture can lose. Include this logging change in the shared-build PR; it does not fix the underlying macOS abort.

The implementation uses one lightweight `core/kontor-build` library from both
`kontor build` and the repository's `tools/kontor` bootstrap. The bootstrap has
no dependency on the generated contracts or SDK. `tools/build.json` fixes the
canonical linux/arm64 platform and actual published image digest; checksum-pinned
SDK tools run inside that image. CI uses the same command with `--check`.
See [the build guide](../../tools/BUILD.md) for provenance, upgrades, and recovery.

Validation should cover a clean build, a repeat build with identical committed outputs, local/CI parity on the chosen architecture, SDK behavior, and build failure handling that preserves the last successful generated outputs.

## Current investigation boundary

PR #564 contains the initialization fuel diagnostic and Wasmtime 48.0.2 update. CI confirmed the same measurements on both 48.0.1 and 48.0.2: 0 fuel on Ubuntu/x86_64 and 16,385 on macOS/aarch64; a 1,000-fuel budget succeeds on Ubuntu and traps on macOS. The 48.0.2 local library suite passed. Do not describe either follow-up PR as a fix for that fuel issue without separate evidence.

The discrepancy is reported in [Wasmtime #14331](https://github.com/bytecodealliance/wasmtime/issues/14331). PR #566 settled the runtime policy by disabling memory CoW and added fixed initialization-fuel regression checks that passed on Linux and macOS. The shared-build PR preserves that policy.

PR #566 also encountered an intermittent macOS integration-process abort in Wasmtime's Mach exception-handler thread. Both fuel regressions passed before the abort, and the full suite passed on retry. The exact Mach receive error/message was absent from the CI log. A local Rust test reproducer confirmed that a worker's `eprintln!` diagnostic is lost on abort under default capture and survives with `--nocapture`. The [failed job and crash artifacts](https://github.com/KontorProtocol/Kontor/actions/runs/34877799356/job/104089220507) remain evidence for a separate root-cause investigation; a passing retry does not establish an environmental cause.
