# Wasm dependencies and shared builds

Agreed scope, 2026-09-14. These are two separate follow-up PRs after the Wasmtime 48.0.2 / initialization-fuel investigation in [PR #564](https://github.com/KontorProtocol/Kontor/pull/564).

## First PR: our WIT/WAVE and binding dependencies

- Upgrade our direct `wit-parser`, `wit-component`, and `wasm-wave` dependencies to 0.259 and `wit-bindgen`, `wit-bindgen-core`, and `wit-bindgen-rust` to 0.62.
- Leave Wasmtime's internal dependency versions under Wasmtime's control. Its internal 0.254 dependencies can coexist with our 0.259 dependencies.
- Remove duplicate WIT parsing where shared parser types allow it, including the second Resolve in `core/macros/src/import.rs`. Remove superseded code and comments about that version mismatch.
- Rebuild native contracts, test contracts, and the checked-in SDK component. Validate runtime loading/execution, macro behavior, WIT/WAVE conversion, SDK code generation, and SDK calls using the rebuilt outputs.
- Use the existing pinned contract container machinery for this PR. Do not mix in the build-command redesign.

The dependency upgrade starts from main and carries the Wasmtime 48.0.2 update without the intentionally failing diagnostic. PR #564 is closed without merging; its branch remains available for the upstream reproduction. The import macros now reuse one Resolve for validation, call shims, and binding generation. The separate `contract!` / `wit_bindgen::generate!` macro expansion stages retain their existing parsing and source-file tracking.

## Second PR: shared `kontor build`

- Add `kontor build` around the existing pinned container machinery, with the same build implementation used locally and in CI.
- Include contract compilation and SDK component/binding generation. Pin the SDK's currently unpinned Wasm tools and all other inputs needed for reproducible generated output.
- Extend reproducibility checks to the checked-in SDK output, including additions and deletions, as well as the native and test contract binaries.
- Remove superseded build scripts and migrate package scripts, CI workflows, documentation, and other callers to the shared command. Retain only necessary container/bootstrap internals, with one clear public build path.

Settle these decisions as part of this PR before implementing the build interface:

1. **Build architecture:** choose and document the supported build platform policy. The existing contract metadata records the producing architecture; builds on different architectures are not currently byte-identical. Local generation and CI verification must use matching pinned inputs without silently changing the committed platform.
2. **CLI bootstrapping:** a fresh checkout must be able to obtain/build the command without depending on outputs it is supposed to generate. Decide how the existing node CLI participates and keep the bootstrap path explicit and reasonably lightweight.
3. **Toolchain provenance:** generated metadata must describe the image and tools actually used. Define image pinning, fixed paths, tool versions, and lockfile enforcement for both contracts and SDK generation.

Validation should cover a clean build, a repeat build with identical committed outputs, local/CI parity on the chosen architecture, SDK behavior, and build failure handling that preserves the last successful generated outputs.

## Current investigation boundary

PR #564 contains the initialization fuel diagnostic and Wasmtime 48.0.2 update. CI confirmed the same measurements on both 48.0.1 and 48.0.2: 0 fuel on Ubuntu/x86_64 and 16,385 on macOS/aarch64; a 1,000-fuel budget succeeds on Ubuntu and traps on macOS. The 48.0.2 local library suite passed. Do not describe either follow-up PR as a fix for that fuel issue without separate evidence.

The discrepancy is reported in [Wasmtime #14331](https://github.com/bytecodealliance/wasmtime/issues/14331). Neither dependency upgrades nor build reproducibility changes settle the runtime's initialization-fuel policy.
