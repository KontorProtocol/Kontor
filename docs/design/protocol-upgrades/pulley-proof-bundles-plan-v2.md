# K1-REPIN: final Pulley proof graphs, proposal v2

Status: proposed for exact-revision agreement, 2026-10-28. No production edit
is authorized by this document alone. This is one Kontor PR, separate from
S2's production-runtime selection and from the later full semantic extraction.

## Baseline and dependencies

Start from S1's verified main merge
`208480b7cd10d0bc1eebc3f1e6e35a577b84e6e6`, whose tree equals reviewed head
`18637a8a4de9389a03f14127fe9ba1b77d92f829`. Fork A is merged at
`0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7`, version `51.0.0-kontor.2`.
Fork B is the version-only candidate
`58a60e34b69a75131e8593088dc7e30c5f972c48`, version `51.0.0-kontor.3`.
Implementation must pin B's actual verified merge after its reviews and CI,
not a branch name or this unmerged candidate.

This PR depends on both fork merges. S2 may proceed independently after S1
and fork A once its own revised plan is approved. S2 qualifies the actual
single-graph node runtime. K2b must still demonstrate the extracted semantic
runtime executing through both independently built bundles and repeat the
required six-cell qualification. K1-REPIN does not satisfy that later gate.

## Resulting behavior and scope

The default isolated bundle builder produces two real Wasmtime/Malachite proof
graphs using `.2` and `.3`, each selecting Pulley. Preserve the conflicting
itoa versions and deliberate portable lifting rates 512 and 513. The proof
continues exercising real cryptography, engine lifecycle, incompatible graph
types, native ownership, and process resources. It remains a qualification
executable, not the production semantic adapter.

Keep `protocol-bundles/first/Cargo.toml`, `first/Cargo.lock`,
`second/Cargo.toml`, and `second/Cargo.lock` byte-identical to S1. These reserve
the development identities `51.0.0-dev` at `bfdee9ba...` and `.1` at
`525ffede...`. Add `protocol-bundles/pulley-first` and `pulley-second` with
independently resolved, checked-in manifests and locks. Only the new pair is
built by default and in current CI. Historical source and reports remain
identified as development evidence.

The builder may retain stable `first`/`second` output labels, but its explicit
graph recipe maps those labels to the new directories. Every fingerprint,
report and attestation binds the directory, full Wasmtime version, immutable
fork commit, manifest and lock hashes. Verification must reject a historical
artifact relabelled as a current graph. Identity validation scans historical
reservations as well as active graphs and rejects reuse of either the full
version or its normalized native suffix. Distinct revisions cannot claim a
reserved version.

Update the proof VM configuration to request `pulley64` explicitly and assert
the resolved `pulley64-unknown-unknown-elf` target and `Engine::is_pulley()`.
Disable the same guest component-async, extra async builtins, async-stackful,
component threading, error-context, shared-thread, stack-switching, Store
concurrency and core-thread capabilities as S1. Keep asynchronous host
suspension, synchronous guest calls, NaN policy and portable lifting charges.
Remove guest-concurrency-only features from the new proof manifests where
unneeded. A focused parity check must detect drift from S1's capability-off
set without treating proof-specific lifting rates as node settings. Run that check
in CI whenever any compared source changes, including
`core/indexer/src/runtime/mod.rs`; update workflow path filters accordingly.

Explicit proof settings are 524,288 bytes for `max_wasm_stack`, 2,097,152 for
`async_stack_size`, and checked 16-byte logical stack rounding. Attest the
configured settings and resolved execution target, and bind them into build
identity and verification. These settings describe the proof; S2 must agree
and qualify its production settings separately. No diagnostic native-JIT
fallback is permitted in the new proof graphs.

Modules: `protocol-bundles`, `tools/protocol-bundles`, their existing CI and
Docker qualification wiring, and protocol build/maintenance documentation.
Do not change the node's `core/Cargo.toml` Wasmtime pin or select Pulley in
`Runtime::new_engine` in this PR. Do not change Malachite source, consensus
wire behavior, protocol activation, guest ownership, or protocol semantics.

## Invariants and acceptance evidence

1. One pinned Rust 1.99.1 toolchain builds independently locked graphs with
   distinct compiler metadata and native namespaces into one executable.
   Preserve the existing independent feature and conflicting dependency
   tests; no workspace unification or IPC boundary.
2. Run the existing full native input/final-link ownership audit on the actual
   new bundles. Cache, profiling and debug-builtins remain forbidden, including
   their native symbols. Default-feature Wasmtime test binaries containing
   debug-builtins are not evidence for this gate. Preserve common compiler,
   signal, unwind and process-resource ownership rules and their negative
   controls.
3. Preserve all existing real VM, portable lifting, crypto, Malachite startup,
   shutdown, repeated replacement and cold resource-count checks. Update
   expected values only when justified by actual Pulley execution; retain a
   deliberate 512/513 metering distinction and fail if it disappears. Each graph
   must also instantiate a synchronous component with an ordinary asynchronous
   host import that actually returns Pending, wakes and resumes. Assert its
   result and metering with guest concurrency disabled. A pure guest
   `call_async` or fuel-yield test alone does not establish host suspension.
4. Add focused negative controls for a reserved historical version/suffix,
   duplicate active suffix, wrong source commit or graph directory, relabelled
   historical artifact, missing target/stack/rounding attestation and an
   unsupported capability. Check actual expected settings, not only that two
   incomplete reports agree. Preserve forbidden-feature rejection.
5. Verify historical manifest/lock hashes are unchanged. Review the new lock
   graph inventory: intended Wasmtime source/version updates and necessary
   feature changes are allowed; unrelated dependency churn is not.
6. Run the existing three-platform release bundle qualification and Docker
   cache qualification on the current PR head. Retain raw logs, compiler and
   artifact hashes, source identities, ownership inventories and lifecycle
   results. Existing relevant local builder tests must pass before PR creation.

All implementation receives lead review, independent subagent review and
Interlink review, with findings addressed or explicitly declined. Create the
PR after reviews, fix CI failures, merge only on exact-head green, and verify
the actual merge. Update the implementation ledger, maintenance guide and
owner-private dark Site. Report the proof's limits explicitly: no production
runtime switch, no completed S2 stack/performance qualification, no completed
OWNERSHIP gate, and no full semantic dual-bundle integration yet.
