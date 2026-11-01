# Independently built protocol bundles

K1 introduces a qualification executable and reusable builder. The production
node still uses its existing P1 execution path. K2a defines the semantic adapter,
K2b extracts P1 and changes the node build, and K7 introduces actual activation.
Passing this qualification does not mean those phases are implemented.

K1-REPIN uses `protocol-bundles/pulley-first` and `pulley-second` as the active
graphs, while retaining the original `first` and `second` manifests and locks
unchanged as historical development inputs. Stable output labels `first` and
`second` map to the active directories through `tools/protocol-bundles/recipes.py`.
Both historical and active locks remain covered by the dependency audit.

| Output | Directory | Wasmtime version | Immutable fork revision | Lifting rate |
| --- | --- | --- | --- | ---: |
| first | pulley-first | 51.0.0-kontor.2 | 0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7 | 512 |
| second | pulley-second | 51.0.0-kontor.3 | 0dbc68b31c0bcf1a05c93122f1939fb8784e4e48 | 513 |

Both active proof engines resolve to `pulley64-unknown-unknown-elf`, with a
524,288-byte logical Wasm stack, 2,097,152-byte async fiber and 16-byte logical
stack alignment. Resolved engine settings are checked during execution and
included in the qualification report. Graph identity also binds the source
revision, version, manifest and lock hashes, directory, settings and lifting
rate. Historical versions and their normalized native suffixes stay reserved.

Guest concurrency remains disabled, matching S1's explicit engine settings.
The builder checks source parity and the live proof asserts resolved feature
flags. The `component-model-async` and `threads` compile features remain because
the configuration API uses them to expose explicit capability setters; these
features do not enable guest capabilities in the configured engines. The
`stack-switching` compile feature is removed from the active graphs.

An ordinary async host import is tested both ready immediately and returning
Pending before waking and resuming the synchronous guest. Both modes return 42
and charge the same exact fuel: `3 + 4 * lifting_rate`, or 2051 and 2055 in the
two graphs. The guest executes a constant, call and return; lifting the host
argument tuple and guest result tuple accounts for two tuple nodes and two u32
nodes. Host readiness must not change this charge. The existing pure component
proof retains its distinct 1026/1028 charges.

This qualifies coexistence of the proof engines. S2 still qualifies the actual
production runtime's stack and performance behavior, OWNERSHIP handles
cancellation, and K2b must exercise the full semantic runtime through both
bundles. These proof settings do not close those gates.

## Build and evidence

Run `RUSTUP_TOOLCHAIN=1.99.1 RUSTC_WRAPPER= ./tools/kontor protocol-bundles` from
the checkout. The command builds the two graphs sequentially with at most two
compiler jobs, links their exact current artifacts into one native executable,
audits ownership, then runs the real VM, crypto and consensus qualification.
Use `--offline` after fetching both manifests to avoid dependency downloads.
Use `--output PATH` to keep evidence elsewhere. Relative output paths resolve
from the checkout root, including when the bootstrap enters `core`.
Concurrent invocations sharing
an output root are rejected. `--target` must match the supported native host.

The supported targets are Linux ARM64, Linux x86-64 and macOS ARM64. CI uses
release on each, matching the current node tests on macOS. Linux runs in the
root Dockerfile's `protocol-bundle-qualification` target, derived from the same
`builder-base` as the node. The ordinary node image is unchanged by K1.
The development profile is available for local diagnosis.

Evidence lives under `OUTPUT/TARGET/PROFILE`. Only a successful run writes
`qualification.json`. A previous success marker is removed before rebuilding.
Logs and source inventories remain after failure. A leftover `proof-wal`
directory is deliberately not deleted automatically: inspect failed engine
ownership before removing it and rerunning. CI uploads inventories and logs,
including failures; it does not upload build caches or treat a cache hit as
qualification.

Install the pinned symbol reader with
`rustup component add --toolchain 1.99.1 llvm-tools-preview` before a local run.
CI and the qualification image install it explicitly. The audit uses that
toolchain's `llvm-nm`, including for Darwin standard-library LLVM bitcode that
older platform readers cannot decode. Addressless bitcode definitions still
participate in ownership and collision checks; final executable definitions
must have concrete addresses. Reader failures reject qualification and retain
their diagnostic, never accept partial symbol output.

The evidence records resolved packages and features, both lockfiles, source
hashes, inherited workspace manifests and Cargo configuration, compiler and
sysroot inputs, build flags, exact staged rlibs and native archives, compiler
plugins, common runtime ownership, final symbol ownership and executable hash.
The symbol reader's path, hash and version are also recorded. The current report
records the native environment and C compiler version, but does not hash the
selected linker backend. K11 release attestation must capture the actual driver
invocation and backend selection, including Rust's linker flags, before claiming
that identity. K1 verifies ownership in the produced executable itself.
Source and staged artifact checks run across compilation and qualification.
Git checkouts must match their pinned commit objects, including raw tracked
file contents, symlink targets, executable modes, staged indexes and recursive
submodule identities. Untracked and ignored files are rejected apart from
Cargo's exact administrative markers. This catches edits made before the build,
including files marked assume-unchanged in Git's index.
Verification ignores replacement refs, rejects graft files and rehashes the
pinned commit and reachable tree objects instead of trusting the local object
database's mapping. Git's own corruption checks vary by operation and version.
Registry source files must match the cached crate archive whose SHA256 matches
the lockfile. Keep those archives in Cargo's cache for offline qualification;
missing archives fail verification rather than trusting an edited extraction.
Absolute source paths and platform inputs are recorded. This is an audit of
the actual build, not a claim that different checkouts or platforms produce
byte-identical executables.

## Isolation and common ownership

### Production node build under development

K2b adds `--build-executors` and `--build-node` to the same builder. These modes
use production recipes independently of the proof recipes. The executor contains
the actual retained runtime, host bindings, semantic policy and dependencies.
The separate `protocol-bundles/node` workspace owns node services and physical
storage, and its resolved graph must not contain Wasmtime or an executor crate.

The production recipes `executor-first` and `executor-second` build the actual
P1 implementation against Wasmtime `51.0.0-kontor.2` and `51.0.0-kontor.3`,
respectively. The second enables `addr2line` to exercise independent feature
resolution. Both retain the P1 lifting rate of 512. These build labels do not
assign a network protocol version or activate an upgrade.

Shared built-in host types express a compatible Wasmtime dependency, while each
embedding workspace patches it to its exact retained fork. This prevents those
types from silently pulling core's older VM into a newer executor. The builder
still requires exactly one expected Wasmtime identity per executor. Guest builds
leave that optional host dependency disabled.

`--build-executors` only stages libraries. `--build-node` additionally builds the
Kontor binary, injects the staged facade into the node library, supplies its
dependency search paths to both node compiler invocations, and checks native
ownership in the final executable. A content-keyed workspace compiler wrapper
makes Cargo rebuild the node when externally staged executor inputs change,
without invalidating every node dependency. The wrapper captures the binary's
codegen objects, which join the current Cargo archive inventory as concrete
node-owned inputs to the audit.

For the bounded integration harness, build with `--build-node
--node-qualification`, then run the recorded executable with `qualify-executors`.
The opt-in Cargo feature keeps that command out of ordinary node builds. It uses
fresh temporary databases and one node owner service to exercise both actual
factories, comparing genesis and resumed genesis, real views and their error
classification, committee derivation, malformed recognition, and lifecycle
rollback/replay. Its raw transaction fixture publishes the committed counter
contract, exercises fee and deposit accounting, distinguishes contract-result
errors from outer execution failures, and compares simulation/inspection,
rollback/replay and commit. Final views check successful calls after failures and
that failed writes did not persist. Synthetic publication provenance tests the
stored claim, not reproducibility of that claim; the pinned contract workflow
checks the committed fixture bytes. Bitcoin signature validation is outside this
execution harness. It emits JSON observations only after every assertion succeeds.
The same feature on the in-tree indexer supplies a comparison route; using it
alone does not establish compatibility with the qualified pre-extraction source.
This harness is part of K2b acceptance, not its entire transaction and ownership
coverage. Native ownership is checked by the builder before running it.

The same opt-in executable provides `kontor qualify-executor-baseline ARCHIVE`.
Supply the preserved pre-extraction directory containing `inputs.json`,
`baseline.json`, `seed.db` and `transaction.bin`. The command verifies the input
checksums and source agreement, copies the seed into temporary databases, and
replays both unbatched and batched scenarios through each linked executor and
the real node coordinator. It compares complete logical database snapshots and
simulation results, including confirmation, rollback and reconfirmation without
duplicate execution or charges. Recognition compares the exported transaction
ID, index and operation positions; parsed instructions remain graph-private and
their materialized inspection is checked by simulation. This is an explicit
projection of the old recognition record, not byte equality of that record.
The command stops and awaits its local consensus engine after each scenario,
rejects any stage mismatch, and leaves the supplied archive unchanged. Its
successful JSON output binds the baseline, seed and transaction hashes to the
observations. Retain that output with the builder's source and binary evidence.

Production evidence is under `OUTPUT/TARGET/PROFILE/executors`. Its
`executor-build.json` records staged libraries, and `node-build.json` records a
successful node build and ownership audit. Neither is execution qualification.
Failure removes the corresponding old success marker and preserves logs.
Actual multi-executor behavior, cleanup, baseline compatibility and platform
qualification remain K2b acceptance requirements.

For a production release executable, use:

```sh
./tools/kontor protocol-bundles --build-node --profile release \
  --output target/protocol-evidence --install-node target/bin/kontor
```

Installation checks the copied bytes against the audited executable hash before
atomically replacing the destination. It does not strip or otherwise transform
the binary. `node-build.json` records the installed path and hash. A plain
`cargo build` in the core workspace remains an in-tree development/test build;
it does not establish retained dependency isolation.

The Docker `builder` stage invokes the same Python builder and installs that
audited output into the runtime image. Its `cacher` stage fetches the three locked
graphs; it no longer compiles a unified workspace whose artifacts the isolated
graphs cannot reuse. The opt-in `protocol-bundle-qualification` image uses
`tools/protocol-bundles/qualify_node.py` to build and execute both real graphs.
The runner rejects stale or changed binaries, missing graphs/cases, mismatched
observations and subprocess failures, and records raw output hashes with the
node build report hash in `executors/node-execution.json`. Its 300-second timeout
is a test timeout, not a Kontor execution cutoff. Full release-image and platform
qualification is still required before the phase can merge.

`tools/protocol-bundles/compare_node.py` verifies the downloaded linked-node
results against an explicit policy: `release` requires Linux x86-64, Linux ARM64
and macOS ARM64 release results; `full` requires both dev and release on all three.
The workflow uses release automatically and exposes full comparison only through
manual dispatch. Missing, duplicate or unexpected cells and failed upstream jobs
are errors. The comparator verifies raw logs, source inventories, local package
files, workspace/graph identities, linker inputs and ownership-report hashes,
then requires identical execution observations across the required cells.
Package documentation and Git ignore files omitted by Docker are excluded from
source equality. Python comparator and test edits do not invalidate unchanged
runtime/build sources; the original source-inventory hashes remain verified.
This bounded linked-node check complements the existing stack qualification and
dev smoke checks. It does not replace their coverage or establish all executions
from the sampled scenarios.

The workflow selects changes from the complete Git diff, including deleted and
renamed inputs. Comparator and Python test changes run the builder/evidence
controls on one Linux runner without repeating the platform builds. Changes to
node execution or build inputs still require the selected matrix; missing Git
history requires qualification. Unrelated changes skip both groups. Builder
checks run once before the matrix rather than once per platform.

Production audit checks the graph-private native symbols that survive linking.
Proof mode additionally requires the specific helpers exercised by its fixture.
An unused proof operation, or a dependency absent from the real executor, is not
a reason to add that dependency to production. Both modes retain input ownership,
reference ownership and final-definition checks.
The production node also declares the platform C++ runtime used by its ZeroMQ
dependency: `libstdc++.so.6` on Linux or `/usr/lib/libc++.1.dylib` on macOS.
Its actual loaded path, library hash and resolved exports are recorded like the
other shared platform libraries. Proof mode does not gain this allowance.

### Shared compiler and graph-private inputs

Each graph has its own Cargo workspace, lock, feature resolution, output path
and compiler metadata. A rustc wrapper adds the graph identity to both target
and host units, including proc macros, while retaining Cargo's unit metadata.
It invokes the exact pinned compiler and rejects a second wrapper. Compiler
plugins are compiler inputs, never node runtime libraries. Bidirectional
wrong-plugin controls require the distinct metadata hashes to reject mixing.

The executable consumes only artifacts emitted by the current Cargo invocation.
The input audit includes Rust and anonymous symbols, not only native helpers.
It rejects cross-graph definitions and references, graph definitions that shadow
common inputs, undeclared imports, global allocators and native symbols without
an owner. Common Rust definitions must appear in the pinned sysroot or the actual
host object files. Platform imports resolve within explicitly allowed runtime
library scopes, with their paths and hashes recorded where files are available.
macOS system libraries may instead reside in the dyld shared cache.

On Linux, `_GLOBAL_OFFSET_TABLE_` references require the actual final executable
to contain that exact local linker anchor (data or absolute symbol). Its address
and kind are recorded separately. This does not permit a bundle to define the
anchor, waive an unknown import, or treat it as optional when absent.

The three optional weak system-libunwind registration imports are named
explicitly. They remain optional only when every reference is weak; making one
strong fails qualification if no owner exists. Darwin uses `nm -m` to retain
the weak-reference attribute, unlike the name-only undefined output. See the
[LLVM nm format documentation](https://www.llvm.org/docs/CommandGuide/llvm-nm.html).

Both graphs share one pinned standard library, allocator and unwind runtime.
The proof boundary carries standard-library values, closures and opaque
`Box<dyn Any + Send>` owners. Tokio values from different graphs cannot cross
that boundary. Wrong-graph opaque owners are rejected. Exported calls contain
panics, including a panic in the host callback. Engine owners are dropped on
control threads, where their graph's destructor can finish joining workers.

## Process resources

Bundles may not subscribe to node control signals or spawn children. A source
check guards maintained Kontor/Malachite call sites; it is a review tripwire,
not a language sandbox. Third-party behavior requires source review. The live
proof verifies node SIGTERM/SIGINT delivery and child exit status with both
engines running and across repeated replacements.

Explicit resident resources are Wasmtime's Unix trap handlers and Rayon pool,
one blst crypto pool per graph, one futures-timer helper per graph and one Tokio
Unix signal registry socket pair per graph. The blst jobs hold crypto inputs,
not node callbacks or state/signing authority. Completion precedes the caller's
return, though final closure cleanup may follow. A stalled crypto job can block
its caller; a timeout must retain ownership rather than free its inputs.

The proof records cold and per-graph crypto, VM and engine counts before checking
repeated use. It requires bounded one-time allocation and no replacement growth.
The blst pool is separate from the VM pool. A future production node with its
own blst copy plus two bundles can retain three pools. These resources stay
resident; bundle unloading is unsupported.

## Changing a retained bundle

1. Preserve the old manifest, lock, source identity and semantics. Add a new
   protocol mapping in the later production phases rather than rewriting history.
2. Assign each retained Wasmtime graph a unique immutable package version and
   native prefix, even when its VM code is otherwise unchanged. Reusing VM code
   requires a new version-only fork release until a separate native namespace
   mechanism has been implemented and reviewed.
3. Resolve and commit the new lock deliberately. Keep F2 native patches and F3
   managed-engine ownership. Do not change blst threading features to make
   resource counts pass. Preserve portable lifting charges.
4. Run the negative controls and real qualification on every shipped node
   platform. Audit both bundle locks using the existing core advisory policy.
5. Obtain independent and Interlink reviews of semantics, native/process
   ownership and integration. Compiler changes require renewed qualification of
   every retained protocol. Historical transaction replay alone is insufficient.

The conflicting itoa patch requirements demonstrate why one unified Cargo
resolution is insufficient. Deliberately different serde_json features, VM
lifting prices and compile-time Tokio types prove that the two graphs remain
distinct. These differences are qualification fixtures, not a definition of P2.
