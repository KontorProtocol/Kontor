# Independently built protocol bundles

The production `production-node` build links the prelaunch P1 executor and one
consensus runtime into one executable. Validated canonical history selects the executor;
installing a newer implementation does not activate it. One pinned Malachite
runtime handles networking and consensus across activations. It is independently
built for dependency ownership, but is not replaced on every protocol upgrade.
See [validator startup](validator-startup.md) for role promotion and protected
state, and [upgrade approvals](upgrade-approvals.md) for authorization and rehearsal.

## Prelaunch maintenance

Nothing has shipped to production. Current `core` sources and
`protocol-bundles/executor-first` are authoritative P1 inputs, including ordinary
Cargo builds and linked production builds. The unused `retained/p1` copy was
removed; its complete archive remains at commit
`16de5b2cfedbea49a6a5b43712156f15fc7a386a`. Freeze the actual P1
source, dependencies, native artifacts and definition when preparing the launch.
After launch, preserve released inputs and introduce successors instead of
rewriting a released execution definition.

The qualification-only P2 observer compiles the same current sources with an
independent lock and native namespace. Its only application addition is the
`upgrade-fixture` contract. The activation migration installs it at
`(upgrade-fixture, activation Bitcoin height, u32::MAX)` and initializes its
read-only version marker to `2`. That reserved transaction index cannot be
produced by an ordinary bounded transaction list. The contract is absent in P1.
Initialization, contract and signer records are part of the atomic migration;
rollback removes them and reactivation reinstalls them. Repeated public `init`
calls cannot change the marker. Existing native contracts, including token
balances and schema, have identical behavior in both executors.

Use this maintenance sequence after changing prelaunch P1:

1. If native sources changed, run the existing pinned `tools/kontor build native`
   build. If a common native binary changed, update its copy under
   `core/indexer/src/protocol/v1/native`, its digest in `manifest.json`, and the
   corresponding build/toolchain and source-provenance records. Encode
   `provenance.bin` with the existing `BuildProvenance` postcard codec, update
   metadata digests in the manifest, then update `NATIVE_GENESIS_ID` in `native.rs`
   to that manifest's SHA-256. Provenance must identify the actual committed
   source and pinned image used to build it. The native-input tests validate
   these bindings. This metadata refresh is an explicit review step, not something
   `sync-prelaunch` invents. Do not copy security-draft binaries blindly.
2. Run `tools/kontor sync-prelaunch --write`. It derives the observer manifest and
   lock from P1 and copies the qualification contract artifact. Without `--write`
   it rejects drift. The normal builder unit tests also check the checked-in pair.
3. Run `tools/kontor freeze-execution first --write`, then
   `tools/kontor freeze-execution observer --write`. Refresh the standalone
   `second` development reference when its shared source inputs changed.
4. If coordinator inputs changed, run `tools/kontor freeze-consensus --write`.
   Inspect changed inventories and identities, then run focused and linked tests.

For local Cargo and bundle commands, use the parent directory's `local-build`
helper and shared slots as described in `AGENTS.md`. No Python or parallel manual
P1/P2 source edits are involved. The only dependency overlay is the pinned
Wasmtime `.2` versus `.3` package/revision identity: these revisions have identical
implementation sources, but the version suffix separates native exports. The
generator rejects a changed pin pair until that overlay is reviewed again.

`tools/kontor protocol-bundles --build-node` defaults to `production-node`, which
links only P1. `--node-qualification` explicitly selects `managed-node`, adding
the generated P2. Only that feature enables successor registration, discovery
and activation. `tools/kontor qualify-node` selects it automatically. The SDK
targets the `kon2` launch transaction format in both P1 and qualification P2.
Direct and aggregate publisher inputs require signed operation consent, and
the SDK validates composed transactions before signing. Marketplace sellers use
`SINGLE|ANYONECANPAY` with a bound Sponsor, while ordinary participants use
`ALL|ANYONECANPAY`. Neither executor accepts the old shape-only input as fresh
launch authorization.

Changing these unreleased identities can require explicit recreation of local
development databases. Back up any needed data first. Nodes do not silently reset
databases or support every intermediate development identity.

## Cleanup configuration inventory

The post-upgrade cleanup retains the following production and diagnostic
configurations. This table does not create additional qualification jobs.

| Configuration | Disposition | Minimum affected validation |
| --- | --- | --- |
| `production-node`: current P1 and one pinned consensus runtime | Default production composition. | Builder and registry exclusion checks, followed by an audited production build. |
| `managed-node`: matching current P1/P2 and one pinned consensus runtime | Explicit upgrade qualification only. | `tools/kontor qualify-node` and `tools/kontor compare-node`, through the existing release workflow, after changes stabilize. |
| Former retained P1 copy | Removed because no build or test consumes it. Git preserves the archive; prelaunch production uses current P1. | Source-root inventory, definition and drift tests. |
| Local runtime/test adapters | Keep intentional test coverage; remove only branches proven obsolete. | Focused ownership, cancellation, settlement and rollback tests when their code changes. |
| `legacy-qualification` and retained K3 | Keep for the preserved pre-extraction, unversioned database replay oracle. Managed history must not be relabeled as this old baseline. This is a diagnostic configuration, not production database compatibility support. | Existing baseline replay, recipe and evidence checks when affected. |
| Standalone proof graphs | Keep the independent VM/type, allocator/import ownership, signal/child-process and resource-lifecycle checks. These assertions are not all supplied by the managed-node harness. | Existing proof/interface/object controls when affected; no new automatic qualification. |
| `k4-node` | Removed. It combined the pre-extraction K3 executor with the observer before managed P1 startup existed. No maintained workflow selected it. Certified-history and rejection checks now exercise managed-node; old factory adapter probes retired with the incompatible predecessor interface. | Builder, wrapper, interface and evidence tests; managed release build after changes stabilize. |
| Local cgroup workload supervisor and Python external Bitcoin/arrival/view services | Removed. Opt-in performance diagnostics had no CI or production caller. Historical implementation remains at `84ac9c72`; Rust correctness workloads and frozen-input validation remain. | Audit callers and local fallback paths; run remaining stack tooling tests. No renewed performance campaign. |
| Retained K4 coordinator snapshot | Removed. It was a development baseline, not an executor selected by any current build recipe. | Source-root tests and bundle-tooling tests. No runtime or cross-platform rebuild is required for this deletion alone. |
| Stack release qualification and bounded dev smoke | Keep. | Existing qualification/comparison commands, only for affected execution/build changes. |
| Intermediate S2 discovery, guard, chain and final diagnostic stages | Retired as a separate prelaunch certification framework; archived at `9a286b68`. Rust regression diagnostics and frozen workload support remain. | Rust stack-tooling and frozen-workload tests. Existing release/dev-smoke gates remain unchanged; they do not replace the retired memory/phase/41-case certification claim. See the native-stack README. |

Supported build and evidence commands use the existing `tools/kontor` entry point.
Final Python removal requires a tracked-file/content audit and a production build
with Python unavailable and fresh build outputs. Dependency download caches may
be reused. That build is part of normal stabilized validation, not an extra matrix.

The removed K4 snapshot remains available at commit
`b3e0fc246d7a859e30b836630372e5658f45afb8`, path
`protocol-bundles/retained/k4`. Its inventory SHA-256 is
`9359c0b7cdca0d9e2852262337061ce43a0856b32e36c173a41c4b874ba1ebf9`.
The historical execution ledger records why it was originally captured. Its
self-preservation test was removed with it; mutation, substituted-inventory,
relocation and path-containment checks remain.

The earlier cleanup removed 35 and 28 duplicate Python tooling files from the
then-retained P1 and K3 snapshots, respectively. P1 has since been removed as
described above. Builds already use orchestration from the current checkout.
Historical Rust fixtures, semantic baselines, manifest vectors, Cargo inputs and
execution-definition bytes remain intact. All four retained definitions were
verified against fresh locked, offline Cargo metadata before and after pruning.
That initial pruning changed packaging and build provenance, not execution identities.

Each `snapshot.json` records the removed paths and its preceding inventory hash.
The complete preceding snapshots remain at commit
`68776fb86df37c48f474683a904d9703641aa190`. Inventory hashes changed as follows:

| Snapshot | Original SHA-256 | After initial tooling pruning |
| --- | --- | --- |
| P1 | `4df4b75941b026b19a6dffcf2371afdd4d997e2b8cd33322002c782e3bc36cfc` | `42c18e71ed5af350fd43682869afc06716176f3198b90a9a76f0064ed46ab2dc` |
| K3 | `fc85d7f7479662012faef9bc43e3efaf7c9299ddc940ffd5ef5865abe5667592` | `161d2f236cd8c033607f429d814276a404382ae1420529a94db750b9f2243b8e` |

The subsequent, operator-approved removal of unused vendored Python and SageMath
generators changes source-bound execution IDs. These are unreleased identities;
databases and artifacts referring to the preceding IDs may require recreation.
No migration of those intermediate prelaunch databases is provided. Generated C
test vectors, licenses, dependency locks, feature selections and execution policy
are preserved. Retained snapshot records include the preceding definitions and
inventory hashes, with the complete preceding trees available at `3cec820f`.

The removed P1 snapshot hash was
`8302f1341414c82ce744f872357f4b919dca3925cac0b38dea68023687ca71d4`
and the retained K3 snapshot hash is `d9d80e4af271ff122aea598778b2f36d0a2d170ffa86ff32a9f42a6328a01c09`.
The archived pre-prerequisite managed-node execution IDs were P1
`56fd93c0af8d716649aafd779038f1bc1dd5d47f9baeea08b5cd400528d362d2`
and P2 `82ca1297a6864bfa962f9cc4fbcd823fe98b18b5086f6ae3d12818e332e618cb`.
Those development references also incorporated previously stale source hashes:
P2's stack-test cleanup and the first/second development graphs' existing V2
sources. Git preserves the former P1 tree; the retained K3 graphs preserve their historical execution sources.

Historical ledger entries retain their original hashes. New executor source
freezes copy required fixture assets individually instead of preserving old build
tools. The legacy coordinator-freeze mode was retired with its unused K4
snapshot. Historical tooling remains available in Git; current snapshot creation
supports executor graphs only.

## Existing build fixtures

CI selection now uses `tools/kontor ci-scope pr`, `stack`, or `bundles`. The CLI
reads `GITHUB_EVENT_NAME` and `GITHUB_EVENT_PATH`, prints a JSON explanation, and
appends action outputs when `GITHUB_OUTPUT` is present. Missing history or
uncovered dependency inputs select checks conservatively; exhaustive development
qualification still requires an explicit manual request.

`core/kontor-build` has its own workspace and lockfile so selector bootstrap does
not resolve the node's dependency graph. The node still consumes the same crate
as a normal path dependency under its own lockfile. The four scope jobs share
the tooling setup action and cache; its tests require Git and jq. Run tooling
checks directly with `cargo test --locked --manifest-path core/kontor-build/Cargo.toml`.
Ordinary CI also formats and lints this independent workspace. The rest of core
continues to use its existing workspace commands.

Bundle build, definition, interface and ownership commands run in Rust.
Source/recipe/identity checks run in the ordinary tooling test suite. Native
object, archive, weak-import and allocator-ownership controls run in the existing
LLVM-equipped `object_tools` test target. Managed consensus provenance binds the
Rust tooling sources; executor definitions remain separate.

Individual retained inventories can now be verified by the Rust build CLI:

```sh
tools/kontor verify-snapshot protocol-bundles/retained/k3 \
  --sha256 d9d80e4af271ff122aea598778b2f36d0a2d170ffa86ff32a9f42a6328a01c09
```

The command prints the authenticated inventory as JSON and fails on changed,
missing or additional files, changed symlink targets, or paths escaping the
snapshot. It does not regenerate identities or inventories. Recipe source-root
checks use this Rust verifier. Create a new executor snapshot with
`tools/kontor freeze-sources --revision <full-commit-id> --destination <new-directory>`.
The destination is relative to the checkout root unless absolute. The command
extracts that exact commit, resolves both executor graphs with locked offline
Cargo metadata, retains their dependency/source closure, and verifies unchanged
execution definitions after relocation. It then writes and verifies the frozen
inventory. Existing destinations, escaping/cyclic inputs and stale definitions
are rejected. A sibling `.NAME.freeze.lock` prevents concurrent writers to the
same destination. This command preserves definitions; it never regenerates them.

The standalone proof graphs below are build/isolation fixtures. Their results
are separate from the real managed-node acceptance evidence recorded in the
[execution ledger](execution-ledger.md).

K1-REPIN uses `protocol-bundles/pulley-first` and `pulley-second` as the active
graphs, while retaining the original `first` and `second` manifests and locks
unchanged as historical development inputs. Stable output labels `first` and
`second` map to the active directories through `core/kontor-build/src/recipes.rs`.
Both historical and active locks remain covered by the dependency audit.

`tools/kontor recipes` accepts JSON operations for the typed graph catalog,
source-root checks, manifest reservations, graph identities and resolved engine
attestations. The Rust builder and evidence tools use that catalog directly.
The catalog binds the current retained snapshot hashes and execution settings.
Attestations require
exact JSON types, so numeric zero cannot substitute for `false`, and a floating
point number cannot substitute for an integer.

`tools/kontor build-inputs` checks the resolved dependency closure, selects current
Cargo artifacts and checks synchronous guest-capability settings. Dependency
reports preserve package and feature ordering, immutable fork pins and native
patch ownership. Duplicate package or resolve-node IDs and missing reachable
nodes fail validation. Artifact selection keeps host proc macros separate from
target archives and requires exactly one bundle facade. The capability check
still verifies both the retained engine and proof settings, plus the node's
delegation to the retained engine. The Rust builder uses these checks directly;
the former `capabilities.py` module has been removed.

`tools/kontor interface` runs and verifies the existing bundle interface controls
and node-adapter checks. Probe selection still distinguishes retained K3, release
P1 and the pinned consensus runtime. Expected compiler error codes, probe order,
source bytes and report bindings are preserved. Relative library reads and
compiler arguments use the caller's working directory. Compiler and adapter
subprocesses retain their 60/120/30-second limits, and a failed interface rerun
removes the previous successful report. Graph fingerprints retain ASCII JSON
escaping, including Unicode paths; malformed identities and non-integer numeric
evidence are rejected. The Rust builder and archive comparator use these controls
directly; the former `type_boundary.py` forwarding adapter has been removed.

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

This qualifies coexistence of the proof engines. It does not replace production
stack, cancellation, or retained semantic-runtime checks. Preserve those existing
results and rerun affected checks when their source or build inputs change.

## Managed-node acceptance commands

`tools/kontor verify-node-evidence` accepts JSON requests for historical semantic,
retained-executor, storage-construction, certified-history and managed-startup
checks. The Rust qualification runner and archive comparator share these validators.
The same command verifies transition, recovery, authorization and join reports,
including native-artifact selection, rollback contexts, crash checkpoints,
successor authority and two successive approvals. Comparisons normalize live
idle-batch heights only after checking each observed handoff at C+1. Publication
claims must be nonempty arrays, matching the node's emitted format. Synthetic
JSON fixtures under `core/kontor-build/tests/fixtures/node-evidence` exercise
these verifiers; they are not records of actual node execution.
The preserved oracle still binds its raw log and fixture sources, and all three
simulation/rollback/commit observations must match. Certified history binds the
selected genesis executor and consensus definition; P2 cannot substitute for P1.
Malformed numeric or boolean evidence is rejected by JSON type as well as value.
These verification commands do not regenerate the historical baseline or execution
identities. The approved prelaunch identity refresh is documented above.
Archive and execution test fixtures now live in the Rust tooling tests. These
synthetic records exercise rejection and comparison rules, not real platform
qualification. The qualification container runs `tools/kontor qualify-node` and
no longer explicitly installs Python. A fresh Python-free production build
remains the final acceptance check.

From the repository root, build and qualify the actual node with:

```sh
CCACHE_DISABLE=1 tools/kontor qualify-node --profile release --output target/protocol-evidence --offline
```

Omit `--offline` only when dependencies need fetching. The default managed link
set contains current P1, the matching P2 observer plus its qualification contract, and one
pinned consensus runtime. It is distinct from the standalone proof command below.
Keep one Cargo operation at a time and the builder's two-job limit.
The Rust runner preserves raw stdout/stderr, removes stale successful execution
reports before a build or execution attempt, and checks the installed executable
and build report hashes before and after execution. Its subprocess deadlines are
300 seconds for executor checks, 390 for transitions, 420 each for recovery and
authorized replay, and 360 for joining. A timed-out child is killed and reaped.
`run-node-qualification` accepts JSON for executing an already audited node or
one diagnostic check. The former Python runner and comparator have been removed.

For focused investigation after a recorded `--build-node --node-qualification`
build, the installed executable offers these acceptance modes:

| Command suffix | Evidence |
| --- | --- |
| `qualify-protocol-transition --cluster` | Real peers activate, roll back and reactivate while RPC/ingestion and engine ownership remain live. |
| `qualify-protocol-transition --join` | Catch-up from P2 peers, quorum-loss stall, safe promotion and restored progress. |
| `qualify-protocol-transition --authorized-replay` | Fresh approvals for two successive upgrades, two migrations, exact reopen and genesis reconstruction. |
| `qualify-protocol-transition --recovery` | Crash checkpoints, finality replay, confirmation without double charging, same-outpoint replacement, unsupported target and successor committee cases. |

These diagnostic modes do not replace the builder's source binding, artifact
checks, ownership audits or cross-platform comparison. Preserve raw stdout/stderr
and use `tools/kontor verify-node-evidence` rather than accepting exit status alone.
The second successor P3 is an exact qualification-only manifest using P2 execution
and a schema-2 no-op migration, not another production executor. Replacement
coverage starts from Bitcoin-accepted inputs, not Bitcoin mempool/RBF policy.
The successor-support case uses real committee/certificate/state transitions with
an explicit missing-support assumption, not different live node binaries.

## Build and evidence

`tools/kontor protocol-bundles` performs graph compilation, node linking,
proof orchestration, audits and installation in Rust. Docker's production build
and the node qualification launcher use this entry point directly.

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
`builder-base` as the node.
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
The symbol reader's path, hash and version are also recorded. The node's
`linker-record.json` records the actual driver invocation, expanded response-file
arguments, working directory, driver identity and selected backend path/hash.
Backend selection comes from the same compiler driver's plan while temporary
link inputs still exist. GCC's collect2 path additionally uses the driver's
program search with Rust's `-B` directories and selected `-fuse-ld` variant;
Clang's plan names the backend directly. This is selection provenance, not a trace
of arbitrary child processes. Custom GCC specs/wrappers and
`COLLECT_LD_OVERRIDE` require explicit qualification and are rejected.
The record binds the link specification and immediate linker-output hash. The
compiler-object record binds that record's hash and the output path/hash after
rustc completes, including post-link debug stripping on macOS. Cargo's final
executable must match the completed compiler output. The two stages need not
have equal hashes; neither stage is replaced by an unverified artifact hash.
The final native-symbol audit remains independently required.
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
`tools/kontor verify-sources` performs these checks in Rust, reading Cargo
metadata JSON on standard input and returning the existing Git/registry evidence
object. The Rust builder invokes the same verifier with its pinned build
environment, including offline policy. It supports SHA1 and SHA256 Git repositories. Ordinary Git filenames retain raw Unix bytes; submodule
names must be UTF8 to appear as JSON object keys. No sources are extracted or
rewritten during verification. Global PAX and GNU sparse archive entries are
rejected. Locked registry archives do not require those extensions; unsupported
formats fail verification rather than bypassing source checks.
`tools/kontor provenance` reads a JSON request identifying an `operation` and
returns the source or toolchain evidence. It supports local/package file lists,
retained/node/consensus inventories, complete `source_inputs`, `locked_packages`,
`toolchain`, and `runtime_libraries`. Complete source inventories verify external
sources before recording them and stop local manifest inheritance at the selected
graph root, including frozen roots without a `.git` marker. Inventory paths must
be UTF8 JSON keys; unreadable directories fail verification.

The Rust builder calls these functions directly. Toolchain and runtime-library
requests carry the caller's working directory so relative compiler paths and PATH
entries keep their meaning. Evidence binds source hashes, compiler/sysroot
records and an environment allowlist. Compiler proc-macro libraries cannot become
runtime dependencies. Recording build evidence never regenerates execution IDs.

The `source_policy` operation preserves the process-control review tripwire and
guarded source exclusions for proof, executor and consensus graphs. Excluded
sources remain hash-bound, and imported consensus source paths must resolve.
The `proc_macro_hashes` operation verifies reciprocal compiler rejection of
foreign graph plugins, retains diagnostic logs and removes temporary probe
directories. Its requests carry the original working directory and environment.

`tools/kontor inspect-object` accepts JSON operations for pinned LLVM symbol and
object records, archive members, section bytes and compiler GDB metadata checks.
Requests include `working_directory` to preserve relative object paths. Binary
results use hex strings in JSON; the Rust ownership helpers use bytes directly. Reader failures reject partial output, section reads
check input identity and bounds, and GDB metadata requires the exact ELF shape and
payload. The separate native-crypto object reporter retains its existing schema;
LLVM tools remain necessary here to inspect compiler bitcode inputs.

The real LLVM integration tests run in the existing bundle controls and platform
qualification jobs, which already install `llvm-tools-preview`. Scope selection
keeps running the default tooling tests without that component. Run the object
integration checks locally with `cargo test --locked --manifest-path
core/kontor-build/Cargo.toml --test object_tools -- --ignored`.

`tools/kontor audit-symbols` owns graph input and final-link ownership rules.
It checks unique graph namespaces and Wasmtime version prefixes, matching PSM
archive copies, staged input hashes for local symbols, and concrete owners for
final global and private symbols. Inventory operations require explicit source
arrays, including intentionally empty arrays. Executor audits permit native
helpers removed by linking, while proof audits require their complete fixture
set. Both reject aliases between independent graphs.
Malformed graph/ownership list lengths fail before symbol inspection, and
failed final audits do not write a partial local-input report.

`tools/kontor audit-shared` checks retained graph imports against concrete sysroot,
platform-library and root-compiler owners. Ordinary node definitions remain
separate and cannot satisfy retained graph imports. Only the named weak system
unwind references are optional; a strong reference to the same name remains
required. The platform-library allowlists and ELF GOT constraints are unchanged.
Library export lookup uses local loader handles and never calls resolved symbols;
handles are released after lookup. Ownership requires an actual library export.

Absolute source paths and platform inputs are recorded. This is an audit of
the actual build, not a claim that different checkouts or platforms produce
byte-identical executables.

## Isolation and common ownership

### Production node build

`--build-executors` and `--build-node` use the same builder. These modes
use production recipes independently of the proof recipes. The executor contains
the actual retained runtime, host bindings, semantic policy and dependencies.
The separate `protocol-bundles/node` workspace owns node services and physical
storage, and its resolved graph must not contain Wasmtime, an executor crate or
one of the independently built consensus crates.

Both `--build-node` and `--build-executors` default to the `managed-node` executor
pair: retained `first` and current `observer`. Node builds additionally compile
the pinned `consensus-first` graph and enable managed startup in the daemon. The explicit `legacy-qualification`
link set remains for the preserved baseline oracle, not intermediate database
compatibility. The retired `k4-node` name is rejected by the CLI, recipes and
compiler wrapper. Executor and consensus roles are recorded
separately, so their shared `first` label cannot alias native ownership or evidence.

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
makes Cargo rebuild the node when externally staged executor or consensus inputs change,
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
qualification require the separate execution checks.

For a production release executable, use:

```sh
./tools/kontor protocol-bundles --build-node --profile release \
  --output target/protocol-evidence --install-node target/bin/kontor
```

Installation checks the copied bytes against the audited executable hash before
atomically replacing the destination. It does not strip or otherwise transform
the binary. `node-build.json` records the installed path and hash. A plain
`cargo build` in the core workspace remains an in-tree development/test build;
it does not establish retained dependency isolation. It does use the same pinned
Malachite fork and shared node coordinator for ownership, durable signing, WAL
recovery, and follower promotion. Its Cargo graph depends on the runtime facade;
the production node graph keeps that runtime independently linked. Raw engine
startup is restricted to test and diagnostic configurations. The ordinary build's
unsupported-upgrade guard remains in place.

The Docker `builder` stage invokes the same Rust bundle builder and installs that
audited output into the runtime image. Its `cacher` stage fetches the locked
graphs; it no longer compiles a unified workspace whose artifacts the isolated
graphs cannot reuse. The opt-in `protocol-bundle-qualification` image uses
`tools/kontor qualify-node` to build the managed node and execute both
real executor graphs. Managed qualification also compiles interface controls
against the pinned consensus library and runs the actual node adapter tests.
The runner rejects stale or changed binaries, missing graphs/cases, mismatched
observations and subprocess failures, and records raw output hashes with the
node build report hash in `executors/managed-node/node-execution.json`. Its 300-second timeout
is a test timeout, not a Kontor execution cutoff. Full release-image and platform
qualification is required for affected release candidates.

`tools/kontor compare-node` verifies the downloaded linked-node
results against an explicit policy: `release` requires Linux x86-64, Linux ARM64
and macOS ARM64 release results; `full` requires both dev and release on all three.
The workflow uses release automatically and exposes full comparison only through
manual dispatch. Missing, duplicate or unexpected cells and failed upstream jobs
are errors. The comparator verifies raw logs, source inventories, local package
files, workspace/graph identities, linker inputs and ownership-report hashes,
then requires identical execution observations across the required cells.
Package documentation and Git ignore files omitted by Docker are excluded from
source equality. Comparator-only edits under `src/node_evidence/comparison/`
and standalone tooling integration tests under `core/kontor-build/tests/` are
excluded from this source comparison. Other Rust tests remain bound. The original
source-inventory hashes remain verified.
The exclusion applies to both tool and local-package inventories. Shared Rust
validators, the execution runner and CLI/module wiring remain bound. The archive
checker is not called by node execution or builds. Comparison failures replace
any stale successful report with an explicit failed report.
This bounded linked-node check complements the existing stack qualification and
dev smoke checks. It does not replace their coverage or establish all executions
from the sampled scenarios.

The workflow selects changes from the complete Git diff, including deleted and
renamed inputs. Comparator-only changes run the builder/evidence controls on one
Linux runner without repeating the platform builds. Other tooling tests and
changes to node execution or build inputs can require the selected matrix; missing Git
history requires qualification. Unrelated changes skip both groups. Builder
checks run once before the matrix rather than once per platform.
The small native-object negative controls also run on ARM Linux and macOS during
release qualification, since those exercise the target object format and native
symbol reader. They do not rebuild the Rust dependency graphs.

Qualification also compiles five interface controls against the exact staged
production libraries, without linking or running another node. The public
factory signatures must be interchangeable structural standard-library types.
Wasmtime engines and Tokio handles from different graphs must fail with Rust's
type-mismatch diagnostic, and direct access to each graph's private runtime must
fail with a privacy diagnostic. Missing dependencies or unrelated compilation
errors do not count as successful negative controls. The node build report binds
these controls, their source, diagnostics and library hashes; the platform
comparator validates those bindings before accepting execution results.

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

## Standalone proof process-resource checks

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
The blst pool is separate from the VM pool. A node with its own blst copy plus
two bundles can retain three pools. These resources stay
resident; bundle unloading is unsupported.

## Changing a retained bundle

### Execution definition references

Each production executor has an explicit `definition.bin`. Its execution ID
binds target-independent semantic source hashes, the graph lock, resolved
features and build policy. The builder verifies this reference before and after
compilation using unfiltered Cargo metadata. Platform-specific artifact hashes
remain separate build evidence. A stale reference fails the build; a build does
not regenerate it. The retained crate embeds its own reference directly, without
depending on a build-script environment variable.

For a changed prelaunch P1, first follow the regeneration sequence above, including
`tools/kontor freeze-execution first --write` and `tools/kontor freeze-execution observer --write`
under the pinned toolchain, inspect the changed inputs and ID, then
qualify the resulting executors. Omitting `--write` only verifies the reference.
The Rust generator resolves locked, unfiltered Cargo metadata offline.
`tools/kontor execution-definition` exposes the same encoding and verification
operations through JSON for diagnostics; builds call the Rust library directly. Canonical bytes,
semantic exclusions, inherited package properties and build policy are unchanged.
Never overwrite a released definition to silence a mismatch. Preserve its
source graph and add the new definition separately. Compatibility qualification
of a new compiler/platform artifact is distinct from changing execution rules.
Preserve released sources and historical fixtures. Coordinator source changes may also
require `tools/kontor freeze-consensus --write`; inspect the
changed source inventory instead of regenerating references automatically in CI.
This Rust command resolves locked, unfiltered node and consensus Cargo metadata
offline. Omitting `--write` verifies the managed reference without updating it.
Previously acquired metadata can be supplied with `--node-metadata` and
`--graph-metadata` (repository-relative or absolute paths). The legacy coordinator
reference is selected only with `--baseline`; it is not refreshed by the managed
command. Neither command changes execution definitions.

The definition also commits the immutable `protocol/v1/storage-contract.json`
reference. It specifies the required logical storage semantics and identifies
the initial SQL adapter sources. The node resolves that requirement before
constructing a retained factory and rejects missing, changed, unknown or multiple
requirements. Distinct executors can require the same StorageV1 contract.

Do not regenerate this reference from the latest adapter. Current SQL, adapter
sources, shared libsql/SQLite dependencies and build settings are recorded in
node artifact provenance. Changing them requires compatibility qualification
against every retained storage contract, including the preserved original oracle.
Two executors agreeing through the same changed adapter is insufficient evidence.
If a shared dependency cannot preserve an old contract, it cannot replace that
contract's implementation merely because a newer executor supports it.

Semantic source inventory is distinct from broad artifact provenance. Whole
node-only coordinator, ownership and pool modules are excluded from execution
identity; shared interfaces and mixed modules remain bound conservatively.
Resolved local package properties capture inherited manifest settings without
binding unrelated workspace dependencies such as Malachite. Node implementation
changes still appear in artifact provenance and retain their applicable tests.

The migration qualification factory registers a fixed test-only Rust routine
alongside the no-op migration. It exercises budgeted reads and writes, immutable
input, atomic rollback and retry through the real executor adapters. The normal
factory rejects that routine. It is not a deployed smart contract or an enabled
network upgrade. Production migration registration and approval are separate.

### Retained graph changes

1. Preserve the old manifest, lock, source identity and semantics. Add a new
   protocol mapping rather than rewriting history.
2. Assign each retained Wasmtime graph a unique immutable package version and
   native prefix, even when its VM code is otherwise unchanged. Reusing VM code
   requires a new version-only fork release until a separate native namespace
   mechanism has been implemented and reviewed.
3. Resolve and commit the new lock deliberately. Keep F2 native patches and F3
   managed-engine ownership. Do not change blst threading features to make
   resource counts pass. Preserve portable lifting charges.
4. Run the negative controls and real qualification on every shipped node
   platform. Audit both bundle locks using the existing core advisory policy.
5. Obtain lead and one independent review of semantics, native/process
   ownership and integration. Compiler changes require renewed qualification of
   every retained protocol. Historical transaction replay alone is insufficient.

The conflicting itoa patch requirements demonstrate why one unified Cargo
resolution is insufficient. Deliberately different serde_json features, VM
lifting prices and compile-time Tokio types prove that the two graphs remain
distinct. These differences are qualification fixtures, not a definition of P2.


### Native artifact provenance across upgrades

`GET /api/contracts/{address}/provenance` returns `entries`, the original
publication-claim log, and `effective_artifact`, the artifact selected by the
protocol at the pinned read snapshot. The latter reports `protocol_id`,
`execution_definition`, `source` (`publication` or `protocol_native`),
`published_sha256` and `sha256`. Both hashes cover stored artifact bytes,
including compression, before component decoding. A protocol-native replacement
can therefore have a different effective hash without changing the publication
row or its claims. Those claims do not attest the replacement; its mapping is
bound to the selected execution definition. Rollback restores the corresponding
protocol selection and artifact record.

The SDK's `session.getContractProvenance(address)` returns `entries` and
`effectiveArtifact` with camel-case field names. Existing
`session.getProvenance(address)` returns only the publication-claim log. The full
method fails explicitly if the node or custom transport does not support it.
These records describe one observed snapshot, not a promise that the canonical
protocol cannot change after the response.

### Managed P1/P2 qualification

The qualification node contains matching P1 and P2 common behavior plus P2's
additional fixture contract. Its runner checks P1 against the historical oracle,
then runs the actual multi-validator transition fixture in the same audited
binary. Common native behavior must remain equal. Legacy retained
link sets continue their two-graph equality comparison.

`node-execution.json` records the linked graphs; `semantic_baseline.graphs`
identifies which graphs were compared with the historical oracle. Managed records
also require `transition` hashes for `node-transition.stdout.json` and
`node-transition.stderr.log`. The comparator verifies those files, their effective
native artifact/definition bindings, and agreement across the explicitly required
platform/profile cells. Transition evidence covers its stated seeded-schedule
scope; it is not a substitute for authorization, crash-recovery or cold-sync tests.

`qualify-protocol-transition --recovery` exercises the real P2 contract-installation migration
through the production closure driver, starting from a seeded accepted schedule.
It checks rollback after an injected activation-persistence failure, fresh-session
recovery before and after migration commit, equality of every persistent table
with uninterrupted execution, a conflicting reserved contract across reopening, and C+1
admission only after closure publication. It does not start consensus engines or
simulate abrupt process termination. The command is separate from `--cluster`;
both options cannot be selected together.

The separate `qualify-executor-baseline <archive>` command consumes an unversioned
pre-extraction archive and requires the `legacy-qualification` link set. A managed
build rejects that command explicitly. Use `qualify-executors` for its preserved
P1 semantic oracle and the transition commands for its actual P1/P2 behavior.
Do not relabel archived unversioned state as certified managed history.


The managed runner also requires `qualify-protocol-transition --recovery` from
that audited executable. Its raw stdout/stderr hashes are recorded under
`recovery` and checked by the comparator. In addition to migration atomicity, it
covers finality expiry of an unconfirmed batch across H, a surviving schedule
whose migration must rerun with the same H hash and changed pre-lineage, and
rollback of signed Cancel and Postpone actions. Reopening after the owned rollback
must match uninterrupted reconstruction. The initial schedule remains a seeded
precondition; this does not claim an end-to-end Schedule approval or abrupt
process-crash test. The harness timeout is 420 seconds, separate from every
protocol execution limit. Existing qualification change-scope selection still
controls which PRs run these checks.


The recovery qualification also branches from its existing H=2 snapshot to
confirm a gas-paying P1 batch transaction in P2 block H+1. It requires zero
reexecution, unchanged transaction fuel and receipts, correct Bitcoin confirmation
position, P2 selection for Batch(H), and full-state equality after database reopen.
The raw recovery evidence verifier requires these observations; a successful
process exit alone does not establish them.

### CI crash diagnostics

`tools/kontor diagnostics prepare OUTPUT` records the pre-test macOS report inventory.
`tools/kontor diagnostics run LOG COMMAND [ARGS...]` streams combined output while
preserving the command's exit status, including shell-style signal statuses. It
stops following output when the direct child exits, even if descendants survive.
`tools/kontor diagnostics collect OUTPUT` polls for new or changed crash reports
for 30 seconds, then captures bounded system diagnostics. Missing or malformed
baselines exclude historical reports; collection errors remain in `reports.json`.
The files and metadata in `baseline.json` and `reports.json` retain their previous
shape. `run.json` now records `started_at_unix_seconds` instead of a local-time
string, and diagnostic error/command text uses Rust formatting.

CI builds this small CLI before tests and invokes its binary directly afterward,
so crash collection does not depend on a successful Cargo rebuild after failure.
The existing macOS abort smoke test is restricted to collector/workflow/bootstrap
changes and manual dispatch. The Linux tooling tests cover growing reports,
missing baselines, copy errors, command timeouts, signal exits and surviving
children; actual macOS report generation still needs the macOS smoke test.

### Graph compiler wrapper

Graph builds now stage `kontor-graph-rustc`, a dedicated binary within the existing
build-tool crate. Its compiled code uses only the standard library, so unrelated
CLI changes do not invalidate the large executor caches. It accepts Cargo's compiler arguments directly;
it does not parse them as CLI options or invoke Python. It requires the exact
pinned compiler and graph namespace, rejects an additional compiler wrapper,
preserves Cargo's own metadata, and leaves toolchain probes unchanged. On Unix
it replaces its process with rustc, preserving exit status and inherited jobserver
descriptors.

The builder stages a content-addressed hard link to the wrapper, or a copy
when the output is on another filesystem. A later bootstrap rebuild therefore
does not replace a wrapper already selected by a graph build. The target cache
key and build record bind the wrapper's bytes. Its hash is checked after graph
compilation and again with the other staged inputs. Source evidence also includes
`core/kontor-build` independently of the retained executor source root. These are
build-provenance changes; execution-definition inputs and identities are unchanged.

`tools/kontor` builds the dedicated wrappers before starting orchestration.
The builder stages them without a second bootstrap. Offline policy passes through
`CARGO_NET_OFFLINE`, and Docker fetches the independent tooling lock before offline
builds. `stage-graph-wrapper OUTPUT` is an internal bootstrap interface.

### Node compiler wrapper

Node compilation uses the dedicated `kontor-node-rustc` binary, staged by the
same build tool through `stage-node-wrapper OUTPUT`. The workspace-wrapper path
binds both the link specification and executable hash, so changing linked inputs
invalidates the node compilation while unrelated CLI edits do not. Evidence
records the wrapper source hash and its executable identity separately. Source
inventories also bind the Rust tooling and its lockfile.

The wrapper checks the compiler, library roles and facade hashes, removes
inherited attestation variables, and supplies the verified managed attestation
only to the node/library compilation. It preserves Cargo jobserver descriptors,
clears stale object/link records before compiling, and binds the completed
compiler output separately from the linker output for Darwin post-link stripping.
Normal compiler exit codes pass through; signal failures use the shell convention
(`128 + signal`).
Captured node invocations require UTF-8 arguments for JSON evidence and reject
unrecordable arguments before invoking rustc. Probes and dependency/library
invocations continue to forward raw operating-system arguments unchanged.

Small real compiler/linker tests cover this boundary locally. Full independently
linked node builds and Darwin validation run after affected changes stabilize,
not as additional per-edit jobs.
The focused test bootstrap allows fetching the small standalone tooling graph on
a cold runner; an explicitly inherited `CARGO_NET_OFFLINE` remains respected.

### Linker recording and verification

`kontor-node-linker` now records the real driver call and selected linker backend
without Python. It is staged by `stage-linker-wrapper OUTPUT`, uses the same
content-addressed binary staging as the compiler wrappers, and excludes unrelated
CLI code from its executable. The node report binds the two linker source files
and executable hash separately; the link specification binds the staged binary.

The recorder preserves GCC `collect2` lookup with `-B` and `-fuse-ld`, Clang's
direct linker selection, four levels of response files, quoted arguments and
text-mode newline handling. Custom driver specs/wrappers and `COLLECT_LD_OVERRIDE`
remain rejected. Executable lookup checks Unix access permissions, using the
already pinned libc version. Inherited descriptors and normal exit codes are
preserved; signals use the same shell convention as the node compiler wrapper.
Stale success records are removed before invocation, and changed tool bytes,
link specifications or expanded response arguments prevent a success record.

The verifier is available as `tools/kontor verify-linker-record`, reading JSON
from standard input with `record`, `spec_hash`, `output_hash` and optional
`compiler_output` fields. It validates both the original linker hash and the
separate completed compiler output used on Darwin. Node builds call the Rust
verifier directly and reuse the staged linker; offline builds do not bootstrap
another tool.

Run the small real compiler/linker checks with
`cargo test --locked --manifest-path core/kontor-build/Cargo.toml --test linker_wrapper -j2`.
The existing cross-platform qualification step runs these tests before its full
node build. No additional job or performance campaign is required.
