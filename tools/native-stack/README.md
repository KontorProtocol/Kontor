# Native Wasm stack qualification

## Resource amendment preflight

`resource_manifest.py` freezes the mandatory case list, six cells, capacity
settings, memory profiles, and hashes of existing fixture inputs for the S2
resource amendment. Run `python3 tools/native-stack/resource_manifest.py` to
check the committed manifest against the current source. The manifest currently
marks every case as missing its paired worker binding. This is intentional:
the old stack tests run on a current-thread harness and cannot satisfy the
amendment's worker and capacity evidence.

The resource validator requires `jsonschema` as pinned in
`tools/native-stack/requirements-resource.txt`. It rejects duplicate JSON keys,
applies the complete schema, checks expected outcomes and Store counts, and
compares each extracted attempt with the complete child JSONL transcript and
its terminal record. Application-state before/after hashes exclude the
separately reported fee and receipt accounting, so failure rollback is checked
without hiding paid-call charges. Resolved Wasmtime feature logs must match the
production and qualification closures already used by the existing stack gate.
The build policy pins Rust 1.99.1, empty custom Rust flags and Cargo feature
arguments, and the exact compile-environment record. It records default
target stack probing as unverified by disassembly. Memory profiles record
physical host CPU/RAM separately from enforced CPU and memory limits.
The resource evidence gate parses full Cargo metadata and the JSON build log,
including the exact indexer test artifact, compiled Wasmtime features, target,
profile and successful build completion. It requires an archived copy of the
test executable with a matching SHA-256, a raw `rustc -vV` record, and child
transcripts that report the executable path and SHA-256 observed by each child.
The child command must name that Cargo artifact and the pinned resource test.
The report source commit must match captured `git rev-parse HEAD`, a clean
`git status --porcelain` record, and the commit embedded in each child binary.
The resource runner and workflow do not emit this evidence yet, so the gate
remains blocked by explicit build and source capture statuses.

`resource-evidence-schema-v1.json` defines the required raw process, build
closure, engine, actual thread ranges, per-attempt worker phases, per-case,
and production-only memory records. `resource_evidence.py`
checks one paired cell and `compare_resource.py` requires all six cells and
equal execution observations across them. Both reject the current preflight
manifest for acceptance. A case may be marked ready only after its complete
operation runs on the explicit multithread Tokio workers in both independent
child processes, with actual capacity observations and raw logs. Missing
native Core, deepest-frame host-call, SQLite range/large-value, cold publish,
blocking Brotli, foreign WAVE, and canonical result-shape fixtures are visible
in the manifest and remain open work. The named native Core cases require the
coordinator's exact staking and filestorage workload budgets. The memory gate
also requires a hashed workload plan with its occupancy, cache and allowance
values frozen before measurements. The worker runner's source hash and each
sample's preparation, operation, conversion and teardown worker IDs must be
bound before acceptance. A successful preflight schema check is not a resource
qualification result.

The ignored `real_paid_large_frame_on_tokio_worker` test is an initial real
call diagnostic. Run it in separate child processes with
`KONTOR_RESOURCE_MODE=reduced` and `KONTOR_RESOURCE_MODE=production`. It uses
two explicit Tokio workers and the existing paid 256-value frame fixture,
including fresh engines and component caches in both modes, normal
publication, receipt and post-call reset checks. Linux
checks that the task begins and ends on measured workers. It does not yet emit
the fiber, guard-fault, build or memory evidence required by the resource
comparator. Its test-only thread trace checks that fixture preparation,
publication, the paid operation, post-call observations and teardown phase boundaries run
on the measured Tokio workers. It checks that the caller of synchronous
Wasmtime compilation runs on a worker and that Brotli decoding runs on a
separate blocking-pool thread. The resolved Wasmtime feature closure excludes
`parallel-compilation`; that exclusion and the pinned Wasmtime source are
needed to rule out internal compiler workers. The trace itself does not
observe Wasmtime internals. These phase markers do not prove that every
awaited suboperation stayed on one worker or supply the comparator's per-case
thread bindings. Canonical ABI and WAVE conversions inside the operation need
their own cases and remain open in the manifest.

On Linux, the ignored `linux_worker_guard_fault_control` runs two additional
test-binary children, one at each worker stack request. Each child verifies its
own worker guard interval, prints the fault address, then makes a single store
to that address. The parent imposes a 30-second child deadline and requires
Rust's `SIGABRT` with a stack-overflow diagnostic naming the same worker thread,
plus the child's exact target record. This control is
diagnostic until its raw child output and status are
bound to every qualification cell. The macOS worker guard and fault control
remain unimplemented.
The resource report now requires a separate complete guard-control process log
per cell. The validator checks the parent test command and terminal success,
exactly one reduced and one production child, each child PID and worker TID,
its verified target interval, the matching stack-overflow abort, and the
embedded source and executable SHA-256 against the Cargo artifact. The runner
does not yet collect this record, so the per-cell attestation remains missing.

Thread records must confirm a protected guard region, not only repeat
`pthread_attr_getguardsize`'s reported size. An unverified guard fails the
resource evidence schema. On Linux, the diagnostic accepts a protected
`---p` VMA or page-by-page `EIO` reads from `/proc/self/mem` below the usable
stack. [glibc 2.42's lightweight guard implementation](https://sourceware.org/pipermail/glibc-cvs/2025q1/087326.html)
can retain an `rw-p` VMA in `/proc/self/maps`, so the VMA listing alone cannot
disprove guard protection. `EIO` proves the interval is inaccessible; it does
not identify which kernel mechanism made it inaccessible. A separate faulting
child control is still required in each qualification cell. Each thread record
includes the measured page size,
process and kernel thread IDs, and the protected guard interval. The local
Linux ARM64 smoke test runs on 16 KiB pages; it does not stand in for the
4 KiB page qualification cells. The macOS guard observation remains unbound.
The amended fiber claim uses a source-grounded effective capacity, not a live
fiber address or high-water mark. The evidence gate now requires archived
copies of the pinned Wasmtime configuration, runtime fiber allocation, Store
cache and reuse path, on-demand allocator, fiber dispatch and Unix allocator
sources with exact SHA-256 hashes, plus Cargo metadata resolving both the
main Wasmtime package and its internal fiber crate, their compiled artifacts,
and the approved feature closure. It checks the
reported Engine request against the frozen 2 MiB or 1 MiB setting, rounds it
to the observed host page size, and requires a separate one-page guard. The
source path assumes no custom stack creator and no sanitizer allocation path.
`capture_fiber_source.py` reads Cargo metadata, verifies the checkout revision
and these six file hashes from their resolved package roots, then archives
the files under `wasmtime-source/`.
`capture_resource_control.py` binds the selected indexer test executable to
one successful Cargo JSON artifact stream, requires a clean checkout at the
explicit source revision, runs the host's guard control with a process deadline,
validates its complete raw transcript, and archives the Cargo inputs and six
pinned fiber source files. `build_resource_test.py` runs the pinned test build
and records the compiler version, lockfile, Cargo command, resolved `testing`
feature, and compiler environment. The three `RUST_FASTNUM_FMT_*` variables
are removed from that environment and recorded as explicit null values.
Empty Rust flag and wrapper variables override inherited Cargo settings.
The builder starts Cargo with a small allowlisted environment, so inherited
native compiler flags, include paths, package discovery settings, and
crate-specific build variables cannot alter the artifact. It selects `cc`,
`c++`, and `ar` from a fixed search path, records the selected native tool
paths and file hashes, and rejects a tool change during the build. It uses
an empty, build-specific Cargo target directory under the output directory
with incremental compilation disabled. This avoids reusing artifacts built
under other settings. The builder also rejects either Cargo config filename
in every parent `.cargo` directory or the active Cargo home, and records the
searched paths for the aggregate gate.
Live validation checks the native tool files again. Archived validation checks
their recorded paths and hashes without requiring the original tool files on
the verifier's host. These hashes identify the tool drivers, not their
subprograms, system headers, or dynamic libraries. The qualification still
needs workload and state parity across nodes.
The Cargo build-script record identifies fastnum's generated output directory.
The builder archives its pinned build script and the generated formatter,
rounding, and serde constants, then checks their exact contents. The control
archive copies and revalidates those files against the same Cargo artifact.
A build with a different formatter setting or missing attestation fails the
control gate. Run both commands from the same clean checkout:

```sh
python3 tools/native-stack/build_resource_test.py \
  --profile dev --output-dir path/to/new-build-directory
python3 tools/native-stack/capture_resource_control.py \
  --cargo-artifacts path/to/new-build-directory/cargo-artifacts.jsonl \
  --metadata path/to/new-build-directory/cargo-metadata.json \
  --build-attestation path/to/new-build-directory/resource-build-attestation.json \
  --source-sha COMMITTED_HEAD_SHA \
  --evidence-dir path/to/new-evidence-directory
```

The capture refuses an occupied output directory. A failed process preserves
its raw log and failure JSON. The helper does not populate the six workload
cells or the macOS guard observation, so full resource qualification remains
missing. The paired diagnostic below adds pthread measurements for the Tokio
workers, one blocking pool thread, and the block-on caller.

`capture_resource_diagnostic.py` takes a guard/source capture from the same
clean source revision and binary, then runs the real paid large-frame call in
separate reduced and production test processes. It archives the complete
process transcripts, measured Tokio worker, blocking pool, and block-on caller
stack ranges, and ordered compiler and Brotli thread events. Each trace worker
must match a measured worker thread and kernel thread ID. The output reports
blocking trace threads without a matching capacity measurement as unresolved.
Use a fresh output directory:

```sh
python3 tools/native-stack/capture_resource_diagnostic.py \
  --control-capture path/to/guard-evidence/resource-control-capture.json \
  --control-sha256 SHA256_OF_CONTROL_CAPTURE \
  --evidence-dir path/to/new-diagnostic-directory
```

This bundle is diagnostic. It records missing paired workload bindings,
macOS guard evidence, and production memory profiles explicitly, and it does
not satisfy the six-cell qualification gate.

`capture_resource_chain.py` runs the root-inclusive 33, 63, 64 and 65 Store
chains in paid, view and Core modes through a measured two-worker Tokio runtime.
Each case and stack configuration has a fresh child process and three attempts
with actual invocation-reservation peaks, fuel, receipts, persistent-state
digests, exact normalized balance transitions, rollback and resource cleanup
checks. The 65 Store cases must reject
with the typed invocation limit after a measured peak of 64. Six additional
children run success, typed trap, success for each call mode and stack
configuration through the same measured worker path, engine and fixed fixture.
The 64 Store target and its trap control must start from the same full state
and have identical successful observations. The driver requires a fresh
guard/source capture for the same committed binary and copies the complete
control closure into its evidence directory. It reports initial full-state
digests across paid, view and Core at each count. A differing cross-mode
prestate requires a reviewed, one-line fixture reason frozen in the driver:

```sh
python3 tools/native-stack/capture_resource_chain.py \
  --control-capture path/to/guard-evidence/resource-control-capture.json \
  --control-sha256 SHA256_OF_CONTROL_CAPTURE \
  --evidence-dir path/to/new-chain-evidence
```

The resulting bundle is a candidate actual binding for 12 cases. The other
29 cases, production memory profiles, and macOS guard remain missing. The
full six-cell validator still fails closed until those inputs are proven.

## Stage 1 finite and canonical development evidence

The finite paid, pending host I/O, and canonical callback adapters run through
the published contract and measured Tokio worker paths. Each isolated child
uses a reduced or production stack configuration with the teardown probe on
or off. The pending host fixture records a real `Poll::Pending` before its
notification releases the host import. Canonical samples cover a 16,384 byte
string roundtrip, realloc traps, a forbidden realloc import, and light and
heavy paid post-return traps. The paid worker and validator independently
check fuel-to-gas conversion and exact actor debit, burner credit, and supply
reduction. The heavy callback must charge more gas and fee than the light one.

The generated initialization adapter uses the production Pulley engine on a
measured Tokio worker. It publishes WIT-encoded components with active data
and element segments, then calls the valid variants through `Runtime::execute`.
Out-of-bounds variants trap during publish-time `init()` and must roll back.
A published component with a 4,096-byte active data segment exhausts a positive
view budget during instantiation, after input precharge and before canonical
input conversion. The same published component first succeeds with sufficient
fuel, and both calls record their Store lifecycle. Each target Store must close,
while receipts, resources,
and the full persistent digest remain stable across every trial.

The resource lifecycle adapter publishes a WIT-encoded guest resource through
the normal `Runtime::publish` path. A successful view explicitly drops the
resource and returns its destructor count. The trapping view checks that the
destructor ran before its distinct `UnreachableCodeReached` trap, then a fresh
successful call verifies reuse. The trapping call drops its gadget before it
traps, so this case proves explicit destructor dispatch and Store closure,
not reclamation of a guest resource still live at the trap. Failed publication
repeats an out-of-bounds active data segment, followed by valid control calls.
The worker records each
target Store teardown, receipts, resources, and the full persistent digest.
The failed initialization case proves that its Store and table lease close
after a component instantiation trap, before the `init` export is called. It
cannot prove guest resource cleanup because the active data trap occurs before
guest code can create one. Contract policy
rejects all start sections before compilation, so no resource constructor
can run during the admitted component's initialization.

The canonical type/value adapter publishes one component and directly calls
exports for nested record and variant values, a list of 64 records, a 16,384-byte
result string, and adjacent 64- and 65-level record results. It compares full
WAVE values and deterministic errors across the two stack settings and both
probe roles, with a fresh Store per attempt.

At source `3add2e56bbd0c28f6eef33883263f954dc4d67aa`, the Linux ARM64
development canonical type/value capture completed four isolated child
processes and 48 attempts. Each child ran the six declared samples twice
through one published component. Full returned WAVE values, system fuel, and
reset state matched across observed and probe-off roles and reduced and
production worker stacks. The 64-level result succeeded and the adjacent
65-level result was rejected deterministically at the result visitor. The two
observed children recorded 24 closed Store lifecycles in total, with zero
live invocations after each attempt. The standalone validator and three
evidence reviews accepted the capture. The exact-source build attestation
SHA-256 is
`75d93bcd532eb1e0ab9818154cf0756697f6729d100afed58daeac8bb674d20d`;
the test binary SHA-256 is
`dccb75d75bd264ac8078eb4709c1a9650f802fb9734c7399a710e14e1b8b581d`.
The guard control SHA-256 is
`a5b73fd0f8744cd02583b00fcce9b431bafc67897aa76556f8341476b1a85bfe`,
and the capture SHA-256 is
`bf3c7276fdcc25356888322edb774e4b6c03389d5cc3fdb7d0499708cd56efa9`.
This is one local diagnostic cell with `qualification_status: missing`. The
capture does not establish the 100-level component type boundary or the
maximum legal result size. It uses unsigned views and system fuel, and provides
no paid-call, cancellation, guest-write rollback, or trap-unwind proof. The
typed trap field is null. The other five cells and remaining case families
are required for S2 qualification.

The foreign WAVE adapter publishes a caller and a target through the same
runtime path. The caller generates each expression inside guest memory and
passes it through `foreign.call`, so the outer `run(index)` expression remains
shallow and short. The target parses 63 nested record values at the 64-level
expression boundary and a 16,384-byte string literal. The adjacent rejected
inputs have 64 nested records or a 16,385-byte literal. Separate target
exports return 64- and 65-level record values to exercise bounded result
printing. The validator distinguishes inner parser rejection from result
visitor rejection using error kinds and canonical conversion events. It checks
the full returned foreign WAVE string, including the nested record value, and
requires both caller and target Stores to close on every attempt. This fixture
does not exercise paid-call accounting or arbitrary third-party WIT shapes.

At source `b9405164a29a1872edb57bb7ec579b2d4d386748`, the Linux ARM64
development foreign WAVE capture completed four isolated child processes and
48 attempts. Each child ran the six boundary samples twice through the
published caller and target. Full returned WAVE strings, deterministic error
kinds, fuel, and reset state matched across observed and probe-off roles and
reduced and production stack settings. The two observed children recorded 48
closed Store lifecycles in total, with zero live invocations after each attempt.
The standalone validator and three evidence reviews accepted the capture.
The exact-source build attestation SHA-256 is
`c09ea40a24f7a7fa368a3c086718c7084e78f3145a9dc7a066079b487df5eeba`;
the test binary SHA-256 is
`5c505e2433e8086b567d90907d94adc41a5fbba8b23ffbb8e258a27328137531`.
The guard control SHA-256 is
`dfb5dad7937171958310b0995a7294b19122cbcadc66bac118396d349fa77891`,
and the capture SHA-256 is
`0d235dcb74a0ade9521b7789af3f720c2282ef902ab966a2fa874b2c23132256`.
This is one local diagnostic cell with `qualification_status: missing`. The
fixture uses unsigned views and system fuel. It provides no paid-call,
cancellation, guest-write, or trap-unwind proof; the typed trap field is null.
The other five cells and remaining case families are required for S2
qualification.

The SQLite pagination adapter prepares 1,024 token accounts, tests token
pages, then mints 1,024 NFTs and tests NFT pages. It uses the generated WAVE
request and result helpers around `Runtime::execute_api`, which reaches the
native contract invocation Store on a measured Tokio worker. The generated
`AsyncCursorQuery` builder has a non-`Send` future and is not used inside the
worker task. The adapter freezes the first, middle, and final page at sizes
1, 7, and 100 for both contracts, then checks every returned account, amount,
NFT ID, agreement ID, owner, creator, and continuation. The first external
signer is ID 7 after Core and five native contract signers at genesis. The
validator rejects the earlier ID 2 assumption and missing, duplicated,
shifted, or altered rows.

At source `743cb3e711afcb3bea7b428a736fa3ad9f9fb370`, the Linux ARM64
development pagination capture completed four isolated children and 144
attempts. All 18 declared samples ran twice per child. Exact full pages,
continuations, system fuel, and full persistent-state digests matched across
both probe roles and reduced and production worker stacks. The two observed
children recorded 72 closed target Stores in total, with zero live
invocations after every attempt. The standalone validator accepted all four
runs. The exact-source build attestation SHA-256 is
`3a007a63ff272d537a16ff17fee70cb61b3da3151ea5d66248567ac3cfc05ac9`;
the test binary SHA-256 is
`a33eef41d86954f11519dd11fd4f6b7c4bcdf48d65a7f12db3a6703bd3d515ae`.
The guard control SHA-256 is
`df2cdea2b57ecadfd4b192d1c140f766e5137195ae9358cc7e522d5f5eeee154`,
and the capture SHA-256 is
`5aeeb3073c1d1cee32a58155946afdc05b977c0cfe6de1a1d1cfbbdd1f97aa60`.
This is one local diagnostic cell with `qualification_status: missing`. The
adapter measures page semantics, fuel, state, and Store cleanup. It records
per-attempt elapsed time for diagnostics but does not establish SQL query
counts or comparative timing as performance evidence. It uses unsigned views
and provides no paid-call, cancellation, guest-write rollback, or
trap-unwind proof. The other five cells and remaining case families are
required for S2 qualification.

The SQLite range adapter publishes the pinned `arith` guest through
`Runtime::publish`, funds a signer, and writes 1,024 numeric map entries through
paid guest operations. The measured `number-entries` views use a lower
inclusive and upper exclusive range. For each page size 1, 7, and 100 and range
length 0, 1, 256, and 1,024, an attempt reads the first page as integers in
ascending order and the last page as decimals in descending order. Both views
reach the SQLite range iterator and have independently frozen exact row order,
values, and bounds. The capture compares measured fuel and persistent state
across runs and verifies Store teardown. The bounded samples
cover the empty and singleton ranges and both ends of longer ranges. They do not
exhaust every interior row of the 256 or 1,024 entry ranges.

At source `4a57b3a193b4a2126a000158ed0dba16408a1833`, the Linux ARM64
development range capture completed four isolated children, 24 attempts each,
and 96 attempts overall. The standalone validator accepted all four runs. The
two observed children recorded 96 created and 96 destroyed target Stores, with
zero live invocations after each attempt. Exact results, system fuel, and full
persistent-state digests matched across both probe roles and reduced and
production worker stacks. The exact-source build attestation SHA-256 is
`8ccfe03694e2890e34772b3eb9f2a158be70adfd4bafb0dae59f36815a2fe0b1`;
the test binary SHA-256 is
`da35dc7541faead4c1c89e9fa3f1a1a43cac9a00fe414cf7211a3304ed66d8a1`.
The guard control SHA-256 is
`3b8779a6ac34b00a9ac9331e5d94616d7abd73c527bdc98cf52b730ded8c2554`,
and the capture SHA-256 is
`458742df7d8460a53ae9eb7c7da60fa1e568154aaed117b63e8e7518cd7f7e23`.
This is one local diagnostic cell with `qualification_status: missing`. It does
not establish SQL query counts, comparative timing, or cross-node and six-cell
semantic equality. The measured calls are unsigned views; paid-call, guest
write rollback, cancellation, and trap unwind remain separate cases.

The SQLite large-value adapter publishes the `counter` guest, funds a signer,
and writes 101 ordered map keys through paid operations. A paid 16 KiB write
succeeds. A paid 1 MiB write deterministically exceeds the storage deposit
budget; the adapter checks its single error receipt and fee effects, then
rolls back an outer fixture savepoint and verifies complete persistent-state
restoration. A Core-signed 1 MiB write prepares the read fixture. The measured
unsigned views return pages of 1, 7, and 100 entries for both value sizes. The
host checks every returned byte, key, and continuation before recording compact
hashes. The outer savepoint isolates the test fixture; it does not imply that
a failed paid operation refunds its execution fee in production.

At source `7f118635ba2f24805ca19d680241b59680079b3b`, the Linux ARM64
development large-value capture completed four isolated children and 48
attempts. The standalone validator accepted all four runs. The two observed
children recorded 24 created and 24 destroyed target Stores, with zero live
invocations after every attempt. Exact page contents, cursors, fuel, receipts,
and full persistent-state digests matched across observed and probe-off roles
and reduced and production worker stacks. The exact-source build attestation
SHA-256 is
`fc49fef3d13ef5a039538742d2f4e28597627a4fcd9de384bd25fd5b09019a37`;
the test binary SHA-256 is
`55619541b260800f90377756b34ea5faf87351ad2aa2d2a72aa60c2440fbb9e3`.
The guard control SHA-256 is
`3af5c03263038935c73edef6d0ac5d8bd585de74df962009a105ad29c6c68a21`,
and the capture SHA-256 is
`1c27db9dca4191d550cdc266d2c02e51a4fcdaad0587003da8f1004111baca5b`.
This is one local diagnostic cell with `qualification_status: missing`. The
1 MiB write is Core fixture setup after a paid rejection. The other five cells
and cross-node semantic comparisons remain required for S2 qualification.

At source `b696727cbf0e189370399a1d3f29b0fbd7227da8`, the Linux ARM64
development native staking reward capture completed four isolated children and
32 attempts at populations 0, 4, 32, and 128, each repeated twice. The
standalone validator accepted all four runs. The two observed children recorded
28 created and 28 destroyed Stores, with no live invocation after any attempt.
Valid seeded x-only keys resolved to canonical signer IDs in the guest; the
validator checked that binding and holder-string ordering, including the final
holder's rounding residue. It also checked the independently calculated
emission, unchanged storage emission budget, validator status and withdrawal
metadata, full measured receipts, and state restoration across roles, repeats,
and worker stack settings. The exact-source build attestation SHA-256 is
`da76d2b90f2fd1dd2f0aa9e29646e376745b1afa92de240215f9a761ee96d359`;
the test binary SHA-256 is
`cc7a4162c528df1f10ebe7344fe4adafec511ec89293ecf6fe2f7b99090facf9`.
The guard control SHA-256 is
`dbe86e1ff4947ac3f5304947385423b3ff53a4e0e1b91097fe269c4e424cedd0`,
and the capture SHA-256 is
`bc889579a15ef6929073d2c67395293fdf92032553ff1be1e33c22c6f556e2f4`.
This is one local diagnostic cell with `qualification_status: missing`. The
other five cells and cross-node comparisons remain required for S2
qualification. It does not establish performance, production recovery, or
capacity policy.

At source `9a80bf5ff32f9df4b6cc40842099b9d995236c5e`, the Linux ARM64
development native filestorage lifecycle capture completed four isolated
children and 24 attempts. Each child repeated expiry of 32 due challenges,
settlement of 32 expired penalties, and a nine-step cleanup call within the
separate 32-step cleanup budget. Deterministic regtest setup created the
backlog; the measured operations used the real native Core calls. The
standalone validator accepted all four runs and checked the exact one,
65, and one receipt graph, each penalty's decimal burn and remaining stake
in challenge-ID order, collateral reservations, obligations, and full
persistent-state restoration across repeats, roles, and worker stack settings.
The two observed children recorded 268 created and 268 destroyed Stores.
Each child measured all three blocking decode threads actually used by the
default pool, including their stack guards. The exact-source build attestation
SHA-256 is
`a56c1ed903e5ad9095e147dba77e71bc76d338ad9be4dadb6767a2aa5a06195c`;
the test binary SHA-256 is
`cf5f285dfc19c472fbdefee6db14c6e8cb40a740dbff3a73e9d79a52da3f9add`.
The guard control SHA-256 is
`99e3d298df5904f22f9c92ac321ba59f5510329fd04fe883ff203867c200f7ec`,
and the capture SHA-256 is
`29a101e571de0f22d1214cc2ec9b274c0494453d2372419acebccfaaffa0c166`.
This is one local diagnostic cell with `qualification_status: missing`.
The other five cells and cross-node comparisons remain required for S2
qualification. Larger-replica staged cleanup, injected recovery failures,
complete reward accounting, and isolated service timing remain untested.

At source `f678cf541e1aef3c8c1813fe8a87638f4b070cf7`, the Linux ARM64
development Brotli raw-ceiling capture completed four isolated children and
16 attempts. Each child twice published a valid component whose decompressed
module was exactly 67,108,864 bytes, then twice submitted a module with one
more padding byte in its trailing custom section. The accepted publication
reached `init`, used 40,523 system fuel, and wrote one `Ok` receipt with gas 41
and the expected contract address. The over-ceiling publication returned a
deterministic content error before compilation, a Store, metered fuel use, or
a receipt. The standalone validator accepted all four runs. It checked the
exact raw-byte hashes, blocking-thread decode traces and stack capacities,
the init receipt, full persistent-state restoration, and equal outcomes across
repeats, roles, and worker stack settings. The exact-source build attestation
SHA-256 is
`8f703b94d01c59af3d8489bb15d0d7855a19c32b26e339e70dea70ab0b8fe11f`;
the test binary SHA-256 is
`7d5e186a08c66542151b8728b1be3efd8cb376a26e1d15940bb8023a795f2d81`.
The guard control SHA-256 is
`7695d9c969ba78168823ce8e8d80df142924f21494ccac357698da69e243f8eb`,
and the capture SHA-256 is
`fcc44584bc1201646d412781552c7c1f8099f956030bfb57fb00c536d3105fd8`.
This is one local diagnostic cell with `qualification_status: missing`.
The other five cells, cross-node parity, and operational qualification remain
open. The capture does not establish that all valid components fit within
the ceiling or that near-boundary publication meets service targets.

At source `8c5fe25a11b286cbbf37ec53958c8409c18626aa`, the Linux ARM64
development canonical capture completed 12 child processes, 56 attempts, and
268 closed Store lifecycles. The standalone validator accepted all 12 runs.
The archived capture SHA-256 is
`e99e60f0f3900f154a9d565f93606941994e5c6183d5cd9e6d6bcb6c236ae91d`;
its exact-source guard control SHA-256 is
`91bd618f1db597eca5dab24e0b5f644b28a839f965f318412e9b628ce3871674`.
The archive is local diagnostic evidence. Its `qualification_status` is
`missing`, since the other five cells and remaining case families have not
been captured. The canonical fixture performs no persistent guest write, so
its reset digest proves cleanup of this fixture, not rollback of a guest write.

The cold publication source now generates three variants of the pinned stack
probe module and submits them through `Runtime::publish`. It checks the
postcard-serialized instruction size against the compose limit, then observes
componentization, compilation, initialization receipts, rollback, and Store
teardown. The function-body candidate is 7,654,321 bytes with a one-byte-over
control. The `br_table` fixture has 7,654,308 zero-depth entries in a
7,654,321-byte body; adding one entry crosses the function-body size gate.
Although wasmparser names a 7,654,321-entry `br_table` cap, this encoding
cannot reach it inside an admitted body. The 256-block control-nesting
fixture is a candidate, not a claimed engine maximum. The source manifest
retains `fixture_admission_status: unverified` pending the remaining cells
and phase review. Postcard size checks establish a
serialized instruction proxy, not a complete signed transaction admission
result. Cross-node parity and the other qualification cells remain open.

At source `7ce943e66bd3b3412cf9554011a0e977119ae9b9`, the Linux ARM64
development cold-publication capture completed 12 isolated children and 40
attempts. The 7,654,321-byte large-function body and the 7,654,308-entry
`br_table` body were admitted in every role and worker stack setting. Their
one-byte-over bodies returned the same deterministic function-body-size error
before a Store, receipt, or metered fuel use. The 256-block control-nesting
fixture was admitted in every child. The 24 accepted attempts each produced
the expected `init` receipt and closed its Store; 16 rejected attempts
restored state without a receipt. The standalone validator accepted all 12
runs and equal semantics across repeats, roles, and stack settings. The
exact-source build attestation SHA-256 is
`c48199d1c97236aa5aef0793e3096ea3d55afa033b6d5729487834b3e173a525`;
the test binary SHA-256 is
`54bf5e4dce315b82ff4359cb5f14eb4aef0dd83fa2e5e629560beb4b4de9aa56`.
The guard control SHA-256 is
`9671e231db487d2e836985a26797dcaf790deebbf97da6ed847d5b219c180b14`,
and the combined capture SHA-256 is
`c028121e35e21c780d20da323c5b2b8b7d28586ea21a628335969984b6de18fe`.
This is one local diagnostic cell with `qualification_status: missing`.
The capture does not establish full signed-transaction admission,
cross-node parity, or service timing.

The S2 suite source registry maps all 41 required cases to 16 capture and
validator groups. `resource_suite_registry.py` checks unique case coverage and
pins each group's capture source, validator source, and parent manifest. Its
`source_registry_only` status is a source inventory, not a measurement.
`resource_suite_closure.py` accepts an archive rooted at
`<cell with slash replaced by underscore>/<group>/<capture name>` for each
of the six cells. It requires one source commit, the same binary and guard
control within each cell, all 16 groups and all 41 cases, and final boundary
captures. It emits `closure_only` because group semantics and cross-cell
parity still require their own validators and comparator. Run it only from the
clean checkout at the capture source commit, with `--root` set to the archive
root and `--output` set to a new index path outside the checkout.

The v2 chain capture and validator now accept every S2 host/profile cell and
bind the trace parser to its host OS. Actual capture is still required on each
host. `capture_resource_suite.py` runs all 16 capture groups for one cell in
registry order after checking the clean source commit, exact control, reviewed
boundary discovery, and frozen v2 auxiliary Store counts. It writes each group
under the archive layout used by the closure index and copies the exact Cargo
test executable once per cell. Run it separately on every
required host and profile with one common source commit. Its output is a
capture inventory, not a qualification decision.

The six-cell suite remains gated by reviewed boundary depths, a measured
macOS guard control, production memory profiles, and a common-source capture
run. `compare_resource_suite.py` checks the clean checkout at the archived
source commit, revalidates each copied binary, recorded Cargo artifact,
guard transcript, and child raw log, then compares the validators' semantic
signatures across all six cells. Archive validation uses the captured host OS
and page size instead of the verifier host. The original executable path
remains bound to the Cargo record and each child command; its bytes come from
the archived copy. The current source package has no measured macOS capture
or six-cell archive yet, so the comparator has only synthetic tests. The
`native-stack-s2.yml` workflow and `resource-suite-runbook.md` describe the
discovery, review, final capture, and comparison commands. Production memory
profiles and phase review remain separate acceptance gates.

The amendment is copied unchanged into
`docs/design/protocol-upgrades/native-stack-s2-resource-amendment-v1.md`.
Neither the manifest nor schema is a resource measurement or a change to the
production stack configuration. The memory profiles require separate
uninstrumented production-capacity runs and preserve actual host hardware and
OS field definitions alongside the reference profiles.

`qualify.py` invokes one worker process and one fresh control process per probe kind. Each process funds and publishes the synchronous `stack-probe` fixture through the normal user contract path, then executes it through `Runtime::execute` or `Runtime::execute_system_view`. Publication populates the compiled component cache once per process. Each observation uses fresh invocation Stores. These measurements describe warm compiled-cache execution, not cold compilation or loading.

After each call, the worker checks guest cleanup before attempting any harness reset. It then rolls back an outer savepoint and verifies the persistent-state digest, balances, collateral floor, token supply, resource count, call stack, savepoints, and actual live invocation leases. A reset failure fails the entire kind. The separate control process builds the same fixture and exercises both discovered boundary depths, or the single bounded large-frame case. Its execution observations must match the worker, including fuel and receipts.

Build the fixture with the repository's pinned test-contract build, then compile the indexer test binary for each profile:

```sh
./tools/kontor build test --runtime podman -j 2
cargo test --locked --manifest-path core/Cargo.toml -p indexer --lib --no-run -j2
cargo test --locked --manifest-path core/Cargo.toml -p indexer --lib --no-run --release -j2
```

Pass the resulting test executable to the driver:

```sh
python3 tools/native-stack/qualify.py --binary path/to/indexer-test --cell Linux-ARM64/dev --output path/to/evidence
```

The Rust worker adaptively finds adjacent boundaries for plain recursion and recursion with 32 live `u64` values per frame, then repeats both depths in forward and reverse order. Separate-contract reentry directly samples depths 62, 63, and 64 three times each, including a reverse pass. It publishes the same 65-contract fixture in both processes. The driver also runs one fixed 256-value frame. Each JSON observation includes the component hash, stack settings, fuel usage, outcome, persisted receipt, state marker, sample identity, and reset evidence. A failed paid or Core procedure must leave its marker at zero and record the matching `Trap` or `Other` receipt. View calls must not record a procedure receipt.

Schema 5 retains each complete process transcript plus separate extracted sample logs, all covered by a SHA-256 manifest. The comparator verifies the extraction against the complete transcript, ordered sample identities, the terminal summary and successful test completion. A signal, timeout, missing sample, failed reset or differing fresh-control result fails qualification without retries. The original scalar probe remains available by invoking the ignored Rust test without `KONTOR_STACK_MODE`; CI uses only the worker/control flow.

The GitHub Actions workflow collects Linux x86-64, Linux ARM64, and macOS ARM64 results in development and release profiles. `compare.py` requires the exact six cells, successful qualification jobs, matching source and lockfile hashes, the approved Wasmtime revision, the Pulley target, the effective stack settings, adjacent repeated stack boundaries, and matching observations. It also checks the root-inclusive 64-Store success and 65-Store rejection in the stack probe. The workflow runs the paid, view, and Core chain fixture separately. The fixed single-frame check is a bounded probe; a passing result does not prove that larger frames are safe.

Run the comparator's negative controls with `python3 -m unittest discover -s tools/native-stack -p 'test_*.py'`. For full qualification, use the workflow, which preserves the Cargo JSON build log in each evidence directory and supplies the separate chain-matrix log to the driver. A selected local `--case` run is diagnostic and cannot satisfy the six-cell comparator. The historical results in `qualification-results.md` use the earlier async guest fixture and are context only. The synchronous fixture requires a fresh six-cell qualification before S2 can merge.

The synchronous probe's compressed SHA-256 is `e396317b4eb14c9a29d47acbe8a9f7b0e29770d47e7df53e4bed12d5c5bfce50`. Its exact encoder inventory is `encoder-inventory/inventory-s2-stack-probe.tsv`, with three embedded modules and zero core or component starts.

S2 replaces S1's default Wasmtime feature selection with the explicit production features in `core/Cargo.toml`: `anyhow`, `async`, `backtrace`, `component-model`, `component-model-async`, `cranelift`, `gc-copying`, `gc-drc`, `gc-null`, `pooling-allocator`, `pulley`, `runtime`, `std`, `threads`, `wat`, `wave`, and `wit-parser`. Cargo additionally resolves `gc`, `once_cell`, and `wasmtime-jit-icache-coherence` through these features. `call-hook` appears only in the indexer's development dependency graph. The `threads` compile feature provides `wasm_threads(false)` for the nine-setting capability check; the runtime disables guest threads. Each cell retains Cargo's build JSON and both raw resolved feature lists. The comparator requires the approved production closure, its test-only `call-hook` addition, and absence of `cache`, `profiling`, and `debug-builtins`. This feature change and the new synchronous binary require fresh target and profile qualification, so S1's earlier measurements cannot be reused. `KONTOR_STACK_TIMING` lines in raw probe logs describe setup, publication, execution, and postcall time; they are diagnostic and excluded from deterministic cross-cell comparisons.
# Local workload resource profiles

`run_workload_profile.py` runs one ignored Rust workload test in a transient
user systemd service on Linux. `conservative` enforces two CPUs and 12 GiB;
`burst` enforces eight CPUs and 16 GiB. Both disable swap. The worker verifies
the actual cgroup limits and inherited limits before launching the binary,
restricts CPU affinity, and records whole-service CPU usage, memory peak,
memory events, binary/log hashes and terminal status. The whole service,
including test children, is stopped on timeout. Its measurements include
fixture setup and validation, so use the workload's event records for service
latency rather than treating total process duration as block application time.
The record also captures CPU topology, physical memory, page size, checkout and
temporary-directory mounts, and visible block devices. This requires the Linux
`lscpu`, `findmnt` and `lsblk` utilities. Storage metadata describes what the host
exposes; it does not establish equivalence to a cloud disk or its performance.

Prepare an environment JSON containing the exact `KONTOR_WORKLOAD_*` settings
for the saved input and consumer identity. Then run, for example:

```sh
python3 -B tools/native-stack/run_workload_profile.py \
  --profile conservative --binary /absolute/path/to/indexer-test-binary \
  --test reactor::workload_tests::smoke::populated::timed::run::workload_timed_mixed_event_replay \
  --environment /absolute/path/to/workload-environment.json \
  --output /absolute/path/to/new-measurement-directory --timeout 1800
```

The output directory must be new. Inspect both `supervisor.json` and
`measurement.json`: missing or nonterminal measurement records, failed tests,
OOM events and nonzero supervisor exits are failures. The wrapper rejects
zero selected tests and ignored tests. A successful measurement establishes
only the recorded local resource constraints. It does not establish production
hardware equivalence, freeze the workload envelope, compare S1 against S2, or
satisfy the phase's performance acceptance criteria by itself.

## Historical replay with live API arrivals

The ignored test
`reactor::workload_tests::smoke::populated::timed::archive::workload_saved_timed_historical_replay`
consumes the same frozen archive and explicit consumer identity as
`workload_saved_timed_events_replay`. It requires complete mixed historical
intervals (`fresh_backlog: 0`). Canonical blocks and all their batches replay
without waiting for their historical timestamps. Eight existing view clients
remain active throughout each of the two independent database restores.

An independent monotonic producer enqueues external API requests every ten
seconds for the representative profile and every second for stress, starting
at time zero. Requests use the archive's distinct signed API inputs exactly
once, in order. At each canonical boundary, at most one due request runs; after
the final boundary, all requests due strictly before the completion observation
must drain. This keeps both canonical work and API work progressing while
making overload visible. No future request is awaited to fill out the archive.
Exceeding the archive's finite real-time input horizon fails the run.

Historical API occurrences are omitted from execution but their frozen
poststate checkpoints are still checked, since those calls originally rolled
back. Each external API request executes at the current canonical tip, checks
its results against the independent recipe oracle, and verifies complete
database rollback and restored runtime context. Its actual tip and results are
logged separately. Original-position API result equality remains the job of
the existing semantic replay test; both tests are needed.

`workload_historical_replay` reports the canonical historical seconds, canonical
completion time, end-to-end completion time, separate canonical/API execution
service totals, and per-request intended arrival, enqueue, dispatch and
completion times. The reported queue peak is the maximum observed at dispatch
boundaries, not a continuously sampled peak. Oracle/checkpoint work is included
in elapsed time and excluded from execution service. Historical throughput is
`historical_seconds / (completion_ns / 1e9)`; API requests never increase its
historical numerator. These records do not by themselves establish release
performance, paired S1/S2 results, or isolated node memory usage.
