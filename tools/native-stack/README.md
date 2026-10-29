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

Cold publish function size, branch-table size and control nesting remain
unverified accepted fixtures. The wasmparser source limits alone do not prove
that a component with that shape passes WIT, serialized transaction and
publication admission. The validator keeps those gates open until near-boundary
accepted fixtures and reject controls are frozen and source reviewed.

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
