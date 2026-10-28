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
Actual Wasmtime fiber stack ranges also remain unbound; pthread measurements
describe the Tokio and caller stacks only.

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
