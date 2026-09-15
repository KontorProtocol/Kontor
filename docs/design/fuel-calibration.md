# Runtime fuel coverage and calibration

Baseline: main `bf6699ae79ff14c084ac2ee20a73066aafea1dfe` (PR #569),
2026-09-15. Tracks [#462](https://github.com/KontorProtocol/Kontor/issues/462).
This investigation changes no charges, prices, contract interfaces or consensus rules.

## Method and boundaries

First establish which work consumes fuel, then measure representative implementations,
then expand to expensive branches before choosing a schedule and capacity target.
The [existing FuelGauge](gas-metering-and-congestion.md#consolidated-gauge) remains
the single execution-usage collector. Benchmarks read the same stores' remaining
fuel; they do not maintain a second cost table. Deposit reservations are collateral,
not CPU/IO consumption, and must stay separate.

Offline measurements inform fixed protocol constants. Nodes must never charge from
local elapsed time, cache hits, platform details or actual disk latency. Reference
hardware and conservative headroom still need agreement. Measuring CPU time alone
cannot establish bounds on memory or IO, or select a KOR price.

Useful precedents:

- [Soroban's metering design](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-10.md)
  decomposes host work and calibrates component models offline. This motivates
  coverage of every expensive path and simple base-plus-input formulas.
- [Ethereum EIP-2929](https://eips.ethereum.org/EIPS/eip-2929) addresses storage
  underpricing and distinguishes cold/warm accesses with protocol-defined access
  sets. Kontor should investigate storage costs without copying EVM constants or
  using a node's physical cache state as a billing input.
- [FRAME benchmarking](https://paritytech.github.io/polkadot-sdk/master/polkadot_sdk_docs/reference_docs/frame_benchmarking_weight/index.html)
  emphasizes reference hardware, input scaling and worst-case branches.
- [CosmWasm's gas advisory](https://github.com/CosmWasm/advisories/blob/main/CWAs/CWA-2024-004.md)
  demonstrates why guest Wasm workloads need validation too: covering host imports
  alone does not establish a safe execution-time budget.

These are methodological precedents, not evidence that Kontor's current constants
are correct or that another chain's constants transfer to this runtime.

## Coverage map

Charges below are raw fuel, before gas rounding. `n` means bytes unless otherwise
specified. The table groups wrappers sharing an implementation; it covers the host
families registered by `Runtime::new_linkers` and the surrounding transaction path.
“Uncharged” means no explicit charge for that host work. A guest invoking it still
executes metered Wasm instructions; this is not a claim of an entirely free transaction.

| Surface | Current charge and timing | Work or dimension to investigate | First benchmark set |
| --- | --- | --- | --- |
| Primitive storage reads (all types) | `10 * stored_bytes`, only after a successful SQL lookup; decode follows charge | Missing lookup has no host charge. Path validation and SQL precede charging. History depth, path length, decode failures and insufficient budgets matter. | Present/missing point reads; byte values |
| Existence | 50 before SQL, after path validation | Subtree existence, key size, tombstones/history; empty subtree | Pending |
| Open keys/row cursor | 200 before query, after path validation | Range bounds/key bytes, empty query, SQL setup | Row scans |
| Advance keys cursor | `100 + 10 * returned_key_bytes` after polling | Deduplication can consume multiple descendant rows per returned child; terminal poll and errors have no explicit charge | Pending deep-key case |
| Advance scalar row cursor | `100 + 10 * (key_bytes + stored_bytes)` after polling, before decode | History/tombstones, non-scalar failure, terminal polls; returned bytes do not describe every visited DB row | Flat u64 row scans |
| Variant match | `500 + 10 * candidate_count` before query, after path validation | Candidate byte lengths and latest-variant subtree query. `Fuel` parameter is misleadingly named `regexp_len`; call site passes count. | Pending |
| Primitive storage writes (including void) | Path charge of 10 per segment; serialize; `200 + 10 * stored_bytes`; optional deposit charge; SQL write | Path validation precedes charge; serialize/allocation precedes size charge. Footprint lookup, depositor changes, checkpoint triggers and version history add work. | Same-height byte overwrites, no depositor |
| Delete / variant cleanup | Discover/materialize rows; `200 + 200 * rows + 10 * (path_bytes + value_bytes)`; then writes | Discovery occurs before charge. Tombstones, hard-delete cleanup and footprint revival have different work. An exhausted budget does not stop discovery. | Pending |
| Context/signer/holder/contract handles | Fixed 50–500 charges, mostly before work | Some include DB resolution/identity creation; others only clone/allocate. Key/ref lengths and repeated use matter. | Pending |
| Block height / network | No explicit charge | Constant field access currently clones the whole runtime first | Runtime-clone diagnostic |
| Transaction accessors | Handle acquisition 500; id/outpoint/OP_RETURN accessors have no separate charge | Repeated id formatting and OP_RETURN copying after acquiring one handle | Pending |
| Drop resources | No explicit charge | Cursor/table teardown, proof deallocation, resource churn | Included in scan timing, not isolated |
| Integer/Decimal | Conversion/comparison/arithmetic fixed 50–500; parse/render `100 + 10 * text_bytes` | Bounded-width values still have expensive operand patterns. Parsing charges first; rendering happens before output-size charge. | Integer add/sqrt, small and large u64 operands |
| SHA-256 / HKDF | Both use `500 + 10 * input_bytes`, before hashing | Different fixed costs; HKDF salt/info dimensions; allocation | Both, 0–64 KiB inputs |
| Generated id / block entropy | 500 / 200 before work | Fixed hash/counter vs block DB lookup | Pending |
| Aggregate root / frontier append (native) | `1000 + 200 * file_count` before validation | Slot positions, tree depth, frontier peaks and carry propagation, invalid inputs | Pending |
| Challenge id (native) | 500 before work | Metadata, seed and challenge construction | Pending |
| Proof parsing (native) | `1000 + 10 * proof_bytes` before decode | Valid/invalid encodings, allocations, resource lifetime | Pending |
| Proof verification (native) | 50,000 before work | Variable challenges/roots/files and proof complexity; late failure. Trace contract limits before deriving worst cases. | Pending |
| Storage floor (native deposit interface) | No explicit charge | Signer resolution, cached-total SQL lookup, numeric conversion | Pending |
| BLS registration / provenance update | Native system callback charges 1,000 before actual executor work | These are existing surrogate charges, not entirely unmetered operations. Benchmark signature/PoP work and DB/update failure branches. | Pending |
| Common host wrapper setup | Many wrappers clone `Runtime` before reaching the charged helper | Includes cloning both component linkers and their definition maps; input-independent overhead plus any copied transaction data | Runtime/linker clone diagnostics |
| Foreign calls | No separate entry charge; child Wasm/host work consumes shared budget | Argument parsing, component loading, savepoints and resource setup outside Wasm; success and caught failure | Existing lifecycle regressions; timing pending |
| Result processing | Procedure result `200 + 10 * serialized_bytes`, before commit | Serialization occurs first; view results and ABI copies need separate accounting review | Existing lifecycle regressions; timing pending |
| Guest Wasm | Wasmtime 48.0.2 operator/bulk-memory/initialization fuel, CoW disabled | CPU-heavy operations, memory growth/copy/fill, async/component call overhead, traps | Integer loop and memory copy |
| Component loading / publication | Init is metered; decompression, validation, compilation and cache loading have no distinct charge | Cold/warm load, publish bytes, malformed/late-invalid components, linking | Pending |
| Transaction admission/execution | Operation calls are metered; parsing and aggregate BLS verification precede them | Signed input size/count, invalid signatures, payer resolution, sponsorship, decompression and instruction decoding | Pending |
| Test imports / type-only interfaces | Error/panic test hooks have no charge; type-only interfaces have no executable methods | Keep fault-injection surface separate from production costing | No benchmark needed for type-only interfaces |

Sources in this repository: [fuel table](../../core/indexer/src/runtime/fuel.rs),
[storage hosts](../../core/indexer/src/runtime/host_storage.rs),
[context helpers](../../core/indexer/src/runtime/host_context/runtime_ext.rs),
[transaction accessors](../../core/indexer/src/runtime/host_context/transaction.rs),
[numeric hosts](../../core/indexer/src/runtime/host_numbers.rs),
[crypto/native hosts](../../core/indexer/src/runtime/host_files.rs),
[call lifecycle](../../core/indexer/src/runtime/call.rs),
[runtime loading/publication](../../core/indexer/src/runtime/mod.rs),
[executor](../../core/indexer/src/reactor/executor.rs), and
[versioned storage queries](../../core/indexer/src/database/queries/contract_state.rs).
`Fuel::ProofChallengeIds` has no call site at this baseline; an enum entry alone
is not evidence that a path is metered.

The confirmed gaps above are code-path observations, not completed exploit or
underpricing proofs. For example, key scans stream live rows, but may skip old
versions/tombstones in SQL and deduplicate descendants in Rust. Metering only returned
children cannot by itself bound that work. Point reads use a latest-version window;
benchmarking one version per path does not establish their cost under long history.

There are partial guards already: point-read SQL withholds a value whose stored
size exceeds remaining raw fuel, although that is not the full `10 * bytes`
charge. Delete discovery selects paths and sizes rather than loading value blobs.
Those guards reduce allocation exposure but do not charge for lookup/discovery
itself. Any fix should preserve them and test the actual exhaustion boundaries.

## Reproducing the first benchmark set

The ignored [calibration test](../../core/indexer/src/runtime/fuel/calibration.rs)
calls actual generated host trait implementations, using production storage and
numeric/crypto functions. Core Wasm probes use the normal runtime engine. Diagnostic clone and bare SHA-256
cases isolate existing implementation costs; their zero fuel is intentional because
they are internal functions, not independently callable host imports. There is
one warmup batch followed by seven measured batches per case. Each batch resets
fuel; timing has no pass/fail threshold. Fixture/result checks catch wrong workloads.

Run alone from the repository root (no competing test suite or compiler):

```sh
mkdir -p .build-cache/fuel-calibration-tmp
TMPDIR="$PWD/.build-cache/fuel-calibration-tmp" RUST_LOG=warn \
  cargo test --manifest-path core/Cargo.toml --locked --release \
  -p indexer --lib runtime::fuel::calibration::fuel_calibration -j 2 \
  -- --ignored --exact --nocapture > /tmp/kontor-fuel-calibration.log 2>&1
sed -n 's/^FUEL_CALIBRATION //p' /tmp/kontor-fuel-calibration.log > /tmp/kontor-fuel-calibration.jsonl
```

Each JSON sample reports **whole-batch** nanoseconds and consumed fuel. Divide
both by `iterations` for per-operation values; summarize repeated samples with
median and range. Do not divide time by fuel for a zero-fuel case. The no-op harness
provides overhead context; raw times are not automatically baseline-subtracted.

Limits of this first set:

- Host calls bypass actual guest/component ABI lifting/lowering. Timings include
  the harness, argument clones, async dispatch, result checking and destruction.
  They locate disparities; they cannot isolate a pure hash instruction cost.
- The DB is local and warm; `TMPDIR` selects its filesystem. Fixtures have one
  version per key; overwrites replace
  the same `(contract_id, height, path)` row. Setup and rollback are outside timing.
  No depositor means no collateral reservation, while non-exempt contract storage
  still exercises footprint bookkeeping. This is not complete user write pricing.
- Core Wasm execution excludes compilation/instantiation from timed calls. It is
  a guest instruction comparison, not an end-to-end component-call benchmark.
- Case order is fixed. Thermal drift, OS scheduling and heterogeneous CPU cores
  can bias comparisons. A first-machine run is exploratory, not a reference-hardware
  calibration or cross-platform guarantee.
- Default gauge profiling is disabled. Consumed fuel is read directly from each
  store, including its real host charges. No additional tracing model is introduced.

## Follow-up sequence

1. Add focused contract regressions for missing reads, exhausted budgets, empty
   cursor polls, long paths and deep-key deduplication. Decide deterministic base
   charges and how to bound or meter work before expensive DB/serialization steps.
   Avoid charging per physical SQLite step or real cache miss.
2. Expand measurements to version history/tombstones, deletes, deposit bookkeeping,
   component/ABI boundaries, publication, proof verification and BLS. Exercise late
   failures and maximal supported inputs, not just ordinary successful calls.
3. Repeat on agreed x86-64 and ARM hardware, with controlled scheduling and cold/warm
   cases. Measure memory and IO as well as elapsed time. Derive conservative fixed
   or input-dependent formulas and verify composite workloads against them.
4. Commit/version the schedule with deterministic billing/rollback/replay regressions.
   Then choose a block-work target and implement congestion pricing. This investigation
   advances #462 but does not close it or supersede [#445](https://github.com/KontorProtocol/Kontor/pull/445).

## First measurements: Linux aarch64, 2026-09-15

Release mode, Apple M2, Linux 7.1.13 Asahi, rustc 1.98.0, Wasmtime 48.0.2.
No concurrent build/test run during measurement; no CPU affinity pinned. The DB
used the repository filesystem via `.build-cache/usage-test-tmp`. All **47 cases**
completed, seven measured batches each. Fuel was identical across all seven samples
within each case. The [compact measurement archive](../measurements/fuel-calibration-linux-aarch64.jsonl)
retains every batch time, the common batch fuel, iteration count, machine details
and benchmark source hash. Divide archived batch values by `iterations`.

Selected per-operation values (scan operations consume the entire indicated set):

| Case | Median μs | Range μs | Consumed fuel |
| --- | ---: | ---: | ---: |
| Runtime clone, diagnostic | 39.393 | 39.343–39.499 | 0 |
| Both linkers clone, diagnostic | 39.279 | 39.222–39.424 | 0 |
| Bare empty SHA-256, diagnostic | 0.188 | 0.188–0.196 | 0 |
| Empty SHA-256 host call | 39.514 | 39.458–39.605 | 500 |
| SHA-256 host call, 64 KiB | 223.314 | 223.287–223.456 | 655,860 |
| HKDF host call, empty inputs | 41.168 | 41.144–41.198 | 500 |
| Present u64 read, 1,024 keys | 56.725 | 56.633–56.817 | 20 |
| Missing u64 read, 1,024 keys | 55.216 | 55.102–55.320 | 0 |
| Scan 1,024 u64 rows | 40,784.958 | 40,776.687–40,820.166 | 149,950 |
| Scan 16,384 u64 rows | 651,183.078 | 650,966.554–651,409.445 | 2,453,950 |
| Overwrite 64 bytes, no depositor | 70.615 | 70.493–70.692 | 860 |
| Integer add, operands u64::MAX | 0.089 | 0.088–0.089 | 100 |
| Wasm integer loop, 65,536 iterations | 62.867 | 61.874–67.489 | 917,509 |
| Wasm memory copy, 64 KiB | 1.129 | 1.102–1.133 | 65,543 |

Three conclusions are supported by this first set:

1. **Remove avoidable linker copying before fitting prices.** Most of the empty
   hash host call's time is explained by runtime/linker cloning. `Runtime` derives
   `Clone`, contains two `Linker`s by value, and wrappers clone it before invoking
   helpers. Wasmtime 48.0.2's component `Linker::clone` copies its string pool and
   definition map. The standalone clone measurements corroborate that source path.
   Share the immutable linkers, retaining user/native capability separation, then
   rerun these cases and end-to-end contract regressions. This is a recommendation,
   not an implemented optimization or an end-to-end speedup claim.
2. **Storage needs a base-cost model.** Present and missing small reads have similar
   elapsed costs but consume 20 and zero host fuel in this fixture. A byte-only
   successful-read charge does not represent the lookup. The flat row scans scale
   roughly with returned rows here, but they do not cover deduplication or history.
3. **One current fuel unit does not imply similar work across families.** The
   integer loop and point read take similar time but consume very different fuel.
   This supports calibration; it does not establish exact replacement ratios.
   The memory-copy case also shows why a single Wasm loop cannot calibrate all
   guest instructions. Bare primitive timings exclude the component boundary.

The first follow-up should therefore share immutable linkers and remeasure, before
changing the charge schedule. After that, follow the coverage/regression sequence
above. No price constants or block-capacity target have been selected.

Validation: the manual release benchmark passed all 47 cases; indexer Clippy with
library/tests and warnings denied passed; formatting and diff checks passed. The
benchmark is ignored in ordinary test runs. This slice does not modify production
behavior, so it does not require rebuilding contract/SDK components or rerunning
the unchanged cluster suite.
