# Conversion work accounting

2026-09-17. Baseline: main `0fc43b5a` (#578), Wasmtime 48.0.2.
The initial investigation measured the baseline below. The implementation now
meters WAVE input construction and output structure; native ABI conversion
remains a separate boundary.

## Implemented WAVE accounting

All charges use the existing Store fuel balance and optional FuelGauge:

| Tariff | Initial cost | Charged before |
| --- | ---: | --- |
| `WaveInputBytes(n)` | 10n | Expression validation and parsing, including malformed expressions |
| `WaveValue` | 50 | Constructing an input value, visiting an output value, or processing a supplied flag |
| `WaveTypeField(n)` | 50 + 10n | Examining an input schema field/case/name and copying a selected name |
| Existing `Result` / `ResultBytes(n)` | 200 / 10n | Output setup / appending encoded bytes |

These coefficients follow existing scalar and byte tariffs. They are provisional
prices to calibrate, not measured CPU-to-fuel ratios. Each boundary traversal pays
again, including nested calls. An absent option and an empty container each count
as one value. Only selected payloads are constructed/visited. Input schema searches
also pay for candidates examined before finding a selected enum/variant case.

Input keeps wasm-wave's parser, AST accessors, and scalar decoding. A small typed
container builder checks fuel before materializing children or defaulted options.
The stock Wasmtime `WasmValue` constructors recursively revalidate children and
search record schemas repeatedly, making wide records quadratic. The runtime
builder resolves fields once, preserving the pinned parser's handling of unordered,
duplicate, unknown, and omitted fields. Compatibility tests compare both builders.
No eager fallback expression is constructed on the normal function path.

Raw source bytes are charged up front. This bounds parsing, string unescaping,
and building the AST/record lookup from supplied syntax. Type-driven expansion is
charged incrementally. The fallback's extra generated source is charged before its
second parse; constructing that source is bounded by the already paid original
source length and WAVE's fixed maximum escape expansion.

Output uses a bounded structural preflight, then the unchanged standard writer
with its existing bounded byte sink. The preflight borrows values, includes omitted
options, and stops on the first unaffordable value. It does not copy strings or walk
their contents. Emitted names and strings are paid by `ResultBytes`; omitted field
names are borrowed, not scanned/copied by this stage. This adds an extra structural
traversal, but avoids a custom WAVE writer or a large adapter implementing infallible
trait callbacks. Both input construction and output preflight reject value nesting
beyond 64, including nesting supplied by types rather than explicit WAVE syntax.

Fuel spent before a failure remains spent, and nested callers inherit that reduced
balance. Existing top-level preparation still precedes escrow hold/settlement:
these charges bound preparation and enter execution usage, but this change does
not add token fee settlement to previously unsettled preparation failures.

**Still outside this bound:** Wasmtime has already lifted an exported result before
the WAVE preflight sees it. Its allocation allowance does not cover all records,
tuples, or field names. No production allocation guard or new ABI decoder is added.
The native import/name audit and preparation fee-settlement policy remain follow-ups.

## Validation and timings

The runtime suite passes 180 tests (13 manual benchmarks ignored), including
rollback, nested preparation failure accounting, token settlement, resource
cleanup, input compatibility, exact output budgets, and early termination for
omitted fields. Release Clippy with warnings denied and formatting checks pass.

An isolated Linux ARM64 release sample, 1,000 constructions per row, with the
same pre-parsed `f({:})` input and profiling disabled:

| Absent optional fields | Stock WAVE construction per call | Metered construction per call |
| ---: | ---: | ---: |
| 16 | 6.10 µs | 1.21 µs |
| 128 | 106.48 µs | 5.63 µs |
| 512 | 1,306.93 µs | 31.31 µs |

The isolated output comparison separates the byte guard already on main from
the new structural pass (1,000 encodings, times below are per encoding):

| Result shape | Existing byte-bounded writer | Structural pass plus byte-bounded writer |
| --- | ---: | ---: |
| Scalar | 0.051 µs | 0.060 µs |
| Escaped Unicode string, 16,386 output bytes | 171.89 µs | 171.88 µs |
| 4,096 scalar list elements, 20,480 output bytes | 57.68 µs | 84.67 µs |
| 512 omitted optional record fields, 3 output bytes | 1.48 µs | 6.00 µs |

Structural output accounting therefore has a real CPU cost: about 27 µs (47%)
in this large-list encoding microbenchmark, and 4.5 µs for the omitted record.
Strings are not scanned twice. This is a tradeoff for bounding work that the
byte sink cannot see; it should not be described as an across-the-board speedup.

These are local microbenchmarks, not end-to-end contract latency or cross-platform
calibration. The improvement comes from removing repeated record validation, not
from charging fuel itself. The ignored `construction_overhead` and
`encoding_overhead` tests retain the comparison for future changes.

## Conclusion

Keep conversion charges in the existing `Fuel`/`FuelGauge` system. Do not add a
second balance or a blanket surcharge to every host import. Several imports
already charge for their variable inputs and outputs. What remains is to cover
unpriced structure and repeated work, and then make the guard enforce that model.

Neither encoded bytes nor Wasmtime's allocation allowance measures all conversion
work. A record of absent options is a concrete counterexample on both sides:
its short WAVE representation expands into many owned values, and those values
are later visited but omitted when writing WAVE again.

## Boundaries and existing coverage

```text
call expression
  -> WAVE parsing and typed value construction
  -> Wasmtime lowers arguments into guest memory
  -> guest instructions
       -> Wasmtime lifts import arguments into owned host values
       -> Kontor import charges and performs its operation
       -> Wasmtime lowers the import result into guest memory
  -> Wasmtime lifts the exported result into owned host values
  -> Kontor's bounded WAVE writer
  -> commit/rollback, fee settlement, parent fuel return
```

Instructions, host tariffs, and result encoding share execution fuel. The
allocation allowance is a separate, replenished limit on selected guest-to-host
conversions. Its public getter reports the configured limit, not consumption;
host-to-guest copying is outside that limit. See the pinned
[Wasmtime API](https://docs.rs/wasmtime/48.0.2/wasmtime/struct.Store.html#method.set_hostcall_fuel).

| Boundary or operation | Current charge/bound | Accounting consequence |
| --- | --- | --- |
| WAVE input parsing and typed construction | Source bytes charged before parsing; values/schema names charged before construction | Includes implicit optional fields; stops construction when fuel runs out. |
| Dynamic argument lowering | Guest allocator instructions consume fuel; native conversion is not an instruction charge | Do not confuse allocator fuel with the entire lowering cost. |
| Storage paths and range bounds | `Fuel::Path`, charged before validation/query work | Preserve this coverage instead of charging identical input bytes again generically. ABI lifting has already occurred at this point. |
| Storage reads, writes, cursor results | Lookup/entry tariffs plus stored/key/value byte tariffs and size guards | Already size-sensitive. Serialized storage bytes are not interchangeable with arbitrary ABI allocation units. |
| Hashing and HKDF | Base plus all input bytes, before cryptographic work | Repetition already pays proportionally; calibrate the combined tariff against conversion plus operation work. |
| Holder reference validation | Base plus supplied variable string bytes, including invalid references | Already handles the input-copy/validation concern explicitly. |
| Numeric imports | Fixed-shape numeric values pay fixed tariffs; text parsing/formatting pays string bytes | Preserve fixed-shape treatment. A host-layout-dependent charge adds no useful information. |
| Transaction data | Base plus bytes before cloning the shared payload | Already size-sensitive on the return side. |
| Context and holder accessors | Mostly fixed-size IDs/resources or validated references with fixed tariffs | Include their conversion cost in base calibration; avoid per-field runtime walks of fixed schemas. |
| Contract address | Fixed tariff, but the returned address contains a variable-length name | The fixed tariff is not a demonstrated bound on name copying. Include names in the follow-up audit. |
| `foreign.call` | Child shares remaining execution fuel and pays expression/construction/result tariffs | Parent ABI argument lifting still precedes the child charge. Include repeated calls, failed preparation, and fallback. |
| Native file/proof imports | Mixture of per-file, per-proof-byte and fixed tariffs | Audit malformed root/seed/peaks inputs as well as valid fixed-size values. Some bytes are lifted before validation rejects them. These imports are restricted to native contracts. |
| Exported result lifting | Wasmtime allowance covers strings/lists but not all record/tuple/name construction | A byte guard alone cannot close this boundary. |
| WAVE result writing | Bounded structural preflight, then base plus emitted UTF-8 bytes bounded before append | Absent record fields pay for visits even though they emit no bytes. |

Relevant implementations: `runtime/call.rs`, `runtime/host_storage.rs`,
`runtime/host_files.rs`, `runtime/host_numbers.rs`, `runtime/host_context/*`,
`runtime/fuel.rs`, and `runtime/call/result.rs`.

## Proposed logical units

Use protocol-defined counts rather than `size_of::<Val>()`, Rust capacities,
allocator behavior, elapsed time, or historical DB size:

- **Values visited or materialized:** each scalar, resource handle, and container
  counts once for the stage doing the work. Include every record field and an
  absent option itself. Count selected variant/result/option payloads, not inactive
  cases. Empty containers still count. A list of N scalars has N+1 values.
- **Variable bytes processed:** UTF-8 string/input bytes and names actually copied
  or examined. Keep emitted WAVE bytes separate from names or other data that the
  output omits. Fixed-width scalars belong in the value count. Existing per-byte
  tariffs for typed `list<u8>` inputs remain combined conversion/operation charges;
  do not add another scalar-byte tariff to them.

These are workload dimensions, with the initial WAVE coefficients listed above. A phase
may use one combined tariff for its conversion and operation work. Document that
ownership so adding a charge elsewhere does not bill the same phase again.
UTF-16 guest encodings need a conservative cost/guard relationship with logical
UTF-8 bytes; native allocation units are not that relationship.

Every repeated boundary crossing incurs its work again. Reusing a guest pointer
does not avoid a new lift. Nested calls use the parent's remaining budget, with
no new allowance of spendable execution fuel. Failed work remains charged across
rollback. A pre-conversion guard and a post-conversion charge are different
mechanisms: a charge in a host body is too late to prevent lifting its arguments.

Do not implement these units by making a complete additional walk of every value
after conversion and calling that a bound. Accounting must stop the expensive
stage, or be preceded by a demonstrated bound on the work already performed.

## Reproductions

`runtime/call/tests/conversion_work.rs` uses the real Runtime engine, async WAT
components, the existing hash tariff/helper, and the production result encoder.
The ABI tests characterize the remaining native-conversion gaps. The omitted-field
test now requires structural output fuel and rejects the former byte-only budget.

The repeated-import fixture uses the same guest memory on every call and actually
suspends in the host. The allocation allowance is exactly one input's size:

| Calls | Bytes per call | Instruction fuel only | With existing hash tariff |
| --- | ---: | ---: | ---: |
| 1 | 8 | 18 | 598 |
| 1 | 8,192 | 18 | 82,438 |
| 4 | 8 | 51 | 2,371 |
| 4 | 8,192 | 51 | 329,731 |
| 16 | 8 | 183 | 9,463 |
| 16 | 8,192 | 183 | 1,318,903 |

The engine-only control has no Kontor import tariff. It demonstrates the engine
gap, not free production hashing. The paired case calls the actual `_sha256`
helper and proves its existing tariff pays on every repetition. These are fuel
counts, not performance calibration measurements.

The record fixture returns absent `option<u32>` fields directly from zeroed guest
memory. All records exceed the async flattening limit and use the same indirect
return path. They succeed with **zero allocation allowance**:

| Fields | Field-name bytes materialized | WAVE output | Baseline output fuel | With structural accounting |
| ---: | ---: | --- | ---: | ---: |
| 16 | 144 | `{:}` | 230 | 1,080 |
| 128 | 1,152 | `{:}` | 230 | 6,680 |
| 512 | 4,608 | `{:}` | 230 | 25,880 |

The record test also parses `{:}` back into the same complete value using the
declared type, exercising input-side expansion. An allowance-boundary test shows
that an oversized import is rejected before its host body, whereas an allowance
that admits the payload permits conversion before the existing tariff can reject
it for insufficient execution fuel. Both failures are deterministic under #578.

WAT fixtures bypass publication validation and account setup to isolate the ABI
boundary. They are not end-to-end publication or fee-settlement tests. Existing
conversion/lifecycle tests cover nested Store propagation, real contract rollback,
resource release, and runtime reuse. No cross-platform timing conclusion follows
from these local runs.

## Implementation order

1. Implemented: bound input construction and output traversal, including omitted
   fields and input schema names, using the standard WAVE parser/writer.
2. Expression tariffs are implemented. Audit remaining contract-name and
   native-only malformed input paths. Settle top-level preparation fees separately:
   preparation currently precedes escrow hold/settlement, while nested preparation
   already returns spent fuel to its parent.
3. Establish a pre-conversion bound that covers the whole model, including records.
   The public call hook only reports a transition, not values or consumed copying
   work. The existing allowance cannot provide complete enforcement by itself.
   Compare a bounded/type-informed approach with an upstream conversion-budget
   hook if needed; do not silently enable the experimental `fuel / 10` guard.
4. Check Linux/macOS parity and feature-enable overhead, then calibrate prices.

This slice does not settle the enforcement mechanism in step 3. It establishes
the counterexamples and criteria that a candidate must satisfy. It neither closes
#462 nor supersedes the broader economic PRs.

Initial investigation validation on 2026-09-17: all three characterization tests passed. The
related conversion suite passed eight tests, with one manual benchmark ignored,
including the existing nested-call and rollback regressions.

Run from `core/`:

```sh
cargo test --release -p indexer --lib runtime::call::tests::conversion -- --nocapture
```

See also [the allocation-hook investigation](abi-conversion-budget.md),
[result encoding](contract-result-budget.md), and
[existing host metering](host-call-metering.md).
