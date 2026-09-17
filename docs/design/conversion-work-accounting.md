# Conversion work accounting

2026-09-17. Baseline: main `0fc43b5a` (#578), Wasmtime 48.0.2.
This is the coverage and accounting-design slice. The accompanying tests measure
existing behavior; no production prices, limits, bindings, or contracts change.

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
| WAVE input parsing and typed construction | Expression depth/string guards; no input-size/value-count tariff in `prepare_in_store` | Raw expression bytes alone cannot cover implicit optional fields. Need both input and structural work. |
| Dynamic argument lowering | Guest allocator instructions consume fuel; native conversion is not an instruction charge | Do not confuse allocator fuel with the entire lowering cost. |
| Storage paths and range bounds | `Fuel::Path`, charged before validation/query work | Preserve this coverage instead of charging identical input bytes again generically. ABI lifting has already occurred at this point. |
| Storage reads, writes, cursor results | Lookup/entry tariffs plus stored/key/value byte tariffs and size guards | Already size-sensitive. Serialized storage bytes are not interchangeable with arbitrary ABI allocation units. |
| Hashing and HKDF | Base plus all input bytes, before cryptographic work | Repetition already pays proportionally; calibrate the combined tariff against conversion plus operation work. |
| Holder reference validation | Base plus supplied variable string bytes, including invalid references | Already handles the input-copy/validation concern explicitly. |
| Numeric imports | Fixed-shape numeric values pay fixed tariffs; text parsing/formatting pays string bytes | Preserve fixed-shape treatment. A host-layout-dependent charge adds no useful information. |
| Transaction data | Base plus bytes before cloning the shared payload | Already size-sensitive on the return side. |
| Context and holder accessors | Mostly fixed-size IDs/resources or validated references with fixed tariffs | Include their conversion cost in base calibration; avoid per-field runtime walks of fixed schemas. |
| Contract address | Fixed tariff, but the returned address contains a variable-length name | The fixed tariff is not a demonstrated bound on name copying. Include names in the follow-up audit. |
| `foreign.call` | Child shares remaining execution fuel and pays its existing work/result tariffs | No separate size charge covers parent argument conversion or child expression parsing. Include repeated calls, failed preparation, and fallback. |
| Native file/proof imports | Mixture of per-file, per-proof-byte and fixed tariffs | Audit malformed root/seed/peaks inputs as well as valid fixed-size values. Some bytes are lifted before validation rejects them. These imports are restricted to native contracts. |
| Exported result lifting | Wasmtime allowance covers strings/lists but not all record/tuple/name construction | A byte guard alone cannot close this boundary. |
| WAVE result writing | Base plus emitted UTF-8 bytes, bounded before append | Covers emitted output. Absent record fields still require visits without producing bytes. |

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

These are workload dimensions, not two newly approved fuel coefficients. A phase
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
These are characterization tests for the identified gaps, not assertions that
unpriced behavior should be preserved when implementing its replacement.

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

| Fields | Field-name bytes materialized | WAVE output | Current output fuel |
| ---: | ---: | --- | ---: |
| 16 | 144 | `{:}` | 230 |
| 128 | 1,152 | `{:}` | 230 |
| 512 | 4,608 | `{:}` | 230 |

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

1. Close the structural input/result gap. Prototype a bounded value traversal
   that includes omitted fields and schema-name work, while retaining the standard
   WAVE parser/writer. Prove that it stops work, not merely output. Keep this
   separate from native allocation guarding.
2. Add the missing variable tariffs for call input/names and audit native-only
   malformed input paths. Reuse `Fuel` and `FuelGauge`; do not add a second meter.
   Include failed preparation, since top-level preparation currently precedes
   escrow hold/settlement, while nested preparation returns spent fuel to its parent.
3. Establish a pre-conversion bound that covers the whole model, including records.
   The public call hook only reports a transition, not values or consumed copying
   work. The existing allowance cannot provide complete enforcement by itself.
   Compare a bounded/type-informed approach with an upstream conversion-budget
   hook if needed; do not silently enable the experimental `fuel / 10` guard.
4. Check Linux/macOS parity and feature-enable overhead, then calibrate prices.

This slice does not settle the enforcement mechanism in step 3. It establishes
the counterexamples and criteria that a candidate must satisfy. It neither closes
#462 nor supersedes the broader economic PRs.

Validation on 2026-09-17: all three new characterization tests passed. The
related conversion suite passed eight tests, with one manual benchmark ignored,
including the existing nested-call and rollback regressions.

Run from `core/`:

```sh
cargo test --release -p indexer --lib runtime::call::tests::conversion -- --nocapture
```

See also [the allocation-hook investigation](abi-conversion-budget.md),
[result encoding](contract-result-budget.md), and
[existing host metering](host-call-metering.md).
