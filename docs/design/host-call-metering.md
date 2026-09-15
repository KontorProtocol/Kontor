# Host-call fuel coverage

Baseline: main `f64b9ab3` (#570). The broader coverage map and measurements remain
on [the saved calibration branch](https://github.com/KontorProtocol/Kontor/tree/investigate/runtime-metering).
This slice fixes previously uncharged host calls and read-budget failure handling;
it does not establish a fully calibrated resource schedule.

## Charges and ordering

All charges still go through `Fuel` and the existing optional `FuelGauge`. Base
and payload charges are separate so a miss, an empty result or invalid input still
pays for work already attempted. Successful payload charges use actual encoded
bytes; there is no fabricated value size for a missing row.

| Operation | Behavior |
| --- | --- |
| Storage read | Pay 50 before resource/SQL access, plus path bytes before validation. Pay 10 per stored byte on a successful lookup. |
| Open keys/row cursor | Existing 200 base moves before validation/access. Path and bound bytes are charged before query construction. |
| Cursor advance | Pay the existing 100 base before polling, including terminal polls and failures. Returned key/value bytes retain their 10/byte charge. |
| Existence | Existing 50 base moves before validation/access; path bytes are charged. |
| Write | Existing 200 base moves before validation/access/serialization. Serialized bytes retain their 10/byte charge. |
| Delete | Existing 200 base moves before validation/discovery. The existing 200/row and 10/freed-byte charge still precedes mutations. |
| Variant match/cleanup | Charge candidate count before inspecting the list, then charge candidate bytes before database work. Cleanup now pays for inputs even when no row matches. |
| Block height, network, transaction id/outpoint | Fixed 50 per access, consistent with existing simple-accessor charges. |
| Transaction data | Pay 50 + 10/input byte before copying the return vector; empty/missing data still pays the base. |
| Storage floor | Pay 50 before inspecting the holder or reading the cached footprint total. |

These initial rates reuse the existing table's lookup/accessor and byte rates.
They close coverage holes; they are not fitted nanosecond-to-fuel coefficients.
Relative prices and a block-capacity target still need broader calibration.

`Fuel::Path` now receives a byte count. The host charges before the single path
validation pass, replacing the previous extra parse inside `Fuel::cost`. Raw
range sentinels and candidate bytes are charged but are not validated as complete
paths; valid exclusive query bounds are not necessarily complete codec elements.
The unused `ProofChallengeIds` cost variant and the superseded path-cost parser
tests are removed. The host path-validation property tests remain.

Transaction payloads are shared inside `Runtime` through `Arc<[u8]>`. Host wrappers
clone `Runtime` before their helper's charge, so retaining an owned vector there
would copy transaction bytes before metering on unrelated imports. Only the
transaction-data accessor produces the guest's owned vector, after charging.

## Stored-value size guard

After the lookup and path charges, the host converts remaining fuel into an
explicit maximum stored-value byte length. SQL withholds a value larger than that
limit, and the host maps `ValueTooLarge` to `wasmtime::Trap::OutOfFuel`. Other DB
errors retain their infrastructure classification. This both applies the actual
10/byte rate to the guard and prevents a budget failure from stopping the node.

The old guard compared stored bytes directly with raw fuel and returned a DB
`OutOfFuel` error. That error was not a Wasmtime trap, so a real counter contract's
large read reproduced a non-deterministic failure. The regression first passed
its small read with the same budget, proving the failure was not initialization.
After the fix, the large read fails deterministically and succeeds on the reused
runtime when given enough fuel.

## Validation and compatibility

Commit `d7e4ef13` records five failing regressions before implementation. Those
cover missing reads, zero-budget access ordering, terminal cursor polls, fixed
accessors and malformed paths. Four further tests cover a real contract's oversized
read, exact stored-value budgets (including serialization framing), transaction
payload sizes/contents, and scalar-cursor target errors. Missing-read fuel remains
spent when the enclosing database savepoint rolls back.

The full library suite passed **525 tests** after implementation, including the
existing nested-call billing, error classification, state rollback and resource
lifecycle tests. Clippy with library/tests and warnings denied, formatting and
diff checks passed. No contract/SDK binaries or interfaces changed.

This is a consensus-visible fuel change: calls may consume more fuel or exhaust
sooner, and oversized reads now receive the correct deterministic classification.
Deploy the implementation consistently across nodes. KOR-per-gas pricing and
storage-collateral conversion parameters are unchanged.

## Remaining work

A base charge is not a bound on all internal work. This slice does not yet bound
historical/tombstoned SQL rows or serialization before its final payload charge.
[Storage traversal](storage-traversal.md) bounds key-iterator deduplication and
meters delete discovery incrementally. Serialization still needs budget-boundary
regressions and guards. Publication/admission,
variable proof-verification costs and full hardware calibration also remain in
the coverage map. This advances #462 without closing it or superseding #445.
