# Storage value budgets

Baseline: main `6a79ceb9` (#572). Traversal limits bound the number of rows visited;
this change bounds value fetching and encoding within an individual operation.
Contract interfaces, stored encodings, and successful-call byte prices stay the same.

## Row reads

The host pays `StorageScan` before touching the cursor, then converts remaining
fuel to a byte limit using `KeysNext`'s existing price. The limit covers both the
returned encoded key and the stored value, including serialization framing.

`StorageRowCursor::next(max_bytes)` streams the row's stored size, key length,
path, and rowid without selecting the value column. It checks the size before
copying the key into Rust or issuing the value query. An oversized row produces
`ValueTooLarge`, which the host maps to the normal `OutOfFuel` trap. It is never
filtered out of the result set. Decoding happens only after the byte charge.

The query starts on the first advance, after its base charge, and then keeps its
streaming cursor. Affordable values are fetched through one reusable prepared
rowid lookup on the same connection, in the same snapshot as the metadata scan.
The rowid identifies the exact version selected by liveness resolution; it is
not persisted or exposed to contracts. The value statement is reset after each
read to release its buffer. Completion or error discards both statements.
Bounds, ordering and the direct-scalar-leaf requirement stay unchanged. This
replaces the unbudgeted row stream; key-only streams remain unchanged.

This does not eliminate database work before the size check: SQLite must locate
the live row and read its metadata. It prevents materializing the value, not
incidental page reads containing some value bytes.

## Read strategy and measurements

The initial implementation checked sizes after SQLite selected the value, before
copying it into Rust. A stricter prototype put the budget in SQL but restarted
and sought the range query on every advance; that cost 2.9–4.9 times the original
unbudgeted scan. The selected approach keeps the range query open and defers only
the value lookup, using the existing safe libSQL API without a schema change.

Paired release measurements on local Linux aarch64, 256 rows per scan, alternating
implementations with three warmups and 24 measured trials (median):

| Value bytes | Copy-guard cursor, ascending | Deferred fetch, ascending | Ascending / descending overhead |
| --- | ---: | ---: | ---: |
| 8 | 147 µs | 256 µs | 74% / 64% |
| 128 | 152 µs | 258 µs | 70% / 62% |
| 4,096 | 283 µs | 408 µs | 44% / 42% |
| 65,536 | 2,767 µs | 2,941 µs | 6% / 6% |

This adds roughly 0.4–0.7 µs per returned row. Rejecting a 4 MiB value with a
16-byte allowance fell from 487 µs to 11 µs; rejecting 4 KiB stayed near 11 µs.
These are database-only measurements, not end-to-end contract throughput or cold
disk measurements. The temporary comparison harness is not included in the change.
The extra lookup is accepted to prevent an unaffordable large value read.

Research checked on 2026-09-15 informed the choice:

- [NEAR's value handle](https://github.com/near/nearcore/blob/master/runtime/near-vm-runner/src/logic/dependencies.rs)
  separates length from dereferencing to allow gas checks before accessing a large value.
- [Cosmos SDK's gas store](https://github.com/cosmos/cosmos-sdk/blob/main/store/gaskv/store.go)
  performs its underlying `Get` before charging value bytes; strict prefetch checks
  are not universal.
- [FoundationDB range reads](https://apple.github.io/foundationdb/api-c.html#c.fdb_transaction_get_range)
  use a soft byte target and batching. That target alone is not a strict gas bound.
- [SQLite incremental BLOB access](https://sqlite.org/c3ref/blob_open.html) could
  fetch values without a separate SQL statement, but our libSQL Rust API does not
  expose that interface. Its performance has not been measured here.

## Writes

After the existing entry/path charges, Postcard writes into a bounded output
buffer using its `Flavor` interface. The buffer refuses a byte or slice before
copying it if it exceeds the remaining encoded-byte allowance. There is no sizing
pass and no alternative encoding. A full buffer maps to `OutOfFuel`; successful
encoding pays the existing `Set` charge before deposits or database changes.

Local paired release measurements put a 4,096-byte list at about 1.97 → 2.45
microseconds for encoding alone (24% higher, about 0.48 microseconds extra).
A 128-byte list added about 13 nanoseconds, a `u64` about 5 nanoseconds, and a
4,096-byte string was approximately unchanged. These figures exclude contract
execution and the database write.

This bounds the storage-layer output, not every allocation in a contract call.
Component argument lifting, SQLite's internal page/history work, procedure-result
serialization, publication, and proof-verification coverage are separate concerns.

## Validation

Commit `1aeee955` records the regressions before the fix: an underfunded row read
copied all 4,098 stored bytes, and a write encoded a 4,096-element sequence with
budget for only 16 encoded bytes.

Boundary coverage includes changing the budget between advances, encoded key and
value framing, forward/reverse reads, exact-budget success, failure without writes,
encoding compatibility, and rollback without refunding spent fuel. A SQLite
authorizer denies access to the value column while an underfunded read must still
return `OutOfFuel`; the prior copy guard fails this regression. Snapshot coverage
checks concurrent committed updates, same-height replacement, tombstones, contract
isolation, release on completion/error, and fresh reads after height rollback.

Deferred-fetch validation passed 119 database, storage, and host-metering tests
(one pre-existing ignored test). The three byte-budget tests passed again after
extending the SQL authorizer check to an already-started cursor. Clippy with
warnings denied, formatting, and diff checks passed. Before this follow-up, all 537 library tests
passed across the suite run and the corrected cluster rerun. The cluster tests
require localhost networking and the package working directory to resolve their
counter-WASM fixture. Temporary benchmark modules were removed after measurement.

This advances #462 without closing it or superseding #445.
