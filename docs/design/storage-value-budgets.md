# Storage value budgets

Baseline: main `6a79ceb9` (#572). Traversal limits bound logical row processing;
this change bounds value fetching and encoding within an individual operation.
Contract interfaces, stored encodings, and successful-call byte prices stay the same.

## Storage reads

Point reads and row scans share `BudgetedStorageValue` and `StorageValueReader`.
The former checks the stored size against the available bytes before admitting
a rowid to the latter's prepared lookup. This keeps one budget check and one
value-fetch implementation. Neither mechanism allocates a buffer for an
unaffordable value. The reader owns its connection and reusable statement;
successful reads reset that statement to release SQLite's result buffer.

A point read finds only the newest row's `rowid`, `size`, and `deleted` flag with
an indexed `ORDER BY height DESC LIMIT 1`. Deletion is checked after selecting
the newest version, so a tombstone cannot resurrect an older value. Its metadata
cursor stays alive until the shared value fetch finishes, pinning the snapshot.
This replaces the previous outer SQL `CASE` around a `SELECT *` window query,
which prevented returning oversized bytes to Rust without preventing the inner
query from accessing values. Missing and deleted keys return `None`; a live
zero-length value remains distinct from a missing key.

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

The shared point-read path was measured against the previous window/`CASE` query
on local Linux aarch64 in release mode, alternating implementations over five
warmup and 24 measured trials of 32 reads each. With one stored version,
successful 8-byte reads fell from about 16.5 to 5.5 µs; 4-KiB reads from 18.9 to
6.0 µs; and 64-KiB reads from 39.2 to 11.3 µs. With 32 stored versions, a
successful 64-KiB read fell from about 60 to 12 µs. Rejecting that value with a
16-byte budget fell from 55 to 4.4 µs. A second run reproduced these results.
Removing the window query outweighed the additional prepared value lookup in
these warm-cache measurements. The temporary benchmark was removed after
measurement; these are not whole-contract speedups.

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
  expose that interface. The follow-up experiment below measures this option.

## Incremental BLOB experiment

An isolated experiment against `e900105d` used the same libSQL 0.9.30 engine,
connection, metadata query, key decoding, byte-budget check, and cursor lifecycle.
A temporary dependency patch exposed the connection handle for the benchmark.
It compared the current prepared lookup, the previous copy guard, opening/closing
a read-only BLOB per value, and retaining one BLOB and reopening it on each rowid.
The experimental binding and benchmark have been removed from the branch; the
implementation above still uses the prepared SQL lookup.

Local Linux aarch64 release results, ascending scans, five warmups and 24 measured
trials per mode, median from the repeated run. The order of modes was rotated and
reversed, and every result was checked against the expected keys and bytes:

| Value bytes | Rows | Prepared SQL | Reused BLOB | BLOB vs SQL |
| --- | ---: | ---: | ---: | ---: |
| 8 | 256 | 258 µs | 161 µs | 38% faster |
| 128 | 256 | 258 µs | 164 µs | 36% faster |
| 4,096 | 256 | 379 µs | 247 µs | 35% faster |
| 65,536 | 256 | 3,248 µs | 3,671 µs | 13% slower |
| 1,048,576 | 32 | 6,436 µs | 7,721 µs | 20% slower |

Across both directions and repeated runs, BLOB reuse was about 28–38% faster for
8-byte through 4-KiB values. Relative to the old copy guard it added about 10–17%
for tiny values and was approximately equal or faster at 4 KiB. Large values
were about 9–20% slower than the prepared lookup; the API is not a universal
speedup for whole-value reads. Opening/closing per row lost much of the small-value
gain. Zero-length values also matched, and rejecting an unaffordable 4-MiB value
remained around 11 µs without fetching it. These are database-only measurements;
a production owned/thread-safe binding and full contract execution were not measured.

The lifecycle probe verified that reopening on another row works after replacing
the previous row, and after rolling back a change to a different row. Reading a
replaced row instead fails with `SQLITE_ABORT`; that failed handle cannot then be
reopened. A failed reopen also aborts the handle. A fresh handle works. The BLOB
shares the metadata connection's snapshot and keeps it pinned even after the SQL
cursor is dropped; dropping the BLOB releases the pin.

A direct binding implementation would need a safe owned read-only BLOB wrapper
retaining its connection, with length/read/reopen methods and guaranteed closure
on drop. The existing runtime cursor could own this instead of its value statement.
Connection lifetime and thread-safety need review because
the resource table requires owned, `Send + Sync` resources.
[Rusqlite's BLOB API](https://docs.rs/rusqlite/0.40.2/rusqlite/blob/struct.Blob.html)
is a useful interface reference, but its borrowed, non-`Send`/non-`Sync` handle
cannot be used directly here. Production regression coverage must observe actual
BLOB operations: the current SQL-authorizer test alone does not cover direct
incremental-BLOB calls. No size-dependent SQL/BLOB split is proposed.

## Loadable extension experiment

The [reproducible prototype](../../experiments/storage-blob-extension/README.md)
uses the unmodified locked libSQL dependency. A loadable C extension registers a
SQL function that checks the supplied byte budget, opens/reopens the selected
BLOB on the calling connection, validates its length, and returns its bytes.
SQLite owns the output allocation until the SQL result is reset; libSQL copies
the result into Rust. There are no changes to contracts or persistent state.

Two variants were measured: opening/closing per invocation, and retaining a
handle per scan. Reuse needs a lifetime visible through the existing Rust API:
the prototype exposes a one-row in-memory virtual table whose cursor owns the
handle. Holding its `Rows` keeps a session ID valid; exhausting or dropping it
closes the handle. Separate cursors have separate sessions, and errors discard
aborted handles. This avoids explicit asynchronous cleanup and raw pointer
exchange, but adds a small session registry and another SQL cursor per scan.

On local Linux aarch64, the first release run (five warmups, 24 measured trials,
rotating/reversing modes) produced these ascending-scan medians. Timings include
session creation and destruction:

| Value bytes | Rows | Prepared SQL | Extension open/close | Extension reuse |
| --- | ---: | ---: | ---: | ---: |
| 8 | 256 | 261 µs | 354 µs | 289 µs |
| 128 | 256 | 263 µs | 356 µs | 289 µs |
| 4,096 | 256 | 384 µs | 466 µs | 390 µs |
| 65,536 | 256 | 3,288 µs | 3,439 µs | 3,369 µs |
| 1,048,576 | 32 | 6,549 µs | 6,661 µs | 6,647 µs |

Across both directions, extension reuse was 10–14% slower for 8/128-byte values
and 1–6% slower for larger values. Stateless reads were worse for small values.
A second run reproduced this result: 9–14% slower for small values and roughly
1–6% slower for larger values. Differences near 1% are small enough that the
useful conclusion is no demonstrated speedup, rather than a precise slowdown.
Both extension variants rejected an unaffordable 4-MiB row in about 11–12 µs,
matching deferred SQL, because neither reaches the value API in that case.
All four modes returned identical data, including zero-length BLOBs. These are
warm-cache database measurements, not end-to-end throughput.

The lifecycle probe passed on the actual libSQL connection: exact and changing
budgets, no BLOB open on rejection, no read after a metadata-size mismatch,
cleanup on EOF/error/abandonment, independent overlapping sessions, failed-reopen
recovery, uncommitted writes, same-height replacement, rollback, shared snapshots,
and release of the snapshot pin. C-level operation counters verify budget behavior
independently of the SQL authorizer. The lifecycle probe also passed with the
extension compiled under UndefinedBehaviorSanitizer. This is not a full production
audit or a cross-platform test. The reproduction runner passed both probes and
restored the temporary module attachment; the runtime and dependencies are unchanged.

The extension mechanism works and avoids a dependency patch, but this SQL-function
interface does not preserve the direct-API prototype's speedup. The recommendation
is to retain the prepared SQL implementation. The extension and comparison harness
remain isolated experimental source, with no production or CI integration.

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

Initial deferred-fetch validation passed 119 database, storage, and host-metering tests
(one pre-existing ignored test). The three byte-budget tests passed again after
extending the SQL authorizer check to an already-started cursor. Clippy with
warnings denied, formatting, and diff checks passed. Before this follow-up, all 537 library tests
passed across the suite run and the corrected cluster rerun. The cluster tests
require localhost networking and the package working directory to resolve their
counter-WASM fixture. Temporary benchmark modules were removed after measurement.

After sharing the reader with point lookups, 132 database, storage, encoding,
and host-metering tests passed in release mode. The new point-read budget test
first failed on the old implementation with a denied value-column read, then
passed with the shared reader. Additional tests cover missing/empty values,
contract isolation, exact budgets, same-height replacement, tombstones, and
height rollback. A synchronized writer replaces a row between metadata discovery
and value-query preparation, verifying that the point read returns the old
snapshot's value and releases the pin before the next read.
Clippy with warnings denied, formatting, and diff checks passed after the shared
reader change. The isolated extension harness was updated for the private reader
layout and both of its probes still passed; its temporary attachment was removed.

This advances #462 without closing it or superseding #445.

## Query audit follow-up

The broader [database query audit](query-audit.md) also moved variant lookup to
metadata-only SQL, removed the superseded window builder, and made historical
existence stop after one row. Point reads and scans retain the shared prepared
value reader. Variant resolution still selects the globally newest row before
checking deletion; it does not become a per-path or candidate-filtered lookup.
The audit documents remaining SQL-work, pagination, and indexing concerns separately.
Historical query differences caused by pruning are an accepted tradeoff.
