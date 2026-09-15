# Storage value budgets

Baseline: main `6a79ceb9` (#572). Traversal limits bound the number of rows visited;
this change bounds value copying and encoding within an individual operation.
Contract interfaces, stored encodings, and successful-call byte prices stay the same.

## Row reads

The host pays `StorageScan` before touching the cursor, then converts remaining
fuel to a byte limit using `KeysNext`'s existing price. The limit covers both the
returned encoded key and the stored value, including serialization framing.

`StorageRowCursor::next(max_bytes)` reads the row's stored size and key length
before copying either byte buffer from libSQL into Rust. An oversized row produces
`ValueTooLarge`, which the host maps to the normal `OutOfFuel` trap. It is never
filtered out of the result set. Decoding happens only after the byte charge.

The query starts on the first advance, after its base charge, and then keeps its
streaming cursor. Completion or error discards the cursor. Bounds, ordering and
the direct-scalar-leaf requirement stay unchanged. This replaces the unbudgeted
row stream; key-only streams remain unchanged.

This guard does not stop SQLite from reading a value internally. A prototype
bound the budget inside SQL before each row, but refreshing that parameter
required resetting and seeking the statement on every advance. Paired release
measurements of 256-row scans made that version 2.9–4.9 times slower. Streaming
with a metadata check added about 5–10%, approximately 0.05 microseconds per row,
for 8-, 128-, and 4,096-byte values on local Linux aarch64. These are database-only
measurements, not end-to-end contract throughput. The temporary comparison harness
is not included in the change.

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
encoding compatibility, and rollback without refunding spent fuel.

All 537 library tests passed across the suite run and the corrected cluster rerun.
The cluster tests require localhost networking and the package working directory
to resolve their counter-WASM fixture. Clippy with warnings denied, formatting and
diff checks passed. Temporary benchmark modules were removed after measurement.

This advances #462 without closing it or superseding #445.
