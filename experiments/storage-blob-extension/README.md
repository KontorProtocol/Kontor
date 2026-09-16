# SQLite BLOB extension experiment

Local prototype against the unmodified, locked libSQL dependency. This code is
not built into Kontor or loaded in production.

Run from the repository root:

```sh
python3 experiments/storage-blob-extension/run.py
```

Requires the repository's Rust build prerequisites and a C compiler on Linux or
macOS. The runner compiles against the locked libSQL headers, temporarily attaches
the ignored probe tests to the indexer, runs them in release mode, and restores
the source file in `finally`. Run without another build or editor modifying
`contract_state.rs`. No dependency patch, lockfile change, or installed extension
is needed. Forced process termination can require removing the final
`extension_probe` module declaration manually.

## Interface and ownership

`kontor_blob_read(rowid, expected_size, byte_budget, session_id)` reads only
`main.contract_state.value`. It validates the budget before opening/reopening a
BLOB and verifies the actual size before allocating its output buffer. SQLite
owns that buffer until the result is reset; libSQL copies the result into Rust.
Session ID zero opens/closes a handle for each invocation.

For reuse, `SELECT id FROM kontor_blob_sessions` opens an in-memory virtual-table
cursor. Holding its `Rows` result keeps the session alive. Calls to
`kontor_blob_read` with that ID reuse its BLOB handle. Dropping or exhausting the
owner cursor closes the BLOB and invalidates the ID. Independent scans have
independent sessions; IDs never expose pointers. Failed BLOB operations close
the handle before returning an error, so an aborted handle is not reused.

The virtual table has no persistent rows or schema changes. It supplies a
destructor-backed lifetime through the existing binding, whose ordinary SQL
results cannot carry SQLite pointer values. Auxiliary function data is unsuitable
as the sole owner: SQLite may discard it, including when a statement is reset.

`kontor_blob_stats` exposes open, reopen, read, byte, and active-handle counters
for the probe. These observe actual C BLOB operations, which SQLite's SQL
authorizer does not cover.

## Comparison

The probe compares the current prepared rowid lookup, the former post-query copy
guard, a stateless extension read, and a session-reusing extension read. Each uses
the same metadata/liveness query, key decoding, and result validation. Budget
checks precede value fetching for all but the former copy guard. Session setup
and destruction are included in timings.

Five warmup trials precede 24 measured trials; modes rotate and reverse order.
Sizes range from zero bytes to 1 MiB, with both scan directions. Separate trials
reject 4 KiB and 4 MiB values with a 16-byte budget. These are warm-cache database
measurements, not contract throughput or cold-disk measurements.

The focused lifecycle probe covers budget changes, exact-budget success,
abandoned and exhausted cursors, simultaneous sessions, failed reopen recovery,
metadata-size mismatch, uncommitted writes, rollback, shared snapshots, and
snapshot release. It is not a production audit of arbitrary SQL, allocation
failure, threading, extension initialization failure, or cross-platform loading.

Results and the implementation decision are recorded in
[storage-value-budgets.md](../../docs/design/storage-value-budgets.md).
