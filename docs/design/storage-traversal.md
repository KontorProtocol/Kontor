# Bounded storage traversal

Baseline: main `be0f204f` (#571). The host continues to use `Fuel` and the existing
call lifecycle. No contract API, database schema or additional meter is introduced.

## Discovery before mutation

Subtree and current-height cleanup discovery return lazy metadata streams. Query
creation is deferred to the first poll because libSQL's `query()` already steps
its statement. The host's shared `collect_delete_rows` helper charges before each
poll, then charges each discovered row before retaining it. It must finish and
release the SQL cursor before changing footprints or deleting rows.

`StorageScan` replaces the cursor-specific name `KeysPoll`, retaining its 100-fuel
price. Delete discovery now pays this per attempt, including the terminal poll,
in addition to the existing base/input and 200/row + 10/footprint-byte charges.
Failure retains spent fuel and follows normal deterministic call rollback.

Ordinary deletes use an ordered live-path scan instead of materializing a window
query. Variant cleanup unions duplicate/overlapping candidate ranges, discovers
current-height rows in path order (including tombstones), then deletes exactly
those paid-for paths in SQL batches of at most 64. This replaces the second broad
range delete and prevents subtracting a duplicate row's deposit twice. Removing a
current row or tombstone can still revive an older deposit; the footprint cache
accounts for that before returning. Its redundant per-path deduplication is removed.

Cleanup merges candidate suffixes before expanding query bounds. Only the active
query copies the shared base path into its bounds, so a long base path cannot
multiply retained memory by the number of candidates.

## Key scans

Flat entries and small records retain their streaming cursor. A key poll skips at
most 32 duplicate descendants before seeking beyond the entire previous child:
`>= subtree_end(child)` ascending, `< child` descending. This bounds duplicate work
without seeking for every small record. Seeks reuse their prepared SQL statement;
only the first ascending seek can change its comparison from `>` to `>=` and need
a new statement. Each poll returns at most one key and retains the same fuel charge
as before. Raw range bounds and escaped
NUL handling continue to use the existing codec rules.

This does not meter SQLite VM steps, cache misses or old/tombstoned versions: those
can differ after pruning. A database step can still perform internal work before
returning. [Storage value budgets](storage-value-budgets.md) checks scalar-row sizes
before fetching values and bounds write encoding; its metadata scan remains streaming.
The guarantee here is incremental logical-row discovery and bounded key deduplication,
not preemption at arbitrary CPU instructions or a complete resource-price schedule.

## Evidence

Commit `ad195b3b` records the failing regressions: a three-key scan read 384 rows,
and an underfunded delete discovered all 32 rows before failing. The fixed key scan
visits at most 99 rows for this fixture; the underfunded delete visits at most one.
Tests also cover duplicate/overlapping cleanup ranges, multiple write batches,
revived deposits, one-fuel-short failure without mutations, rollback, reverse/range
scans with escaped NUL keys, and fuel parity before/after pruning.
Review regressions cover suffix-only range planning and long base paths with
duplicate and empty candidates, including preservation of escaped-NUL siblings.

Temporary paired measurements used the baseline query implementation and new host
path in the same release binary on Linux aarch64. Each comparison alternated old/new
runs, discarded warmup and compared medians; three independent runs agreed on the
relative results. These are storage microbenchmarks, not transaction throughput or
calibrated fuel prices. The comparison harness is not part of CI.

| Workload | Baseline → new | Observed change |
| --- | --- | --- |
| 64 flat keys / records with 2, 8 or 32 fields | — | Within 5%, usually within 1–2% |
| 64 records with 33 fields (seek boundary) | 0.92 ms → 1.04 ms | ~14% slower (~2 µs/record) |
| 64 records with 64 fields | 1.79 ms → 1.07 ms | ~1.7× faster |
| 64 records with 128 fields | 3.63 ms → 1.10 ms | ~3.3× faster |
| Ordinary delete, 256 rows | 7.39 ms → 7.24 ms | ~2% faster |
| Variant cleanup, 256 rows | 1.30 ms → 1.39 ms | ~7–8% slower |

All 529 library tests passed before the review fix, including the existing call-lifecycle and active-cursor
cleanup tests. The latter fixture now uses valid encoded keys and checks its first
read: previously it ignored a codec error, which the old stream retained alongside
its SQL cursor. Failing streams now release that cursor immediately.
After the suffix-planning fix, all 15 focused metering/planning tests and 88 database
query tests passed; Clippy with warnings denied also passed.

This advances #462; it does not close calibration/congestion work or supersede #445.
