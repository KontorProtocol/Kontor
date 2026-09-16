# History cursor versus maintained current state

> Historical experiment: reproduce the comparative prototypes at commit
> `6088778b`. Production now uses the live pointer index described in
> [current-state storage](current-state-storage.md). The remaining
> `benchmark_storage_history` exercises the production host calls; obsolete
> alternative-layout prototypes were removed to avoid benchmarking them on top
> of the new production index.

This experiment follows [the storage-history investigation](storage-history-costs.md).
It compares a cursor that skips historical versions with two derived current-state
tables. It changes no production schema, queries, or fuel behavior.

## Candidates

- **History:** the existing version log and current liveness query. Also measures
  **Seek**, the streaming/latest-version cursor that seeks past duplicate paths.
  Their write, disk, and rollback costs are the same: neither maintains extra state.
- **Pointer:** a `WITHOUT ROWID` table keyed by `(contract_id, path)`, containing
  the current live version's height and encoded value size. Value reads look up
  the history row through its existing unique `(contract_id, height, path)` index.
  References use logical version identity, not persistent SQLite rowids.
- **Values:** the same current table, also containing the encoded value. This
  measures whether avoiding the history lookup justifies duplicating values.
- **RowValues:** the copied-value design using an ordinary rowid table instead
  of `WITHOUT ROWID`. It has a separate primary-key index as well as the height
  index. Large values behaved poorly in the clustered layout, so this additional
  case avoids conflating copying values with that physical layout choice.
  [SQLite recommends comparing ordinary tables for larger rows](https://www.sqlite.org/withoutrowid.html#when_to_use_without_rowid).

Deleted keys are absent from the derived tables. Normal ascending/same-height
writes maintain them with insert triggers inside the existing write transaction.
Their height has a foreign key to `blocks` with `ON DELETE CASCADE` and a supporting
height index, so rollback removes discarded current entries through the existing
block cascade. The extra index is included in the storage and write measurements.
These triggers are a benchmark implementation, not a proposed final integration
boundary. The production checkpoint trigger and all existing history indexes
remain enabled in every configuration.

## Rollback algorithm under test

Within one SQL transaction:

1. Use the history height index to capture distinct `(contract_id, path)` keys in
   the removed block band into a temporary table.
2. Call the existing block rollback query, including its foreign-key cascades.
3. For each affected key, seek its newest surviving version and insert a current
   entry only if that version is live. Its discarded current entry was already
   removed by the block cascade (or absent because the key was deleted).
4. Commit.

Affected keys must come from the removed **history**, not just current entries:
a key deleted in the removed blocks has no current entry, but may need its older
live value restored. Conversely, rolling back a creation can restore absence or
an older tombstone rather than a live entry.

The experiment times affected-key discovery, the existing cascade, repair, and
the complete rollback separately. It also times initial full table construction,
which is explicitly **not** the normal rollback path.

An initial prototype explicitly deleted affected current entries with a composite
`IN` query. libSQL's plan constrained only `contract_id`, scanning unrelated keys
within that contract. Using the height cascade avoids that query entirely. The
benchmark emits plans for height-band capture, indexed height deletion, and
latest-version restoration so this distinction can be inspected directly.

Repair scales with distinct affected keys, but discovery and history deletion
still scale with the number of versions in the removed blocks. Repeatedly updating
100 keys across 100 blocks therefore requires deleting 10,000 historical writes,
but only repairing 100 current entries. It is not a constant-time rollback.

## Reproduction and scope

```sh
cargo test --manifest-path core/Cargo.toml --locked --release -p indexer --lib benchmark_current_state -- --ignored --nocapture
# Optional subset: keys per subtree : versions per key : unencoded value bytes
KONTOR_CURRENT_CASES=1000:10:32,1000:10:4096 cargo test --manifest-path core/Cargo.toml --locked --release -p indexer --lib benchmark_current_state -- --ignored --nocapture
```

The benchmark is
`core/indexer/src/runtime/fuel/host_metering_tests/history_benchmarks/current_state_benchmarks.rs`.
It is ignored in normal CI. It emits `CURRENT_READ`, `CURRENT_MUTATION`, and
`CURRENT_SPACE` JSON records. Each configuration starts with a fresh production
test database and native genesis, then uses the history fixture described in the
earlier investigation. This experiment uses empty tombstone values, matching
production deletion, and 32-byte or 4,096-byte live values encoded with Postcard.

The default matrix covers 100–10,000 keys per subtree and 1–1,000 versions per key.
There are four seeded subtrees: live, entirely deleted, 90% deleted, and an active
variant payload. Reads test the first three and an absent prefix. The variant
subtree contributes background rows; variant resolution itself is not benchmarked.

Read cases are 20-key pages, 20-value pages, existence, and exact-key values,
including ascending/descending pages and archive/pruned databases. Timings include
query preparation, database calls, and result collection. Five single-call samples
follow one warmup; the median is reported. They exclude guest execution and host
fuel metering. The range queries reproduce the current/seek SQL shapes; these are
database-level comparisons, not end-to-end contract throughput. Values are fetched
separately after selecting metadata; this does not benchmark a new guest ABI or
prove budget enforcement. Exact history point reads use the existing production
helper. Every result is checked against independently constructed expected keys
and height-stamped values.

Mutation cases write 100 keys per synthetic block over 1, 10, or 100 blocks. They
either revisit the same keys or use disjoint keys across ten blocks. Every third
block writes deletions; others write live values. The baseline therefore includes
overwrites, insertions, deletion, and recreation. The batch is one SQL transaction;
write timings include its commit. Rollbacks are committed separately.
Write calls reuse a prepared insert within each synthetic block; guest/runtime
execution and per-call production preparation overhead are excluded. The median
of three samples after one warmup is reported for each component independently,
so component medians need not add up exactly to the median total. Each trial rolls
back to the initial fixture before the next trial. These are warm repeated writes,
not isolated measurements of every mutation type or fsyncs per block.

`extra_bytes` is the increase in allocated database pages excluding freelist pages
after creating/populating the derived table. It includes schema/page allocation
overhead and excludes temporary affected-key tables and WAL growth. Values depend
on path lengths, live-state fraction, and page occupancy. `history_bytes` measures
the entire baseline test database, including native genesis, not just history rows.

## Results

Measured on 2026-09-16, Linux aarch64 on Apple M2, release build. The final matrix
was pinned to performance core 4 with `taskset -c 4`, with no concurrent build.
These are synthetic warm workloads, not a measured distribution of production
traffic. They establish scaling and tradeoffs rather than a single overall speedup.

### Reads

Median microseconds, ascending pages on archival databases. `Copy` below is the
ordinary rowid `RowValues` layout, which handles larger values better than the
clustered copied-value layout.

| Operation and fixture | Seek cursor | Pointer table | Copy table |
| --- | ---: | ---: | ---: |
| 20 keys; 100 keys, one version, 32-byte values | 19.3 | 9.4 | 9.9 |
| 20 keys; 100 keys, 1,000 versions | 65.9 | 10.9 | 11.9 |
| 20 values; 1,000 keys, ten versions, 32-byte values | 53.7 | 28.1 | 25.3 |
| 20 values; 1,000 keys, ten versions, 4 KB values | 70.3 | 44.4 | 40.7 |
| One live value; 1,000 keys, ten versions, 32-byte values | 6.5 | 6.3 | 6.0 |
| Existence in 10,000 deleted keys, ten versions | 26,179 | 4.6 | 4.7 |

The unmodified history query took 19.4 ms for the second row and 48.7 ms for the
last row. Both candidates improve history-heavy reads. Only a maintained live
table removes the remaining distinct-deleted-key scan: its cost is governed by
the current live index, rather than the deleted historical keyspace. Exact point
reads were already efficient and change little.

The clustered `Values` layout was competitive for small values but poor for
4 KB values: its 20-value page took 134.8 microseconds versus 40.7 for `RowValues`.
The alternative layout was therefore necessary for a fair copied-value comparison.
Copying is not inherently that slow, but even its better layout provided only
modest read savings over pointers in these warm tests.

### Writes and rollback

The cursor needs no extra write maintenance. The following uses 1,000 keys per
seeded subtree, ten retained versions, and 32-byte values. Times are milliseconds.

| Operation | History / seek | Pointer table | Copy table |
| --- | ---: | ---: | ---: |
| Write 100 keys in one block | 0.67 | 1.36 | 0.93 |
| Write 1,000 versions over ten blocks, same 100 keys | 9.72 | 15.99 | 15.00 |
| Roll back one block, 100 affected keys | 0.27 | 0.54 | 0.52 |
| Roll back ten blocks, same 100 affected keys | 1.43 | 1.84 | 1.82 |
| Roll back ten blocks, 1,000 affected keys | 1.60 | 3.47 | 3.36 |
| Roll back 100 blocks, same 100 affected keys | 13.41 | 15.37 | 15.25 |

The pointer table adds about 64% to the representative 1,000-write batch and about
29% to the 10,000-write batch. Its single-block batch roughly doubles in this
case. These are isolated database-write costs including checkpoint hashing and
commit, not whole-contract or whole-block slowdowns. The cost is material and
must be weighed against read frequency and predictable metered execution.

Current-state restoration itself took 0.112 ms for the same 100 keys after ten
blocks and 0.120 ms after 100 blocks. Restoring 1,000 distinct keys took 1.192 ms.
Capturing affected keys grew from 0.152 to 1.399 ms when the removed band grew
from 1,000 to 10,000 writes, while retaining the same 100 affected keys. This
separates the unavoidable work over removed versions from once-per-key repair.

Increasing the baseline from 100 to 10,000 keys per subtree kept one-block
100-key pointer restoration around 0.1–0.15 ms. The earlier contract-wide removal
scan is gone. Normal rollback does not rebuild the entire current-state table.

Large values make copying more expensive to restore. With 4 KB values, rolling
back ten blocks affecting 1,000 distinct keys took 1.89 ms for history alone,
3.84 ms for pointers, and 11.76 ms for the ordinary copied-value table. Its
restoration copied payloads and took 6.10 ms, versus 1.25 ms for pointers.

### Space and initial construction

Additional allocated KiB, including the supporting height index:

| Fixture | Pointer table | Copy table |
| --- | ---: | ---: |
| 1,000 keys/subtree, 32-byte values | 148 | 248 |
| 10,000 keys/subtree, 32-byte values | 1,444 | 2,348 |
| 1,000 keys/subtree, 4 KB values | 152 | 9,568 |

The first/last fixtures contain about 2,100 live workload paths; the middle has
about 21,000. Native genesis contributes a few additional rows. Pointer space
depends mostly on live keys, their lengths, and metadata; copied space also grows
with payload size. Historical versions do not get additional current entries.

Initial construction over 400,000 workload history rows took roughly 0.19–0.20
seconds in these fixtures. This is a single construction measurement including
DDL/index/trigger setup and plan diagnostics, not a tuned or guaranteed startup
time. It scans historical state once and should belong to migration/recovery,
not ordinary rollback or every restart of an already-maintained table.

### Recommendation

The pointer table is the leading candidate for predictable reads. It removes
both history-depth and deleted-key traversal from live queries, keeps values
in one place, and supports incremental rollback using the existing block-cascade
model. The additional height index and write maintenance are real costs.

The seek cursor is still attractive if avoiding additional persistent maintenance
is the priority. It preserves the existing write/rollback paths, but cannot bound
an empty scan independently of the number of distinct historical deleted keys.

Do not choose value duplication by default based on these results. Small copied
values can be slightly faster, including some mutation cases, but large values
add substantial space and rollback copying for modest warm-read gains. Cold-cache
and end-to-end contract workloads remain useful follow-ups before production
selection; no production implementation is included here.

## Correctness checks and integration gaps

Outside measured rollback intervals, reconstruct the full logical live set from
history and compare it in both directions with the current table. Check sizes and,
for the value-copy variant, payload bytes. Require checkpoints to return to their
initial hash after rollback. Exercise same-height set/delete/recreate followed by
SQL abort, abort an attempted reorg and verify its original tip is restored, then
successfully roll it back. Verify derived entries after finalized-history pruning
and database compaction as well.

The table is a disposable derived view with explicit atomic maintenance, not a
second consensus history. Production adoption would still need to cover every
mutation entry point: same-height hard deletion, migration/out-of-order writes,
startup recovery and schema upgrade, contract deletion, and reader snapshots.
The benchmark uses exempt contract-state writes and does not model transaction
indexing, storage-deposit accounting, or concurrent node traffic. It demonstrates
SQL transaction rollback, not process-kill or power-loss fault injection.
Read pages contain flat scalar keys; caller-side nested-record deduplication,
cold-cache behavior, and real workload read/write frequencies are not measured.
The copied-value tables do not duplicate transaction/depositor metadata, which
would still be read from history when needed.

The current enum/option lookup asks for the globally newest write, including
tombstones, and cannot simply be redirected to a table of live values. It remains
a separate concern. Gas parity and exact-budget regression tests are prerequisites
for either production integration, rather than claims made by this comparison.

Validation passed the final four-layout matrix (1,440 read observations and 96
mutation observations), with independently expected read results and the state
checks above. The first three layouts were also repeated for the 1,000-key and
10,000-key ten-version workloads, including 4 KB values; representative read,
write, and rollback timings were consistent. The 20 existing host-metering tests,
five pruning tests, and original host-history benchmark at depth one also passed.
Indexer library/test Clippy with warnings denied, workspace formatting, and diff
checks passed. All timing benchmarks remain ignored in normal CI.
