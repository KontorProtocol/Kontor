# Current-state storage

Contract reads should depend on live state, not on how many obsolete versions a
node retains. `current_contract_state` is a derived index with one row per live
`(contract_id, path)`, storing its history height and encoded value size. It uses
a clustered primary key (`WITHOUT ROWID`) and a height index for block cascades.
Values and deposit attribution remain in `contract_state`. This is an index over
one canonical history, not another history or consensus commitment.

## Read and fuel boundary

Point reads first fetch height and size. Ordered key/value scans traverse only
current entries. Value reads check the remaining byte budget before issuing the
prepared history lookup by `(contract_id, height, path)`. That logical identity
survives VACUUM; no persistent SQLite rowid is stored. The metadata cursor stays
open through the value read to preserve the reader's snapshot. Key-only and
existence reads never access history. Deletion discovery joins the selected live
entries to their deposit attribution without copying values.

Archive and pruned nodes visit the same live entries and charge identical fuel.
This removes traversal of obsolete versions and historical deleted keys, not
all physical cost variation from database size, caching, or compaction. Existing
nested-record key deduplication and bounds remain in place. Fuel rules and the
contract ABI are unchanged; eventual calibration must include index maintenance
in write costs.

## Maintenance and failure boundaries

An AFTER INSERT trigger maintains the pointer within the history write's SQL
statement, including same-height replacements and tombstones. Older imported
versions cannot displace a newer live value or tombstone. SQL transaction and
savepoint rollback revert history and pointers together.

Reorgs use `rollback_to_height`, which:

1. Captures distinct affected keys from the removed history band, including keys
   whose current version is a tombstone and therefore has no pointer.
2. Deletes blocks, allowing the height foreign key to remove discarded pointers.
3. Restores each affected key from its newest surviving version, only if live.

A nested savepoint makes all three steps atomic, even for direct query callers.
Discovery and history deletion scale with removed versions; restoration scales
with distinct affected keys. No full-state rebuild occurs during a reorg.
Same-height variant cleanup explicitly removes its affected pointers and restores
surviving versions through the same repair query. Finalized-history pruning
cannot remove a pointed-to live version, so it needs no pointer maintenance.

Block rollback and hard deletion must use these query helpers. Raw SQL deletion
of history or blocks bypasses repair. Inserts are covered by the trigger, including
native initialization and tooling. The current table follows the history table's
contract lifetime: history has no contract foreign key; removing a contract row
alone is not a supported state-deletion operation.

## Upgrade and recovery

Database initialization creates, backfills, and installs maintenance in one
transaction before exposing the connection. The table's existence marks completion;
reopening a migrated database does not scan history. An interrupted migration
rolls back its table and trigger along with the backfill. Normal SQL crash recovery
keeps committed history and its index together. This has transaction-failure and
reopen coverage, not process-kill/power-loss fault injection.

## Deliberate remaining history reads

Enum/option discrimination (`matching_path`) selects the newest write across an
entire subtree, including tombstones, with insertion order breaking height ties.
A live-only index cannot preserve that rule. This operation remains unchanged and
can still have history-dependent work; replacing it requires separate language/
runtime design and regression coverage. The pointer index does not claim to make
that operation history-independent.

Footprint reconstruction, affected-depositor discovery, and transaction-history
APIs still use history. Contract storage-floor checks already use the eager
per-depositor cache, so they do not perform those reconstruction scans per call.

See [the comparison](current-state-comparison.md) for the measured storage,
write, read, and incremental rollback tradeoffs motivating this layout.

## Validation

The indexer release library suite passed: 552 tests, 12 ignored. This includes
multi-node checkpoint/reorg/restart scenarios, native-contract accounting, exact
fuel boundaries, and reader snapshots during concurrent replacement. New tests
compare the index against an independent window-query oracle, exercise upgrade
and reopening, injected failure during reorg repair, SQL abort, pruning, replay,
and VACUUM. An authorizer denies all history reads during key discovery and
unaffordable value reads; a host-level test verifies result/fuel parity before
and after pruning. A query-plan check ensures repair drives history seeks from
the affected-key set. Clippy with warnings denied, formatting, and diff checks
passed.

The initial full-suite attempt was stopped because sandboxed cluster listeners
could not bind localhost. The successful full suite ran with local networking
available. An existing 130-key fuel-boundary test caught a prepared-statement
reuse error in the first hard-delete repair implementation; batched key capture
fixed it and the same test passes in the full run.
