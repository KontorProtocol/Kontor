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
nested-record key deduplication and bounds remain in place. Existing metered
scalar and deletion operations also cover enum/Option tags; eventual calibration
must include index maintenance in write costs.

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
Finalized-history pruning cannot remove a pointed-to live version, so it needs
no pointer maintenance.

Block rollback must use this query helper. Raw SQL deletion
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

## Enum and Option layout

This is the current implementation. The subsequent [path-layout comparison](variant-layout-comparison.md)
found a viable alternative and recommends evaluating it through the compiler
before finalizing this format.

Enums store their declaration-order variant id as a scalar `u64` at the enum
root. Payloads stay beneath their existing interned variant child. Options store
`0` (None) or `1` (Some) at their root, with Some's payload beneath `some`.
Unit variants and empty payloads need only a root tag. Reading a variant performs
one ordinary metered scalar lookup, regardless of payload size or retained history.
Missing Option tags read as None; invalid tags trap deterministically.

Replacement tombstones the entire old live subtree before storing the tag and
payload. This removes prior-block payloads as well as same-block ones, releasing
their storage floor and charging for their deletion. Payload writes do not change
the tag. Normal call rollback and block rollback restore tags, payloads, pointers,
and deposit attribution together. There is no special hard-delete/revival path.

Path-based tags are also viable with full replacement cleanup, a first-live-child
lookup, and markers for empty payloads. The root scalar was chosen to reuse the
existing scalar host API and give all payload shapes one representation.

The tradeoff is one additional small row for payload-bearing variants/Some, and
real deletion work when replacing large payloads. Reads no longer infer variant
selection from whichever descendant happened to be written last. This also
represents Some(empty record) and enums with empty-record payloads unambiguously.

This is an incompatible guest ABI and stored-layout change: the variant-matching
host imports are removed. Deploy rebuilt contracts with fresh pre-production
state; the pointer backfill alone cannot migrate old variant layouts. No legacy
reader or dual encoding is retained.

## Remaining history reads

Footprint reconstruction, affected-depositor discovery, and transaction-history
APIs still use history. Contract storage-floor checks already use the eager
per-depositor cache, so they do not perform those reconstruction scans per call.

See [the comparison](current-state-comparison.md) for the measured storage,
write, read, and incremental rollback tradeoffs motivating this layout.

## Validation

Tests compare the pointer index against an independent window-query oracle and
exercise upgrades, reopening, injected reorg-repair failure, SQL abort, pruning,
replay, and VACUUM. An authorizer denies history reads during key discovery and
unaffordable value reads. Host tests verify result/fuel parity across pruning and
exact deletion-budget boundaries, including deposit release and rollback. A
query-plan check ensures repair drives history seeks from the affected-key set.

Compiled-contract coverage exercises unit, scalar, collection, and empty-record
variants; None/Some transitions; cross-block replacement and payload edits;
failed-call rollback; reorg; and pruning. Variant reads are checked for fixed
scalar-read counts and equal fuel after payload growth and history pruning.

Validation on 2026-09-16: 546 release library tests and 124 contract integration
tests passed, along with stdlib/macro tests and 158 SDK tests. Clippy with warnings
denied and formatting passed. `./tools/kontor build --check` reproduced all native
contracts, test contracts, and SDK outputs byte-for-byte.

The production history benchmark (`benchmark_storage_history`, release mode)
measured a 100-field variant at 1, 10, 100, and 1,000 retained payload versions.
Tag reads charged 230 host fuel in every archive/pruned case. Archive timings were
13.6, 5.7, 5.8, and 5.9 microseconds respectively; pruned timings were 5.7–6.4
microseconds. These are local timings, not a calibrated fuel schedule. The
benchmark asserts result, fuel, and checkpoint preservation through pruning.
