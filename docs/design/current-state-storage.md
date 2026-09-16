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
key-cursor, scalar, and deletion operations also cover enum/Option values; eventual calibration
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

Enums keep declaration-order variant IDs in interned child paths. Options keep
`none`/`some` child paths. Readers take one child from the existing metered key
cursor over current state, then drop the cursor. They neither search history nor
materialize the payload to select the variant. Missing Options read as None;
invalid tags trap deterministically.

| Payload | Live representation |
| --- | --- |
| Unit / None | `field/variant = ()` |
| Scalar | `field/variant = value` |
| Compound | `field/variant = ()`, with fields below that path |

The compound marker persists even when populated, so removing the last descendant
cannot erase the variant. `Store::STORES_ROOT` is required metadata identifying
types whose value already supplies presence, including primitive scalars,
Integer, Decimal, and Holder.
Derives supply it automatically; hand-written implementations must declare it.
The shared variant-payload writer adds a marker only for compound types, after
writing the payload because a nested replacement may clear its own subtree.
This is storage-layout metadata, not a new contract-facing API or host operation.

Replacement tombstones the entire old live subtree before writing the new value.
This removes prior-block payloads as well as same-block ones, releases their
storage floor, and charges for deletion. Ordinary payload edits leave the variant
marker in place. Call and block rollback restore payloads, pointers, and deposit
attribution together. There is no separate scalar tag or hard-delete/revival path.

The [layout comparison](variant-layout-comparison.md) records the rejected root-tag
alternative and its measurements. The path layout saves one row for scalar
payloads; compound payloads use the same row count. Existing cursor fuel tariffs
are higher than point-read tariffs, so these changes do not claim cheaper variant
reads. Calibration remains separate from this representation change.

This remains an incompatible guest ABI and stored-layout change: old variant-
matching imports are removed, and old layouts could leave obsolete variants live
or omit empty-payload markers. Deploy rebuilt contracts with fresh pre-production
state; pointer backfill alone cannot repair old variant representations. No legacy
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
failed-call rollback; reorg; and pruning. Variant reads are checked for exactly
one cursor poll per selection, no payload value fetch during selection, and equal
fuel after payload growth and pruning.
Nested enum/Option regressions include Integer, Decimal, Holder, compound
ContractAddress values, and deletion of a compound payload's last descendant.

The production history benchmark (`benchmark_storage_history`, release mode)
measures point, key, value, existence, and variant reads at 1, 10, 100, and 1,000
retained versions. It asserts result, fuel, and checkpoint preservation through
pruning. The smaller archive/pruned parity case runs in the normal test suite.

Validation on 2026-09-16: 546 release library tests passed (12 ignored), along
with 124 contract integration tests, 158 SDK tests, and the stdlib unit, macro
snapshot, and compile-fail suites. Clippy with warnings denied and formatting
passed. `./tools/kontor build --check` reproduced all native contracts, test
contracts, and SDK outputs byte-for-byte.
