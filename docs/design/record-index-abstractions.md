# Records, derived indexes, and logical updates

Status: research record. The implemented scope is
[conditional index membership](indexed-map-index-system.md#conditional-membership).
Broader record-update, deferred-write and query-abstraction proposals below remain
deferred; they are not additional supported APIs.

Research date: 2026-09-13. This is a design investigation, not an implemented API.
It builds on the [local scan and index-maintenance measurements](contract-query-opportunities.md#investigation-conditional-membership-versus-combined-updates).
Sources below are official documentation and upstream implementations. Moving
`latest`/`main` links describe the versions consulted, not permanent compatibility
guarantees. No external implementation was benchmarked locally.

## FoundationDB: separate the key-value substrate from the record abstraction

FoundationDB itself provides ordered keys and transactions. Its indexing recipe
puts derived entries beside primary data and updates both transactionally. The
application or a library supplies that data model; the database does not infer
secondary indexes from arbitrary writes. [Data modeling](https://apple.github.io/foundationdb/data-modeling.html),
[simple indexes](https://apple.github.io/foundationdb/simple-indexes.html).

The Record Layer supplies that library abstraction. Index metadata identifies an
index and expressions that derive its entries. Its standard maintainer evaluates
the old and new record, removes common entries from the work lists, and applies
the remaining removals/additions. This is a logical record-update boundary, not
an automatic promise to combine every save in a transaction. [Record Layer extension points](https://foundationdb.github.io/fdb-record-layer/Extending.html),
[StandardIndexMaintainer.update](https://github.com/FoundationDB/fdb-record-layer/blob/main/fdb-record-layer-core/src/main/java/com/apple/foundationdb/record/provider/foundationdb/indexes/StandardIndexMaintainer.java#L202).

The core metadata API also exposes `IndexPredicate` for selecting records for
indexing. Separately, the Relational Layer describes index definitions as
incrementally maintainable materialized views of SELECT statements. Its current
documented SQL index rules disallow predicates in those queries. Thus the
materialized-view model and core predicate support are useful precedents, but
are not evidence that arbitrary filtered SQL index declarations are supported.
[IndexPredicate](https://foundationdb.github.io/fdb-record-layer/api/fdb-record-layer-core/com/apple/foundationdb/record/metadata/IndexPredicate.html),
[Relational index definitions and restrictions](https://foundationdb.github.io/fdb-record-layer/reference/Indexes.html).

## Smart-contract precedents

### CosmWasm: indexed maps with record-level updates

`cw-storage-plus` provides `IndexedMap`, with indexes maintained during saves,
updates, and removal. Its `update` closure receives the loaded value and produces
the replacement. The inspected `replace` implementation removes old memberships,
saves new memberships, and writes the primary value. It does not generally skip
unchanged indexes at that layer. An exposed `old_data` argument can avoid a second
read, but the caller must supply the actual stored version. [IndexedMap API](https://docs.rs/cw-storage-plus/latest/cw_storage_plus/struct.IndexedMap.html),
[implementation](https://docs.rs/cw-storage-plus/latest/src/cw_storage_plus/indexed_map.rs.html#73-126).

Lesson for Kontor: the explicit edit boundary is useful. Retain our dependency
tracking and index diffs, and avoid making callers supply trusted old snapshots.

### Antelope: a modify closure with automatic secondary-index maintenance

Antelope's C++ `multi_index` exposes `modify(iterator, payer, updater)`. The caller
edits a record in the updater. The implementation captures old secondary keys,
invokes the updater, writes the modified record, and updates changed secondary
keys. Its API also accounts for storage payment. [Multi-index API](https://docs.antelope.io/cdt/latest/reference/Modules/group__multiindex/),
[modify implementation](https://github.com/AntelopeIO/cdt/blob/main/libraries/eosiolib/contracts/eosio/multi_index.hpp#L1600).

Lesson for Kontor: contract authors can express a multi-field logical operation
without manually sequencing secondary-index updates. This evidence establishes
an update pattern, not predicate-index support in Antelope.

### Solidity and Move: useful contrasts

Solidity's built-in mappings do not enumerate their keys; its documentation builds
an additional collection for iterable mappings. That is a lower-level starting
point than Kontor's generated indexed maps. [Solidity mapping documentation](https://docs.soliditylang.org/en/latest/types.html#iterable-mappings).

Move on Aptos exposes mutable references to stored resources, subject to module
and borrowing restrictions. This offers a record/resource mutation model, but
the cited storage API is not a facility for maintaining sorted predicate indexes.
That distinction matters when borrowing its ergonomics. [Move global storage](https://aptos-labs.github.io/move-book/global-storage.html).

## Recommended abstraction for Kontor

This recommendation is an inference from those implementations and our local
measurements: **records are authoritative, indexes are declared derived views,
and a logical record edit reconciles affected views once**.

For example, a pending-activation view means:

```text
source:     stake accounts
membership: status is PendingJoin
order:      activation height, then account key
result:     account keys (or a declared projection)
```

Filtering, optional equality grouping, ordering, and projection are aspects of
one index declaration. If membership fixes the status, requiring the query to
repeat that status serves little purpose. Supporting an omitted `by` would need
an explicit global-bucket representation and generated no-argument accessor;
it is not supported by today's attribute parser.

An illustrative update API, not a settled signature or working code:

```rust
accounts.update(&holder, |account| {
    account.deactivation_height = height;
    account.status = ValidatorStatus::PendingExit;
    Ok(())
})?;
```

Both assignments describe one transition. The framework compares the relevant
old state with the final state and maintains each affected index once. The edit
must finish before later index queries or cross-contract calls can observe it.
Failure must preserve the existing deterministic rollback behavior. A transaction
containing multiple explicit edits does not automatically imply one deferred diff.

This is a logical unit, not a requirement to pack the whole record into one
physical slot. Our field-based storage makes cheap field access valuable. A
naive load-clone-rewrite implementation could increase reads, writes, and guest
code, even if it improves index maintenance. Existing whole-record `set` already
computes one diff, so measure extending that path against a changed-field edit
scope before choosing new machinery. Keep ordinary single-field setters using
the same maintenance engine and touching only their dependent indexes.

## Implementation boundaries and order

1. Share index declarations, predicate semantics, and field dependencies between
   Rust records and the WIT-record adapter. Keep WIT name/type translation at the
   adapter boundary. This is distinct from the already-completed host forwarding
   cleanup; neither requires putting validator-specific rules in the host.
2. Add narrow, deterministic membership predicates over each record's own fields.
   Generate them consistently for initial writes, replacements, setters, and
   removal. Allow ungrouped indexes for named filtered views. Retain stable index
   IDs and existing key encoding, scans, and rollback paths.
3. Adopt the pending-validator views and measure again. Design one explicit
   record-edit boundary around existing `set`/diff machinery; evaluate field
   access cost before committing to the illustrative closure implementation.
4. Treat general joins, cross-record dependencies, and automatic query planning
   as separate capabilities requiring concrete consumers. A named index keeps
   the chosen access path apparent; predicates depending on another map or the
   current block would need additional invalidation machinery.

The research strengthens the case for a coherent record-update API as an
ergonomic improvement. It does not overturn the probe showing that conditional
membership is the larger immediate saving for staking. The exact syntax and
implementation remain open; no new runtime interface was added by this research.
