# Contract queries that motivate language work

Investigated on 2026-09-10 at main `6a64d4653b5c9015d9274dea0852a5a9cd3204f7`,
after #557 merged. The first phase is now implemented on `feat/key-range-queries`;
see [the current API guide](indexed-map-index-system.md). Later phases remain proposals. The investigation
traced native contract declarations, query bodies, repository callers, generated
models, and the runtime/database scan path. No new benchmarks were run.

## Implemented first phase: key ranges, used by cleanup and NFT pages

### Remove an index maintained only to obtain a cursor

Sources: `native-contracts/filestorage/src/lib.rs` (`NodeState`) and
`native-contracts/filestorage/src/cleanup.rs` (`step`).

Memberships have primary keys `(agreement_id, node_id)`. The existing
`by_agreement_active(agreement_id, true)` index therefore already visits members
in node-ID order inside a fixed agreement bucket. Cleanup nevertheless uses a
third index, `reward_members`, with the same bucket and `sort = node_id`, because
only sorted index queries expose `.range(...)` today.

Give ordinary index queries a typed range over their primary keys. Cleanup can
resume exclusively after `(job.agreement_id, preparation.cursor)` in the existing
bucket, then remove `reward_members`. The traversal order stays the same because
the agreement component is constant and node IDs are unique within the bucket.

This removes one of the three secondary member entries per membership, plus the
removed index's bucket counts. It also removes the corresponding maintenance on
creation, deletion and active-status transitions. This is a reduction in index
state, not a claim of one-third less total membership storage. Removing this last
index declaration leaves the first two IDs unchanged; native contract state still
requires fresh replay under our current preproduction upgrade model.

### NFT pagination that does not walk all earlier pages

Source: `native-contracts/nft/src/lib.rs`: `list_nfts`,
`list_nfts_by_creator`, `list_nfts_by_holder`, `agreement_ids_by_creator`.

All four use `.skip(offset).take(limit)`. Fetching a 100-item page at offset
100,000 advances through 100,100 keys or covering rows, assuming enough entries.
Covering agreement-ID queries also retrieve projections for the discarded rows.
The existing page-size cap does not bound the skipped work. Global NFT enumeration
can additionally traverse several field rows per NFT while finding distinct keys.

Expose key ranges on ordinary maps and on both plain and covering index queries.
Add cursor-based contract views taking an optional exclusive NFT-ID cursor and a
capped limit. A page starts at a database seek instead of a guest-side skip. The
cursor must use the last scanned NFT ID, including for agreement-ID results whose
projection is a different ID. Replace the existing offset signatures with explicit cursor arguments and page
responses; do not retain two pagination APIs. This is a preproduction API change.

At fixed state, successive pages must equal a full enumeration exactly. Between
calls, inserts before the cursor are not returned and holder transfers change
bucket membership; key cursors alone do not provide snapshot pagination. Define
that behavior explicitly. No persisted cursor table is needed.

### Shared implementation boundary

`core/stdlib/src/map.rs` already offers sort-value ranges and reverse scans.
`core/macros/src/model.rs` generates plain map `keys()` without ranges;
`IndexQuery` and `CoveringQuery` also lack key ranges. The runtime's
`get-keys`/`get-index-rows` already accept lower/upper byte bounds and direction,
backed by lazy, index-served versioned scans. Reuse those facilities.

Use one typed key-range implementation in stdlib and small generated adapters.
Exclusive bounds must skip the complete key subtree, including compound keys,
instead of seeking just beyond its parent row and re-emitting its children.
Keep existing sorted `.range(...)` semantics on the sort value; do not make the
same method silently mean a primary-key range on sorted indexes.

Validation and measurement for this PR:

- Fixed-page deep versus shallow scans: compare `KeysNext`, covering-row work,
  value reads and instrumented latency. Earlier page depth must not add discarded
  rows; ordinary B-tree seek cost and per-record work still exist.
- Empty/inclusive/exclusive/reversed bounds; string prefixes and embedded NULs;
  compound keys; missing/deleted cursor keys; zero limit and capped page sizes.
- NFT pages after transfer and block rollback; covered agreement IDs must match
  the corresponding NFT pages at the same state.
- Large-membership cleanup must retain bounded steps, reward conservation,
  cursor progression, exhaustion handling and savepoint/block rollback behavior.
- Measure membership index writes, deposits and rows before/after removing the
  extra index. Ordinary numeric key ordering and zero canonicalization remain intact.

### Implemented validation and measured work

The completed first phase passed the 778-test release workspace suite with
`REGTEST=1` (three tests/doctests remain opt-in), Clippy with warnings denied in
core/native/test workspaces, formatting, macro snapshots and compile-failure
checks, and the pinned native/test contract builds.

The new runtime test creates 110 NFTs through the native contract. It verifies
that early and late five-item pages consume the same number of storage rows;
covering agreement pages consume six index rows including lookahead and fewer
point reads than full NFT pages. It also checks complete enumeration, embedded
NUL IDs, missing cursors, the 100-item cap, zero limits, transfers and savepoint
rollback. Database tests separately check subtree deletion and block rollback.
Existing reward tests cover cursor progression through preparation/folding,
exhaustion, conservation and replay with the smaller index set.

The opt-in reward benchmark passed all six population scenarios (54 measurement
rows). Compared with the retained main baseline from the earlier buffer study:

| Operation | Population | Host Set calls, before → after | Delete calls | Get calls |
| --- | --- | ---: | ---: | ---: |
| Rejoin | 3 members, 1 file | 37 → 34 | 3 → 2 | 45 → 43 |
| Rejoin | 128 members, 1 file | 662 → 659 | 3 → 2 | 795 → 793 |
| Leave | 128 members, 1 file | 659 → 656 | 4 → 3 | 791 → 790 |
| Entire exhaustion cleanup | 3 members, 64 files | 1757 → 1565 | 202 → 138 | 2667 → 2602 |

Cleanup took the same number of bounded calls in both versions. These are
instrumented operation counts, not a throughput claim. The comparison includes
the first-phase changes; the separate buffer-only experiment showed identical
host-operation counts. Local logs are `/tmp/kontor-ranges-costs.log` and
`/tmp/kontor-path-probe/baseline-run-1.log`.

## Second PR: scalar map entries, used by token balances

Source: `native-contracts/token/src/lib.rs`, `balances`.

The ledger is `Map<Holder, Decimal>`. Listing balances currently enumerates its
keys, converts each holder, and separately reads each included balance. After
#557 each Decimal is directly stored at the holder key. A typed map-entry scan
can return `(holder, amount)` from that row, eliminating the separate numeric
point reads. Retain the current exclusion of Core and Burner holders and the
ordering of results. Holder conversion costs remain.

Pair this with an additive, capped balance-page view; the existing `balances()`
still returns the full ledger. With filtered holders, the continuation must
advance by scanned keys, not only returned results, and the scan budget must be
explicit. This is useful for account listings and inspection; repository usage
found here is in tests, so production client demand is not yet established.

A second existing consumer is NFT `get_attributes`: a `Map<String, String>` is
read through `keys()` plus one `get()` per attribute. Attributes are capped at 32,
so this is a small simplification rather than a scalability emergency.

Keep this facility restricted to values with a genuine single-leaf storage
representation. `KeyElement` alone does not imply that property. Stored values
also retain host serialization framing; even when payload codecs match, raw
database values cannot simply be decoded as index projections. Introduce a small
shared scalar-storage decoding abstraction if needed. Do not add reward-aware
runtime behavior or assume structs, options and enums occupy one leaf.

The existing row cursor is a potential foundation, but its contract and decoding
must be generalized deliberately. Charge row bytes and preserve deletion,
version visibility, rollback and lazy iteration. Test Integer/Decimal, strings,
zero, missing rows and full-range values. Measure actual eliminated `Get` calls
before claiming an end-to-end speedup.

## Independent contract improvement: due validator transitions

Source: `native-contracts/staking/src/lib.rs`, `process_pending_validators`;
called every Bitcoin block from `core/indexer/src/reactor/blocks.rs`.

The contract collects every PendingJoin and PendingExit key, reads each account's
scheduled height, then ignores entries scheduled for later. Existing attributes
can add status-bucketed indexes sorted by `activation_height` and
`deactivation_height`, allowing `.range(..=block_height)` to retrieve only due
entries. No new macro syntax or numeric-storage feature is required.

This trades extra index writes/state for fewer repeated per-block reads during
the 12-block activation/exit delay. Benchmark realistic pending populations first.
Preserve processing of all due validators, joins-before-exits, aggregate stake
checks, and deterministic effects; explicitly check whether changing within-bucket
processing order matters. Snapshot selected keys before mutations move index
members. Test height boundaries, slashing/cancellation, and reorg reactivation.
Do not introduce a work cap that silently delays scheduled transitions.

## Useful follow-up views: a storer's own work

Sources: `native-contracts/filestorage/src/lib.rs`, `get_active_challenges`,
`get_all_active_agreements`, `get_agreement_nodes`, and existing
`by_prover_status` / `by_node_active` indexes.

The current active-challenge view returns all active challenges using a covering
index. A prover-specific view can use `by_prover_status(node_id, Active)` to avoid
downloading other storers' work. Likewise a node-membership page can use
`by_node_active(node_id, true)`. These indexes already exist for obligation cleanup.
Page these views using the first PR's key ranges; fetch details only for the
selected page. Existing global active-agreement/challenge views can gain additive
paged counterparts for network-wide inspection.

An earliest-deadline-first prover work queue would motivate a sorted
`by = (prover_id, status), sort = deadline_height` declaration. It needs a cursor
over `(deadline_height, challenge_id)`, because deadlines can tie; a deadline-only
cursor skips or repeats work. This is the concrete use case for a later full
sorted-member cursor API. Proof acceptance still enforces deadlines independently
of what these views return.

Repository searches found test callers of the global challenge view, not a
production storer polling implementation. Treat the prover dashboard/queue as a
proposed client feature, not a confirmed current hot path. Start with existing
indexes; add deadline order or covering fields when a client needs them and the
read/write tradeoff is measured.

## Features not justified by these consumers yet

- Multi-field `sort = (a, b)`: no audited native query requires it. Existing sorted
  indexes already use the primary key as a deterministic tie-breaker; cursor
  support for that pair does not require a multi-sort attribute.
- General predicate/query-planner DSL: equality/status buckets plus typed ranges
  cover these requests. Keep query selection explicit and metered.
- An index predicate that reads another map: challenge generation filters members
  against `bond_cleanup_pending`. A generated index over `NodeState` cannot stay
  correct when another map changes unless it maintains cross-record dependencies.
  This is a lifecycle/selection design problem, not a small attribute addition.
- Paginating full consensus-set construction or per-file reward reweighting:
  these operations need the complete relevant population for their current
  semantics. Page APIs do not make that work disappear.
- An automatic numeric range scan over map values: scalar values are stored in
  key order, not value order. Balance thresholds still require a declared
  value-sorted index; numeric compaction alone does not supply one.

The first PR has two existing consumers and removes redundant maintained state.
The second directly uses scalar numeric storage. The staking change can be
assessed separately with existing language facilities; the storer views should
follow the client workflow they serve.
