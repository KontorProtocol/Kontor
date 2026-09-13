# Contract queries that motivate language work

Initial investigation: 2026-09-10 at main
`6a64d4653b5c9015d9274dea0852a5a9cd3204f7` (#557).
The first phase was merged in #558 (`367f7a42`); the second phase below
builds on that main commit.
See [the current API guide](indexed-map-index-system.md) for supported syntax.
The native/test contract adoption audit below examines that local commit and
repository callers; it does not claim verification of a newer remote head.

## Implemented first phase: key ranges, cleanup, and NFT pages

Reward cleanup uses an exclusive primary-key range on
`by_agreement_active(agreement_id, true)`. The compound primary key
`(agreement_id, node_id)` already orders nodes inside that fixed agreement bucket,
so the redundant `reward_members` sorted index is removed. This saves one of
three secondary member entries per membership, plus its bucket counts and
maintenance. The remaining index IDs are unchanged. Existing deployed state needs
fresh replay under the preproduction upgrade model.

All four NFT list views now take an optional exclusive NFT-ID cursor and a capped
limit, returning `{ items, next }`. Offset signatures are removed. A later page
seeks directly to its starting key rather than consuming earlier entries.
Agreement pages use the NFT ID as their cursor even though the returned projection
is an agreement ID. Calls read current state; there is no snapshot across pages
or persistent cursor table.

`core/stdlib/src/query.rs` implements bounds and iteration once, using the existing
lazy host key/covering-row cursors. Maps and unsorted indexes range over primary
keys; sorted indexes range over their declared sort field. Reverse iteration keeps
the same bounds. Exclusive bounds skip a complete element subtree, including
struct fields, without absorbing a distinct escaped-NUL sibling. Covering key-only
reads avoid fetching projections, and bounded queries do not expose bucket counts.

## First-phase adoption audit: all native and test contracts

The scan covered all five native contracts and eleven test contracts (18 Rust
source files), their WIT exports, and repository callers. Searches included
`skip`, `skip_while`, `take_while`, `filter`, `filter_map`, `find`, `keys`, `iter`,
`range`, direct storage lookups, and loops over stored collections. No offset or
guest-side range-skipping implementation remains in these contracts. This is an
adoption audit, not a general correctness review of every contract.

| Contract | Existing query use and conclusion |
| --- | --- |
| Native `nft` | All four paginated views use ranges; agreement pages use the existing covering index. Attribute listing is a complete, at-most-32-entry map read; removing its separate value reads needs scalar-entry iteration. |
| Native `filestorage` | Reward cleanup uses key ranges; expiry and overdue obligation selection use deadline ranges. Cleanup queues deliberately consume/remove their first pending item. Active challenges are already covering reads, and node listings derive data from membership keys/buckets. Full agreement exports, reward reweighting, and challenge-member selection have no cursor boundary to push into storage. |
| Native `staking` | Consensus-set reads, reward recipients, and pending-stake capacity checks already use covering status reads and require the full relevant population. The duplicate-key check uses an equality bucket. Pending activation/exit is the remaining range candidate, but its heights are not ordered in that bucket; it requires an index/layout change and measurement. |
| Native `token` | Full balance export scans scalar keys and separately reads values; a scalar-entry scan is the relevant missing facility. Its Core/Burner exclusions must remain explicit. No offset pagination exists. |
| Native `system` | Lifecycle hooks; no stored collection query to range. |
| Test `arith` | Complete numeric map/index enumeration verifies canonical numeric storage and index ordering. Sorted covering projections already use `.values()` and benefit from the common query implementation. There is no skipped prefix to eliminate. |
| Test `fib` | `cached_values` exports all cached keys; Deque iteration exercises FIFO storage. The caller checks the complete cache. Neither needs a cursor. |
| Test `test-token` | Full Integer balance export is another scalar-entry consumer. Preserve its Burner exclusion (which differs from the native/Decimal token filters). |
| Test `decimal-token` | Same scalar-entry opportunity as the native token; preserve Core/Burner exclusions. |
| Test `shared-account` | `tenants` returns the owner plus all co-tenants; authorization uses point lookups. A partial tenant response would change the API's meaning. |
| Test `amm` | Pools and balances are accessed by exact keys; no collection scan to range. |
| Test `pool` | Balances and reserves use exact lookups; no collection scan to range. |
| Test `counter` | Scalar reads and exact-key writes/removal; no listing query. |
| Test `crypto` | Scalar/byte values and entropy/hash operations; no listing query. |
| Test `error-test` | Error/trap fixtures; no collection query. |
| Test `proxy` | Exact stored address and forwarded calls; no collection query. |

The NFT cursor migration and removal of the duplicate reward index cover the
existing direct key-range uses. Replacing a complete `.keys()` scan with
`.range(..).keys()` would do the same work. Likewise, ordinary lists do not need
page-response wrappers when there is no continuation metadata.

At the end of the first phase, the remaining worthwhile changes were:

- Scalar-entry iteration can serve native token balances, both test token ledgers,
  and NFT attributes without a second value lookup. The second phase below now
  implements it; a stored leaf still needs its own decoding/framing rules.
- Due-validator processing could seek by activation/deactivation height after an
  index change. Applying a height bound to the current Holder-keyed status index
  would be incorrect. Measure the saved per-block reads against index maintenance,
  preserving joins-before-exits, complete due processing, and deterministic order.
- Paged filestorage exports and prover-specific work views would be useful client
  APIs. Current repository callers consume complete lists (including the eager
  reward-accounting oracle); changing them requires an explicit API/caller migration.
  Challenge selection also reads another map's cleanup status, which cannot be
  replaced with a bound over membership primary keys.

No additional contract source changes were justified solely to adopt the current
feature. This audit updated the stale implementation descriptions above; it did
not rerun the already-passing suite for documentation-only changes.

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

## Implemented second phase: scalar map entries

Scalar maps expose `.entries()` directly and after `.range(...)` / `.rev()`.
The native token, Decimal test token, Integer test token, and NFT attributes now
use it. Complete result shapes and ordering remain unchanged. Native/Decimal
ledgers still exclude Core and Burner; the Integer test ledger excludes Burner.

`ScalarStorage` defines single-leaf decoding separately from ordered key encoding.
The shared `storage-rows` cursor replaces the covering-only cursor, returns raw
stored bytes, and meters key plus value bytes. Postcard framing is decoded once
in stdlib, borrowing numeric/covering byte payloads; numeric types reuse the same
codec decoder as their point reads. Compound values cannot expose `.entries()`.
No additional index, database table, or value copy is maintained.

The follow-up audit again examined native/test contract key scans. The remaining
ones require only keys or read compound models. For example, the reward folding
queue supplies a node ID to `rewards::settle`, which owns its state reads; passing
a preloaded delta would require a separate reward API change and is not needed
for this language feature. No alternate preloaded-settlement path was added.

The ABI rename requires rebuilt contracts and SDK component. Existing stored
values retain their format; preproduction deployments replay with matching
runtime and binaries. This phase does not add balance pagination, value ordering,
or a new query-planner syntax.

Second-phase validation passed the release workspace suite with `REGTEST=1`
(781 tests passed, 3 tests/doctests opt-in), all 158 SDK tests, macro UI and
snapshot checks, formatting and Clippy in all three workspaces, and the pinned
native/test contract builds.

### Second-phase measured reads

The actual Wasm runtime tests verify:

- Five numeric entries: five metered rows and zero point `Get` calls, for both
  Integer and Decimal, including zero and signed 256-bit extremes.
- A reverse numeric range limited to two entries: exactly two metered rows;
  a zero limit consumes none. Key plus serialized value bytes are charged exactly.
- Thirty-two NFT attributes: thirty-two rows and zero point reads. Reading the
  same attributes individually performs thirty-two point reads.
- Native token balance export: zero point reads, with results checked against
  individual balance reads and the Core/Burner exclusions preserved.

These are storage-operation counts, not an end-to-end throughput claim. Entries
fetch values even for holders filtered out afterward; the older key-only loop
avoided those excluded value reads. No extra stored copy or index is introduced.
Numeric tests also exercise removal, overwrites, savepoint rollback, and block
rollback/reappearance. Existing covering-index and NFT pagination checks run
through the same generalized cursor.

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
selected page. Paging the existing global active-agreement/challenge views requires an explicit
API/caller migration; avoid preserving competing pagination conventions.

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
