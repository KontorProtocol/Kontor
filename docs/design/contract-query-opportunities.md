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

`ScalarStorage` selects the typed host row method for each single-leaf value.
The shared `storage-rows` cursor replaces the covering-only cursor and meters
key plus stored value bytes. Point reads and row reads share strict Postcard
deserialization in the host; numeric and covering payloads retain their existing
guest codec decoders. Invalid storage types, malformed values, and compound scan
targets fail deterministically. u32/i32 point reads and entry scans share checked
narrowing. Compound values cannot expose `.entries()`. No additional index,
database table, or persisted value copy is maintained.

The follow-up audit again examined native/test contract key scans. The remaining
ones require only keys or read compound models. For example, the reward folding
queue supplies a node ID to `rewards::settle`, which owns its state reads; passing
a preloaded delta would require a separate reward API change and is not needed
for this language feature. No alternate preloaded-settlement path was added.

The ABI rename requires rebuilt contracts and SDK component. Existing stored
values retain their format; preproduction deployments replay with matching
runtime and binaries. This phase does not add balance pagination, value ordering,
or a new query-planner syntax.

Initial second-phase validation passed the release workspace suite with `REGTEST=1`
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

## Due validator transitions: measured implementation

Baseline: main `49a815faddf2bf08f61e705158e651bc1638fe34` (#559),
measured 2026-09-13. Source: `native-contracts/staking/src/lib.rs`,
`process_pending_validators`; called every Bitcoin block from
`core/indexer/src/reactor/blocks.rs`.

The old query collected every PendingJoin and PendingExit key and read each
scheduled height, including future transitions. Two appended status-bucketed
indexes sort by activation/deactivation height. Existing index IDs 0/1 retain
their meaning. `.range(..=block_height).keys()` now retrieves only due entries.
No new macro syntax or WIT method is required for this query.

Both groups are snapshotted before mutation. Each is sorted back into canonical
Holder string order, matching the old primary-key traversal, before processing
all joins and then all exits. There is no work cap. Existing aggregate stake
checks remain in place. The regression covers exact height boundaries, future
members, cancelled and slashed joins, simultaneous joins/exits, repeat calls,
and block rollback followed by overdue replay. An idle mixed population must
produce zero point reads and zero consumed cursor rows.

Validation: the indexer release library suite passed (486 tests, 3 opt-in skips),
including the existing scalar/covering reads and error-classification tests.
The new lifecycle regression passed in that suite; a final focused run also
checks the zero-read idle-work assertion. Native contracts were rebuilt using
the pinned repository container. Core/indexer and native-workspace Clippy and
formatting checks cover the changed source. No SDK ABI or guest storage adapter
changed.

### Costs and limits

The opt-in real-Wasm test `validator_transition_costs` measures populations
0, 4, 32, and 128. It includes registration, 11 idle join blocks, activation,
one reward distribution, exit requests, 11 idle exit blocks, and deactivation.
Run from `core`:

```sh
cargo test --release -p indexer --lib validator_transition_costs -- --ignored --nocapture
```

At 128 pending validators, a single idle call changes as follows:

| Metered host operation | Before | After |
| --- | ---: | ---: |
| GetKeys | 2 | 2 |
| KeysNext | 128 | 0 |
| Get | 128 | 0 |
| Exists | 128 | 0 |
| Host fuel | 78,560 | 1,440 |

The bounded database seeks still cost work; zero rows does not mean zero database
operations. The local instrumented idle calls took roughly 50–54 ms before and
0.7–0.8 ms after. These timings are illustrative single-run measurements, not
production throughput or a controlled CPU benchmark.

The complete measured lifecycle shows the write tradeoff clearly:

| Population | Point Gets before → after | Sets before → after | Deletes before → after | Local elapsed before → after |
| --- | ---: | ---: | ---: | ---: |
| 4 | 265 → 253 | 176 → 276 | 33 → 61 | 137 → 124 ms |
| 32 | 2,141 → 2,101 | 1,380 → 2,180 | 257 → 481 | 1,013 → 921 ms |
| 128 | 8,573 → 8,437 | 5,508 → 8,708 | 1,025 → 1,921 | 4,825 → 4,783 ms |

The benefit is concentrated in the recurring block hook. Registration and
transitions become more expensive; the total lifecycle timing is only modestly
better and almost unchanged at 128. At that population measured host fuel rises
from 79,593,730 to 112,414,510, including storage-deposit charges. Do not equate
that quantity with CPU time or describe this as a general fee reduction.
Reward distribution has identical host operation counts: indexed-field setters
already reconcile only indexes that mention the changed field, so stake-only
updates do not maintain either new height index.

Each account, including storage-only and inactive accounts, gains two index
membership leaves, plus shared bucket-count state and height-versioned writes.
The indexes use ordinary contract state and its existing block rollback; there
is no separate queue/table. Deployments need fresh replay under the preproduction
upgrade model. The compressed staking binary grows from 98,265 to 100,204 bytes.

Local raw logs: `/tmp/kontor-transitions-baseline.log` and
`/tmp/kontor-transitions-indexed.log`. They include operation counts per phase.

### Investigation: conditional membership versus combined updates

The subsequent [real-Wasm conditional-index measurements](conditional-index-measurements.md)
include predicate reads, complete lifecycles, retained state and three alternating
runs. They support conditional membership primarily for storage reduction, with
only a modest improvement to complete challenge-lifecycle latency.

Follow-up investigation on 2026-09-13 used the existing `apply_index_diff`
routine with a temporary instrumented storage backend. The probe models just the
two new height indexes through registration, activation, exit request, and exit.
It feeds real index descriptors to the shared maintenance routine; it does not
implement the missing declaration syntax or claim an end-to-end Wasm benchmark.

| Height-index strategy | Count reads | Count writes | Membership writes | Deletes | Live membership leaves after exit |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full indexes, successive setters (current candidate) | 16 | 16 | 9 | 7 | 2 |
| Full indexes, combined exit update | 14 | 14 | 8 | 6 | 2 |
| Conditional indexes, successive setters | 6 | 6 | 3 | 3 | 0 |
| Conditional indexes, set exit height before status | 4 | 4 | 2 | 2 | 0 |

The final row reduces these indexes' writes from 25 to 6 (76%) and deletes
from 7 to 2. These are index-maintenance counts for one lifecycle, not total
transaction reads, fuel, fees, or timing. Predicate evaluation and generated
field reads still need measurement. Shared zero-valued bucket-count rows and
height-versioned history still exist even when no membership leaves remain.

The isolated probe and all 48 existing stdlib unit tests passed (49 total).
The probe was removed from production sources after the investigation; its
reproducible patch and results are `/tmp/kontor-index-maintenance-probe.patch`,
`/tmp/kontor-index-maintenance-probe.log`, and
`/tmp/kontor-index-maintenance-stdlib.log`.

**Implemented: conditional declarations, without a general batch-update API.**
The [index API guide](indexed-map-index-system.md#conditional-membership) documents
`when = matches!(field, Pattern)` and its WIT form. Rust and WIT declarations share
one predicate parser; value entries, read-model entries and setter diffs share
membership generation and field dependencies. The existing index-diff routine
maintains leaves, projections and counts. No new host operation, WIT storage
interface, persistent queue or rollback system was added.

All nine candidates below are adopted. Validator key availability now uses
`.is_empty()` instead of scanning holders and reading their statuses. The new
runtime regression covers reservation through pending/active/exiting states,
cancellation, key reuse and restoration of both the reservation and user
collateral on block rollback. Generated-model tests cover predicate-only fields,
whole-record and field updates, sort/projection changes, failed updates, counts
and removal. Existing native lifecycle and rollback tests also run against the
conditional Wasm.

The [complete measurements](conditional-index-measurements.md) distinguish the
original full-index candidate, the experimental conditional implementation and
merged main. The final implementation adds a direct user-charge comparison:
128 storage-only accounts require 40.6% less collateral, pay 7.2% less for bond
creation and 6.2% less for top-ups at the configured test rates.

Two further optimizations remain deferred: changing setter order to avoid
intermediate membership writes, and lazy-loading shared sort/projection fields
when every relevant predicate is false. The current generated setters preserve
the existing dependency hoists; those reads are included in the measurements.
Neither is required for correctness or the measured savings. Native deployment
requires fresh disposable state; no in-place index migration is implemented.

### Native-contract adoption

Caller audit on 2026-09-13 covered all five native contracts, including filestorage
cleanup/reward modules, on the current scan branch based on `49a815fa`. It found
seven existing index declarations that could omit unused memberships, plus the
two new staking height indexes. These are candidates from current callers, not
implemented changes or newly measured performance gains.

| Contract/index | Membership needed by current callers | Purpose and likely saving |
| --- | --- | --- |
| Staking `activation` / `deactivation` (new candidate indexes) | PendingJoin / PendingExit respectively | Due transitions; omit both memberships for active/inactive accounts and avoid moving entries into unused buckets. |
| Staking covering `status` | PendingJoin, Active, PendingExit | Capacity reservations, consensus-set counts/reads, and ordering rewards. Inactive/storage-only bonds need no covering entry or updates to its copied stake/key. |
| Staking `ed25519_pubkey` | Status other than Inactive | Duplicate consensus-key checks already ignore inactive accounts after reading them. Omitting those memberships could remove the per-candidate account/status reads while preserving the existing self-key exclusion. |
| Filestorage covering challenge `status` | Active | Active-challenge listings and count for challenge generation. No current caller reads another status bucket; keep historical details in the primary challenge record instead of an unused covering projection. |
| Filestorage challenge `due`, `by_prover_status`, `by_membership_status` | Active, Expired, Failed, Invalid | Expiry, penalty settlement, withdrawal protection, exhausted-bond cleanup, and reservation release. Proven/Settled records need no memberships in these indexes. |
| Filestorage membership `by_node_active` | `active = true` | A node's live memberships for obligation checks and cleanup. Departed memberships remain in primary storage and the per-agreement index. |

Across the four challenge indexes, a Proven/Settled challenge could have zero
current membership leaves instead of four. The primary record, historical
versions, and shared bucket-count rows remain. This may be a useful longer-term
state saving as challenges accumulate, but needs actual storage/write benchmarks.

Do not apply an Active-only predicate to the three obligation indexes: Expired,
Failed, and Invalid challenges still carry unsettled penalties. Inactive node
memberships with outstanding challenges remain protected by these challenge
indexes and their primary reservation state.

The other four declarations should retain their complete membership with current
APIs: agreement `active(false)` contributes to `agreement_count`, membership
`by_agreement_active(..., false)` supplies departed nodes to `get_agreement_nodes`,
and both NFT indexes support arbitrary holder/creator listings and counts. Token
has a scalar balance map, and system has no indexed record collection; no direct
conditional-index adoption is justified in either.

Most of these changes simplify maintained state rather than contract algorithms.
The consensus-key duplicate check is a small exception: its explicit inactive
filter could be enforced by the index itself. Each adoption still needs lifecycle
and rollback tests, especially settlement/withdrawal coverage in filestorage.

## Simplifying the WIT storage adapters

WIT exposes concrete resource-method signatures, whereas the Rust implementation
can share generic operations. The five typed row methods select string, unsigned
integer, signed integer, boolean, or bytes, matching existing point getters.
Their shared host implementation owns cursor advancement and stored-value
framing. This boundary does not require five decoders or five database paths.
See the [WIT reference](https://component-model.bytecodealliance.org/design/wit.html).

A private `storage_methods!` macro now generates the identical forwarding body
for 31 proc/view storage and row methods. Each declaration retains its complete
argument/result types and target runtime method, checked against Wasmtime's
generated traits. Resource destruction and the unit-valued setter remain explicit
because their forwarding differs. The old repeated bodies are removed.

This is a host source-code cleanup: no WIT/SDK ABI change, added guest decoding,
new storage format, or expected performance improvement. A tagged scalar union
would move type selection and mismatch handling into runtime dispatch; it is not
needed to remove this boilerplate. Keep the typed boundary and shared host decoder.

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

The host-decoding follow-up also passed the complete release/regtest workspace
suite (781 passed, 0 failed, 3 opt-in skips), all 158 SDK tests, formatting and
Clippy in all three workspaces, and the pinned contract builds. Its 14 runtime
error-classification tests cover shared host deserialization, numeric/Holder
payload traps, checked narrowing, direct/proxy rollback, and infrastructure
failures. Native binary changes relative to the guest-decoding version were
-248 bytes (token), -484 (NFT), -154 (staking), -343 (filestorage), and +86 (system),
measured on the committed Brotli-compressed binaries. The typed interface adds
metadata, so removing guest deserialization does not shrink every contract.
