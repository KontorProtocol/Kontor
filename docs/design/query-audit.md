# Database query audit — 2026-09-15

Scope: production queries in `core/indexer/src/database/queries/`, their schema
and indexes, and relevant storage, reactor, rollback, and HTTP callers. SQL outside
that directory was searched for additional production paths. This is a source and
focused-test audit, not a production database workload benchmark.

Starting branch: `fix/storage-value-budget`, HEAD
`88fcaeec965c5a6f295d2fdc6cab9204dda0134f`; merge base with local main:
`6a79ceb9022b6e8a6927047d25e96ccaebf2031d`. The audit includes the uncommitted shared
storage reader changes. Remote main was verified unchanged while preparing the PR.

## Adjustments

- **Retained transaction bodies:** `select_unconfirmed_batch_tx` previously selected
  by transaction ID alone despite the table's `(txid, batch_height)` key. A Bitcoin
  transaction ID does not commit to its witness. The reactor now passes the exact
  decision height through replay, deferred draining, and finalization, preventing
  selection of another batch's witness. Raw entries and pool/RPC fallback behavior
  are unchanged. A regression uses two real same-txid/different-witness transactions
  and checks both heights, a missing height, and lookup after older-body pruning.
- **Variant lookup:** `matching_path` now selects only path and deletion metadata
  with `ORDER BY height DESC, rowid DESC LIMIT 1`. It preserves global newest-row
  semantics, including same-height insertion order and tombstones. The previous
  window's `SELECT *` requested the value column unnecessarily. An authorizer test
  denies value-column access; it failed before the change and now passes.
- **Latest full-row lookup:** replaced the remaining window query with an indexed
  point lookup. Deletion is checked after selecting the latest version, so old
  values cannot reappear behind tombstones. Removed the unused `LatestMany` builder
  and its SQL-format tests.
- **Finality retention floor:** replaced `anchor_height + window >= tip` with an
  index range on `anchor_height >= tip.saturating_sub(window)`, using the existing
  anchor index explicitly. This avoids scanning finalized history on every cleanup.
  Coverage includes the inclusive deadline, tips smaller than the window, empty
  and block-only records, record-only batches, and differing anchor/consensus order.
  An actual libSQL query-plan test verifies an indexed range search.
- **Existence:** `contract_has_state` stops at the first row rather than counting
  the contract's history. It still means any stored history, including tombstones;
  live-subtree existence remains a different operation.
- **Pagination:** normalize away offset when cursor is supplied, so the internal
  helper's documented cursor precedence also produces a continuation cursor.
  The regression failed before the fix. HTTP validation already rejects this
  combination, so this was an internal-helper inconsistency.

These changes add no schema, index, or encoding migration. Point values and row
scans continue to share the budget-checked prepared SQL reader described in
[Storage value budgets](storage-value-budgets.md).

## Follow-ups

Pagination counts and targeted indexes are implemented in the follow-up described
in [Optional pagination counts and measured query indexes](pagination-query-indexes.md).
The observations below record the starting behavior for that work; internal SQLite
work accounting remains open.

1. **Page limits do not bound exact-count work.** `get_paginated` runs
   `COUNT(DISTINCT ...)` over all matching rows before returning a limited page.
   Cursor predicates reduce the count to the remaining matches, but large histories
   still cost proportional work. Count and page also use separate statements rather
   than one read snapshot. Consider optional counts or a cursor-only API; preserve
   the current response contract until that decision is made.
2. **Measure targeted indexes on growing tables.** Transaction height queries and
   block-deletion cascades lack a full `transactions(height)` index. Other tables,
   including contract results and signer key histories, have block foreign keys
   without height-leading indexes. Reverse BLS-key lookup lacks a public-key-leading
   index. These merit query-plan and rollback benchmarks before adding persistent
   indexes with write/storage costs. Existing composite indexes are useful only
   when their leading columns match the lookup.
3. **Logical-row metering does not bound all SQL work.** Storage cursors stop
   yielding when fuel runs out and check value budgets before fetching BLOBs, but
   SQLite can inspect superseded rows/tombstones while finding the next live row.
   Variant lookup can inspect and sort a subtree's metadata to find its newest row.
   These remain physical-work questions for indexing or metering; the byte-budget
   fix does not promise a bound on SQLite VM steps or page reads.

Historical transaction filtering remains unchanged. Its contract filter joins
`contract_state.tx_id`, so pruning old state versions can reduce the transactions
listed for that contract. This is an accepted difference between pruning and
archival nodes, not a requirement to introduce a durable activity index. No promise
of complete historical results on a pruning node is added here.

Other growth-sensitive paths reviewed include startup/reorg late-confirmation
probes and exclusions, the legacy batch-txid fallback, full provenance history,
and depositor footprint listings. They are candidates for workload measurements
or pagination, rather than reasons to delete rollback state or change semantics
in this patch.

## Coverage and limits

Checked latest-version and tombstone ordering, contract isolation, exact byte
budgets, same-height replacement, snapshot pinning, rollback cascades, deposit
liveness, execution-usage lifetime, batch-body retention, and cursor continuation.
The new retained-body regression exercises database resolution with real witness
variants; it is not a multi-node consensus reproduction. The internal SQLite work-accounting follow-up remains open.

Validation: all six focused checks passed. The broader release run passed 177
library tests across database queries, runtime storage/host storage, host metering,
batch logic, and consensus state (one pre-existing ignored test). The full library
suite and multi-node cluster suite were not rerun for this audit.
Clippy for indexer library/tests with warnings denied, workspace formatting, and
whitespace checks also passed.
