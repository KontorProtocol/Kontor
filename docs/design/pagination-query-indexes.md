# Optional pagination counts and measured query indexes

Baseline: main `3cad43ff` (#573). This changes API count availability and adds
SQLite indexes; it does not change contract execution, stored records, encodings,
checkpoint inputs, or pruning semantics.

## Pagination

The blocks, contracts, transactions (including per-block transactions), and results
list endpoints accept `count=true`. By default, and when explicitly
false, `pagination.total_count` is `null` and no count query runs. For example:

```text
GET /api/transactions?limit=20
GET /api/transactions?limit=20&count=true
```

`has_more`, cursor/offset continuation, filtering, and page ordering are unchanged.
The query still requests one extra row to determine `has_more`. Opting into counts
retains the old semantics: count distinct matching records after any cursor
predicate, but before offset/limit. With a cursor, this is the number of remaining
matches rather than a chain-wide total. Count and page remain separate SQL
statements; an opt-in count is not a promise of one snapshot under concurrent
writes.

This is an API change: clients needing an exact count must request it and handle
the nullable response. SDK bindings were regenerated with `kontor build sdk`;
the SDK poller uses `has_more`, so it needs no count. No count cache or second
pagination implementation is introduced.

## Why these indexes

Eight height indexes let block rollback locate dependent rows without scanning
each table's history: transactions, contract results, contracts, provenance,
signers, x-only keys, BLS keys, and nonce versions. Transaction/result height
filters benefit from the same indexes.

The other indexes serve reverse BLS-key lookup, contract/signer result filters,
publisher filtering, and foreign-key checks on `contract_state.tx_id` and
`contract_results.payer_signer_id`. Those last checks happen when deleting
transactions or signers even though the foreign keys do not themselves cascade;
height indexes alone do not remove that work. Nullable signer/transaction/payer
indexes omit null entries.

No index was added for provenance author: its synthetic probe improved, but no
current query or foreign-key check uses that predicate. There is also no new
historical activity index; a pruning node can return less historical information
than an archival node.

## Reproduction and interpretation

Run the opt-in benchmark from the repository root with no competing workloads:

```sh
cargo test --manifest-path core/Cargo.toml --locked --release -p indexer --lib benchmark_query_indexes -- --ignored --nocapture
KONTOR_BENCH_ROWS=300000 cargo test --manifest-path core/Cargo.toml --locked --release -p indexer --lib benchmark_query_indexes -- --ignored --nocapture
```

The harness uses the pinned libSQL and production schema/index definitions. It
removes the new indexes to reconstruct the baseline, populates related tables,
then measures each index individually. Finally it measures the full set with
actual query helpers and database rollback. It uses no `ANALYZE` or forced index
selection absent from production. Query plans accompany each lookup measurement.
The benchmark is ignored by normal CI; it has no timing assertions.

Fixtures contain 100,000 or 300,000 transaction, result, and state rows; ten
transactions per block; one contract per hundred transactions; signer/key and
nonce records; and provenance. State values are 64-byte BLOBs. Half the signers
are old accounts and the remainder are created in later blocks so rollback
exercises signer deletion too. This is synthetic SQL data, not contract execution.

Lookup medians use nine measured trials after three warmups, each with 16 queries.
Actual paginated-query medians use eight calls per trial. Rollback measures six
blocks, five trials after two warmups. A write batch creates one block, signer,
key pair, nonce, contract/provenance, and 50 transaction/result/state rows; its
median uses nine trials after three warmups. Writes/rollback run inside savepoints
and are restored outside the timed section. Consequently these are warm-cache
SQL costs excluding transaction commit/fsync, networking, and contract execution.
Index space is the change in in-use database pages, excluding WAL/SHM files.

## Measured results

Local Linux aarch64, Rust 1.98.0, libSQL 0.9.30, release build, 2026-09-16.
Each row below corresponds to an index retained in the schema. Lookup times are
microseconds, before → after adding that index alone. The exact predicates and
returned row counts are emitted by the harness alongside the query plans.

| Index | 100k lookup µs | 300k lookup µs | Added KiB at 100k |
| --- | ---: | ---: | ---: |
| `transactions(height)` | 2674.7 → 4.0 | 9633.2 → 4.0 | 1048 |
| `contract_results(height)` | 2079.3 → 3.9 | 6821.1 → 3.9 | 1048 |
| `contracts(height)` | 22.2 → 2.3 | 61.3 → 2.4 | 16 |
| `contract_provenance(height)` | 19.4 → 2.4 | 53.5 → 2.4 | 16 |
| `signers(height)` | 163.5 → 2.3 | 499.0 → 2.3 | 92 |
| `x_only_pubkeys(height)` | 162.2 → 2.4 | 481.6 → 2.4 | 92 |
| `bls_keys(height)` | 162.8 → 2.4 | 484.9 → 2.4 | 92 |
| `nonces(height)` | 939.8 → 3.5 | 2951.7 → 3.5 | 564 |
| `bls_keys(bls_pubkey, height DESC)` | 287.2 → 3.6 | 1125.6 → 3.6 | 1072 |
| `contract_results(contract_id)` | 1895.5 → 5.2 | 6528.2 → 5.2 | 1036 |
| `contract_results(signer_id)` | 2666.2 → 3.9 | 8706.5 → 4.0 | 1048 |
| `contracts(signer_id), nonnull` | 22.0 → 2.8 | 61.6 → 2.8 | 16 |
| `contract_state(tx_id), nonnull` | 1761.4 → 2.5 | 5422.6 → 2.5 | 1124 |
| `contract_results(payer_signer_id), nonnull` | 2672.9 → 2.3 | 8513.1 → 2.3 | 852 |

The unindexed probes scan tables or existing covering indexes. Every indexed
probe uses a range/equality search on its intended index. The payer probe is an
absence check, matching the foreign-key work when removing a signer with no
payer references. The other probes return matching rows. The height probes
represent the lookups that cascades perform; the full rollback below measures
actual deletion through the production `rollback_to_height` helper.

| Whole-set tradeoff | 100k fixture | 300k fixture |
| --- | ---: | ---: |
| Six-block rollback | 234.98 → 0.55 ms | 753.65 → 0.62 ms |
| 50-transaction write batch | 564 → 588 µs (+4.3%) | 614 → 692 µs (+12.6%) |
| In-use database size | 49.35 → 57.28 MiB (+16.1%) | 149.66 → 173.91 MiB (+16.2%) |

The database-only rollback grows with retained history before indexing and stays
near the cost of the six affected blocks afterward. The added write/storage cost
is explicit; these are not claimed improvements to contract execution throughput.

Actual paginated query helpers (20-row limit; µs, before → after all indexes):

| Query | 100k fixture | 300k fixture |
| --- | ---: | ---: |
| `transactions_page` | 14.2 → 14.2 | 14.5 → 14.3 |
| `transactions_counted` | 2521.2 → 1482.5 | 9115.6 → 4709.3 |
| `transactions_contract` | 55.4 → 55.5 | 56.2 → 56.0 |
| `transactions_signer` | 2738.2 → 18.2 | 8748.1 → 18.4 |
| `results_contract` | 1964.4 → 52.8 | 6589.3 → 53.4 |
| `results_signer` | 2726.7 → 31.3 | 8924.4 → 31.7 |

`transactions_page` omits the count; `transactions_counted` includes it. Other
rows use the contract or signer filter without counting. Thus opting out removes
the remaining full count: with the new indexes, approximately 1.48 ms → 14 µs at
100k and 4.71 ms → 14 µs at 300k. Contract-filtered transaction queries and ordinary
uncounted pages remain essentially unchanged, while signer/result queries benefit.
These measurements include query construction and row deserialization, but not
HTTP/JSON serialization or network latency.

## Count-query experiments

The branch also contains benchmark-only alternatives to the current count SQL.
They are not yet wired into `get_paginated`. The API flag has been shortened to
`count=true`; there is no alias for the earlier, unpublished name.

Run the additional benchmark with the production indexes installed:

```sh
cargo test --manifest-path core/Cargo.toml --locked --release -p indexer --lib benchmark_pagination_counts -- --ignored --nocapture
KONTOR_BENCH_ROWS=300000 cargo test --manifest-path core/Cargo.toml --locked --release -p indexer --lib benchmark_pagination_counts -- --ignored --nocapture
```

These use the same fixtures, platform, warmups, and median calculation as the
index benchmark. Each count statement is prepared, executed, and consumed; times
exclude fetching a page and HTTP serialization. Every candidate's actual count
is checked against the original before timing. No writes, counters, or caches are
introduced. The two fixture sizes were measured sequentially without other builds.

For single-table queries, replace `COUNT(DISTINCT primary_key)` with `COUNT(*)`:

| Count | 100k fixture µs, before → after | 300k fixture µs, before → after |
| --- | ---: | ---: |
| All transactions | 1471.39 → 11.22 | 4416.64 → 35.58 |
| Transactions before midpoint cursor | 1376.30 → 1127.06 | 4932.54 → 4190.38 |
| Transactions at one height (10 matches) | 3.07 → 2.76 | 3.09 → 2.79 |
| All blocks (10k / 30k blocks) | 155.17 → 8.07 | 462.49 → 22.32 |
| All contracts (1k / 3k contracts) | 17.00 → 1.86 | 46.45 → 1.99 |
| Contracts by publisher (1 match) | 2.77 → 2.54 | 2.80 → 2.57 |

For results, both joins target unique primary keys, so they cannot duplicate a
result row. Compare the old `COUNT(DISTINCT r.id)`, `COUNT(*)` with both joins, and
`COUNT(*)` without the transaction join. The contract join remains in all three:
`contract_results.contract_id` has no foreign key, and the inner join excludes
results without a matching contract. Dropping it would change count semantics.
The transaction join is a left join used only to populate response fields, so it
can be omitted from the count even when `tx_id` is null.

| Results count | 100k µs: distinct → rows → rows without transaction join | 300k µs: distinct → rows → rows without transaction join |
| --- | ---: | ---: |
| All | 7227.43 → 5822.16 → 2056.16 | 22631.08 → 18457.42 → 6158.22 |
| Before midpoint cursor | 3582.40 → 3027.88 → 1437.00 | 11471.48 → 9797.38 → 4919.62 |
| By contract (100 matches) | 13.72 → 11.73 → 6.51 | 13.56 → 11.70 → 6.56 |
| By signer (10 matches) | 8.92 → 8.22 → 5.80 | 8.94 → 8.39 → 5.82 |
| At height (10 matches) | 6.34 → 5.76 → 4.30 | 6.37 → 5.83 → 4.39 |
| By function (all match) | 8956.11 → 7502.18 → 3883.75 | 27637.97 → 23509.15 → 12687.07 |
| Contract + height + function + cursor (75 matches) | 15.08 → 13.32 → 10.52 | 14.82 → 13.28 → 10.52 |

Both changes are worth applying. In particular, the unfiltered single-table count
can use the database's page-level count operation: the bundled libSQL source's
`isSimpleCount` excludes DISTINCT and WHERE predicates, and `sqlite3BtreeCount`
visits B-tree pages and sums their entry counts. It is exact but not constant-time.
Filtered and cursor counts still inspect matching entries; the result contract
join also prevents the single-table shortcut. At 300k rows, a midpoint transaction
cursor still costs 4.19 ms, and counting all visible results still costs 6.16 ms.
Thus these improvements do not make every count as cheap as fetching a small page.
Transaction counts with contract/signer joins still need duplicate elimination;
these experiments do not propose replacing those with a plain joined `COUNT(*)`.

## Validation

136 API/database tests passed in release mode, including an authorizer that denies
SQL `COUNT`, explicit false/true/default HTTP requests on all four list endpoints,
existing count/cursor/filter cases, and an existing-database reopen test that
checks index plans, six-block rollback, retained checkpoints, and foreign keys.
The opt-in benchmark passed at both fixture sizes with the final schema.

The pinned SDK rebuild passed its 64 indexer-types tests and changed only the
pagination binding; all 158 SDK unit tests and both SDK builds passed.
Clippy for indexer/indexer-types library and tests with warnings denied, Rust
formatting, SDK formatting, and whitespace checks passed. The full workspace and
multi-node suites were not rerun for this follow-up.
