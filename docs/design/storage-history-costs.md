# Storage queries over retained history

Baseline: main `83db3333` (#574). This investigation measures the current storage
host calls before proposing changes to their SQL or fuel schedule.

## Reproduction

```sh
cargo test --manifest-path core/Cargo.toml --locked --release -p indexer --lib benchmark_storage_history -- --ignored --nocapture
KONTOR_HISTORY_DEPTHS=1000 cargo test --manifest-path core/Cargo.toml --locked --release -p indexer --lib benchmark_storage_history -- --ignored --nocapture
```

The benchmark lives in
`core/indexer/src/runtime/fuel/host_metering_tests/history_benchmarks.rs` and is
ignored in ordinary CI. `HISTORY_BENCH` emits JSON timing/fuel observations;
`HISTORY_PLAN` emits query plans for the current live-scan and variant SQL shapes.

## Workload and interpretation

Each fresh runtime contains four synthetic 100-key subtrees:

- Live scalar entries, all still present.
- Deleted scalar entries, all tombstoned at the tip.
- Sparse scalar entries, the first 90 keys tombstoned at the tip.
- One active enum/option variant with 100 payload fields.

The default run writes 1, 10, 100, and 1,000 versions per path in separate
fixtures: up to 400,000 workload rows, plus genesis state. Stored values are valid
Postcard byte vectors with fixed length and a height stamp, so the checks detect
an incorrect surviving version. Paths use the real ordered key codec. Fixture
construction inserts version rows directly, with the production schema and
checkpoint trigger; it does not execute 400,000 guest contract writes.

Each fixture is measured in three states, in order: archival, pruning through
`tip - 8`, and pruning through the tip. Eight is a benchmark retention choice,
not a proposed protocol setting. The middle case keeps the most recent eight
heights plus the latest version at/below the watermark. The last case collapses
finalized history and removes finalized tombstones completely.

Measurements call the real storage host methods through a Wasmtime store:
point reads, existence, forward/reverse key and scalar-entry scans (up to 20
entries), and variant resolution. An absent prefix is also tested. Each batch
contains four calls; the median uses seven batches after two warmup batches.
Times include host dispatch, resetting the fuel budget, collecting/comparing
results, and benchmark JSON value construction. They exclude runtime/genesis
initialization, fixture insertion, pruning, networking, and guest execution.
They are warm local measurements, not block-throughput or fuel-price calibration.

Checks independently construct the expected values and ordered keys, then
require identical outputs and raw fuel consumption before/after pruning.
Checkpoint hashes must also remain unchanged by pruning. Timings never decide
whether a test passes.

## Measurements

Measured on 2026-09-16, Linux aarch64 on Apple M2, release build, temporary
on-disk databases. No concurrent build or other benchmark was launched during
measurement. These are individual host-operation timings, not per-block costs.

Median microseconds per operation at 1,000 versions per path:

| Operation | Archive | Retain eight heights | Prune through tip | Raw fuel |
| --- | ---: | ---: | ---: | ---: |
| Read one live value | 6.81 | 6.65 | 6.56 | 530 |
| Check existence in entirely deleted subtree | 107,507 | 323 | 8.01 | 190 |
| Return first 20 live keys | 19,630 | 80.4 | 22.1 | 2,730 |
| Exhaust entirely deleted key subtree | 106,862 | 323 | 9.11 | 440 |
| Return ten remaining keys, past 90 deleted keys | 106,356 | 335 | 15.9 | 1,660 |
| Return first 20 live scalar entries | 19,594 | 98.6 | 39.2 | 9,330 |
| Resolve variant with 100 payload fields | 6,279 | 65.6 | 21.5 | 810 |

Scans shown above are ascending. Descending scans also exhibit history growth;
reversing the sparse scan does not avoid it when the caller exhausts the subtree.
The physical row counts for the three states are 400,004, 3,604, and 214,
including four unrelated genesis rows for the same contract.

The archival existence check over deleted keys grows from 12.4 microseconds at
one version, to 353 at ten, 4,648 at 100, and 107,507 at 1,000. The live point
read stays between 6.59 and 6.81 microseconds across those same depths. This
separates history-sensitive discovery from the already efficient exact-path
lookup. An absent prefix is cheap because there are no matching historical rows.

An independent repeat of the 1,000-version fixture passed all 75 observations:
the archival deleted-prefix existence check took 104.5 ms, the live-key page
19.3 ms, variant resolution 6.31 ms, and the live point read 6.81 microseconds.
The large differences are repeatable; the small timing differences are not a
claim about statistical significance.

## Explanation and next experiment

The live-scan query uses `idx_contract_state_lookup` for the outer path range
and an indexed correlated `NOT EXISTS` probe for newer versions. It nevertheless
visits old versions before rejecting them. A result limit bounds returned rows,
not the historical rows examined to find them. The existing subtree seek after
duplicate child keys helps with live descendants; it cannot skip history that
SQL filters before returning a row. Existence checks share this query shape.

Variant lookup instead orders the entire matching range by descending height
and rowid. Its diagnostic plan uses the path index plus a temporary ordering
B-tree. It must find the globally newest write, including tombstones, to avoid
resurrecting an older variant. Replacing it with the first live path would change
semantics. The diagnostic plans reproduce the production SQL shapes; timings
come from the actual host calls.

Next, benchmark distinct-path seeks followed by latest-version lookup against
the current live-scan implementation, using the existing indexes. The prototype
must preserve bounds, direction, deletion, fuel exhaustion, rollback, and pruning
behavior. Include short histories and large distinct-key sets to expose extra
seek overhead. Skipping versions alone still leaves work proportional to the
number of distinct deleted paths; it is not a complete bound on empty scans.
Treat newest-variant lookup as a separate query optimization with its own
same-height/tombstone tests.

Do not calibrate a fixed scan price from the pruned timings or charge SQLite
steps: local retained history changes the physical work, while consensus fuel
must stay identical. Optimize the history-dependent work first, then revisit the
remaining bounds and fuel pricing under #462. These measurements justify that
prototype, not a new persistent index/table or a production query rewrite yet.

## Validation and limits

The full four-depth run passed all 300 observations, including independently
expected values/order, fuel parity after pruning, and checkpoint preservation.
This fixture covers overwrites and final deletions; it does not establish
performance for cold caches, concurrent nodes, wide/deep record trees, changing
enum variants, or large values. It does not execute rollback itself; existing
pruning/rollback regressions remain relevant to any future query change.

Validation also passed the 20 existing host-metering tests, five pruning tests
(including rollback within the retained window), indexer library/test Clippy
with warnings denied, and workspace formatting checks. The new timing test is
ignored by default and adds no benchmark runtime to normal CI. Production SQL,
schema, and fuel prices are unchanged.
