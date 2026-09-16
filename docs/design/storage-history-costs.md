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

## Distinct-path seek experiment

The follow-up prototype is in `history_benchmarks/seek_prototype.rs`. It is
test-only and compares the current production key scan with three alternatives:

- **PreparedSeek:** one prepared query per distinct path, selecting its latest
  version before checking deletion. All older versions are skipped by an index
  seek, in either direction.
- **RecursiveSeek:** the same seeks inside a recursive SQL query, stopping at the
  first live path. There is at most one output per query, so this does not rely on
  recursive traversal order or materialize a page ahead of demand.
- **StreamingSeek:** stream paths joined to their latest-version metadata. When
  a second version of a path appears, restart the prepared range query strictly
  past that path. Single-version paths keep streaming; a path with history yields
  at most two candidate rows before the cursor seeks past its remaining versions.

All use existing indexes, without a schema change, cache, or maintained counter.
These are flat scalar-key experiments, not general storage cursor replacements:
they fix the contract ID and subtree-only bounds for the fixture, omit the host
fuel layer, and do not implement nested child-key deduplication or value reads.

```sh
cargo test --manifest-path core/Cargo.toml --locked --release -p indexer --lib benchmark_storage_seeks -- --ignored --nocapture
# Optional: choose key counts and versions independently.
KONTOR_SEEK_CASES=100:1,100:1000,1000:100 cargo test --manifest-path core/Cargo.toml --locked --release -p indexer --lib benchmark_storage_seeks -- --ignored --nocapture
```

The default matrix covers eight `(keys, versions)` cases, both directions, live,
deleted, and 90%-deleted subtrees, before and after pruning through the tip.
Each strategy returns at most 20 keys, checked against an independent ordered
oracle. It records 384 `SEEK_BENCH` observations per run. Timings include preparing
the query and collecting keys; the median uses five batches of two calls after
one warmup batch. The baseline calls the production database key-scan function,
so these timings should be compared within this experiment rather than against
the host-call timings above.

### Results

Two complete runs passed. The table below is from the second, pinned to M2
performance core 4 with `taskset -c 4` to reduce scheduling variation. No build
ran concurrently. All numbers are median microseconds for ascending scans.

With 100 distinct keys, streaming plus seeking largely removes history depth
from the cost once the query encounters multiple versions:

| Versions per key | Current: 20 live keys | StreamingSeek: 20 live keys | Current: all deleted | StreamingSeek: all deleted |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 18.4 | 17.6 | 13.2 | 48.2 |
| 10 | 83.7 | 54.0 | 356 | 241 |
| 100 | 914 | 58.3 | 4,695 | 265 |
| 1,000 | 20,017 | 62.2 | 106,996 | 285 |

At ten versions per key, increasing the subtree from 100 to 10,000 distinct keys
changes a live 20-key page from 54.0 to 60.4 microseconds, while exhausting a
deleted subtree grows from 241 to 26,353 microseconds. This is the desired shape:
roughly flat for a fixed live page, roughly linear in distinct paths when the
scan must examine them all. B-tree seeks still have logarithmic cost; these are
not strictly constant-time operations.

The alternatives also eliminate history traversal, but have different overhead:
at 1,000 versions, PreparedSeek takes 53.9 microseconds for the live page and 229
for the deleted subtree; RecursiveSeek takes 101 and 147 respectively. For the
one-version live page they take 44.2 and 90.7, versus 18.4 currently. StreamingSeek
preserves that common streaming case best and avoids recursive SQL complexity.

There is a material downside: newly deleted paths with no older retained version
are cheaper for the current query to discard entirely inside SQL. At 10,000
such paths, the current scan takes 530 microseconds and StreamingSeek takes
4,813 microseconds. Full pruning removes those tombstones, but it is legitimate
to encounter them before finality, including after same-height create/delete.
This tradeoff must not be hidden by reporting only the long-history speedup.

### Decision and remaining work

Streaming plus a seek on the first duplicate is the leading integration
candidate: ordinary live scans retain streaming performance and history-heavy
scans improve by hundreds of times. The recent-tombstone regression remains a
tradeoff to assess before adopting it. The experiment establishes that we can
remove the versions-per-path multiplier using existing indexes; it does not
establish a constant bound on scanning arbitrarily many deleted distinct paths.

A production change should provide one shared latest-path cursor for existence,
keys, scalar rows, and deletion discovery, with the existing child-subtree seeks
layered above it. Preserve metadata-before-value budget checks, lazy polling,
and the current snapshot lifetime while fetching a selected row's value. Verify
inclusive/exclusive bounds, empty bounds, escaped keys, both directions, nested
records, writes during iteration, same-height updates, rollback, and archive /
pruned output and fuel parity. Those guarantees are not established by the flat
prototype. Variant resolution remains separate because it chooses the globally
newest row rather than the newest row for each path.

No production query or fuel behavior has changed. Both benchmarks remain ignored
in normal CI. The shared fixture was also rechecked through the original host
benchmark at depths 1 and 1,000 (150 observations, including fuel and checkpoint
parity); its recheck timings were not used for the comparison. Indexer library /
test Clippy with warnings denied and workspace formatting checks passed.
