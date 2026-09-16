# Variant paths versus root tags

Status: test-only comparison on top of `a5c41726`, 2026-09-16. The contract
compiler and shipped binaries still use root tags. This experiment does not
introduce another supported contract encoding or change fuel prices.

## Question and recommendation

Can enums and Options keep their discriminants in their paths without searching
retained history? Yes, provided replacement clears the previous live subtree and
compound payloads keep a presence marker when their last descendant disappears.
The current-state index then answers variant selection with its first live child.

The measurements favor taking this path-based layout through the compiler and
compiled-contract regressions before finalizing the storage format. Scalar
variants save a row and mutation work; compound variants need the same number of
rows as root tags. Existing key-cursor reads were slightly faster in the host
benchmark, and both layouts stayed flat across retained history.

Use the existing metered key cursor first. The direct SQL-only prototype was only
modestly faster than the existing cursor at depth 1,000 (4.65 vs 4.99 microseconds
for enums; 4.66 vs 5.24 for Options). These results do not justify another WIT
operation by themselves. Fuel calibration remains separate: the existing cursor
schedule charges more than a point read despite these local execution timings.

## FoundationDB precedent

FoundationDB's [hierarchy example](https://apple.github.io/foundationdb/data-modeling.html#hierarchies)
represents structure through paths and uses special markers for empty objects and
arrays. Its [tuple format](https://github.com/apple/foundationdb/blob/main/design/tuple.md)
encodes types and nulls inline. These support path-based modeling but do not
prescribe Rust enum storage. The [Record Layer](https://foundationdb.github.io/fdb-record-layer/Overview.html)
uses serialized Protobuf records, a different granularity from Kontor's separate
field rows. The application chooses the layout; FoundationDB does not require a
separate row for each variant tag.

## Layouts compared

Both use equal-length six-byte encoded field prefixes, the existing interned enum
variant IDs, and the existing Option `none`/`some` string elements. Paths below
are illustrative names, not literal stored bytes. These are alternative states:

| Value | Root tag | Path tag |
| --- | --- | --- |
| Unit / None | `field = tag` | `field/variant = ()` |
| Scalar payload | `field = tag`, `field/variant = value` | `field/variant = value` |
| Compound payload | `field = tag`, `field/variant/... = fields` | `field/variant = ()`, `field/variant/... = fields` |

The compound marker must persist while the payload is populated, not just when
initially empty. Removing its last map entry must leave Some(empty), not None.
A scalar's value supplies that presence itself, so it does not need a marker.
Both writers use ordinary metered subtree deletion before replacement.

## Results

Median host lookup time in microseconds, for a 128-leaf compound payload:

| Payload versions | Enum root | Enum path | Option root | Option path |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 5.95 | 5.04 | 6.19 | 5.35 |
| 10 | 6.02 | 5.10 | 6.16 | 5.30 |
| 100 | 6.14 | 5.09 | 6.16 | 5.26 |
| 1,000 | 6.08 | 4.99 | 6.17 | 5.24 |
| Pruned and vacuumed | 6.02 | 5.09 | 6.00 | 5.07 |

Every case returned the same variant and charged the same fuel across history
and pruning. For these six-byte prefixes, root selection costs 120 host fuel;
path selection costs 380 for enums and 420 for Options. The difference comes
from existing cursor opening/polling prices and returned key lengths. These are
current tariffs, not calibrated estimates or end-to-end transaction costs.

Live row counts and logical bytes (key bytes plus encoded value bytes):

| Payload | Root rows | Path rows | Enum bytes root/path | Option bytes root/path |
| --- | ---: | ---: | ---: | ---: |
| Unit / None | 1 | 1 | 7 / 8 | 7 / 12 |
| Scalar | 2 | 1 | 16 / 9 | 20 / 13 |
| Empty compound | 1 | 1 | 7 / 8 | 7 / 12 |
| Four leaves | 5 | 5 | 58 / 59 | 74 / 79 |
| 128 leaves | 129 | 129 | 1,670 / 1,671 | 2,182 / 2,187 |

For scalar enum replacement, the path layout measured 91 microseconds versus
165 for root tags, and 1,040 versus 1,680 host fuel. With 128 leaves, replacement
was essentially unchanged: 9.70 versus 9.64 milliseconds. The row saving helps
small values most. Logical bytes exclude SQLite indexes, page overhead, historical
versions, and storage-deposit attribution; they are not database file sizes.

## Method and limits

The harness calls production storage host implementations through a Wasmtime
store, including real SQL, fuel accounting, resource-table access, and subtree
deletion. Path reads open the existing key cursor, take one child, and drop it.
Root reads use the existing scalar API. No new host import or variant lookup
function is installed. The separate SQL-only prototype selects a bounded tag
slice and checks that the result is a complete variant-root key; its timings do
not include host metering or a proposed new fuel schedule.

Read medians use nine measured batches of twenty calls after two warm-up batches.
Replacement medians use nine measured calls after two warm-ups, with savepoint
rollback outside the timed interval. History seeds 256 payload leaves across the
two layouts at each block, reaching 256,000 payload versions. Tests run serially.
The raw results include some slower early Option samples; absolute timings are
machine/workload dependent and should not be treated as production latency.

The harness bypasses guest Wasm instructions and component ABI crossings. It
compares variant selection, not complete record materialization. Writers choose
the known payload shape explicitly; production codegen still needs to ensure
scalar payloads supply their own root value while compound payloads receive a
persistent marker. Nested enums/Options, numeric scalars, index maintenance, and
full guest fuel should be checked when implementing that representation.

The functional regression covers missing variants, deletion of every descendant,
same-block replacement and abort, cross-block replacement, scalar retrieval,
reorg, and pruning. A SQL authorizer denies history reads during path selection.
The timing harness checks unchanged variant results and fuel through 1,000
versions and pruning. Both tests and Clippy with warnings denied passed.

## Reproduction

```sh
cargo test --manifest-path core/Cargo.toml --locked --release -p indexer \
  --lib variant_layout -- --include-ignored --nocapture --test-threads=1
```

[Raw results](variant-layout-results.jsonl) contain the `VARIANT_LAYOUT`,
`VARIANT_HISTORY`, and `VARIANT_PRUNED` records from the final run. Keep this
comparison as an experiment, not a second production encoding; retire the
superseded implementation and redundant timing code when the layout is settled.
