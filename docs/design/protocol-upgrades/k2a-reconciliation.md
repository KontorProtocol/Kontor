# K2a storage reconciliation

Status: preparation only. No P1 baseline freeze, phase acceptance, or merge.

Base: `af04da0d992450905c54f8d8b903ea240820e8bb`, freshly fetched from
origin/main on 29 October 2026. Reconciled source:
`524782c396aaeaa1d580c2e0955d3be19f04ca58`.

The previous unfinished K2a branch predates synchronous guest WIT and contains
rejected direct-await ownership work. This checkpoint ports its reviewed storage
separation onto current main without importing that implementation.

## Source mapping

Each original commit below maps to the combined reconciliation commit above.
The 30 new non-module adapter, semantic, and test files are byte-identical to the
previous reviewed source. Module registration and integration edits are described
below. The local source comparison is `.build-cache/k2a-reconcile/source-audit.json`.

| Original commit | Retained extraction |
| --- | --- |
| `c3ebc10a` | Row interpretation and live cursor ownership |
| `50ccf4b2` | Point reads and key scans |
| `5453999d` | Ordered state writes and deposit accounting |
| `43827e56` | Savepoint bookkeeping and node SQL session callbacks |
| `0321b315` | Contract records, provenance, and result writes |
| `e3459c04` | Identities, BLS records, and nonce validation |

Integration keeps main's synchronous `Access` bindings, host fuel calls, canonical
resource error classifier, spawned guest call, pool behavior, component policy,
and engine configuration. The new protocol modules register storage only.
The existing native binaries and build provenance are unchanged. Decompression
retains main's `spawn_blocking` path; the optional blocking-work host abstraction
from `ee75e228` is not part of this checkpoint.

Point/row/key failures retain the `ValueTooLarge` fuel trap and `NonScalarRow`
deterministic error distinction. SQL/driver failures remain infrastructure errors.
Savepoint ordering, allocation before missing-context panic, checkpoint write order,
and cursor lifetime are preserved rather than repaired implicitly during extraction.

Node-local confirmation coordinates and receipt-stream state remain outside the
retained storage modules. The existing node rollback query, including its generation
journal write, remains inside the same rollback transaction. No metadata schema,
trigger, index, API, or stream behavior is removed by this port.

## Review and validation

Parent source review and independent subagent review found no material source
regression in the selective port. The subagent verified the base/head, byte-identical
new files, caller coverage, synchronous host signatures, error classification,
ordered storage behavior, and untouched runtime/metadata paths. Interlink exact
source review independently approved preparation in receipt
`58f46e16205a15fc3bcc1147474104bb`, under `kontor-k2a-reconcile-524782c3`.
This receipt was read and acknowledged. It is not a phase acceptance.

`rustfmt` and `git diff --check` pass. On documentation head `47cf689a`, with
source unchanged from `524782c3`, the following locked/offline checks passed:

- 28 versioned storage differential tests, 6.77 seconds after compilation.
- 45 integration regressions covering synchronous guest calls, capability rejection,
  canonical resource errors, aggregate infrastructure failures, BLS, and deep
  separate-process chains, 135.11 seconds. The one ignored child helper is invoked
  explicitly by the passing parent test.
- Indexer Clippy with tests and warnings denied, 27.60 seconds.

Exact commands, environment, terminal exit codes and log hashes are recorded in
`.build-cache/k2a-reconcile/validation.json`. These checks validate this preparation
slice; the complete final K2a library/CI and acceptance gates remain pending after
S2 and OWNERSHIP-1 integration. The prior branch's tests are not used as evidence
for this candidate. Parent released the Cargo slot back to the native agent after
all three commands terminated.

## Remaining phase work

This checkpoint is not a versioned executor API or independent dependency graph.
It must be reconciled again with the reviewed S2 and OWNERSHIP-1 results before
freezing P1. Include S2's typed depth limit, InvocationStore ordering and corrected
table lifetime. Preserve the accepted owned guest mechanism and portable metering.
Archive only the final qualified synchronous native artifacts with explicit identity.
Finish recognition, execution, lifecycle, views/committee derivation, simulation,
and coordinator-rules-v1 boundaries, then perform K2a acceptance and K2b extraction.

External Explorer/Indexer work is excluded from the goal and is not a dependency.
SDK publication remains deferred until completion and review of all in-scope work.

## Transaction semantics preparation

Source `6e0e4f175f5acf50d44635970fc10cd6f17ca291` follows storage checkpoint
`5d9e634d22f3365a1e5db557d782e2546544e8c7`. It moves actual recognition,
materialization, Sponsor state, and batch eligibility into
`protocol/v1/transactions.rs`. The existing `block` and `reactor::executor`
paths re-export these items. SQL-backed inspection and result lookup stay in
`block.rs`, with no second parser or materializer.

| Old location | Versioned location |
| --- | --- |
| `block::TransactionFilterMap`, `block::OpMetadataBase` | `transactions::TransactionFilterMap`, `transactions::OpMetadataBase` |
| `block::materialize_op`, `block::core_payment` | `transactions::materialize_op`, `transactions::core_payment` |
| `block::TxWalker::{new,payment_override,capture,next_input,materialize}` | `transactions::TxWalker`, same methods |
| `block::filter_map` | `transactions::filter_map` |
| `reactor::executor::is_batchable` | `transactions::is_batchable` |

The complete relocated source sections are byte-identical after replacing three
qualified types with imports (`bitcoin::Transaction`, `bitcoin::OutPoint`, and
`indexer_types::Input`) and removing the final blank line after `is_batchable`.
Function bodies, error strings, and parser acceptance rules are unchanged. This
includes raw transaction and input indices, OP_RETURN bytes, aggregate batch
eligibility, direct Publish exclusion, and Sponsor precedence and expiry.
Existing block tests, node inspection, and the rest of the reactor executor are
byte-identical. Existing identity test bodies are unchanged.

The separate dependency cleanup moves the documented `CORE_SIGNER_ID = 1`
constant from `database::types` to `v1::storage_identity`. Its original path
re-exports the same item. The identical function-local constant in
`create_core_signer` is removed. A new test checks the reserved value and alias.
The transaction module has no dependency on database, reactor, or API modules.
It still uses the shared Bitcoin, indexer-types, and anyhow dependencies; this
preparation does not establish independent dependency graphs.

The local reproducible comparison is
`.build-cache/k2a-reconcile/transaction-source-audit.py`; its report is
`transaction-source-audit.json`, SHA-256
`56a2d5dbef83f6a70666374f2756c92a8cff71cadafeef659d51b33cfacff791`.
Formatting and whitespace checks passed. Parent source review found no material
regression. Interlink source review approved the exact revision in acknowledged
receipt `4e41e085a2e41fb8a4ca22e67a404f6c`, independently comparing the moved
source. Independent subagent review also found no material findings, checking
the complete Git-object source sections, both batch-selection callers, aggregate
shape rejection, parser indices, Sponsor transitions, and facade type identity.
Runtime tests remain pending. The native-stack agent retains the shared Cargo
slot until an explicit handoff. Neither review checked remote freshness; both
reviewed the explicit local base and head above.

This is preparation, not protocol selection. Ingestion still uses the current
parser through its existing facade. K2a/K2b must pass raw inputs through the
selected protocol boundary without prematurely discarding inputs recognized by
a newer protocol. Dispatch, a stable cross-graph codec, and a complete retained
semantic dependency closure remain required. No activation or P1 freeze is
claimed by this relocation.
