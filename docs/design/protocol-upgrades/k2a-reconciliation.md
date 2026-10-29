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
On documentation head `3429514f`, all 91 targeted parser, Sponsor, BLS, identity,
batch, aggregate-failure, and confirmation/reorg tests passed (30.72 seconds
after a 67-second build). Indexer Clippy with tests and warnings denied passed
(17.37 seconds). Both commands terminated successfully. Commands and log hashes
are in `.build-cache/k2a-reconcile/transaction-validation.json`, SHA-256
`dd0a6a0fe8da6cb2f614519a761ed3f0166b7da71ca4a243b1eaecab75c73349`. Neither review checked remote freshness; both
reviewed the explicit local base and head above.

This is preparation, not protocol selection. Ingestion still uses the current
parser through its existing facade. K2a/K2b must pass raw inputs through the
selected protocol boundary without prematurely discarding inputs recognized by
a newer protocol. Dispatch, a stable cross-graph codec, and a complete retained
semantic dependency closure remain required. No activation or P1 freeze is
claimed by this relocation.


## Publication characterization baseline

Test-only commit `88360cd9` ports both `runtime/call/tests/p1_publication.rs`
and `p1_transaction_publication.rs` from
`92e7b0b3adccdb2924206bb57d6d8fa466a39a8a`, byte-identical, plus their two module
registrations. No assertions or imports changed. The local hash mapping is
`.build-cache/k2a-reconcile/publication-source-mapping.json`.
These tests characterize existing duplicate-publication effects, receipts,
payments, stored bytes, and raw transaction positions through the actual parser
and transaction executor. They are retained behavior tests, not a correction of
that historical behavior. Both passed on `88360cd9` before the execution move
(10.47 seconds after a 34.31-second build). Evidence is
`.build-cache/k2a-reconcile/publication-before.json`. The same unchanged tests
must pass after the move.


## Operation execution entry preparation

Source `484d3421` moves the real per-transaction operation loop from
`RuntimeExecutor::execute_transaction_inner` into `v1::execution::execute_transaction`.
The trait implementation performs one tail-await delegate. The same module now
owns `process_input`, `process_direct_input`, `process_aggregate_input`, and
`execute_op`. The old public `reactor::executor::process_input` path re-exports
its versioned implementation.

The semantic bodies are unchanged after imported type substitutions, method
indentation, and rustfmt signature wrapping. Removing the unused `&self` receiver
and adding the node delegate are the only new call wiring. The mechanical audit
is `.build-cache/k2a-reconcile/execution-source-audit.py` and its JSON report.
It compares the entire moved source, exact quoted strings, and remaining node
bodies. Parent and independent subagent source reviews found no material
findings. Interlink independently approved the source in acknowledged receipt
`08525ca791f7dabb085204dcb783dd9a`, checking its own normalized source diff and
the publication test port. Post-move debug validation is recorded below;
release CI and final phase acceptance remain pending.

The loop preserves input order, `tx.index` and `tx.txid`, OP_RETURN payloads,
height selection before identity allocation, aggregate verification before
execution, per-op nonce advancement, error-vector positions and classifications,
and Sponsor state transitions. The node retains the `Executor` trait's usage
wrapper, including start/finish accounting and SQL recording, Bitcoin RPC,
mempool policy, replay signaling, and `NoopExecutor`.

Temporary dependencies, each a K2b boundary item:

| Current dependency | Required final boundary work |
| --- | --- |
| `Runtime` and `TransactionContext` | Retain execution implementation and context inside the independently locked graph. |
| `Signer` and `database::types::Identity` | Retain identity semantics; replace node-owned types at the shared interface. |
| `bls::verify_aggregate` and `AggregateVerificationError` | Retain verification and classification with the protocol dependency graph. |
| `ExecutionError` | Preserve classification internally and encode the common result envelope explicitly. |
| `runtime::system` | Retain native identity and dispatch mappings with the protocol. |
| `OpKind` and other `indexer_types` | Retain protocol schemas internally; define the explicit cross-graph codec. |
| `bitcoin` and `anyhow` | Keep dependency types inside the graph, outside the standard-library-only linked interface. |

These dependencies are deliberate intermediate links, not independent graph
isolation. OWNERSHIP-1 must wrap these entry points with the agreed
`CanonicalRootLease` and `RootKeeper` ownership before final baseline acceptance.
The signatures are not frozen. This slice adds no activation or alternate executor
selection and does not change existing cancellation behavior.

## Execution validation and test readiness correction

All 120 targeted tests passed at `09512a6a` with two concurrent test cases
(600.33 seconds), and indexer Clippy with tests and warnings denied passed
(7.04 seconds). This is debug diagnostic evidence for the preparatory extraction,
not a replacement for CI. Actual CI runs `REGTEST=1 cargo test --release
--workspace -- --nocapture` with default test concurrency. That configuration,
the full K2a acceptance suite, and reconciliation with S2 and OWNERSHIP-1 remain
required before a phase PR or P1 freeze.

Two default-concurrency debug runs each passed 119 tests and failed one cluster
test. Their original logs are preserved. The first exhausted the startup recovery
deadline while follower initialization still waited at the existing round-zero
barrier. The same binary passed that test alone in 28.58 seconds. Separate
test-only commit `09512a6a` signals readiness from that barrier, bounds the readiness
wait at 120 seconds, then starts the unchanged 40-second recovery check. Fault
injection, recovery assertions and production timeouts are unchanged. Both error
paths reach cluster shutdown. The setup wait starts after seed initialization in
`start_with_faults`, and existing assertion panics retain their prior cleanup.
All three source reviews approved this correction. Its focused test passed in
28.75 seconds and it passed both subsequent broad runs. An initial sandboxed
invocation could not open its localhost listener; that terminated attempt is
recorded separately and is not test acceptance evidence.

The second default-concurrency debug failure expected replayed batch 3 with two
transactions. The trace contains that exact replay, but a preceding replayed
block took 50,255 milliseconds versus 92 milliseconds on its first execution.
Batch completion was logged immediately before the deadline assertion. The
same binary passed the isolated test in 35.27 seconds. The waiter already polls
the event channel until a fixed deadline; no assertion or timeout was changed.
These observations support contention and a missed observation deadline, but
the logs do not establish the exact scheduling cause or successful event enqueue.
The unchanged LiteExecutor and this cluster test do not execute the relocated
transaction entry. Independent source comparison confirms their preservation.

Commands, terminal results, log hashes and both preserved failures are recorded
in `.build-cache/k2a-reconcile/execution-validation.json`, SHA-256
`d506747318783a21170cf6b2772b79b778e22de9b24fd656f13d4d170e0a8ec3`.
Interlink receipt `85aa524648bba67792abd534c193f500` agrees to this bounded
preparation evidence and retains the release/default-concurrency CI gate.
No missing-transaction production fix or broader qualification is claimed.
