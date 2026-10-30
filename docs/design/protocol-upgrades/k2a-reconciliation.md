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

Native provenance is still an unresolved retention boundary. Current
`runtime::native_provenance` embeds the node's build commit in the Postcard
provenance stored during publication. Rebuilding unchanged guest artifacts at
another node commit therefore changes the initial persistent state. S2 discovery
at `d4acc6e8` versus `69169de0` reproduced all 137 non-digest semantic observations
and boundaries, but its full database baseline hashes differed. Each capture
restored its own exact baseline. The digest-only archives cannot establish that
provenance is the only changed row, so they are not full cross-build state-parity
evidence. K2a/K2b must retain explicit artifact/provenance inputs before freezing
P1, preserve historical rows, and test the resulting state projection. Do not
normalize away actual state differences in qualification or silently rewrite old
provenance records.

K2b build metadata must also account for fastnum's compile-time formatting
inputs: `RUST_FASTNUM_FMT_EXPONENTIAL_LOWER_THRESHOLD`,
`RUST_FASTNUM_FMT_EXPONENTIAL_UPPER_THRESHOLD`, and
`RUST_FASTNUM_FMT_MAX_INTEGER_PADDING`. Decimal formatting is guest-visible through
`host_numbers`. Committee stake conversion splits `decimal_to_string` output on
'.' and parses the integer portion, which fails if the build configuration produces
exponent notation. The source extraction preserves that behavior; it does not establish
that arbitrary formatting build environments are compatible with retained P1.

### Native artifact and provenance integration

The implementation must retain both the artifact bytes and the inputs written to
state. Archiving only Wasm is insufficient. The current genesis path obtains one
`BuildProvenance` from `native_provenance`, then publishes the ordered native set.
That helper uses `built_info::GIT_COMMIT_HASH`, with an all-zero fallback, while
`GenesisConfig` contains only `sigma_min` and validators. Neither the existing
configuration nor the committed binary build metadata selects a stable provenance
commit. Existing publication returns early for an already present address, so a
successful restart does not prove that a fresh node would reproduce those rows.

Implement the already required retention boundary as follows, after prerequisite
integration and before the P1 baseline freeze:

1. Archive the qualified synchronous native set inside the retained protocol source.
   Record its ordered names, reserved IDs, privilege/deposit rules, exact compressed
   bytes and hashes, build image, platform and reproducing source revision. The old
   archive in `protocol-semantic-api` pins `804cd9e0`; it predates the reconciled
   prerequisite and must not be copied forward as the final set.
2. Retain the exact serialized provenance supplied to native publication alongside
   those artifacts. Decode it using the retained protocol's codec and validate it
   at build/qualification time. Runtime publication must use these retained values,
   never the current node commit, checkout state, an environment override or the
   all-zero fallback. Ordinary user publication still uses its transaction payload.
   Node build provenance remains diagnostic metadata outside canonical state.
3. Bind this artifact/provenance set to the initial protocol/network definition.
   Later native-contract changes use an explicit protocol migration; selecting a
   new node binary cannot republish or change the old genesis set. Keep historical
   sets resident with their executor and include the retained files in K2b's source
   and artifact identity checks.
4. Inspect actual prelaunch database provenance before claiming compatibility.
   Preserve existing rows. A database created with another build-derived genesis
   input is not proven replay-compatible merely because its Wasm matches. Record
   any such mismatch and resolve its network-definition mapping explicitly before
   accepting that database; do not rewrite provenance or reset state implicitly.

Use the same explicit artifact/provenance inputs for both sides of K2a's baseline
comparison. Compare fresh genesis state and newly published provenance, not only
reopened databases. Build two node revisions with the retained inputs unchanged
and require equal provenance bytes and full logical state. Separately verify that
artifact/provenance tampering is rejected by identity validation and that loading
an existing database leaves historical provenance untouched. These are the existing
retention/parity gates made concrete, not permission to freeze inputs before S2
and OWNERSHIP-1 qualify or to exclude provenance from state comparisons.

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

## Block lifecycle preparation

Source `f5714b4f3e50a5643c52f3ade788299ba9c9832e` moves the complete
`Reactor::run_block_lifecycle_inner` body into
`protocol::v1::lifecycle::run_block_lifecycle`. The node's existing usage wrapper
calls it once and retains usage restoration, error precedence and SQL recording.
Block transactions, rollback, commit, finality and lifecycle scheduling are unchanged.

The ordered body is identical after replacing the receiver with a mutable Runtime
argument, normalizing reborrows and formatting. Exact error and log strings match.
The comparison also checks the entire remaining node source, not only the moved
lines. Its reproducible audit is `.build-cache/k2a-reconcile/lifecycle-source-audit.py`;
the JSON report has SHA-256
`5acab71a82681b9ca455bb8d1505a421d776ddf9b43165034e9396371eed2c68`.
Parent, independent subagent and Interlink source reviews found no material
regression. Interlink approval `978753794597febc13945702633aa34f` was acknowledged.
Combined post-move diagnostics and Clippy passed as recorded below. These checks
do not replace final release CI.

The versioned body preserves context reset, reward eligibility, emission, ordering
reward distribution, storage reward accrual, root recording, challenge expiry,
settlement, challenge generation and pending-validator processing, in that order.
It retains the distinction between nested results handled by `await??` and errors
wrapped with context or debug formatting. The lifecycle still runs with no transaction
context. ID0's missing-context generated-ID audit must cover this new path; relocation
does not resolve that separate obligation.

Temporary K2b dependencies are Runtime, `Signer::Core(Nobody)`, the shared Block
type, Bitcoin hash conversion, and staking, token and filestorage native bindings.
Their execution semantics and dependencies still need retention in the independent
graph. Native validator processing remains in the staking binding. The unchanged
filestorage contract selects eight challenges on regtest and one hundred on other
networks during initialization; this extraction does not assume regtest values.
No final cross-graph API, protocol selection or baseline freeze is claimed.


## Committee derivation preparation

Source `35dc5736f4062f5773ca68ad27e2db02db7c380e` moves `build_validator_set`
and `stake_to_voting_power` from the reactor into `protocol::v1::committee`.
The complete bodies are byte-identical; only their visibility changes to
`pub(crate)`. Genesis assembly and live committee refresh remain node-owned
and call the same imported implementation. Existing tests retain their import
path through a test-only reactor import. Each function has one definition.

The staking system view and native binding decode preserve active-set order.
Stake is formatted using the existing decimal conversion, truncated to its
integer part, parsed as `u64` and rejected if zero. The Ed25519 key length is
checked before copying, then validated by `PublicKey::from_bytes`. Every error
string and propagation operator remains unchanged. The staking contract supplies
the sorted set; `ValidatorSet::try_new` preserves that order and checks emptiness,
positive powers, aggregate overflow and quorum-arithmetic limits. This extraction
does not add sorting or duplicate-key validation. The staking contract enforces
Ed25519 key uniqueness during registration and genesis. Additional rejection in a
future committee implementation is a possible hardening change, not a P1 edit or
a blocker for this preserved extraction.

Parent, independent subagent and Interlink source reviews found no material
regression. Interlink receipt `8e52f12a32ad52f25dda443d2c6ffd6c` was acknowledged.
The reproducible comparison is `.build-cache/k2a-reconcile/committee-source-audit.py`;
its JSON report has SHA-256
`89eb8e155d641c8e4c4f7da35e19a9e281cbf7837629aededf18414aa8af158e`.
The audit checks exact complete bodies, the entire remaining reactor source,
module registration and single definitions. Runtime validation is recorded below.

Temporary K2b dependencies include Malachite `VotingPower`, node consensus
`Validator`, `ValidatorSet` and `PublicKey`, Runtime, Decimal and its conversion,
and staking view bindings. Their behavior and dependencies still need retention
inside the independent graph. This source move is not a final cross-graph API,
validator-authorization mechanism or activation policy.


## Combined lifecycle and committee validation

Exact source `35dc5736f4062f5773ca68ad27e2db02db7c380e` passed:

- 124 debug tests with two test threads, 531.46 seconds after a 55.28-second build.
  This includes the prior 120-test baseline and four storage-penalty regressions.
  Both ordering-reward tests, fractional voting power, exhausted committee behavior,
  reorgs, startup recovery, simulation and publication passed without changing tests.
- Four existing validator-set arithmetic tests, including zero power, aggregate
  overflow, quorum bounds and the expected panic for a deserialized invalid total.
- Indexer Clippy with tests and warnings denied, 7.42 seconds.

All commands terminated with exit code zero. Exact commands, log hashes and
summaries are in `.build-cache/k2a-reconcile/lifecycle-committee-validation.json`,
SHA-256 `f55ea31f1d2ecfb1bd9c8e4fc46f5e389daabcee4dd774235010ac1a705a3062`.
The lifecycle body and block coordinator remain byte-identical to their reviewed
f5714b4f source at this committee head. No additional source changes were made
while these checks ran. Final release/default-thread CI and the complete K2a
acceptance gates remain required after S2 and OWNERSHIP-1 reconciliation.

Parent and both independent reviewers verified this evidence. The subagent
rehashed the logs and counted unique passes, including all prior baseline cases;
Interlink accepted both moves in acknowledged receipt
`a398e302ebef8224b22140f3e20ae5c5`. This closes preparation review only.

## Coordinator rules preparation

Source `716e120af944868d4bba162c8d8023a16905565c` follows `3439d528`.
`protocol/coordinator/v1.rs` now owns the existing dependency ordering functions
and finality window arithmetic. `reactor::batches` and
`consensus::finality_types` retain their existing import paths through re-exports.
The complete moved sections are identical except for imported `Transaction`
signatures and crate-local visibility for the ordering helpers. All existing
batch tests remain unchanged and exercise the same facade as node callers.
The original tie breaking, duplicate handling, cycle fallback, unchecked deadline
addition and saturating tracking floor are preserved, not hardened in this move.

Node pruning uses `minimum_prune_retention_blocks()` separately from the selected
consensus rules. Its value is still six blocks, from the sole retained v1. Both
rollback-depth validation and state pruning apply this same floor. Before enabling
any additional coordinator version, include its required rollback window in the
maximum, and test transitions in both directions. Selecting a smaller current
window must not allow deletion of history still needed by an older version. This
floor does not recover history already pruned; the accepted reconstruction policy
still applies when required undo data is absent.

Parent mechanical comparison is reproducible with
`.build-cache/k2a-reconcile/coordinator-source-audit.py`. It compares complete
remaining node files as well as moved rules and unchanged batch tests. Formatting
and whitespace checks passed. The independent subagent and Interlink reviewer
approved the exact source; Interlink receipt `db6f6354b784efad5615ad5139e5ea77`
was acknowledged. After the native capture released the local Cargo slot, all
46 targeted ordering, replay, finality and body-retention tests passed
(0.06 seconds after a 51.86-second build). Indexer Clippy with tests and warnings
denied passed in 8.09 seconds. Both commands terminated with exit code zero.
Commands, log hashes and limits are recorded in
`.build-cache/k2a-reconcile/coordinator-validation.json`. These debug checks do not
replace final release/default-thread CI or full K2a acceptance. Both independent
reviewers verified log hashes, actual pass names and the boundary inventory below.
Interlink evidence approval `efa251d69d70481c44ee91b4b4580696` was acknowledged.
The subagent caught an inaccurate vacuum-test coverage claim; it was removed.
No vacuum test ran in this invocation, and no vacuum behavior changed.

### Remaining coordinator boundary inventory

These locations are inspected at `716e120a`. They identify required work, not a
claim that the full coordinator closure has been extracted.

| Rule or operation | Classification and current location | Required versioning work |
| --- | --- | --- |
| Parent-before-child proposal validation and deterministic proposer tie breaking | Pure, now `protocol/coordinator/v1::{batch_is_ordered,dependency_sort}` | Route through the manifest-selected coordinator version; preserve independent transaction order rather than imposing a new canonical order. |
| Six-block deadline and inclusive restart tracking floor | Pure, now `protocol/coordinator/v1::{deadline_for,tracking_floor}` | Retain each batch's applicable rule identity across activation and reorg; do not reinterpret old deadlines with a new window. |
| Earliest unsettled transaction and unfinalized body floors | Stateful deterministic queries in `database/queries/{transactions,batches}.rs`, consumed by startup rehydration, divergence checks and `prune_finalized_bodies` | Version the finality interpretation of persisted rows. Keep record-only batches in body-retention calculations, and do not substitute the in-memory executed set. |
| Deadline verdict and settlement ordering | Stateful deterministic, `ConsensusState::check_finality`, `probe_at_deadline`, `build_finality_events` and `Reactor::{advance,settle_finality}` | Preserve `(anchor_height, consensus_height)` evaluation order, probe-before-consuming behavior, durable exclusions before truncation, and repeated drain/settle before permission to start the next height. |
| Replay exclusion and descendant availability | Deterministic over resolved decisions and exclusions, `build_replay_queue` | Retain execution-position availability separately from queue emission. Current code already sorts availability by `(anchor_height, consensus_height)`; it does not walk availability in node-local queue order. The existing `build_replay_queue_availability_is_anchor_order_not_queue_order` regression remains unchanged. |
| Replay queue placement and input acquisition | Node-local scheduling and I/O coupled to deterministic application, `resolve_decisions`, `build_replay_queue`, `drain_deferred_decisions` | Replay-first queue order exists for progress while waiting on blocks; it must not change the transaction exclusion set. Preserve certified original bodies when narrowing execution, and bind replay to authenticated history in K4/K9. |
| Empty batch heartbeat | Node-local event projection in `BatchOutcome::announced_txids`, both immediate and deferred decision paths | Preserve an empty `BatchProcessed` event for empty recorded batches, and silence for nonempty recorded-only skips. It drives API information refresh; it is not proof those skipped transactions executed. |
| Committee refresh and next-height parameters | Stateful deterministic derivation, node cache and engine coordination in `refresh_validator_set`, `handle_block`, `rollback`, `resume_next_height`, and startup handlers | Derivation is already in `v1::committee`; current refresh follows committed block execution and rollback. Bind snapshots and engine start parameters to the certified height boundary in K4-K8. No historical committee lookup or engine-era activation is implemented by this extraction. |
| Simulation admission, temporary block, execution and result projection | Node-local admission/rollback with versioned transaction semantics, `Reactor::{simulate,simulate_inner,execute_block}` | Keep one coordinator-issued execution context and selected semantic implementation. Do not move the Reactor into the semantic graph or introduce a semantic-to-Reactor back-reference. OWNERSHIP-1 must preserve cleanup on cancellation. |
| State pruning and rollback-depth policy | Node-local retention constrained by every retained version, `check_rollback_depth`, `maybe_prune_state` | Use the shared minimum retention floor and add each new version before activation. Archive mode remains unbounded local retention, not a consensus rule. |

Production dispatch, complete scheduling/replay isolation, cross-version floor
selection, S2/OWNERSHIP reconciliation and final K2a acceptance remain outstanding.
This source does not freeze P1, change any rule, or establish independent graphs.

## Finality and replay policy preparation

Source `bcf438fed64bd80f8fd68677f9c05d041a345436`, based on `ca3e5e5f`,
continues the coordinator extraction above. The complete `build_finality_events`
and `build_replay_queue` algorithms now live in `protocol/coordinator/v1/finality.rs`
and `protocol/coordinator/v1/replay.rs`. The node retains its database probes,
transactions, runtime ownership, queues and I/O. Its existing call sites and all
finality/replay tests use imports of the retained implementations without wrappers
that change their inputs or outputs.

`DeferredDecision` and its `decided_txs`/`decided_txids` accessors now live in
`protocol/coordinator/decision.rs`, re-exported at the original
`reactor::consensus_state` path. Fields, visibility, cloning, certified-body
preservation and the accessors are unchanged. The module imports only Bitcoin
`Transaction`/`Txid` and consensus `Height`/`Value`; it does not import the reactor.
The type has no serialization derive, so this relocation adds no wire encoding.
Those dependency-owned types remain temporary in-tree dependencies, not a final
cross-graph API.

The replay function still combines deterministic exclusion calculations with
node-local replay-first queue placement. Its availability walk uses
`(anchor_height, consensus_height)` independently of queue placement; versioning
the whole function does not make local queue order a valid input to exclusion
decisions. Per-height string-keyed exclusions, descendant propagation, later
re-decisions, and earliest certified bodies across repeated filtering are retained.
Finality preserves its aligned-input debug assertion, first failing anchor,
same-anchor invalidation, pending-batch partition and per-decision missing txids.

Operator-visible logging change: the two `Batch finalized` information events and
the `Cascade invalidation triggered` warning now have tracing target
`indexer::protocol::coordinator::v1::finality`, previously
`indexer::reactor::consensus_state`. Their messages, fields and ordering are
unchanged. Deployments using target-specific log filters should include the new
target. The replay function has no tracing events.

The mechanical audit
`.build-cache/k2a-reconcile/coordinator-policy-source-audit.py` compares the complete
moved bodies, type/accessors, unchanged tests and remaining node source. It passes
after only imported-type substitutions, visibility and formatting normalization.
Both independent source reviews approved the exact head; Interlink receipt
`0d96d1191a85148da70ca814a9b1faa0` was acknowledged. All 46 targeted batch,
consensus-state and retained-body query tests passed in 0.05 seconds after a
59.53-second build. Indexer Clippy with tests and warnings denied passed in
11.84 seconds. Both commands terminated with exit code zero. Commands and log
hashes are recorded in `.build-cache/k2a-reconcile/coordinator-policy-validation.json`.
The parent and both independent reviewers accepted this bounded validation and
documentation; Interlink evidence-review receipt
`8d6986cd6e7e65ddfbc8bc72b621760d` was acknowledged. These debug checks preserve
the existing tests and do not replace final phase CI.
No claim of phase completion, selected rule dispatch or historical isolation is
made by these relocations.


## Remaining executor API and context design

Design agreed following source `3e13c5ee`; not implemented yet.
This completes the existing K2a boundary design and feeds K2b, K3 and K7. It does
not introduce another prerequisite phase or change the agreed activation rule.

### Selection and state identity

The node's coordinator selects an executor once for an admitted root operation.
The selected executor and its live storage session must describe the same canonical
state. Selection binds the protocol definition and artifact identity, canonical
application position and lineage, legacy checkpoint, completed migration identity,
and network/genesis identity. These are the identities already required by K3/K7,
not a new full-state root or a replacement for the legacy ordered checkpoint.
K2a initially supplies P1 through the same API; it must not fabricate completed
migration metadata or claim that K3/K7 persistence already exists.

Bitcoin height alone is insufficient. Block H completes with the old rules; the
post-migration state and subsequent Batch(H) still have height H but use new rules.
Read the selected protocol and canonical identity in the same database snapshot
that serves the operation. Never select from a separate latest-tip connection,
`info_rx`, a wall clock, the live Malachite era, or a schedule lookup alone. During
reorg recovery the canonical executor can be historical even while the live engine
and signing era remain newer. An unsupported selected executor is an explicit
unavailable condition, never a fallback to the newest installed executor.

For a canonical block or batch, the coordinator supplies its ordered application
position and explicit phase. For a view, it supplies the committed snapshot's
position. For simulation, it supplies the pinned base position plus the existing
fabricated next-block position. The simulated block height remains tip+1, but
selection follows the base state's completed boundary. A scheduled activation at
H does not authorize P2 execution on a P1 pre-migration snapshot.

### Requests spanning activation

Public views use snapshot pinning. Begin a read transaction, read the canonical
identity and protocol from that connection, then acquire the matching executor
and run every contract read through that transaction. A view whose first snapshot
read precedes the migration commit completes with the old state and executor;
a view whose first read follows it gets the new state and executor. The commit's
linearization point determines which complete snapshot it sees. Do not re-read
latest protocol halfway through a view, and do not retry a partially executed view
against a different snapshot. Old bundles remain resident under the retention plan.

Simulation uses coordinator admission. Queue raw requests through the existing
bounded channel; issue the root context only when dequeued at an open canonical
execution boundary. Do not dequeue/start simulation between closing the activation
boundary and completing migration/handoff readiness. An already admitted simulation
finishes and rolls back before the coordinator advances the canonical boundary.
If recovery or unsupported-protocol state leaves admission unavailable, return the
node's explicit unavailable result rather than execute on mismatched state. A
queued request has no promised old version; admission selects its actual base.
Caller response loss does not cancel admitted work, per OWNERSHIP-1.

Preserve the current production queue capacity, `available_parallelism()` in
`main.rs`, and `send().await` backpressure (the test Env uses ten). A full queue
waits for space; it does not produce a new queue-full error. The API router
currently applies `API_REQUEST_TIMEOUT_MS = 30_000` and returns HTTP 408 with an
empty body when its timeout wins. A timed-out pending send has not enqueued work;
an already enqueued request remains eligible for admission even if its response
receiver closes. Do not add a queue-age expiry or silently discard it on reopening.
It executes against the base selected at eventual admission and then rolls back.
These are node request-lifetime semantics, not a consensus execution deadline.

Views may serve an already committed canonical snapshot while Malachite is stopped,
provided the matching executor and storage snapshot are available. This does not
reopen canonical simulation/application admission or confer signing authority.
The existing 30-second HTTP timeout requests view cancellation, but does not prove
that its read transaction is already released. OWNERSHIP-1 retains resources during
drain, with its five-second cleanup deadline and quarantine on expiry. Gas limits
and fuel yields do not bound cold compilation or synchronous/blocking host work.
An old SQLite snapshot can therefore delay WAL checkpointing and grow the WAL;
no finite WAL-size or root-lifetime guarantee is claimed from these timeouts.
Retain the bounded global pool capacity through quarantine as already specified.

Partition compiled caches by executor artifact and engine identity, plus immutable
code identity resolved from the root's own snapshot. A bare `contract_id` is not a
safe cache key: reorg/republication can reuse it for different code within the same
protocol and engine while an old view still holds its original snapshot. Do not
look up the old ID in a shared cache before resolving that snapshot's code identity.
Share one explicit node-wide view capacity across retained executors, including
active and quarantined roots. Keep one aggregate bounded compile-cache budget
across namespaces rather than multiplying the cache allowance for each protocol.
Resident historical bundles remain governed by the separate retention policy.

### Context and ownership

Use a coordinator-created root context with private construction outside the
coordinator/selected-executor adapter. It carries the selected definition/artifact,
base identity, intended position/phase, root purpose (canonical, simulation, public
view or trusted lifecycle), immutable resolved runtime policy, network identity,
and the node-owned live storage session capability. The policy comes from the
selected protocol, not request fields or mutable latest-runtime configuration.
Public view gas caps remain a local limit on that root only; they cannot alter
canonical or trusted system budgets. Pricing, conversion factors, resource limits,
native artifact/provenance identities and semantic error policy must come from the
retained implementation/definition with the context binding which one is active.

Do not put a single payer on a whole block, batch or transaction root. Existing
Sponsor materialization, per-operation payment, Core signer distinction and nested
fuel inheritance can produce different effective payment modes inside one root.
The selected executor derives each operation context under that root after its
own recognition/authentication rules. Operation and child contexts inherit the
same protocol and storage authority, with the existing payer and budget rules;
none may reselect from ambient node state. A Runtime field may cache this immutable
resolved policy internally, but it cannot independently override the selected root.

OWNERSHIP-1 owns root admission, retained tasks, cancellation/drain, commit authority,
pooled object quarantine and table-before-lease release. Reuse its accepted design
and qualified API/view yield policy, rather than implementing a second cleanup
mechanism here. The node owns physical SQL connections, transactions, cursors and
ordered metadata writes. The executor owns versioned recognition, materialization,
execution, lifecycle, view evaluation, committee derivation and simulation semantics.
Do not move the Reactor into the semantic graph. Cross-graph K2b envelopes must use
std-only owned data and logical callbacks; temporary in-tree Runtime/anyhow/Bitcoin
interfaces are not evidence of that isolation.

### Concrete call-site conversion

| Current path | Required conversion |
| --- | --- |
| `api::handlers::transactions::post_simulate` and `reactor::Simulation` | Carry raw transaction bytes to coordinator admission; selected executor performs Bitcoin decoding and Kontor recognition. Transport hex validation and size limits stay node-side. Preserve P1's parser acceptance and input filtering. |
| `Reactor::{simulate,simulate_inner}` | Own admission, temporary transaction and unconditional cleanup; pass a selected root and raw request into the semantic simulation path. Preserve fabricated block construction and current omission of lifecycle in simulation. |
| `Reactor::execute_block` | Keep node confirmation/usage bookkeeping and already-executed transaction deduplication. Dispatch fresh operations through the selected executor; confirmation never reruns an earlier batch merely because the confirming block selects another protocol. Per-block lifecycle and file-root batching use the confirming block's selected rules; prior effects keep their execution identity. Local pruning retains the maximum required history across retained rules. |
| `api::handlers::contracts::post_contract`, `runtime::pool` | Bind one read transaction, canonical identity and matching executor before evaluation. Pool reuse cannot retain a previous root context or an incompatible engine/cache. |
| `Runtime::{execute,execute_api,execute_system_view}` | Route public, paid and trusted calls through the selected root/derived operation context. Retain portable charges and existing distinctions between view, user and system budgets. |
| `v1::{execution,lifecycle,committee,transactions}` and coordinator policies | Enter through selected implementations. Internal calls inherit root identity; coordinator policies come from the same network definition while remaining distinct from local queues and I/O. |

The simulation transport currently decodes Bitcoin and calls `filter_map` before
queueing a materialized transaction. Its error mapping and failure projection must
remain compatible for P1 when moved behind selection. Malformed input must stay an
ordinary request/recognition result, not become an infrastructure error that stops
the reactor. Real database, executor infrastructure and cleanup failures retain
their fatal/unavailable handling. Preserve error text where required by P1; do not
silently fix old acceptance or classification during the extraction.

### Acceptance and implementation sequence

1. Reconcile the reviewed S2 and OWNERSHIP-1 source before changing runtime ownership
   or constructing the final P1 runtime. Complete K2a's in-tree API and call-site
   wiring with one P1 implementation and explicit context, preserving actual behavior.
2. Before changing call sites, capture P1 simulation, view and execution outcomes,
   receipts, fees and full logical state from the reconciled pre-change source.
   Use identical explicit native artifact/provenance fixture inputs or cloned
   starting databases on both sides. Publication cases must also compare newly
   stored provenance. Do not exclude provenance rows to claim full-state parity;
   unequal build-dependent inputs must be identified and fixed through the existing
   retained-provenance boundary before using that case as an equivalence oracle.
   Preserve source, fixture and output hashes for the baseline. Cover raw simulation
   ingress with malformed and partly recognized transactions,
   deterministic per-op errors, infrastructure failures, existing deduplication,
   rollback and cache suppression. Verify results/receipts/fees and persistent state
   against the current path, not only the same new helper called twice.
3. Cover pool reuse with held cursors, cancellation, discarded objects and incompatible
   engines. Hold an old view across reorg/republication that reuses the same row ID
   for different code; verify both old and fresh views with a shared P1 engine.
   Check that every logical read and every nested call uses its root's
   selected state and implementation. Keep system budgets independent of local view caps.
4. K2b must prevent unselected entry points and dependency-owned types crossing the
   graph boundary. Complete native artifact/provenance and formatting-build retention,
   existing logical storage callbacks and actual production bundle qualification.
5. Once K3/K7 provide durable identities and real activation, test views on both sides
   of the same H migration commit, a pre-commit view held across it, queued simulation
   spanning handoff, unsupported target, and reorg replay with a newer live engine.
   Use deliberately different P2 behavior to prove dispatch. Height-only mocks cannot
   establish these invariants. These remain required goal acceptance, not optional
   post-completion follow-ups.

All three design reviews accepted revision SHA-256
`a54865ec9d08b572f4d9e2e4a3d00c5836565b796d87a45e8cffc119ebabe410`
(the text before this acceptance record and status update). Interlink agreement
`f643c9e9031dc8b8c3b8f50c97be4704` was read and acknowledged. Independent subagent
review required the same-protocol reorg/cache identity correction above. Parent
review corrected production queue capacity, rejected a finite WAL bound inferred
from cancellation deadlines, and retained full-state/provenance comparison rather
than excluding rows. No runtime code or qualification acceptance changed.


## Retention reconciliation and simulation ingress checks

Source `e81ea3df` carries the existing S2 retention correction into the versioned
coordinator policy. The rollback floor retains the finality window plus its
predecessor block. Both pruning and rollback use that versioned floor. Startup
always loads the persisted pruning watermark, and rollback checks it even after
pruning is disabled or retention is increased. A configuration change cannot
restore deleted history.

Regression `b37dc6b0` uses real contract-state pruning: before pruning at tip 108,
rollback to the anchor predecessor 101 is allowed; after pruning to watermark
102, rollback to 101 is refused under the original, increased and disabled
pruning configurations. This is not a substitute for the complete finality
redelivery regression after prerequisite integration.

Test-only source `77b2b4db` characterizes simulation HTTP ingress before moving
recognition behind executor selection. Invalid hex, truncated Bitcoin bytes and
a non-Kontor transaction return HTTP 400 without queueing. A partly recognized
transaction preserves its original input index, outpoint, instructions, txid and
raw multi-push OP_RETURN bytes. A reactor rejection retains the HTTP 400 envelope.
These tests use the real parser and HTTP handler with a supplied reactor response;
they do not establish execution, fee or full-state parity.

On exact head `77b2b4dbda0915afc7c45bd962738958fa8e859e`, all 49 selected
retention, simulation, batch, finality and retained-body tests passed in 6.79
seconds after compilation (87.40 seconds total). Indexer Clippy with tests and
warnings denied passed in 22.79 seconds. Both used pinned Rust 1.99.1, locked
offline resolution and at most two build jobs. Commands, terminal results and
raw-log hashes are in `.build-cache/k2a-reconcile/retention-simulation-77b2b4db/`.
These checks validate the preparation branch only. S2/OWNERSHIP-1 integration,
selected executor/context wiring, full phase acceptance, independent reviews and
release CI remain required. No P1 freeze or phase merge is claimed.

## Retained pricing extraction

Source `63c343b229f2c15cdefbdf6a04e268b62deaec17` moves the existing `Pricing`
implementation into `protocol::v1::pricing`, preserving the `runtime::Pricing`
re-export and existing tests. Methods, constants and error strings are unchanged
after adjusting imports. This is code organization for retained semantics, not
selected-context wiring or a change to gas allowances.

All four existing pricing tests passed on that exact clean source in 9.62 seconds
(80.82 seconds including compilation). They cover rate independence and retained
storage reservations, free execution with collateral, overflow and legacy bounds,
and the property that a hold covers execution plus collateral. Indexer Clippy,
including tests with warnings denied, passed in 17.52 seconds. Both checks used
Rust 1.99.1, locked offline resolution and two jobs. Reproducible commands, source
and lockfile hashes, terminal results and raw-log hashes are retained under
`.build-cache/k2a-reconcile/pricing-extraction/`. These checks do not qualify the
complete executor extraction or replace the prerequisite integration and parity
evidence described above.

## Retained gas constant extraction

Source `40ffdf553dd0e553e7014b1e92fa71278f2ef529` moves the existing gas constants
to `protocol::v1::gas`, retaining the runtime imports and public re-exports.
The whole-call allowance, nested fuel inheritance, portable lifting charges and
numerical values are unchanged. This is preparation for protocol selection;
selected-context wiring remains outstanding. No aggregate block budget or
additional per-operation cap is introduced.

On that exact clean source, the root fuel-limit regression passed (one test,
7.70 seconds, 58.51 seconds including compilation), and the separate view-budget
regression passed (one test, 0.03 seconds, 0.46 seconds total). Indexer Clippy with
tests and warnings denied passed in 7.67 seconds. All three commands used Rust
1.99.1, locked offline resolution and at most two jobs. Commands, source and
lockfile hashes, terminal results and raw-log hashes are recorded in
`.build-cache/k2a-reconcile/gas-extraction/`. These focused checks preserve the
existing behavior; they do not establish complete historical executor isolation.

## Ownership integration preflight, 30 October

A read-only merge preview compared K2a `4e2823b604bdc647940c2e3061a5a28a4eff1207`
with OWNERSHIP-1 `0a9af2171153089b7ec4207edb2bc9cb263e736a`, using merge base
`af04da0d992450905c54f8d8b903ea240820e8bb`. It reports fourteen conflict regions
in eight files. The raw preview and machine-readable inventory are preserved in
`.build-cache/k2a-reconcile/k2a-ownership-0a9-preview.patch` and
`ownership-integration-preflight.json`. No production files were merged or changed.

Resolve the conflicts after the qualified prerequisite merges as follows:

- In `runtime/storage.rs`, retain ownership fields, tracked blocking decode, and
  test hooks alongside K2a's retained storage callbacks. `commit` must call
  `ensure_commit_authorized` before invoking `storage_session::commit`: the latter
  pops the savepoint stack before issuing COMMIT/RELEASE, so authorization after
  that call would be too late. Keep the rollback-failure injection before the
  retained rollback function clears the stack or invokes SQL. Neither branch's
  entire method is a sufficient resolution by itself.
- Keep K2a's coordinator policy exports in `consensus/finality_types.rs` and its
  `minimum_prune_retention_blocks()` calls in `reactor/blocks.rs`. The retained
  coordinator already defines the finality window and predecessor rollback depth.
  Do not reintroduce a competing node-local constant or discard the ownership
  branch's durable pruning-watermark behavior. Resolve associated configuration
  and reactor comments to describe the resulting retained-policy floor.
- Combine the API simulation and ownership test modules. Combine retained
  publication tests with S2 native-stack test modules. Keep the pruning boundary
  assertions from K2a and the owner service required by the updated reactor
  constructor. Import reconciliation must retain `OwnerService` without restoring
  the pre-extraction committee implementation.

Automatic merges also need semantic inspection. A conflict-free result does not
prove that the node storage adapter preserves owner lifetime, commit authorization,
tracked blocking jobs, cancellation rollback, or retained coordinator dispatch.
The integration checks must cover the existing storage differential tests, ownership
commit/cancellation and rollback-failure tests, pruning predecessor boundaries, and
real startup/finality shutdown tests. This preflight neither freezes P1 nor replaces
final S2 parity, affected six-cell qualification, or the consolidated K2a review.

### Selected-executor preparation, 30 October

Merge `11dd942a` reconciles K2a `65677ded` with S2/OWNERSHIP `d9f85886` in an
isolated preparation branch. The lead verified the exact-head all-target compile
record and three focused rollback/commit-authorization/pruning passes. This does
not qualify S2 or freeze P1; the final prerequisite merges remain required.

The pre-dispatch comparison source is `c7554ca8`. Its ignored
`reactor::confirmation_position_tests::parity::retained_executor_matches_baseline`
test preserves a SQLite seed, signed raw transaction, checksums and full logical
database rows (including SQLite sequence state). Record mode refuses to overwrite
an existing archive. Compare mode reopens the same seed and compares all eleven
recognition, simulation, execution, confirmation, rollback and reconfirmation
stages. The baseline and a separate replay passed. Native artifacts and provenance
remain byte-identical through the saved database, rather than being normalized out
of the comparison. This is a bounded real-execution baseline, not coverage of all
transaction shapes, lifecycle behavior, migration identities or future protocols.

Simulation ingress now queues the complete Bitcoin transaction and recognizes it
in the reactor when the request is admitted. An unrecognized transaction is an
explicit `None` result, preserves the existing HTTP 400 response, and does not stop
the reactor. Infrastructure errors retain their fatal treatment. Malformed Bitcoin
encoding is still rejected before queueing. This prepares the simulation path for
selected execution; the current production executor remains P1. Protocol selection,
raw mempool ingress, proposal revalidation and admitted executor dispatch are
still required. No activation or historical bundle isolation is claimed here.

Validation of `60fbec07`: the three simulation API tests, four context-restoration
tests, reactor channel test and preserved-baseline comparison all passed. The
comparison matched all eleven stages against `c7554ca8`, using the original seed
and signed bytes. It also confirmed that unrecognized input leaves state unchanged
before a subsequent valid simulation. The locked/offline indexer/testlib all-target
check passed. The only subsequent source cleanup removes an unused test import;
it does not change execution. The phase-level independent reviews remain pending.

Raw block ingestion now retains complete Bitcoin transactions through poller
delivery and the reactor's pending-block queue. Recognition happens after canonical
root admission, using the current executor. P1 still parses on a blocking worker
with ordered parallel collection. Original Bitcoin transaction indexes and witness
bytes survive filtering, and confirmed txids are removed from the pending pool.
The parsed-block conversion exists only for synthetic unit-test fixtures, not
production ingress. This is preparation for protocol selection, not activation.

Validation at `6f0f3831`: 28 poller tests passed, including retaining unrecognized
inputs and distinct witnesses under one txid. The real-execution replay matched
all eleven saved baseline stages. Three-node confirmation-without-reexecution and
below-tip replay tests passed, as did the indexer/testlib all-target check. An
earlier cluster attempt was stopped after the sandbox denied its loopback listener;
the successful run had loopback access. Raw logs, source revisions and checksums
are under `.build-cache/selected-executor-baseline/6f0f3831/`.

Lead review covered raw delivery, pending queues, original indexes, confirmation
deduplication, replay, and parser-worker failure cleanup. It found that the latter
must drain the admitted root before completing it; that ordering is corrected.
The normal-path checks above precede this error-path correction. Full selected
dispatch, raw mempool handling, final prerequisite reconciliation and consolidated
phase reviews remain outstanding.

Raw mempool snapshots and deltas now cross the Bitcoin listener without a
protocol filter. The reactor recognizes them with its executor, retains unknown
raw inputs separately from current proposal candidates, and keeps fee samples and
snapshot replacement behavior. A replacement witness invalidates the previous
candidate even when the txid is unchanged. Unrecognized deltas do not reset
proposal debounce. Confirmation and removal clear both retained bytes and the
candidate; candidate-only policy filtering does not destroy the raw input.

At `5272200b`, 24 listener tests, three retention/witness/snapshot tests and the
three-node batch-confirmation test passed. The indexer/testlib all-target check
passed. Lead review then moved initial recognition before consensus startup to
preserve the startup barrier and removed an unused import. No phase acceptance is
claimed: protocol reselection and cache identity remain required. The subsequent
preparation change below addresses reconnect parsing on the reactor loop, exact
witness freshness across async validation, and suppression during pending parsing.
It does not yet implement rebuilding candidates under a different protocol.

### Bounded mempool preparation and witness freshness

Recognition now returns an owned future. The production executor performs witness
parsing on a blocking worker, and the reactor polls that future alongside block,
consensus, simulation and shutdown events. Only one mempool preparation runs at a
time. Later listener events stay in the existing bounded channel, preserving
snapshot/delta order and backpressure. Initial startup recognition remains before
engine startup. Snapshot installation and fee projection still have synchronous
work; this change does not establish a bound on total reactor latency.

Raw inputs are staged before preparation, with candidates withheld until recognized.
Block removals and local candidate suppression apply while parsing is pending.
Completion requires the same complete raw transaction and an eligible entry, so a
late result cannot restore an input removed by a block, rejected by validation, or
excluded by finality. A new listener snapshot/delta resets local eligibility as it
did before. Proposal cache insertion retains its raw input and cannot overwrite a
different witness from the listener or bypass local suppression.

Both freshly returned and banked Bitcoin validation results now require exact
candidate bytes, rather than txid membership. Rejection also applies only to the
raw input actually checked. Incoming proposals continue to validate their own
bytes; local cache eligibility does not become an additional consensus vote rule.

The focused mempool run passed 29 tests, including an actual reactor loop with
pending recognition, continued block/request handling, channel backpressure and
shutdown, plus production proposal-apply/banking checks with same-txid witness
replacements. Initial test-only fixture errors (empty committee and a private
helper import) were corrected before the successful run. Protocol selection stamps,
reselection at activation/recovery, and retained implementation dispatch remain
unfinished. These checks do not establish those later capabilities or final K2a
acceptance.


On `f1c84c4e1939e496a8b129a31754424eef42261f`, the 29 focused tests,
existing banked-verdict and pending-RPC block-progress consensus regressions,
and indexer/testlib all-target compile check passed. The preserved P1 comparison
was explicitly run with `--ignored` and passed, producing candidate report
SHA-256 `554d781fa0dda9236709a5b3730145da125827b007101077e11cca3858d0f7a3`.
The first parity invocation skipped the opt-in fixture and is not acceptance
evidence. A sandboxed consensus attempt could not bind localhost; the test process
was stopped and the checks passed with local networking enabled. Logs and the lead
review are in `.build-cache/selected-executor-baseline/f1c84c4e-local-network/`
and `.build-cache/selected-executor-baseline/f1c84c4e-parity/`.

### Selected P1 reactor path (30 October 2026, preparation)

The reactor now captures an explicit P1 selection for block, batch, simulation
and proposal preparation. The same selection routes recognition, batchability,
transaction execution and block lifecycle. Block and simulation entry check their
purpose and coordinates; transaction execution also checks network and height.
This remains an in-tree P1 implementation, not independently linked historical
bundles or a functioning upgrade schedule.

The unversioned database provides a local freshness marker from one SQL snapshot:
receipt epoch and rollback generation, tip height/hash, latest transaction ID and
checkpoint height/hash. Canonical execution compares this marker again in its
write snapshot before mutation. The marker is neither a network protocol identity
nor a migration commitment. K3 must replace legacy admission with persisted
protocol/migration selection, and K2b must bind the independently built artifact.
No storage authority is conferred by holding or cloning this selection; the
existing canonical lease retains that responsibility.

Proposal preparation can survive another batch at the same anchor, because its
returned Bitcoin verdict still undergoes current database and exact-witness
checks. It cannot survive a changed anchor, network/rules, receipt epoch or
rollback generation, even when replay produces the same block hash. This applies
both when a verdict arrives and when banked candidates are consumed. Pure
recognition can survive a state-only change; a changed recognition rule causes
pending mempool preparation to reparse retained raw inputs without resetting
local suppression.

Public views, matching runtime policy and nested-entry binding, committee
selection, cache isolation and final K2a/K2b acceptance remain outstanding. No
activation, historical artifact freeze, resource qualification or performance
waiver is established by this preparatory wiring.

Validation on `2643bd388036036b10c1fa2887b91e669b11b158` passed 44 tests:
four selection/snapshot tests, 31 mempool tests, four simulation restoration tests,
two confirmation/reorg tests, both real-cluster proposal/blocked-validation
regressions, and the explicitly opted-in P1 parity comparison. The indexer/testlib
all-target compile check also passed. The comparison matched all 11 saved logical
state stages against baseline `c7554ca8b7a104d28f41eb1e9a0c48200c34d5f1`, including
receipts and provenance, with candidate report SHA-256
`ad625235e36900c65deb5369ade36484ef318d1e6d4d96bf3ad992a4cfdf1668`.
Logs, commands, exit status, hashes and the lead's scope/limitations record are in
`.build-cache/selected-executor-baseline/2643bd38-selection/`. The parity fixture is
ignored in the ordinary confirmation suite; only its separate `--exact --ignored`
run is counted here. These are preparatory integration checks, not the final
phase's independent reviews or full protocol-upgrade qualification.

### Snapshot-bound public reads and compile caches (30 October 2026)

Public contract reads now select explicit P1 rules inside the owner service's
existing read transaction. Evaluation checks the selection's view purpose,
network, runtime version and pinned database base. A selection is not storage
authority and cannot authorize canonical execution. Cleanup, cancellation and
pool admission remain owned by OWNERSHIP-1. Reusing a pooled runtime does not
reuse the previous request's selection.

Compiled component lookup first reads the stored contract bytes from that root's
database snapshot. Its key combines the contract row ID, SHA-256 of those stored
bytes, executor version and actual Wasmtime engine identity. A cache miss decodes
and compiles the same owned bytes, without another database lookup. Publication
admission inserts into that same namespace. The engine registry uses weak engine
references and checked monotonic identifiers; it does not itself retain engines.
All namespaces within a cache share its existing 256 MiB encoded-byte weight
limit. Existing separate canonical and pool caches remain separate; this is not
yet the final node-wide retained-bundle resource policy or an exact compiled-memory
measurement. Cache hits now read and hash stored bytes, an additional cost not
quantified by these correctness checks.

The held-view regression executes real Wasm before and after an actual database
rollback and republication that reuses the same contract ID and block hash. Old
and fresh views share an engine and cache, yet repeatedly return their own code's
result. Recycling then rejects the old selection and admits a new one. Additional
controls cover foreign-engine entries, the shared weight budget, invalidation,
publication admission, simulation cache suppression, and pooled cleanup.

The runtime's P1 version field is private and matched at selected transaction and
lifecycle entry. Complete immutable root/operation policy, nested-entry binding,
committee dispatch, independently locked artifacts, durable migration identities
and actual P2 activation remain required. This checkpoint does not freeze P1,
complete K2a/K2b, or resolve S2 performance and final-source qualification.

Validation covered 24 distinct tests: 20 passed in the initial focused run, the
remaining engine-isolation test passed after correcting its fixture address,
both real HTTP contract-view tests passed, and the opt-in P1 parity fixture
passed. The initial engine test requested height 1 after genesis setup left its
fixture at height 0; reading the stored address corrected the test without a
production change. HTTP coverage includes normal view/pool reuse and shutdown
while cold decode is pending. The indexer/testlib all-target check, formatting and
diff checks also passed. No extra independent review round was requested for this
intermediate checkpoint.

The P1 report matched all 11 saved logical-state stages, including receipts and
provenance, with SHA-256
`2095169ae05bd69c353561a0b462e94e98dab361c3dedf6d8ebd7983a3598332`.
Commands, successful exit statuses, log hashes, changed-source hashes and the
lead's coverage/limitations record are in `.build-cache/snapshot-cache-final/`;
the initial focused run is `.build-cache/snapshot-cache-focused.log`. These
checks establish this preparatory behavior, not final protocol-upgrade acceptance.

### Scoped P1 runtime context and committee derivation

Selected transaction execution, lifecycle and public views now bind a private,
immutable semantic context for their execution scope. Guest-store Runtime clones
inherit the same context. Nested code cannot replace it with another selection;
runtime entry and store creation reject a network or executor mismatch. Dropping
the scope restores the caller's prior context, including when an async caller is
cancelled. This guard only restores semantic context. It neither creates storage
authority nor replaces owner-service admission, retained tasks, draining, rollback
or quarantine.

Whole-call allowances, gas-to-fuel conversion, trusted system fuel and pricing
resolve from P1's retained policy. Holds, reservation conversion, settlement and
gas reporting use that same policy. A local view allowance is captured only for a
public-view selection; canonical, simulation, lifecycle and committee scopes use
the selected rules' allowance. Nested calls retain their parent's remaining fuel
without applying a fresh root allowance. No numerical charge or cap changed, and
no block budget was introduced. Unselected native/test entry still exists during
this in-tree preparation and retains its existing fixture configuration; K2b must
close unselected production entry through the actual bundle adapter.

Committee construction and refresh now enter through selected derivation. The
adapter opens a storage savepoint before selection and rolls it back after the
staking read; nested savepoints preserve any enclosing application transaction.
Selection and derivation therefore use one snapshot, including startup before
the engine starts. Purpose checks keep committee selection separate from public
views and canonical writes. The existing staking conversion, fractional voting
power rules, validator ordering and error behavior remain in P1. This is not yet
a certified historical committee identity or an engine-era handoff.

These bindings complete more of the agreed preparatory call-site wiring. They do
not provide independently linked executor artifacts, durable protocol/migration
identity, native-artifact retention, P2 activation or the final resource policy.
Final-source prerequisite reconciliation, production graph extraction and the
remaining upgrade phases are still required.

Validation passed 14 distinct tests across the initial focused run and affected
follow-up: selection purpose/snapshot checks, scope restoration and nested-store
policy inheritance, real nested success/error/refund/cleanup, root fuel bounds,
trusted view behavior, HTTP view cleanup/reuse, voting-power rounding/rollback,
and the real multi-node ordering-reward rollback/restart/late-join test. The P1
comparison again matched all 11 baseline logical-state stages, with report
SHA-256 `8da53b418e6f640689c553763f4441a557794f2cd86a6f7cc3bf4e24dad5eab8`.
Indexer/testlib all-target compilation, formatting and diff checks passed.
Evidence and lead review are in `.build-cache/selected-context-final/` and
`.build-cache/selected-context-followup/`. The first committee filter omitted its
parent test module and ran zero tests; it is excluded from acceptance evidence.
Both actual committee tests passed after correcting the filter. The follow-up
also verifies that non-public selections ignore mutable local view settings.

Separately, targeted native-stack correction run `41137129283` at `52a0cf89`
passed macOS dev and release. The lead independently validated each archived
binary and its 60-process/180-observation chain evidence. These archives do not
qualify the later context/cache changes above. The retained reviewed discovery
input is run `41110674101`, artifact `13003214982`, capture SHA-256
`4cf03721ac9cd81a8f8e75171050532ed5949e80f3cfb50c712653cc6d806702`.
Prepare one clean combined candidate, regenerate source manifests, and execute
the existing final six-cell workflow. Existing production-memory, operational
performance and consolidated phase-review gates remain separate and open.
