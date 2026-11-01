# K4: certified history and historical committee authority

Status: implementation plan revision 2, agreed by the lead and the sole independent
planning reviewer before production changes. K4 begins at verified K3 merge
`fdf6a65d3a14cf88af7271d666bf13b001849d2f` (PR 619). The planning source was
`653ad035487cbff5ae5f0f949af9d240feb6a4a9`; the subsequent K3 correction only makes
migration qualification fixtures reproducible across independent runs.

This is the second of the six remaining grouped PRs specified in the implementation
plan. Keep certified history, deterministic application closure and historical
authority together. K5/K6 add signing coordination and authorized upgrade control;
K7/K8 add activation and cross-upgrade recovery; K9 extends history transport to
cross-era cold catch-up. None of those capabilities is claimed complete by K4.

### Local implementation checkpoint

K4 is not yet fully integrated into the production reactor or ready for a PR. The local
implementation has canonical manifest/input/decision codecs, checked historical
authority, durable certificate/input append, registration-generation observations,
and restartable application-stage records. A stage retains its original K3
application records even when canonical rollback removes those applications.
Its effects, observation and remaining work commit together. Normal stages consume
one work item; finality processing may replace the remaining work with rollback
and replay. The stage-recovery API verifies the chain and rejects unjournaled
canonical effects rather than repeating a committed stage.

The stage runner uses the actual retained-runtime ownership and observation paths.
Focused local checks cover transaction interruption, reopen/retry, stale admission,
input substitution, omitted block lifecycle, rollback/replay and missing/corrupt
records. These checks do not establish complete reactor behavior or cross-platform
qualification. The durable Decided/Finalized callbacks and next-height gate are now
connected, as are certified-branch admission rules. Live block and batch handlers
now commit through owned stages, and completed-closure/committee publication has a
validated persistence API. Certified replacements now plan and execute owned
rollback stages. The reactor finality/replay driver, post-genesis startup recovery
and oversized-proof transport still need complete integration and qualification.
The Bitcoin poller now retains the complete decoded Bitcoin block, including its
header and transaction witnesses. Its checked history conversion validates the
requested hash, parent, size and Bitcoin commitments, and replay reconstructs the
same block from the retained body. Synthetic transaction-only ingress is test-only.
The poller-to-history round trip is covered locally. Live values and proposal
signatures now use the canonical descriptor as described below.
Baseline composition now derives KPM1 and the genesis-era context from the selected
executor reference, its committed parameter sources, the verified native manifest,
and an explicit equal-schema no-op migration. The consensus/coordinator reference
binds implementation source, all-target resolved dependency features, aliases,
target conditions and locked dependency checksums/revisions. The node build checks
that reference before and after compilation. References are not refreshed implicitly;
this baseline remains unreleased while K4 is under development.
Baseline composition and foreign-context rejection have focused local coverage.
The production executor-session startup now reserves the manifest and genesis
context before native initialization, then records the initial registration
observation and committee through the retained executor. The manifest and genesis
reservation commit atomically. Reopening verifies the stored manifest, genesis
observation and closure; before any certified decision, the canonical lineage must
still match genesis. Ready startup does not republish native initialization stages.
Old populated databases are preserved and refused with an explicit
history-unavailable/rebuild-required error. Local checks cover a new connection,
corrupt records, cancellation during initialization and resumption of its suffix.
Live values now require complete validated inputs. ValueId and proposal-part signing
bind the same canonical descriptor, including witnesses and protocol context.
Proposal streaming and native sync use the new descriptor/body framing; old
hash-only values are rejected. The proposal receiver checks the persisted context
and full block input against local Bitcoin ingress. Batch validation retains the
original immutable value while host I/O runs. Replay exclusions have a separate
execution list and cannot change the certified identity.
Startup now selects its height and committee from the certified frontier and
historical authority, without deleting a batch suffix or consulting MAX(batches).
An unfinished closure currently prevents engine startup until recovery is connected.
History readers now load authenticated retained inputs instead of reconstructing
values from transaction IDs. Their paging and replay-query bounds still need work.
Five focused public-wire tests passed locally: identity/signature binding, protobuf/
stream/serde round trips, malformed and legacy rejection, full Bitcoin block input,
and maximal batch-body framing. The latter covers proposal-stream encoding and
reserves outer-envelope space; complete signed gossip framing is still pending.
The production library compiles. The broader test compile currently reports 32
errors in old constructors/fields/imports and the removed transaction resolver test.
Migrate these fixtures to real inputs and certified genesis; do not restore a
production hash-only fallback just to preserve old fixtures.
Decided now retains the exact input and verified original proof in a FULL-WAL
transaction before acknowledging. A missing body leaves the callback pending;
failed persistence cannot acknowledge it. Finalized reads the durable input even
if the volatile proposal cache has been lost and retains at most one verified proof
augmentation. Next remains withheld until the entire closure and next authority
are durable. Per-block and per-rollback committee refreshes have been removed.
The new branch index records the certified Bitcoin prefix in the same transaction
as decision persistence. Replacements close historical intervals rather than erase
them, preserving a batch's original anchor during later replay. Proposal admission,
post-I/O validation and native value sync reject invalid branch structure. Typed
structural rejection remains distinct from a database or integrity failure.
Two focused local checks passed: actual executor-session/Malachite callback methods
(including interrupted append and reopen), and isolated branch-index transitions.
The latter supplies persistence fixtures and does not establish certificate or
closure validation. The callback check includes a validly signed pre-anchor batch
that durable admission rejects, and an initial Bitcoin height of 100.
Live block and batch handlers now bind their retained certified input and commit
effects, original K3 application records, registration observation and stage progress
under one owned transaction. Deterministically skipped batches also commit through
that stage transaction. Batch obligations, metrics and notifications update only
after commit. Pruning waits until the closure is complete.
The KCC1 completed-closure record commits the decision, preceding closure, plan,
complete stage chain, resulting canonical position, certified Bitcoin tip,
registration observation and next committee. Publishing the record, committee and
closed frontier is one FULL-WAL transaction. Publication requires no remaining work
and an applied Bitcoin tip matching the certified branch. Exact retries return the
retained record. Startup verifies the completed stage chain and canonical position
before selecting its next committee.
The focused callback qualification now runs actual block/batch handlers through
four certified decisions: a block at Bitcoin height 100, an empty executed batch,
an unrecognized batch recorded without application, and a same-height replacement.
It injects application-stage, rollback-stage and closure-publication failures,
checks rollback and retry, reopens the database, verifies historical records and
releases the next-height gate only after completion. Replacement plans persist the
rollback to height 99 before executing their retained block. The rollback transaction
includes maintenance, canonical lineage truncation, registration observation and
stage progress. Native genesis and historical authority remain intact.
Local Bitcoin rollback notifications now invalidate candidate caches without changing
canonical execution or certified history. The proposer admits same-height replacements
against D and rejects exact duplicates. This local qualification passed two tests in
34.95 seconds after a 39.56-second build; evidence is retained in
`.build-cache/k4-replacement-stages-final.log`.
For this qualification, the no-obligation finality stage is driven explicitly using
the real finality check and owned stage APIs. The production event loop does not yet
drive finality stages or publish completion automatically. Full event-loop recovery,
finality replay scheduling, obsolete unit-fixture migration and proof paging remain
unfinished. This checkpoint is not a merge candidate.
Both explicit link sets still need their complete integration acceptance evidence.

## Result and boundaries

A fresh baseline node records a contiguous authenticated consensus history with
exact witness-inclusive inputs. It applies that history through durable,
restartable closure stages and derives the authority for the next consensus height
only after the complete closure. Local Bitcoin event timing cannot choose canonical
state or the signing committee. Preserve old populated databases and expose their
unavailable certified history explicitly; never manufacture certificates or delete
state to enable an upgrade.

Implement the Site's KPM1 fixed-order encoding and domain-separated SHA-256,
checked sorted format/ABI lists and explicit no-op migration identity. The baseline
definition commits actual executor, consensus/codec, coordinator-rules-v1,
parameters, native artifacts and storage/bridge schemas. No placeholder roots or
mutable path-only identities. K3's Baseline execution records remain Baseline.

The baseline accepts BatchV1 and BlockV1. Common control framing does not enable
unsigned Schedule, Cancel or Postpone commands. Actual control authorization is K6.
There is no block gas budget, gas-number change or new transaction ordering here.

## Exact inputs and identities

Use one canonical descriptor for ValueId and proposal-part signing. It binds chain,
era/codec context, command kind, ordered input count, lengths and witness-inclusive
body digest. A batch includes its anchor. A block includes height, hash, parent,
full header and raw-body commitment. Keep the complete original block bytes,
including transactions that recognition does not select as Kontor operations.
Validate header identity, parent, Bitcoin transaction/witness commitments and raw
digest before accepting the input as available.

The decision identity binds global consensus height, predecessor decision identity,
era/protocol/committee context and value identity. Valid certificate signer subsets
and later proof augmentation must produce the same decision, closure and committee
identities. Store exact certificate bytes separately.

Decoders validate lengths before allocation. Decode each transaction inside its
declared slice and reject trailing or noncanonical bytes. Do not preallocate from
an unchecked claimed transaction count. Proposers select the dependency-ordered
prefix fitting wire admission, leaving the rest in the mempool. Once work is
certified, local resource pressure must not truncate, reorder or invalidate it.

## Durable records and callbacks

- `certified_decisions`: chain/height uniqueness, predecessor and decision digests,
  era/protocol/codec/committee identities, descriptor, exact-input identity and
  original proof. Append requires the predecessor and exact equality on retries.
- `certified_inputs`: original ordered bodies with checked counts, lengths and
  digests. Retain the inputs required to reconstruct historical decisions.
- `decision_closures`: prior closure digest, command outcomes, newly eligible work,
  resulting K3 application lineage, authenticated branch tip and next committee.
- `historical_committees`: exact ordered executor result, checked bridge identity
  and registration-generation provenance at deterministic application positions.
- Closure-stage progress: exact input/output lineages and durable outcomes needed
  to resume without repeating committed effects.

Certified decisions, closures and historical authority are monotonic records.
Canonical rollback must not delete them. Track received/unverified, contiguous
authenticated, closed/applied and next-engine frontiers separately. Remove startup
inference from `MAX(batches)` and deletion of a supposedly speculative suffix.

On Decided, authenticate the exact value and proof using the independently
established committee for C. Persist the validated certificate and required raw
inputs durably before acknowledging. Missing bytes produce bounded pending work;
never hold the writer transaction while waiting for network or Bitcoin I/O.
Ingestion and transport continue.

Finalized may add one validated proof augmentation. Keep the original proof and
an idempotent augmentation slot; later equivalent proofs are ignored. Proof choice
does not change deterministic execution or authority. Withhold Next(C+1) until the
complete closure and next committee are durable.

## Restartable application closure

Use existing exact-position owned units, not one writer transaction spanning an
entire prefix. Each stage atomically commits its effects, K3 lineage and progress.
Make the stage's registration observation durable before another canonical stage
can run. During an unfinished closure, block competing canonical application and
Next while allowing ingestion and bounded transport.

Observe registration state immediately after rollback and before replay. Otherwise
an effective exit and rejoin within a closure could disappear from final-state-only
comparison. A restart verifies stage input/output lineages, reconstructs volatile
queues/cursors and returns committed outcomes on exact retries. Publish the final
closure and next committee only after the deterministic worklist finishes.

Keep the future activation seam after H's old-protocol transactions and lifecycle
have committed, before the separate migration-owned unit. This preserves K3's
committed-entry snapshot requirement.

## Certified Bitcoin branch and committee provenance

Derive canonical branch D from ordered certified Block commands. A command extends
the tip or replaces the first differing block after a common ancestor. Check parent
D[h-1], reject gaps/repeats and support same-height replacement in candidate caches.
The baseline reservation persists the configured first Bitcoin height H0 >= 1,
which is already committed by ChainId. Reopening with another height fails.
Native storage block 0 and the scheduling cursor H0-1 are not Bitcoin anchors.
Before the first certified Block at exactly H0, reject every Batch, including empty
batches. That first block fixes parent P0. Replacement at H0 must retain P0;
replacement below H0 or a reorg changing P0 stops progression and requires explicit
recovery outside this baseline, never automatic boundary reset.
Finality recovery can roll execution back to H0-1 and replay H0 without requiring
a Bitcoin SQL row at H0-1. Native genesis, the immutable parent, certified journal
and historical committees must survive. An empty applied prefix does not reset the
authenticated branch. The sole planning reviewer explicitly agreed this clarification
against cf1cc01bc4efc88b286175bd4bd58f49f44eb53a before implementation; complete
live finality-replay acceptance remains pending.
Live voting also checks the locally validated Bitcoin best chain. Local reorg
notifications invalidate candidates; they do not directly rewrite committed state
or authority.

Apply a certified replacement by rollback to h-1 and execution of its retained
exact block. Replay certified inputs even if bitcoind now serves another branch.
Preserve K3 identities and decision-scoped exclusions. A deferred batch can wait
for local reconstruction only if its anchor was valid in D at the original
decision position. Quorum cannot authorize a structurally future anchor. Missing
bytes mean retrieve/wait, not skip. Preserve the existing finality/dependency rules
selected by coordinator-rules-v1.

Derive committee(C+1) once, after closure. Preserve executor ordering and power;
reject duplicate keys or invalid bridge representations rather than silently
sorting or deduplicating. Invalid or zero authority stops progression with a typed
status. Committee(C) remains fixed while C is applied or replayed.

Registration observations include holder, key, activation/deactivation/status and
decision/stage/lineage or genesis provenance. Same-key replacement after rollback
is a distinct generation even at an equal activation height. Unrelated membership
churn does not renew consent. Trusted observations use native system views and
remain independent of the public view gas cap. No native-contract migration is
needed for this interface.

## Preserve old executors while adding the observer

Use two explicit link sets:

| Link set | Implementations |
| --- | --- |
| `legacy-qualification` | Original first and original second |
| `k4-node` | Original first and a new observer implementation on the existing second Wasmtime revision |

Freeze one source root mirroring the original logical paths, with both manifests,
locks, definition bytes, complete local dependency/include closure, inherited
configuration and build support. Reject escapes into mutable current sources.
Old definition bytes and IDs must reproduce unchanged after relocation.

The new observer gets its own source identity, recipe, definition and exported
factory mapping. Original second remains explicitly qualification-only. Never map
its ID to the new observer or use positional first/second fallback for an unknown
definition. Original first remains the available historical production executor.

Do not link independently compiled original second and observer together because
their native prefixes would collide. Preserve the existing strict ownership audit.
This design needs neither another Wasmtime fork revision nor a shared-dependency
facade. Reuse the original-first artifact across link sets only when verified build
inputs match. If later policy requires all three definitions simultaneously in the
production node, revisit the namespace design explicitly.

## Framing and bounded baseline recovery

| Item | Bound |
| --- | ---: |
| KPM1 manifest | 65,536 bytes |
| Command descriptor | 1,024 bytes |
| Canonical batch body, including count and length prefixes | 4,186,112 bytes |
| Individual raw transaction | 4,000,000 bytes |
| Full raw Bitcoin block | 4,000,000 bytes, plus existing Bitcoin validity/weight checks |
| Complete pubsub wire message | 4,194,304 bytes |
| Existing native sync request / response | 1,048,576 / 10,485,760 bytes |
| History request | 1,024 bytes |
| History page payload | 1,048,576 bytes |
| Complete history response frame | 1,056,768 bytes |
| Retained proofs per decision | Original plus one augmentation |

Transaction count is bounded by remaining framed bytes divided by four before
iteration. Certificate logical size is checked `1024 + 96*N`, where N comes from
the established inclusion committee. The current address is 20 bytes and signature
64 bytes. Require distinct known signers and no extensions; do not invent a fixed
validator-count cap.

The 8 KiB pubsub allowance is provisional until actual complete encoding proves
fit. Test a maximal transaction and many minimal transactions through descriptor,
protobuf, stream, signature and gossip framing. A local preflight of the existing
encoders passed, but it does not replace tests of K4's completed encoding. Correct
the implementation or explicitly revise the limit before freezing the baseline if
those tests fail.

Proof paging is required in K4, including proofs exceeding the native 10 MiB sync
frame. Requests/pages bind decision, proof digest, position and total. Reject gaps,
overlap and mixed proofs. Validate total size from the known committee before
accepting it; verify incrementally with bounded buffers and duplicate-signer
tracking. Disk staging remains untrusted until validation completes. Integrate
this into actual journal/engine recovery, not an oversized reassembled native sync
message. K9 adds cross-era exchange, cold catch-up orchestration and discovery.

Pending descriptors: at most 16 and 8 MiB in total. Unverified descriptors: at most
four and 1 MiB. Raw untrusted reassembly: at most 16 MiB. Separate body/proof staging
from descriptor pools so a large known committee is not limited by the unknown
descriptor pool. Reserve admission for the next required decision; charge buffers
and release them on cancellation/rejection. Saturation means retry/backpressure,
not protocol invalidity or dropped certified work.

## Startup and acceptance

Create an explicit idempotent genesis predecessor and initial committee. K3 Ready
lineage alone does not prove certified history. Validate contiguous immutable
records on startup, resume unfinished stages from retained bytes and start the
engine at the resulting global frontier. Preserve old databases in an explicit
inspection/rebuild-required mode, without fabricated authority or history.

Required evidence includes:

- Golden encodings and negative decoder cases for manifests, values, committees
  and decisions; altered witnesses, ordering, empty bodies, wrong headers/parents,
  digests, trailing bytes and overlong lengths.
- Equivalent valid certificate subsets with identical deterministic identities;
  rejection of duplicate/unknown signers, wrong context/round/value/committee and
  insufficient power.
- Failure/crash injection around append and every closure-stage commit, reopen
  retry, and rejection of corruption/gaps/conflicts without deleting evidence.
- Actual reactor Decided/Finalized interleavings, WAL redelivery, restart, delayed
  inputs, invalid future anchors, finality replay and local best-chain disagreement.
  Compare receipts, state, lineage and authority across event permutations.
- Committee churn, intermediate exit/rejoin, same-height branch replacement,
  zero power, duplicate keys and preservation of earlier authority after rollback.
- Trusted registration observation with public view gas set to zero; exact retained
  graph/reactor callers and independence from API pool availability.
- Both old definitions reproduced from frozen inputs; both old graphs still
  build and qualify; actual K4 adapters run original first and the new observer;
  source-root mutation, escape and substitution rejection; unchanged native audits.
- Complete framing limits and real proof recovery above 10 MiB, including mixed,
  reordered/interrupted pages, duplicates, saturation, cancellation and restart.

Use the existing mock Bitcoin service and real linked-node qualification harness.
Complete focused local checks and one consolidated lead plus independent review
before a coherent final CI candidate. Preserve scoped release-three/bounded-dev
coverage and the operator's CI cost policy. No performance campaign is reopened.


## Finality replay clarification (1 November 2026)

The sole planning reviewer explicitly agreed this policy against checkpoint
`fe1b14ec8d22b4effd0f95bf5c2bf22e05e57ba0`. It completes the deterministic
replacement rules below; implementation and acceptance remain pending.

At finality verdict C, freeze the surviving branch intervals at that prefix.
For each replayed Bitcoin height, select the D interval containing C. A batch is
eligible only when its original decision is at most C, lies in that same interval,
and names the matching anchor height and hash. An A-to-B-to-A replacement creates
a new incarnation of A. It must not resurrect batches from the first A interval.
Unchanged lower intervals retain their eligible batches.

Roll back to the minimum failed anchor minus one, preserving the native baseline.
Execute selected blocks in ascending Bitcoin height, each followed by all eligible
batches at that anchor in original consensus order, including passing and not-yet-due
batches. Retain the existing block transaction and lifecycle ordering.

Filter direct exclusions by the same surviving interval rule before deriving
subsequent unavailable descendants. This includes exclusion seeds below the rollback
height. Preserve the existing confirmation/deadline applicability predicate and
decision attribution. A later retained re-decision may restore a parent's output
availability for subsequent work. Effective descendant exclusions belong only to
that replay attempt, never permanent global child-exclusion rows.

Bind each frozen attempt to C, the input lineage, selected interval identities,
applicable direct exclusions and derived per-decision drops. Resume those exact
subsets after a crash; do not derive them from partially replayed SQL state. Evaluate
finality again after finishing the attempt. Later verdicts recompute applicability.
Historical certificate verification still processes the earlier certified history
and its authority transitions, including subsequently displaced branches.

Replace the intermediate suffix-vector representation before integrating arbitrary
replay: append immutable ordered plan rows once, commit their count and ordered
digest, and atomically advance an indexed cursor with each stage's effects and
observation. Build plans in bounded pages into unpublished staging rows; publish the
completed plan and verdict metadata before rollback. Recover the chain once and
load one bounded decision body at a time. Use indexed attempt-scoped availability
state where needed. Do not introduce a replay-count cap, truncate accepted work, or
copy the remaining suffix into every stage. Bitcoin depth does not bound the number
of batches at one anchor.

Acceptance includes A-to-B-to-A without resurrection, retained lower-anchor batches,
superseded exclusion seeds, reorg-healed exclusions, parent re-decision between
children, passing batches sharing a failed anchor, interrupted replay, and many
batches at shallow Bitcoin depth with linear worklist storage and bounded iteration.


### Bounded work-plan implementation checkpoint

The intermediate remaining-work vectors have now been replaced in production stage
records and progress by a fixed-size cursor: plan identity, ordinal, count and the
consumed-prefix digest. Initial block/batch/replacement work uses this representation.
Each work item is stored once in indexed rows. Plan identity commits the closure,
originating stage head, input canonical position, item count and ordered digest.
Ordinary stages consume exactly one item. Only a finality stage at the end of its
plan may install a new plan, and that plan must start at zero and match that exact
stage origin. A cursor cannot skip work or reuse a plan from another lineage.

Builders append at most 128 items per transaction call, with stale-draft checks.
This is a construction page size, not an accepted-work limit. Partial drafts remain
unpublished and cannot authorize execution. Publication verifies the complete ordered
plan and happens in the same owned transaction as finality stage completion. Normal
stage processing loads one indexed item, without copying or scanning the suffix.
Recovery verifies each installed plan once and then its stage/cursor chain.

Focused local qualification passed two tests in 47.36 seconds after a 33.78-second
build (`.build-cache/k4-work-cursor-replay.log`). It covers a 512-item paged plan,
interrupted construction and reopen, stale/published append rejection, missing and
changed item rejection, forged cursor rejection, linear encoded item storage, and
foreign-origin plan rejection through an actual owned finality stage. An injected
stage-write failure rolls back replay-plan publication. Retrying then uses actual
rollback and block handlers to replay retained input and restores the same canonical
lineage. This replay plan is deliberately supplied by the test, so it proves the
stage/cursor machinery, not finality verdict selection or complete event-loop recovery.
The broad old unit fixtures are still awaiting their certified-genesis adaptation.

Remaining K4 integration includes plan-scoped branch-incarnation and exclusion
commitments, bounded finality-plan construction, replacing the volatile live driver,
pre-engine unfinished-closure recovery, proof transport bounds, and complete grouped
acceptance/review. The existing replay policy above remains the agreed target.

### Replay selection checkpoint

Certified append now records an indexed Bitcoin height, hash and command kind
alongside the immutable decision. Authenticated loads verify those index fields
against the decoded decision. Replay selection reads metadata in bounded pages of
64 decisions, ordered by Bitcoin anchor and original consensus height. It selects
the branch interval at the specified verdict prefix and requires each batch to
belong to that same interval. Returning to an earlier block hash does not revive
its superseded batches. Older verdicts still resolve their original intervals.

Exclusion scanning also uses bounded pages and the existing confirmation/deadline
and execution-attribution predicate. It filters seeds using the same interval
eligibility, including seeds below the replay start. Its continuation cursor follows
scanned rows, so an entirely superseded page does not hide later surviving seeds.
These APIs select replay inputs; the live finality planner has not yet been connected
to them, and freezing their results across rollback remains pending.

Two focused checks passed locally in 47.28 seconds after a 48.22-second build
(`.build-cache/k4-replay-selection.log`). The isolated index fixtures cover returning
blocks without batch resurrection, retained lower-anchor batches, anchor order when
consensus order differs, more than one metadata page, historical-prefix stability,
future-prefix rejection, a fully filtered exclusion page, confirmation attribution
and reorg-healed applicability. The actual authenticated callback fixture rejects a
changed execution index. Index fixtures do not prove that a finality verdict
legitimately produced their synthetic exclusions or replace full reactor acceptance.


### Frozen batch replay inputs

Replay work items now commit a stored input record binding the verdict and its
pre-state lineage, originating closure stage, original certified decision, selected
branch interval, direct/effective exclusion receipt, and exact dropped transaction
positions. Positions preserve occurrence-level filtering even when a raw batch
contains repeated transaction IDs. The record is checked against the retained full
input and historical branch interval before admission. Only an unpublished plan at
its finality pre-state can accept these records; publication commits their digests
through the ordered work list.

The actual batch handler validates the supplied execution subset against that record
before parsing or effects. It uses the frozen exclusion receipt instead of querying
mutable confirmation/exclusion state. Replay requires the selected anchor to be the
current canonical tip. Application-stage persistence and recovery also verify that
the resulting batch application carries the same frozen receipt. Ordinary first
execution keeps its existing path.

The focused callback checks passed locally in 59.73 seconds after a 39.33-second
build (`.build-cache/k4-frozen-positions.log`, SHA-256
`b57e4982919e8704849c778b5fb55ae1635f8e6082ca3202ce70188aa9d7f2a7`).
They include actual rollback/block/batch handlers, database reopen, a fully excluded
batch with no live direct-exclusion rows, an incorrect supplied subset, atomic retry
of plan publication and batch-stage failure, changed stored input rejection at plan
publication, wrong interval/origin/decision rejection, and repeated-transaction
position handling. The plan and direct exclusion in this fixture are explicitly
supplied by the test. This proves frozen-input consumption and persistence, not
legitimate finality verdict derivation or complete reactor/startup recovery.

Remaining integration is the bounded finality planner: capture the applicable seed
set before rollback, derive descendants using indexed attempt-scoped availability,
freeze each selected batch and publish the complete verdict/work plan atomically.
The volatile live replay driver and pre-engine recovery still need replacement,
followed by complete K4 acceptance and the grouped review. No PR or CI run has been
started for these intermediate checkpoints.
