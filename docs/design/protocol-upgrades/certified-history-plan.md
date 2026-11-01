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

### Current implementation status, 1 November 2026

K4 production integration is implemented locally. The reactor persists verified
certificates and exact inputs before acknowledgement, applies durable closure
stages, derives successor authority from completed execution, and resumes retained
work before starting consensus. Local checks cover certified branch replacement,
finality replay, interrupted recovery, committee exit, confirmation accounting,
cluster catch-up and ordinary maximum-size signed gossip delivery.

The independently linked first/observer node passed its local ARM64 dev semantic
and certified-history qualification. Both linked graphs also matched all eleven
stages of the preserved historical execution archive at `e9033433`. That archive
has no certificate history and is used only for execution comparison. Separate
signed-certificate fixtures establish the authority and closure checks.

Consolidated lead and independent review, final-candidate scoped CI and merge are
still required. The newest test-helper cleanup changes the unreleased observer's
source identity; earlier linked evidence retains its original source binding and
is not presented as a build of that new identity. Final candidate qualification
must use the current definitions. No remote CI has been launched for K4.

The implementation checkpoints below are chronological development records. Their
statements about unfinished integration describe their recorded checkpoint, not
current outstanding tasks. The execution ledger contains the later results. K4
does not implement K5/K6 engine handoff and upgrade authorization, K7/K8 activation
and cross-upgrade replay, or K9 cross-era retrieval.

### Operator scope correction, 1 November 2026

Oversized-certificate paging is deferred outside this goal. It is not a K4 or
later-phase prerequisite or acceptance gate. The operator rejected pursuing this
extreme-committee case as a current need. Earlier checkpoint references below to
proof paging, oversized-proof recovery or bounded proof serving are historical
and superseded by this correction.

Keep normal bounded proposal streaming/sync batching, verified exact history and
cross-era catch-up. Do not claim oversized-certificate support, silently truncate
certified work or introduce a consensus committee cap. No new page protocol, HTTP
source configuration, disk-staging project or early engine handoff is required
solely for oversized proofs. The tested incremental verifier and bounded journal
reads remain useful. Managed lifecycle integration and signing/generation fences
remain in K5/K6; K9 retains necessary cross-era history retrieval.

### Historical local implementation checkpoint

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
still need complete integration and qualification in this historical checkpoint.
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
The unreleased registration observer can record an empty active set after the
last validator exits. This does not authorize an empty committee: closure
publication still rejects successor authority and withholds the next consensus
height. The exit, registration observation and stage remain committed, so restart
reaches the same authority gate without repeating or undoing the exit. Watched
holders remain validated even when the active set is empty. The frozen K3
committee derivation and executor definitions remain unchanged; correcting the
draft observer explicitly changes its definition and the draft baseline identity.
Existing database reservations cannot be rebound to that changed identity.
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

Individual-proof paging and its proposed request/page frame formats are deferred
by the operator correction above. Existing native sync batches remain bounded by
their response limit; do not assemble an oversized native response or claim it is
supported. K9 still implements the required cross-era historical exchange.

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
- Existing complete framing limits and bounded native sync behavior, including
  saturation, cancellation and restart. Oversized-proof paging qualification is
  explicitly deferred.

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

### Automatic finality planner checkpoint

The planner now scans executed overdue transactions and applicable historical
exclusions in bounded pages. Each step commits only staging data. It freezes the
rollback boundary and direct seeds before deriving replay subsets, using indexed
attempt-scoped availability to propagate descendant drops and restore availability
when a later retained transaction is kept. Each selected batch binds its exact
dropped positions and original branch interval. A sealed verdict commits the seed
count and ordered digest; the work-plan identity includes that verdict.

Plan publication and insertion of direct exclusions occur in the owned finality
stage transaction, before rollback. Descendant exclusions remain in the attempt's
frozen inputs. The new closure driver executes saved work from retained certified
bodies, reevaluates finality after replay, and publishes the completed closure.
It is exercised directly by qualification; live consensus callbacks and pre-engine
startup recovery have not yet been switched to this driver.

The focused test now reaches twelve certified decisions. A parent issued in a batch
at Bitcoin height 100 misses its deadline at 106. Its child, batched at 101, is not
yet due. Automatic planning rolls back and replays the selected history, excludes
both from this attempt, and persists only the parent's direct exclusion. The test
interrupts a planner seed write and finality-stage publication, verifies rollback
of partial writes, resumes planning through a reopened connection, checks the
frozen child subset, and completes replay through actual block and batch handlers.

Both focused tests passed in 75.36 seconds after a 29.83-second build. Evidence:
`.build-cache/k4-finality-final.log`, SHA-256
`eb7a5ce6bb39920c2dcdeeae00f7bef0ece32a96db8ae192553dd6a95d0d053c`.
The expanded debug fixture initially exhausted the Rust test thread's native stack.
GDB identified a roughly 1.5 MiB poll frame in its large async body. Separating the
fixture into sequential phase helpers resolved it with the default thread stack.
Pulley stack limits, production runtime limits and execution semantics were unchanged.

This is local planner/driver integration evidence, not full K4 acceptance. Remaining
work includes replacing the volatile live driver, recovery before engine startup,
bounded proof transport, adapting the old unit fixtures, broader replay-policy
cases, independent graph acceptance and the consolidated K4 review. No new PR,
remote CI campaign, or performance investigation was started for this checkpoint.

### Live certified execution checkpoint

Live `advance` now consumes the unfinished authenticated decision through the saved
closure driver. The old volatile replay queue, local-block redelivery dependency,
and block-decline path have been removed from live execution. A durable decision
ends pending proposal work. Execution may finish after Decided persistence and
before Finalized arrives, but Next is released only after the completed closure
establishes the next historical committee. Finalized verifies its proof against
retained inputs; redelivery does not execute completed effects again. Cancellation
of a particular Next receiver does not erase durable completion.

Batch notifications and mempool suppression follow committed execution. Empty
executed batches still emit a heartbeat. A conflicting locally buffered block stays
a proposal candidate while the certified block executes. Optional test finality
observation state is maintained separately and cannot select canonical replay work.
Observation events are emitted after stage publication; failed publication restores
their temporary tracking state. Normal nodes do not build that in-memory tracking
set. Full certified inputs remain retained when legacy raw-body caches are pruned.

The focused fixture now closes fourteen decisions. New coverage supplies a
conflicting local block and no volatile proposal cache, interrupts live application,
checks that Next remains pending, retries from saved work, repeats Finalized without
new effects, and handles an empty batch that completed before Finalized. It verifies
exactly one batch heartbeat. Both tests passed in 75.36 seconds after a 29.13-second
build. Evidence: `.build-cache/k4-live-final.log`, SHA-256
`eda706f0c076b58f07bf1a510120897fcc4687586286f4acf23835060f44a46b`.

Startup still refuses unfinished closure work. The next extraction must share the
actual canonical execution handlers with an engine-independent recovery context,
then launch Malachite only after recovery and historical committee selection.
Old broad fixtures, obsolete executor I/O capabilities, bounded proof serving,
broader replay-policy cases, independent graph acceptance and complete K4 review
remain. These local checks do not establish full node restart or cluster acceptance.

### Agreed engine-independent recovery boundary

The sole planning reviewer explicitly agrees to extracting the shared canonical
execution context. This is planning agreement, not review of its implementation.
The context owns the existing session, executor, recognizer, network/protocol
context, applied tip, pruning bounds and owner service. Startup moves that same
context into the Reactor after recovery, without duplicating mutable tip/session
state or opening another writer. Admission, signing and Next remain outside it.

The shared interface consumes the next durable work item and exact retained input,
preserving the existing owned transaction for effects, K3 applications, registration
observation and stage/cursor advancement. It exposes bounded progression between
planning pages as well as committed execution stages. Ownership must settle before
yielding. Committed outcomes carry the data needed for live cache invalidation,
mempool suppression and notifications; observer failure cannot make a committed
operation appear retryable. Startup reconstructs durable obligations and may omit
ephemeral notifications.

Startup must complete/verify native initialization, construct this context, and
load the persisted prune watermark before recovery, even if pruning is disabled.
Validate saved stage/work history once, resume published cursors and unfinished
planning drafts, complete the closure, verify the resulting canonical position and
successor committee, and release execution ownership. Only then prepare the mempool
against the recovered position and start Malachite. Do not reuse pre-recovery tip
values. At the baseline boundary the scheduling tip is `(H0 - 1, None)`, not native
block zero's mock hash; recover the applied position independently of authenticated D.

Recovery uses no current bitcoind acceptance, proposal cache or block redelivery.
Cancellation settles ownership and leaves no running engine or ready signal while
closure work is unfinished. Acceptance must reopen midway through block/lifecycle,
rollback, replay and planning, recover without an engine, and compare state,
lineage, cursor and committee with uninterrupted execution. Include a nontrivial
starting height and persisted pruning watermark. Keeping the existing Executor
trait temporarily is acceptable if recovery cannot invoke its admission/RPC methods.

### Shared execution context and pre-engine recovery checkpoint

The Reactor now owns one `ExecutionContext` containing its session, executor,
recognizer, protocol/network context, applied position, pruning bounds and owner
service. Owned block/lifecycle, batch and rollback handlers execute on this context.
The shared closure step consumes retained inputs and published work, returning only
after a settled planning page or application stage. Live proposal-cache cleanup,
mempool suppression, metrics and notifications consume committed results outside
canonical execution. Optional observation failures cannot make committed work look
retryable. The rollback tip/hash read now occurs inside the owned transaction.

Production startup invokes recovery after native initialization and before initial
mempool preparation or Malachite startup. Recovery loads the persisted prune watermark
regardless of current pruning configuration, validates saved stages, reconstructs
the actual applied position, and resumes unfinished work. Native block zero maps to
scheduling position `(H0 - 1, None)`. Shutdown is honored between settled steps;
unfinished closure work cannot reach engine startup. Completed state and historical
successor authority are verified before passing the same execution context to the
live Reactor. Initial mempool recognition uses the recovered position.

Focused qualification now closes fifteen decisions. Before initial engine creation
it checks the nontrivial H0=100 baseline position. After stopping the engine it
certifies a replacement at 107, closes/reopens executor sessions, exercises shutdown,
rejects rollback below a persisted prune watermark even with pruning disabled,
resumes after rollback to 106, interrupts block/lifecycle stage persistence and
finality-plan publication, and completes recovery using an unreachable Bitcoin RPC
endpoint. It checks canonical lineage/cursor, ownership settlement, restored tip,
next committee and idempotent completed restart. The existing automatic finality
replay and live callback tests run through the same shared step driver.

`cargo test --locked -p indexer --features protocol-qualification --test certified_callbacks -- --nocapture`
passed both tests in 87.91 seconds after a 41.05-second debug build. Log:
`.build-cache/k4-recovery-test3.log`; SHA-256
`d875160300c64ceca2ef9523662b67493a4f5e671518c36199bdadc227a8ecd5`.
Unreleased coordinator definition:
`f38d0deeee0199208889046c695bf02e1e2eab10d2c110305e8b78f7da657016`.
Two preceding compile attempts exposed fixture-only errors (a missing `Ok(())` and
a private draft-field assertion); both were corrected before this passing run.

This is actual shared-handler and engine-free recovery evidence, not full process
restart or cluster acceptance. Remaining recovery coverage includes interruption
inside multi-page planning and batch replay with reopened executor sessions and
comparison against uninterrupted execution. Broader replay-policy cases, legacy
unit-fixture adaptation, bounded proof serving, independent graph acceptance and
consolidated K4 review remain. No remote CI, performance campaign or merge was
performed for this checkpoint.

### Interrupted finality/replay parity checkpoint

A frozen database immediately before the parent-deadline verdict is now forked into
uninterrupted and interrupted executions. Both fork contexts use fresh actual executor
sessions and have no engine handle. The interrupted path reopens between multiple
planning pages, after rollback and after each replayed batch. A failed replay-stage
commit must leave every persistent table unchanged before reopening. Completion must
match the uninterrupted path's entire typed SQL snapshot, including receipt-stream
metadata, frozen planning work, replay inputs, canonical application lineage,
registration observations and historical authority. No tables are excluded from
this comparison. The fixture also compares the completed closure and applied tip.

The focused callback/branch tests passed (2 tests, 115.15s; build 40.67s). Evidence:
`.build-cache/k4-replay-parity.log`, SHA-256
`212aeeb8bce16da71c31a33c6d049305fe20f6a5f6c387e7cc9961aa8e69bd10`;
coordinator definition
`346ff34104c8241da63abc0661945a72d55831b8f793e06b47cf81bddc1d54ef`.
This closes the interrupted multi-page planning and frozen-batch replay parity gap
for the parent/child deadline scenario. Wider replay-policy scenarios and complete
node/cluster integration remain required.

The broader unit-test compile was attempted separately and failed with 136 errors.
Most are test-only references to the fields/helpers moved into ExecutionContext;
the rest include old hash-only value constructors, obsolete replay-queue assertions
and an obsolete transaction-resolver test. These must be adapted, without restoring
production fallbacks or weakening the behavioral assertions. No unit-suite pass or
full K4 acceptance is claimed by the focused regression result.


### Retained and certified harness split, 1 November 2026

The sole reviewer agreed against 8d59b615 to preserve per-graph execution, storage,
root ownership, lifecycle, failure atomicity, journal rollback and replay checks
separately from current certified-baseline checks. Original first remains selectable
for its exact definition and cannot acquire the observer capability. The old
execution-only fixture no longer attempts to start K4 consensus from uncertified
state. Its synthetic batch records establish adapter/journal behavior; the existing
certified fixture establishes actual current caller behavior.

The k4-node executable now invokes the fifteen-decision certified fixture once
through the linked observer factory. Its result sits outside per-graph outcome
equality, and both local and cross-platform evidence gates require the complete
result with observer definition and baseline identity bindings. The historical
semantic fixture is restored unchanged; the new issuance helper is separate.
Local adapter, certified integration and gate regressions pass, as recorded in the
ledger. The combined independently linked executable has not yet been rebuilt or
run at this checkpoint, and this is not full K4 acceptance.
