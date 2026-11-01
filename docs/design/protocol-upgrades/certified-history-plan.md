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

K4 is not yet integrated into the production reactor or ready for a PR. The local
implementation has canonical manifest/input/decision codecs, checked historical
authority, durable certificate/input append, registration-generation observations,
and restartable application-stage records. A stage retains its original K3
application records even when canonical rollback removes those applications.
Its effects, observation and remaining work commit together. Normal stages consume
one work item; finality processing may replace the remaining work with rollback
and replay. Startup recovery verifies the stage chain and rejects unjournaled
canonical effects rather than repeating a committed stage.

The stage runner uses the actual retained-runtime ownership and observation paths.
Focused local checks cover transaction interruption, reopen/retry, stale admission,
input substitution, omitted block lifecycle, rollback/replay and missing/corrupt
records. These checks do not establish complete reactor behavior or cross-platform
qualification. The live Decided/Finalized and next-height gates, final closure and
committee publication, baseline composition, certified-branch rules, startup
integration and oversized-proof transport remain to be connected and qualified.
The Bitcoin poller now retains the complete decoded Bitcoin block, including its
header and transaction witnesses. Its checked history conversion validates the
requested hash, parent, size and Bitcoin commitments, and replay reconstructs the
same block from the retained body. Synthetic transaction-only ingress is test-only.
The poller-to-history round trip is covered locally, but proposal signing and
ValueId still require integration with the canonical descriptor.
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
