# Protocol upgrades implementation plan

> Operator scope correction, 29 October 2026: external Explorer and Explorer
> Indexer redesign is excluded from this goal. Leave the existing local consumer
> work untouched. It is neither a prerequisite nor a completion gate. Resume core
> runtime qualification, production executor extraction (K2a/K2b), and the
> remaining protocol-upgrade phases. The referenced goal file contains the full
> correction and supersedes conflicting consumer-phase notes. The goal resumed on
> 29 October 2026.

Revision: PLAN-1, 2026-10-27. Approved for phased implementation.

Approved content was DRAFT-4, SHA256
`e08a3a8e3903d800e73d306d0992fd67202932e9994c72df1ad53aff04085eb1`.
Implementer approval: Interlink message `fbd3b0b2f35e0398793c7f8a353cb137`.
Reviewer approval: Interlink message `ccdf27c803fafe9291ab1ffd2bacfc4e`.
Initial approval changed only agreement metadata. Approved amendments follow below.

Repository baseline: `2c5cff0ddc3eada52f143f61109b6360d3732c6f` (origin/main).
Design input: https://kontor-protocol-study-20261026.wilfred714608.chatgpt.site
Review task: `kontor-upgrade-plan-v1`; reviewer session
`64900b0a-c524-49d4-889a-138292b608db`.

The goal is the complete merged system, including integrated failure/recovery
evidence. A build experiment, this plan, or an early merged phase is not completion.
Each phase below is one PR. Fork PRs receive the same two reviews and CI gates as
node PRs. Production changes begin only after both implementer and reviewer
explicitly approve the same revision. Material revisions require renewed agreement.

## Implementation checkpoint, 31 October 2026

S2 merged in [PR 613](https://github.com/KontorProtocol/Kontor/pull/613) as
`a94587744cd7bce30d6662fb4b32a7c65ce67912`. The lead verified the actual merge
tree against the reviewed and tested source. Its final six-cell comparison and
required current-head CI passed. The operator accepted ordinary Pulley performance
for continuing prelaunch implementation; the preserved slow extreme-workload
measurements are not throughput passes or production-readiness guarantees.

OWNERSHIP-1 merged in [PR 614](https://github.com/KontorProtocol/Kontor/pull/614)
as `dfacbefdac22b898c5bad5b2cae5e2513e147afd`. Its actual merge tree
`c553f315f4fc400f6f3d900f7c93029b6abd3540` matches the reviewed head and CI
checkout. All current-head checks passed. The lead and both independent reviewers
accepted the implementation and focused corrections for blocking-task panic
handling, actual owned-path qualification, and canonical supervisor release order.
The release regression fails with the former order and passes with the fix.

Owned qualification run `41202697348` passed all six platform/profile cells and
the aggregate comparison. The lead validated raw evidence, source, lockfile and
contract hashes, and reproduced the GitHub comparison byte-for-byte (SHA-256
`4065b5f5f5d2594951790e410e262ac734264ce2b43130c04fbc4af7d82e2dcd`).
The preserved-input comparison matches all eleven logical-state stages against
merged S2. Linux and macOS ordinary CI each passed all 129 integration tests.
These are bounded correctness results, not a throughput qualification.

Qualification scope selection merged in [PR 615](https://github.com/KontorProtocol/Kontor/pull/615).
The release-plus-dev-smoke policy merged in [PR 617](https://github.com/KontorProtocol/Kontor/pull/617)
as `e7361411fcf812602a736370577267db81a1ceb0`. Relevant changes require full
release qualification on three platforms and eight bounded dev smoke tests on
those platforms. Exhaustive dev/release qualification is available manually.
The exact candidate's release comparison, smoke evidence and ordinary CI passed.
The post-merge qualification was cancelled only after verifying that the merge
and qualified PR test commit have identical tree `44c74d28f1eeec754f5d7003a90609e061e377a6`.
Batch changes before CI, retain valid evidence, and investigate failures before
rerunning only the affected jobs. Cost control does not waive acceptance checks.

K2a merged in [PR 616](https://github.com/KontorProtocol/Kontor/pull/616) as
`a41ffce532005723b4b4784a03300064bfdcb9ca`, with its final six-configuration
comparison and required CI passing. It provides selected in-tree P1 execution,
retained policy and native artifact/provenance inputs, and logical storage
callbacks. It does not establish independent production dependency graphs.

K2b production extraction is implemented locally and remains unmerged. The
[agreed extraction design](k2b-production-boundary.md) defines its boundary and
acceptance criteria. Two independently locked production graphs contain the
actual retained Runtime and Wasmtime `.2`/`.3`, including conflicting features.
The node links their structural factories without depending on Wasmtime itself.
Node-owned scheduling and physical SQL sessions drive retained operations and
cleanup through the typed facade. Recognition, canonical transactions, lifecycle,
committee derivation, views and simulation now use that facade.

The actual linked ARM64 dev executable passes thirteen bounded scenario groups
through both graphs: genesis/resume, views, committee, malformed recognition,
lifecycle rollback/replay, opaque-session rejection, transaction recognition,
publication, fees/deposits, deterministic failures, simulation inspection and
transaction rollback/replay. The preserved pre-extraction comparison also passes
all eleven recorded logical-state stages, including confirmation without
reexecution and rollback/reconfirmation. Five compile controls against the actual
libraries accept the structural factory interface and reject graph-owned engine
and scheduler types and private runtime access. These results are samples, not a
proof for every transaction or platform.

The maintained node builder records source, lock, compiler, native ownership,
link and execution evidence. Docker's production build route now installs its
audited executable. The full release image is not yet validated. Platform
comparison explicitly requires release results from all three supported platforms,
with exhaustive dev/release comparison available only manually. Comparator-only
changes run focused evidence controls instead of rebuilding all platforms.

Before K2b can merge, finish actual linked-graph pending-I/O, cancellation, cursor,
fault and shared-capacity coverage; validate the complete release image and
required platform checks; consolidate the lead and two independent phase reviews;
and pass final-candidate CI. The Daybreak implementer has the bounded ownership
qualification assignment. No delegated result is accepted solely from its status
message. No K2b PR or broad CI campaign has been started at this checkpoint.
The remaining activation, authorization, consensus handoff, migration, historical
verification and recovery phases below are still required for goal completion.

The operator replaced the unavailable external reviewer with a second independent
Codex reviewer using a complementary brief. Preserve valid reviews and consolidate
focused follow-up on material corrections. Publication of the Site and SDK remains
deferred until the end of the goal and review of the complete work. Current evidence
and exact revision records are tracked in [the execution ledger](execution-ledger.md).

## Planning baseline evidence, 27 October 2026

- `core/Cargo.toml` pins Wasmtime fork `bfdee9ba` and Malachite 0.8.2; the network
  override is vendored. The research Site's older Malachite baseline is stale.
- `reactor/executor.rs` exposes `Runtime`, Bitcoin, anyhow, and Tokio types. It is
  an orchestration/testing abstraction, not an independently built bundle boundary.
- `reactor/engine.rs` clones private signing keys, uses `consensus.wal`, and returns
  an engine handle that does not itself prove all spawned work has joined.
- `consensus/signing.rs` and `reactor/consensus_state.rs` include arbitrary-byte
  signing and proposal-part paths. All must pass through durable node authority.
- `reactor/batches.rs::resume_next_height` gates progress after deferred application
  and finality. This is the existing place to withhold next-height permission.
- `ConsensusState::new` deletes an unexecuted batch suffix. `blocks.rs` rollback
  refreshes the live committee from restored state. Neither can remain the source
  of certified progress/authority after upgrades.
- Native contract IDs/privileges derive from array order. Runtime storage exposes
  libsql directly; the SQL checkpoint hashes ordered writes, not a full state map.
- The native closure includes Wasmtime helpers, blst, libsql, secp256k1, ring,
  aws-lc, psm, zstd, and zmq. Isolation must audit the actual retained closure, not
  assume Wasmtime and blst are the only possible collisions.
- Rust 1.99.1 is installed and used for generated artifacts, but node CI currently
  follows stable. The whole-node compiler and final-link recipe need explicit pins.

## Preserved decisions

One immutable coordinated protocol selects execution and consensus. Formats and
contract ABIs do not select an obsolete executor. Preserve multiple implementations
in one executable through independent Cargo resolutions, locks, features, metadata
and target directories. Link in process; no IPC or runtime network boundary. One
pinned compiler builds all graphs. Retain portable lifting accounting.

Bitcoin H completes transactions and lifecycle under P1. The transition runs after
H; Batch(H) and Block(H+1) use P2. Canonical prior execution is confirmed without
another charge. Persist the boundary, fence and join the old Malachite engine,
then start the selected engine at the next global consensus height. Node, RPC,
and ingestion survive. No live wire compatibility is assumed. Validator approval
is explicit and separate from binary installation or ordinary consensus voting.

## Proposed policy for reviewer agreement

1. Schedule/Postpone needs at least 5/6 CURRENT inclusion-committee voting weight;
   Cancel needs strictly more than 2/3. Use checked u128 arithmetic and bounded,
   unique sorted approval entries. The action binds chain/domain, tag, control head,
   nonce, expected pending plan, exact target/H, an authenticated reference R
   (consensus height and decision digest), and high-water expiry. R bounds expiry
   to high_water(R)+144 and must precede inclusion; it does not freeze voting weights.
   Each entry signs action ID, signer key and that key's registration generation.
   The monotonic committee journal advances a key's generation on effective exit
   and re-registration/key reuse, including a changed registration identity
   (key, holder, activation_height). Observe intermediate effective membership
   transitions during multi-block replay, so an exit/rejoin between final snapshots
   is not lost. Registration provenance must distinguish replacement-branch events
   at the same numerical activation height; tuple equality alone is not sufficient. Count only matching current registrations.
   Other validators' churn does not invalidate an approval. A-B-A key reuse cannot
   revive old consent. No contract-state counter is introduced into frozen P1.
2. Notice is 1,008 Bitcoin heights from certified monotonic high-water. One pending
   plan, compare-and-swap expected plan and monotonic nonce serialize actions.
   Readiness is advisory, refreshed every six heights with 24-height expiry and an
   H-144 checkpoint. Supported nodes also dry-run the target migration in an isolated
   snapshot at least every six newly applied Bitcoin heights throughout notice,
   under the manifest work budget. Readiness reports carry last input lineage,
   outcome and work-used/budget. Deterministic failure or budget excess withdraws
   readiness and triggers the documented operator Cancel/Postpone procedure; it
   does not itself authorize a control action. No expedited upgrade or emergency
   maintainer authority.
   Consume a plan when its transition Block H is authenticated and recorded in
   consensus decision order, even if execution lags. Cancellation must precede it. UpgradeControl validity bypasses pending/deferred
   Block gates that apply to batches. Proposers prioritize eligible control actions
   before Block work, including H with insufficient target support. They do not wait
   for the H round to fail before proposing Cancel/Postpone.
3. Block H carries TransitionDescriptor{chain_id, plan_id, H, H_hash, old/new
   protocol_id, next_era_id, next_codec_id, start_height=C+1}. It does not certify
   execution roots or a successor committee. Prevote checks the ordinary Block
   predicate, exact authorized descriptor and installed target support. An absent
   descriptor at pending H or an unsolicited/wrong descriptor is invalid. Unsupported
   validators prevote nil. After C is certified, gate C+1 until old H/lifecycle and
   deterministic due finality settle, migration and atomic intent commit, fencing,
   complete join and selected-engine readiness. No migration execution inside voting
   timeouts. Future finality deadlines may replay H without repeating engine handoff.
4. Canonical rollback is decision-driven. D is the chain determined by the ordered
   Block decisions (including exact raw-input commitments): a replacement at h
   truncates D above h-1 then appends the new block. BlockV1 includes explicit
   height/hash/parent_hash and raw-input commitment; parent_hash must match its header. Its header must extend D[h-1], h cannot skip above D.tip+1, and live votes
   require the block on the voter's locally validated Bitcoin best chain. A replacement
   must differ from D[h]; repeating the same block is invalid, not another rollback. Propose the first differing
   block after the common ancestor. A local Bitcoin reorg notification invalidates
   candidate caches and gates stale-anchor proposals; it does not mutate committed
   canonical state or the committee. Applying a certified replacement rolls back
   to h-1 and executes that exact block. Retain all certified raw block/witness bytes;
   a lagging node must execute historical X even if its bitcoind already knows Y.
   Batch prevotes bind anchor == D.tip and hash == D[anchor], require applied D and
   deterministic prefix closure, and never substitute local Bitcoin tip as authority.
   Future-anchor decisions occur only as lagging application, not valid live proposals.
   Derived finality rollback/replay occurs deterministically within decision
   application using retained inputs, not later poller arrival order.
5. committee(C+1) is derived once from the state obtained by deterministic application
   closure of authenticated decisions through C, including due finality replay.
   Each command has a durable applied/deferred/inapplicable outcome. A future-anchor
   batch may be deterministically deferred so it cannot deadlock its enabling Block;
   its eventual activation/order is determined by the authenticated prefix. Missing
   bytes are a wait, never an inapplicable outcome. Closing C must account for all
   newly eligible prior decisions, not merely the deferred Block numbered C. It changes
   only at the next-height gate. Persist it outside reversible canonical state.
   No BeginRecovery/RecoveryExit ceremony or temporary committee authority. Current
   engine orders replacement blocks, retaining its era and monotonically increasing
   consensus/signing heights. Replay selects old executors/migrations by position.
   New user batches below the latest activated H are invalid until reconstruction
   re-crosses H. Ed25519 CommitteeV1 is the defined v1 bridge; other key systems need
   a future bridge/protocol definition. Zero power halts NO_ACTIVE_VALIDATORS.
6. An activated migration replays under identity (plan, H hash, pre_lineage,
   pre_checkpoint, migration definition). A different finality exclusion must produce
   a different lineage even if H hash is unchanged. Lineage commits canonical input
   bytes/IDs (including witnesses), genesis/definition IDs, branch, ordered application
   phase, prior migrations, protocol and decision-scoped exclusion set, restored
   with the canonical snapshot and extended on deterministic replay. It is a local
   deterministic execution identity, NOT a certified full-state root. Preserve legacy
   ordered checkpoints separately; their partial state coverage is not a full-state
   proof. Validate final state/receipts independently in differential replay tests.
7. Control/decision/signer history and engine eras never roll back. Record control
   actions after authenticating their ordered prefix; received bytes alone do not
   advance authority. Keep separate received, contiguous verified, applied, live-era
   and signing frontiers. Because committees are execution-derived, historical
   certificate verification must replay each committee-changing prefix. Peer-supplied
   committee records/snapshots are claims, not proofs. Unsupported nodes may verify
   boundary C with old authority but cannot assert verification beyond an unknown
   successor committee. Full genesis replay is required; no trusted bootstrap shortcut.
8. Preserve existing contract-state pruning as an optional local retention policy.
   check_rollback_depth is bypassed on archive nodes, so its default 288 is not a
   consensus depth limit. A pruned node lacking undo data stops application/signing
   and rebuilds from retained authenticated history; it does not reject a valid branch
   as a network rule. Retain all activated executors/codecs, raw certified inputs,
   control/signer history and archive material. No historical retirement in v1.
9. Storage is one node-owned live transaction. Bundles use versioned logical
   callbacks for reads, ordered writes, ranges and nested savepoints. Return receipts
   and usage, not a second write journal. No libsql types or copies inside bundles.
   Recognition/batchability, execution, lifecycle order, views/committee derivation
   and simulation belong to the executor. Scheduling, finality deadlines, dependency
   ordering and replay/exclusion rules are explicitly frozen coordinator-rules-v1,
   selected by the manifest, not freely mutable node plumbing.
10. Assign each native object an owner. Divergent native copies require distinct
    names. Byte-identical objects may share only with verified compile identity and
    an explicit process-global-state safety review, not object equality alone.
    Keep VM images/handlers resident and test trapping through all retained versions.
    Pin compiler and build metadata; reject unaudited symbol collisions.

The ordered-boundary design trades pre-vote result certification for compatibility
with Kontor's order-then-execute flow. Old-quorum support does not guarantee a
supported successor committee or a successful migration. Test both failures: the
plan is consumed at C and nodes fail-stop, never apply a late cancellation or run P1
past H. Rehearsal/readiness reduce this risk but cannot prove availability. Explicit
bounded migration work remains required. Missing quorum/history stays visibly gated.

### Accepted availability limitations

An authorized deterministic target can halt the network with no in-protocol exit.
A zero-power or unavailable committee can also prevent progress. Old-quorum target
support does not guarantee successor-quorum readiness. Missing history or locally
pruned undo data gates signing until authenticated reconstruction. These are explicit
limits, included in operator docs and final handoff, not promises of automatic repair.
Continuous migration rehearsal reduces target risk without proving future success.

### Deterministic migration-failure incident procedure

This v1 has no automatic abort-to-P1, target substitution, emergency maintainer key,
or guaranteed in-protocol exit from an invalid authorized target. The operational
outcome is explicit:

1. Fence signing/admission, retain the certified transition and consumed plan, and
   preserve the last complete canonical transaction, handoff intent, raw inputs,
   control journal, signer slots and WAL. Export failure class, target, exact input
   lineage and checkpoint. Never commit partial migration or erase the decision.
2. Reproduce from authenticated inputs. Local I/O/OOM/corruption is an infrastructure
   repair, not a deterministic migration result; restore/reconcile and retry without
   changing rules or signing history. Unsupported successor validators install the
   already-authorized target and reconcile before voting.
3. If an implementation bug can be repaired while preserving the immutable target's
   specified semantics, qualify that repair independently and resume the same target.
   A desired different result is not evidence of equivalence.
4. If the authorized target rules themselves fail on these inputs, the network stays
   halted under those rules. No built-in admin command resumes it. Any coordinated
   network fork is a new explicit validator/operator governance decision, not approval
   inherited from the failed plan or this implementation task. It must specify a new
   chain/rules identity, authenticated history and recovery snapshot provenance,
   committee/key policy and operator consent. Preserve the original chain's history
   as halted; never present the fork as continuation validated by the old rules.
5. K11 rehearses deterministic failure, infrastructure recovery and a conforming
   implementation repair, proving no late cancel, manifest overwrite, P1 extension
   or signer rewind can resume an irreparably invalid target. It documents the
   external network-fork requirements, but does not manufacture a maintainer bypass.

The availability limit is part of the approved design, not unimplemented automatic
recovery. A plan can authorize a bad deterministic program; this system cannot both
preserve its immutable rules and silently replace its result. A replay-dependent
abort would also make one consumed plan select different executor/consensus mappings
across reorgs, contrary to the agreed coordinated activation boundary.

## PR sequence

### F1. Wasmtime bundle namespaces

Repository: existing `wilfreddenton/wasmtime` fork, based on `bfdee9ba`.
Dependencies: approved plan. Modules: workspace package versions, versioned exports,
C/assembly helper builds and process-global VM handlers. Give every retained bundle
build a unique immutable Wasmtime package-version suffix. Current helper build uses
versioned_suffix from the same macro crate, so first verify that version identity
covers every native import/export. Add a namespace patch only for uncovered paths.
Portable lifting stays unchanged. Validate two same-upstream-version different
revision/features builds in one process, traps/fuel/async stacks, simultaneous
execution, symbol ownership and handler residency. Green linking alone fails.
This provides the VM isolation needed by K1 and historical execution.

### F2. Native crypto isolation

Repository: Kontor, vendored blst patch under core/vendor with preserved license
and reproducible source provenance; this phase is its own reviewed node PR. Dependencies:
approved plan, namespace convention from F1. Result: blst C/assembly exports and
Rust imports use the same bundle namespace without changing crypto results.
Audit other actual bundle native libraries and extend this phase's explicit scope
before approval if they need patches. Validate native symbol maps, BLS vectors,
portable/nonportable feature differences and concurrent calls across both graphs.
No accidental sharing of mutable crypto implementations. This closes native
ownership needed for independently resolved execution graphs.

### F3. Malachite complete lifecycle ownership

Repository: existing Malachite fork rebased to the 0.8.2 source used by Kontor.
Dependencies: approved plan. Modules: app-channel builder/run/connector, engine
actors, networking, WAL workers. Result: tracked, awaited stop/start contract for
all tasks/threads/sockets/WAL resources, including partial startup failure.
Preserve the current network listen-address fix. Tests repeatedly restart actual
engines on one port/WAL, inject blocked worker teardown, and prove no success is
reported until ownership is released. The node adds fencing separately in K5.
This makes in-process handoff possible without assuming process exit cleans up.

### K1. Reproducible isolated bundle build

Repository: Kontor. Dependencies: F1/F2/F3. Modules: tools/kontor-build, new protocol
build recipes and bundle workspaces, CI, node-owned proof adapters. Result: one
pinned Rust compiler, independent --locked graphs/feature sets/output directories,
metadata, exact rlib consumption, deterministic artifact attestations and native
symbol ownership report. Real Wasmtime with Kontor VM configuration/fixtures and real Malachite implementations
must run from both graphs in one executable, with conflicting patch/transitive
versions/features and private consensus runtimes. A build-only harness does not
replace K2a/K2b extraction or final node integration. Qualify Linux ARM64/x86-64 release/Docker profiles and macOS node test profiles
(the existing CI runs the indexer tests on macOS). Mobile SDK consumers do not embed
the node; keep their existing checks green without pretending they run consensus.
The K1 proof executable is an independently built qualification artifact, not
isolated node execution. The existing node remains explicitly P1-only and may
retain its current single-graph release path until K2b. CI requires bundle
qualification on shipped node targets. The release-path clarification below
places the mandatory node builder route in K2b and the multi-protocol attestation
gate in K7; no unqualified unified multi-protocol artifact may ship.

### K2a. Versioned semantic API and live storage adapter

Dependencies: K1. Modules: block/witness parsing, runtime, reactor execution and
lifecycle, database queries/checkpoints, native artifacts, indexer-types boundary.
Result: an in-tree versioned executor API for recognition, batchability, execution,
lifecycle, views/committee derivation and simulation. Keep frozen scheduling rules
explicit in coordinator-rules-v1. Node-owned transactional logical callbacks preserve
read-your-writes, repeated write order, ranges and savepoints. Archive original
native/genesis bytes and explicit IDs/privileges, coordinated with storage work.
Compare original/extracted paths on real contracts, malformed inputs, decompression,
nested failures, fees/deposits, allocation and ordered legacy checkpoints. Preserve
P1 text-based error classification unless equivalence is established. This standalone
PR is CI-coherent and does not yet claim independent graph isolation.

### K2b. Independently locked historical semantic source

Dependencies: K2a/K1. Move the complete P1 semantic closure to its locked workspace,
with std-only envelopes/callbacks and node adapters. No Wasmtime/Tokio/Malachite/libsql
or dependency-owned types cross the common interface. Every execution/simulation/
replay entry needs coordinator-issued context. Compile-fail/import checks prevent
bypasses. Repeat P1 differential fixtures and native ownership audit on the real node,
not only K1's VM harness. Node Docker and release builds must now route through
the pinned builder and consume its exact P1 bundle artifacts, with no unified
Cargo resolution of historical semantics. Include vendored-path panic-location strings in error-text
parity checks: vendoring changes embedded Rust source paths, and host-side error
rendering must not silently change consensus behavior. Keep one node database owner
and explicit runtime ownership.
The export-level panic guard must map a direct executor unwind to an
infrastructure or halt outcome, never a deterministic receipt. Keep that export
failure distinct from the existing guest-call decoder's `host panic: {payload}`
text. Qualify both catch scopes, including missing-context publication/provenance
panics and their prior writes. This clarification is agreed in Interlink receipt
`5e92b3b31ecde8846f2b543ad8f94c61`; it does not authorize changing P1 panic
payloads or manufacturing a successful/rejected transaction after an unwind.
When the node graph joins the link, do not add its dependency definitions to the
common-runtime inventory. Add a negative control proving a bundle's unnamespaced
blst, secp256k1 or ring reference cannot resolve to the node's native copy. The
common inventory remains restricted to qualified host/std/platform inputs.

### K3. Atomic migration substrate and execution identity

Dependencies: K2b. Modules: logical state adapter, database transaction/snapshot
service, legacy checkpoint and migration registry. Result: deterministic budgeted
migration effects, marker and applied cursor in one atomic transaction; canonical
lineage as specified above; unchanged ordered checkpoint algorithm. No full sparse
Merkle subsystem or certified-root claim. Test duplicate/tombstone ordering, nested
rollback, I/O failure, crash atomicity, changed exclusions with same H hash, marker
rollback/reapplication, and byte-for-byte SQL/checkpoint equality. Independent full
state/receipt comparisons validate equivalent replay beyond checkpoint coverage.

### K4. Certified history and baseline consensus envelope

Dependencies: K2b/K3. Modules: consensus values/codecs, reactor proposal/decision/startup,
database durable journal and committee records. Result: stable bounded value/control
envelopes, immutable definitions/IDs, contiguous authenticated decision/input journal,
separate applied cursor, derived committee-per-height journal and no suffix deletion.
Persist exact bytes before acknowledging availability. New value/proposal-part
IDs must bind exact raw input digests/wtxids, not only txids: the current value hash
can alias different witnesses carrying different Kontor instructions. Commit and
validate raw Block input identities as well as header/Bitcoin commitments, and
record decision-ordered control state and descriptor-only transition authorization.
Tests cover gaps, altered raw bytes/certificates, crash before/after append/apply,
churn, zero voting power, same-txid/different-witness rejection and deterministic
finality closure. Persist command outcomes and prefix closure before granting the
next height; missing inputs cannot silently become an orphan/skip. Move committee updates
to the height boundary here, with decision-driven branch replacement and retained-input
replay sufficient to prevent local event timing from changing historical authority.
This prerequisite cannot wait until K8 after authorization/activation are enabled.
Keep K4 as one PR: removing suffix deletion and deriving historical committees
requires the immutable raw-input journal simultaneously; splitting it out first would
leave an incoherent intermediate authority model. Revisit scope with the reviewer if
implementation evidence permits a genuinely self-contained split. Baseline wire
changes are explicitly prelaunch; no claim of compatibility with older dev networks.

### K5. Durable signer and engine coordinator

Dependencies: F3/K4. Modules: signing/proposal-part paths, engine adapters, reactor
next-height gate, node startup. Result: one node signer with separately durable slots,
round/step/high-water checks, exact retry signatures and generation leases. All
consensus signing paths use typed codec-validated requests, never an exposed raw key
or arbitrary-byte bypass. Network identity signing has its own limited domain.
Test Malachite signing-callback errors and separate network-identity key use.
One engine owns socket/WAL and a private runtime at a time; explicit stop-and-join
keeps node services alive. Crash/sign-retry, stale callbacks, old snapshots, partial
startup, blocked teardown and WAL reopen tests prove no competing authority.
Account for fork-to-exec inheritance of advisory locks during WAL startup: inspect
node subprocess overlap and prove that any startup retry retains exclusive
coordinator ownership. A transient lock error never authorizes a second writer.
This F3 follow-up was identified in Interlink receipt
20ada81588f8fc1a137cf6f1e1b84e0d.

### K6. Validator-authorized upgrade control

Dependencies: K4/K5. Modules: protocol registry/control state, proposal validation,
approval CLI/API/SDK, continuous snapshot migration dry-runs and readiness diagnostics. Result: immutable hash-bound manifests,
signed schedule/cancel/postpone, committee references, nonce/replay guards, notice,
expiry and telemetry per agreed policy. Unsupported targets remain opaque schedules;
installation/readiness does not authorize activation. Golden cross-language codecs,
threshold boundaries, duplicate/unknown signers, overflow, weight drift across thresholds, per-signer A-B-A registration reuse, unrelated churn, conflicting
actions, expiry, cancellation cutoff and superseded plans are tested. Include exit/rejoin
inside one replay span, same-height replacement registration, and valid control
ordering despite pending/deferred blocks. Test dry-run isolation, six-height
refresh, work-budget reporting and readiness withdrawal on failure before H. Existing plans
retain their original authorization as certified history changes.

### K7. After-H activation and deterministic migration

Dependencies: K1/K2a/K2b/K3-K6. Modules: reactor block/batch/finality coordinator, migration
registry, durable handoff intent, engine selection, mempool/admission. Result: a real
deliberately different P2 plus incompatible consensus codec transitions after H.
H and lifecycle use P1; Batch(H)/H+1 use P2; earlier canonical executions confirm
without duplicate effects/charges. Unsupported nodes park at the documented atomic
boundary. Test actual multi-validator engines, migration limits/idempotence, lagging
nodes, pending requests, retained certified work, transaction revalidation, same-port
handoff and no node/RPC/ingestion restart. Crash inject through intent/application,
join, WAL startup and first new-era signature. Include unmined/RBF batch(H-1) whose
deadline later replays H with changed pre-state; old unsupported quorum prevotes nil;
new successor committee unsupported/zero power; deterministic post-decision migration
failure and the incident procedure. Over one-third unsupported at H must still allow
Cancel to be decided, after which ordinary H is valid under P1. Release CI and
node startup must refuse an artifact whose registry contains multiple protocols
unless its embedded builder attestation verifies. No live switch before these pass.

### K8. Deterministic cross-boundary replay and committee safety

Dependencies: K7 and K4's decision-driven branch/committee foundation. Modules:
reorg/finality scheduler, journal/committee/control, snapshot restore and migration
replay. Result: ordinary current-era consensus orders replacement blocks without
rewinding eras/heights/authority; no recovery ceremony. Replay across one or several
activated H boundaries; below latest H gate new batches. Test earlier/later local
notifications around decision/application/resume, including orphan X never seen by
local bitcoind, shorter higher-work branches, second reorg, finality exclusions,
expired batches and same H hash/different pre-lineage. Independent state/receipt/
committee comparisons must match for all event permutations. Test pruned-node archive
rebuild, zero validators, missing history and unavailable quorum. Do not mutate
committee authority merely because a local Bitcoin notification arrived.

### K9. Stable history transport and cold catch-up

Dependencies: K4/K7/K8. Modules: node history service, bounded peer synchronization,
archive storage and startup. Result: current-era peers serve exact historical input
and certificate envelopes independent of live Malachite codecs. Fresh nodes verify
from original genesis through all eras and recovery before signing. Limit chunks,
total decoded sizes, inflight ranges and peer work. Test entirely new-era peers,
missing middle records, tampered values/certificates/input/committee claims, unsupported
codecs and restored snapshots. Keep separate received/verified/applied/era/signer
frontiers. Re-execute committee-changing prefixes before trusting successor
certificates; missing target support cannot advance authentication beyond its
unknown derived committee.
Do not use trusted snapshots as evidence of full genesis verification.

### K10. Protocol-aware clients, caches and operations

Dependencies: K7-K9. Modules: API/indexer-types/SDK, simulation/fee estimation,
component/state caches, operator commands/docs and private Site. Result: expose IDs,
supported formats, execution position, lineage/checkpoint/build identity (not certified state roots), approval/readiness,
missing support/history and handoff/recovery status. Simulation uses selected state
and protocol; future assumptions are explicit. Cache keys bind all semantic/build
inputs. Test rollback/activation contamination, old receipts, API handoff continuity,
unsupported/recovery admission failures and SDK format discovery. Implement format
and ABI descriptors, including the bounded disjoint format-1 specified by the Site; legacy parsing/signatures remain exact. Publish maintenance rules
for historical backports, compiler changes, migrations and retained artifacts.

### K11. Integrated qualification and release evidence

Dependencies: all above. Modules: real multi-validator integration harness, CI
qualification matrix, artifact release checks, docs and private Site. Result: full
goal acceptance suite runs against actual embedded bundles/engines and real state,
including deliberate P2 divergence, two successive upgrades, all crash/recovery
boundaries, unsupported validators and cold sync. Shadow/differential cases include
new malformed inputs beyond historical transactions. Qualify compiler, platform,
profile/native symbols and realistic maximum migration work. Explicitly rehearse RBF near H, old quorum/new committee support
mismatch, no-quorum stalls and repeated local reorg notification permutations.
Record actual merged
PR/head/check evidence and run operator rehearsals. The Site describes implemented
behavior, remains owner-only/dark, and has no obsolete alternative path presented as
implemented. Missing evidence or an unresolved feasibility gate means not complete.
Release attestation also records the actual linker-driver invocation and selected
backend path/hash, accounting for Rust's linker search/selection flags. K1's
compiler/native environment and produced-binary ownership reports do not claim
an explicit linker-backend hash.

## Review and merge ledger

For each phase record base/head, acceptance commands/results, independent subagent
review, Interlink review, findings/dispositions, any follow-up review after material
edits, PR URL, current-head CI and actual merge commit. Begin dependent phases from
the merged state. New security advisories may receive exact documented exceptions
in `core/.cargo/audit.toml`; these are accepted exceptions, never described as fixes.
No blanket suppression and no weakening other tests to pass CI.

## Agreement and remaining planning decisions

- Both parties explicitly approved the DRAFT-4 digest recorded above.
- Decision-driven branch/committee rules, per-signer generations and reference R
  and the deterministic-failure incident policy are agreed.
- Fork destinations: wilfreddenton/wasmtime and KontorProtocol/malachite;
  native crypto patch lives in the Kontor repository. Never submit upstream Wasmtime
  PRs or comments; its local instructions restrict those to humans.
- Actual node matrix: Linux ARM64/x86-64 release/Docker, macOS current node tests;
  keep SDK mobile checks but do not require mobile consensus engines.
- Storage audit agent 01a14ab3 reports no active production edits, identifies native
  deployment constraints and unresolved economic policies. Query to 01a147e5 remains
  pending. Preserve existing economics during extraction; do not resolve unrelated
  staking/penalty/sponsorship policy by accident.
- Every phase needs both review channels and green current-head CI before merge.

## Planning review evidence

Independent subagent review against 2c5cff0d confirmed an early/late reorg
counterexample: the current stale-block skip can produce different committees at
C+1 for the same certificate C. The decision-driven canonical branch and durable
prefix closure above replace that path. It also identified txid-only commitment
(aliasing witness instructions), unsupported successor committees, and historical
verification's execution dependency. All are included in K4/K7/K9 acceptance. This
planning review is not a substitute for either per-PR implementation review.

## Approved native-owner amendment (F1 investigation)

Interlink task `kontor-upgrade-f1-native-owner`, reviewer agreement
`4f2da3f765c0db29d6a4518b5957a570`: compile every protocol graph without Wasmtime
`debug-builtins`. Its process-global GDB descriptor otherwise has per-graph locks.
K1 rejects the feature and GDB descriptor/register symbols, and records an explicit
process-global ownership allowlist. The node graph must not reintroduce Wasmtime.
Adapters assert native debug_info(false). K2b qualifies this intentional P1 feature
delta against the original build, including trap/backtrace/error-text equivalence.
F1 tests both differing minimal features and the full intended Kontor feature set
without debug-builtins. System unwind registration is explicitly shared; concurrent
registration/trapping/deregistration is exercised. No portable lifting change.

Review amendment `4ce03db4c79e30f01750f58c9395212c` (task
`kontor-upgrade-f1-review`), accepted by implementation: also exclude Wasmtime's
unused `cache` feature. Kontor uses its own ComponentCache; removing this feature
removes wasmtime-cache/zstd from protocol VM graphs. K1 rejects `cache` and K2b
qualifies this delta with the debugger exclusion. Preserve the existing
`macos_use_mach_ports(false)` setting in K1/adapters, with macOS CI covering signal
chaining; this is not a change to P1's current configuration. Rayon's global pool
is separately owned by each graph and remains resident.

Review amendment `c289a78411b46d06a5bbbebc9ae7fc47` (task
`kontor-upgrade-f1-review`), explicitly approved by both parties: also exclude
Wasmtime `profiling` from every protocol graph. Kontor already uses the default
ProfilingStrategy::None. K1 rejects the feature and ITT/iJIT native symbol families;
adapters explicitly preserve None. K2b qualifies the cumulative debug-builtins,
cache and profiling feature-set delta against original P1. Bundle definitions
record all three exclusions with their rationale. The exact Mach-O executable
header `_mh_execute_header` may be accepted only in the final macOS audit; an
input library defining it must still fail.

F1 final-review carry-forward (receipt 5463eaacf940bd74c44a7c48c0a754a3): K1
also intersects Rust-mangled and anonymous compiler symbols across graphs to
detect metadata mistakes, with any false-positive exemption explicitly scoped.
The version/source identity guard must be enforced by code, not documentation.
This async-guest acceptance item is superseded by the approved S1-2 amendment:
K2b rejects async-lift/async-lower and guest-concurrency components, and positively
qualifies synchronous guest components using asynchronous host I/O. F1's earlier
async/JIT proof is historical prerequisite evidence, not qualification of the
final synchronous/Pulley baseline.

## Approved F2 native-crypto scope amendment

Interlink task kontor-upgrade-f2-native-plan, reviewer receipt
7f362ce63833d9e90868fe0e71aeddac, explicitly accepted by implementation. F2 is
one Kontor PR vendoring opt-in namespace hooks for blst 0.3.17, ring 0.17.14 and
secp256k1-sys 0.10.1, with pristine provenance and licenses. ring's existing prefix
is extended consistently across native and Rust surfaces. secp's hardcoded
v0_10_0 prefix is insufficient for patch-version divergence; rename C symbols and
all four exported Rust callbacks consistently. blst post-preprocessing rewriting
preserves conditional compilation and token-paste semantics. Ordinary single-graph
builds remain unchanged without a namespace; this is not a permitted bundle mode.

Additional acceptance criteria:

1. K1 rejects any bundle build without an explicit deterministic namespace derived
   from bundle identity and recorded in its attestation. Node graph may retain
   original names, with the node-versus-bundle distinction audited.
2. Compare upstream and namespaced native objects under identical flags on each
   shipped target. Normalize symbol names in disassembly and data comparison; any
   remaining instruction or data difference fails. Retain BLS, ECDSA, Schnorr and
   digest/signature vectors and concurrent dual-graph execution.
3. Namespace CPU-capability and other mutable globals, secp's Rust definitions and
   C callback references, and blst's Linux x86/ARM ELF and macOS Mach-O assembly
   exports. Native audit must show zero intersection and zero unowned definitions.
4. Default-build objects match pristine upstream with identical inputs/flags.
   Crypto outputs remain byte-identical for node, SDK Wasm/native and mobile
   consumers; existing CI stays green.
5. A script regenerates each vendor tree from pinned pristine archives plus a
   recorded patch, checks source SHA256s, and verifies vendor equality in CI.
   Document the dependency-bump procedure.

A fresh independent Malachite graph has ring but no AWS-LC; the earlier workspace
view reflected node reqwest/metrics feature unification. K1 must verify AWS-LC,
libsql and zstd remain node-owned in the actual extracted closure. Do not assume
that ownership from package names or from a unified Cargo tree.


## K1 release-path clarification

Agreed 2026-10-27 in Interlink reviewer receipt
`4c46e3a37b9ff40aee9b901cfbe759c5`, accepted by implementer in
`43d93fce3b650b4eaa3a2199b2eea644`.

The prohibition on unqualified unified releases applies to retained multi-protocol
artifacts. K1's intermediate node contains only the existing P1 and no upgrade
capability. It must remain usable while semantic extraction proceeds in K2a/K2b.
K1 delivers the pinned builder, two real independently locked VM/consensus proof
bundles, combined qualification executable, attestations, and required qualification
CI on shipped targets. Real consensus qualification consumes F3's managed lifecycle.
It does not claim that the node executes through those proof bundles.

K1 must enforce immutable Wasmtime version/source identity (including the reserved
51.0.0-dev baseline), reject debug-builtins/cache/profiling, set the F2 native
namespace requirement on every graph, reject unpatched if-watch, and audit every
native intersection/owner including Rust-mangled and anonymous names. K2b switches
the node's release/Docker build to exact builder artifacts. K7 adds release and
startup verification of embedded attestations for multi-protocol registries. These
are explicit acceptance items, not untracked later work.


## Process-lifetime service ownership clarification

F3 review receipt `33e55cc703d83f1c0e077ae28de25ac8` records the locked
futures-timer 3.0.3 fallback helper as one lazy, resident service per consensus
graph. It parks and wakes task wakers, owns no sockets/FDs, and cannot poll engine
futures. Runtime teardown destroys the engine's Delay futures; cancellation clears
deadlines and queues heap removal, so physical notification-record reclamation is
asynchronous. This does not permit retained engine authority or per-engine growth.
K1 must include the helper in its per-graph ownership map with no sharing/unloading.
K5/K7 resource baselines warm each relevant graph before measurement and still
reject unexplained per-engine growth. New process-lifetime exceptions require
explicit ownership review; they cannot be inferred from a stable warm baseline.

## K1 concrete build and interface refinement

Agreed with the reviewer in Interlink receipt
`e4ceca617f9c69b3d1173273f0a94e02` before implementation:

- Expose a separate `./tools/kontor protocol-bundles` command over a reusable
  builder module. Keep the existing contract/SDK generator's fixed-platform
  behavior unchanged.
- The original K1 development proof checked in two independently resolved
  manifests and lockfiles with the following Wasmtime pins. The approved Pulley
  fork amendment below supersedes these pins for the final proof pair. Baseline `bfdee9ba9a483915dc95432708cf7db8281adbc1` (reserved 51.0.0-dev) and
  F1 merge `525ffedef9bc8babdd9c0b3bd703a5ba5793fcb8` (51.0.0-kontor.1).
  Pin the verified F3 merge for both real managed consensus implementations.
  Combine VM, consensus and native crypto inside each graph, with conflicting
  itoa 1.0.14 and 1.0.15 requirements and differing feature closures.
- Build with graph-specific compiler metadata, native namespaces and output
  directories, then consume only the exact rlibs reported by that Cargo
  invocation. Audit all input definitions, including Rust-mangled and anonymous
  names, plus final native addresses. Sharing requires an explicit runtime owner.
- The proof boundary uses only the common sysroot's standard-library types.
  Use opaque `Box<dyn Any + Send>` engine owners and synchronous entry points;
  graph-owned types remain inside their graph. Drop engine owners on a control
  thread because dropping waits for complete shutdown. Qualify rejection of
  cross-graph Tokio/dependency types with a compile-fail control.
- No bundle may define a global allocator. The allocator is process-owned.
  All graphs use the same pinned compiler and unwind panic runtime; catch panics
  at exported calls and return std-only errors. Add a bidirectional std-closure
  callback proof so live-storage callback ownership is exercised before K2b.
- Attest compiler identity, target/profile, source hashes, locked packages and
  resolved features, native ownership and artifact hashes. Reject mismatched
  panic strategy, forbidden Wasmtime features, unpatched if-watch, missing F2
  namespaces and reused immutable source/version identities.

This specifies K1's proof and reusable builder, not a completed historical
semantic extraction or a production multiprotocol node. K2a/K2b and K7 retain
all previously agreed extraction, release-route and runtime-attestation gates.

Wasmtime version/native-prefix uniqueness is mandatory across independently
linked graphs, even when the VM code is otherwise identical. F1 derives native
helper names from the package version; those helpers interact with graph-private
Rust trap/TLS/unwinder state. Byte-identical helpers cannot use the generic shared
runtime exemption. A future protocol reusing VM code must receive a version-only
fork release with a new immutable recorded source identity (for example,
a new unclaimed version). K1 rejects duplicate versions and duplicate normalized prefixes.
This procedure remains mandatory until a separate graph-namespace mechanism is
reviewed. Interlink agreement: `363896efaf026401cd8dd6fa2c1de9c2`.

K1 also records Tokio's Unix signal registry as a named process-lifetime resource:
the OnceLock retains one UnixStream pair (two descriptors) per Tokio copy; each
runtime owns a duplicate receiver that is released on Drop. Review receipts
`5e476ff359000469af853d342588b208` and `3aac0eadc7a134f7a5501daf623fdbd3`
approve this bounded ownership class, not a generic descriptor allowance.
Cold-start and repeated-runtime evidence must identify the pair once per graph
and show no per-engine growth. The isolated Tokio 1.47.1 Linux probe observed
four cold descriptors and six after each of forty runtime create/drop cycles;
this preflight does not replace combined-graph platform qualification.

Bundle Kontor/fork source may not subscribe to node control signals or spawn
children (tokio::signal, signal-hook subscription, tokio::process and equivalent
child-spawn call sites). Wasmtime's F1 trap handlers remain a separate explicit
exception. A blanket symbol-definition ban is invalid because Tokio compiles
subscriber helpers and its lazy orphan path even without a bundle subscription.
K1 therefore checks source policy and proves host SIGTERM/SIGINT delivery with
both engines live, then after runtime replacement. Engines continue until the
host requests stop. A node-owned child must also be reaped with its observed
exit status while both bundles are live, guarding SIGCHLD ownership. New third-
party subscription behavior requires renewed ownership review. F3 receives a
separate reviewed documentation follow-up naming this existing resource.

## K1 explicit blst process resource

Interlink4afa1ddbd9d3db4f68c6e9e45bf9a2a7 accepts the existing blst0.3.17
std threadpool as a separate named process-lifetime resource, preserving features
and source. Each independently linked graph lazily leaks one Mutex<ThreadPool>
with num_cpus::get workers. It is distinct from Wasmtime's Rayon pool and the
futures-timer helper; a node retaining two bundles plus its own blst graph can
therefore retain three such pools. K1 records actual cold/VM/crypto/engine worker
counts separately for each graph and platform, then requires no per-engine growth.

The jobs in aggregate_verify, verify_multiple_aggregate_signatures and
miller_loop_n carry crypto inputs, Pairing/field accumulators and atomic counters,
not node callbacks or signing/storage authority. Each caller receives one result
from every scheduled job before returning. Borrowed-input access finishes before
the completion send. Trailing closure cleanup may still decrement Arc/Sender
counts or drop borrowed references without dereferencing them; this is not a
claim of exact pool-idle at return. Graph code and pools remain resident.

The caller retains its own sender while waiting, so a job that panics or hangs
before sending would leave that call waiting indefinitely rather than unwind
past borrowed input lifetimes. Teardown must retain the owner in that case;
there is no timeout escape that frees live input or starts a competing owner.
This is an explicit availability failure mode, not permission to detach work.
No silent no-threads feature change is allowed; such a change would require
separate compatibility reasoning and K2b parity qualification.

## Corrective F3 shutdown ordering before K1 qualification

Interlink agreement 13a640d2b404ff98fccc6139a39cf089 adds a corrective Malachite
PR based on c9a313bd after K1 exposed a live shutdown race. Broadcasting stop to
all actors closes the WAL while consensus can still perform its final WAL RPC.
Stop and await children in reverse construction-dependency order: sync,
consensus, connector, WAL, network. Give each a bounded graceful interval, then
kill if necessary and await Stopped before touching its providers. Keep both
supervisor barriers, first-fault reporting, runtime destruction and final WAL
worker joins. Caller timeouts retain ownership; stuck post_stop is not detached.

Acceptance requires a deterministic dependent-RPC regression that fails the old
manager, real inbound networking after a subscriber stops, the existing complete
failure/timeout lifecycle suite on all three platforms, both required reviews,
exact-head green CI and verified main. K1 then pins the corrected merge and
reruns its original cold-engine reproducer. No public API, signing, WAL-format
or dependency-lock change is needed. Later phases retain their agreed scope.

The corrective review's non-blocking registration guard is assigned to K5's
engine coordinator: represent or assert the provider-before-dependent actor
sequence, so a future builder reorder cannot silently change teardown order.
The current correction documents the sequence at its registration sites and
tests its dependency invariant. K5/K7 timeouts must account for up to five
sequential one-second graceful intervals, followed by mandatory ownership waits
that may remain unbounded for stalled work. Never interpret that grace budget
as permission to start a competing engine.

## Corrective aggregate infrastructure errors before K2a completion

Interlink agreement `33bb8892dcb25c009aa6073f3972f9c7`, task
`kontor-upgrade-aggregate-errors`, adds a corrective Kontor PR on main
`9d4da6798ac7c499fc2060282bca1d42e0301393` before completing K2a. Aggregate
verification currently turns database lookup and identity-insertion failures
into ordinary input rejections. A healthy node can execute the same input while
the affected node skips it, and partially inserted identities can commit.

Introduce a typed distinction between deterministic verification rejection and
infrastructure failure. Keep all existing deterministic rejection text,
including chained error formatting, unchanged. Propagate infrastructure failure
through the executor to the existing block rollback/fatal reactor path. The
publisher identity lookup after verification already propagates failure and
must retain that behavior. Do not change valid execution, signature validation,
nonce rules, dependency locks or storage schemas.

Acceptance requires real signed aggregates with database read faults in both
signer-ID resolution paths and public-key resolution, plus a nonce-insertion
fault after identity allocation. Reproduce against unchanged main, then show
that `Reactor::handle_block` restores all touched tables and checkpoints, keeps
the previous tip, and successfully retries the unchanged signed input after the
fault is removed. Preserve deterministic invalid signature, missing signer and
shape rejection behavior. Complete both reviews, appropriate local checks,
current-head CI and verified merge. Rebase K2a on the correction and include
these sites in its retained error-classification inventory. Later phases keep
their agreed scope.


## Approved S1 sequential-contract prerequisite

S1-2 in [sequential-contracts-s1.md](sequential-contracts-s1.md), SHA256
`3ced8fbd90a328da713be08ac165df99e9856762de5fe9b59575fcea8b0fad8a`, was
approved by the lead in Interlink `a20f975f127926c9450bde3bf8e35da2` and the
independent reviewer in `9860218ad942fcca4c7ef630d0d55b59`. The independent
subagent approved the same revision. S1 implementation starts from main
`ca0e6a768a841a8dfee8a3f8cc3565f4570af97b` and preserves asynchronous host I/O
and native APIs while admitting only synchronous sequential guest components.
S1 alone must not be deployed or frozen as P1. S2 stack/capacity/performance and
OWNERSHIP-1 remain separate exact-revision approval gates before their production
changes. No later protocol-upgrade phase or final acceptance gate is removed.


## Approved Pulley logical-stack fork prerequisites

The lead, independent subagent, and Interlink reviewer agreed
[pulley-logical-stack-fork-proposal-v3.md](pulley-logical-stack-fork-proposal-v3.md),
SHA256 `83e618b5c303cec66d023b9c10b106ad8c9bd4d6d01cde3ad7ea14766cd9f997`.
Lead agreement: `637d8be538d9e2acdae3eed1707a823a`; reviewer agreement:
`c759ef1961ea20af31e46174fb8b23d9`.

- Fork PR A implements the bounded logical-stack fix on F1
  `525ffedef9bc8babdd9c0b3bd703a5ba5793fcb8`, with a new immutable
  `51.0.0-kontor.2` identity for final P1.
- Fork PR B follows A's reviewed merge and changes only versions, internal
  constraints and necessary lock references to `51.0.0-kontor.3` for the second
  proof graph. Both final graphs select Pulley. Recheck version availability
  before each publication; a collision requires a newly reviewed reservation.
- The earlier `bfdee9ba` / `51.0.0-dev` and F1 / `.1` identities remain reserved
  development history. They are not the final retained P1. S2/K2a creates and
  requalifies the new proof pair, preserving the old evidence as history.
- Only packages inheriting Wasmtime's workspace version, including
  `pulley-interpreter`, change version. Independently versioned packages keep
  their versions, sources and checksums. Work stays in the user's fork; no
  upstream Bytecode Alliance PR, issue or comment is authorized.
- Bundle identity and attestation include `max_wasm_stack` and 16-byte logical
  rounding. Final synchronous artifacts must pass the strengthened six-cell
  qualification for both bundles. S2's native reentry bounds, capacity and
  performance gates, and OWNERSHIP-1, remain separately unapproved.

This records plan agreement, not implementation completion or qualification.
Each fork PR still requires the lead's review, an independent subagent review,
Interlink review, current-head green CI and verified merge.

## S1 and fork A completed, K1-REPIN agreed

S1 merged in Kontor PR #609 as
`208480b7cd10d0bc1eebc3f1e6e35a577b84e6e6`. Its tree equals reviewed head
`18637a8a4de9389a03f14127fe9ba1b77d92f829`. All 19 applicable CI checks
passed, with three main-only Docker jobs skipped. Parent, independent
subagent and Interlink reviews were completed and addressed. This completes
S1 only; S2 and OWNERSHIP still gate deployment and the final P1 baseline.

Fork A merged in `wilfreddenton/wasmtime` PR #2 as
`0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7`, with the same tree as reviewed
head `8416d4673d0d4bf5b6cab35c75194c64817d8073`. All ten push jobs and ten
PR jobs passed. Its `.2` logical-stack implementation is complete. Version-only
fork B merged in PR #3 as `0dbc68b31c0bcf1a05c93122f1939fb8784e4e48`.
Its tree equals reviewed head `58a60e34b69a75131e8593088dc7e30c5f972c48`;
all three reviews and all ten exact-head CI jobs passed.

The lead, independent subagent and Interlink reviewer agreed
[K1-REPIN v2](pulley-proof-bundles-plan-v2.md), SHA256
`9f4649f45845ed453fce206f8c16c5ebb7e408c67bd5a0086b502d398b662ef1`.
Lead agreement is recorded in Interlink `3dfab746679e08633708a70755c4a7a4`;
reviewer agreement is `55c88e5cd8ccee89e9072bdef799b333`. This separate
Kontor PR preserves historical manifests and locks, creates the `.2`/`.3`
Pulley proof pair, and requalifies actual bundle ownership and attestations.
It starts after B's verified merge. It does not change the node runtime.
S2 independently qualifies the single production `.2` runtime after its own
plan agreement; K2b retains the final both-bundle semantic qualification.

K1-REPIN implementation now pins those actual fork merges. Local Linux ARM64
release qualification passed with 47 builder tests, exact 1026/1028 VM charges
and 2051/2055 ready-versus-pending host-call charges, both runtime engine
attestations, native ownership audits, 42 consensus decisions, and 20 engine
replacement cycles. Historical manifests and locks are unchanged; all
non-Wasmtime lock entries are identical. The initial local run reached the VM
checks but failed at a sandbox-denied loopback listener; its evidence was
preserved, and the complete rerun passed with local-network permission.
Implementation reviews and three-platform/Docker PR qualification remain
required before merge. This is not production runtime or final protocol
upgrade-system acceptance.

## K1 proof bundle repin completion

K1 repin PR 610 merged as `13b0d814f7a085d8b84ec88a87ad2682386f2934`.
The reviewed tree was `5bb92226`. Its 49 Python checks, three platform release
builds, and two Docker cache jobs passed. The reserved historical first and
second bundle recipes remain byte-identical; the active proof graphs now use
the pinned Pulley fork identities. S2 is based on this merged state for final
qualification and does not reinterpret K1 proof success as S2 acceptance.
