# Production executor extraction

Status: implementation planning for the already agreed K2b phase. This is not
phase acceptance, a frozen P1 artifact, or permission to skip S2 and OWNERSHIP-1.
Source inspected: `protocol-selected-executor` at
`6bf63360bcc5684ef2c595ba499374937c96d4e6`.

K2a's selected in-tree API and logical storage callbacks are preparation. K1's
separate builds link a proof executable. Neither currently makes the production
node independent of its historical execution dependencies. K2b must close both
gaps in one coherent phase after prerequisite integration.

## Source boundaries that still need implementation

| Current source | Required production boundary |
| --- | --- |
| `runtime/mod.rs`, `call.rs`, host bindings, lowering, component validation/cache, native bindings, numeric conversions and `protocol/v1` | Retained executor implementation. Engine, Store, linker, component, WIT, numeric and error types stay within its dependency graph. Moving selected policy files alone is insufficient. |
| `runtime/storage.rs::Storage` | Replace its `libsql::Connection` with node-created logical capabilities. Existing `protocol/storage_*` callback signatures already use standard-library data, but the runtime still constructs them from its own physical connection. |
| `database/storage_*_v1.rs` and versioned query adapters | Node owns connections, statements, cursors and transactions. Preserve logical operation order, read-your-writes and error rendering. Do not expose SQL or a connection as a generic escape hatch. |
| `Storage::block_entropy` | P1 retains the height/window rule and byte representation; a node callback supplies the selected snapshot's block hash. |
| `Storage::{rollback_with_footprint,prune,freelist_count,incremental_vacuum}` | Separate canonical rollback/footprint semantics from node maintenance. The node owns physical pruning and vacuum. Preserve transactional footprint repair and failure ordering. |
| `runtime/ownership.rs`, `runtime/pool.rs` | Preserve accepted root admission, child retention, cancellation, quarantine and commit authority across the linked boundary. Their current public handles contain graph-local Tokio types and cannot become shared API types. |
| `protocol/v1/committee.rs` | Export canonical validator key bytes and powers through standard-library envelopes. Retain stake conversion, key validation, validator ordering and duplicate/zero-power behavior with the versioned rules; do not let a new node's `ValidatorSet` reinterpret an old result. |
| `bls`, `indexer-types`, `stdlib`, generated WIT bindings and relevant local crates | Include the actual semantic dependency closure in the historical lock and source identity. Shared source paths are inputs to fingerprint, not evidence that dependency versions may be shared. |
| `reactor/executor.rs` and selected view/simulation adapters | Replace temporary dependency-owned parameters/results with the linked facade. Node retains Bitcoin RPC, ingestion, ordering, confirmation deduplication, usage persistence and root admission. |
| Native artifact/provenance construction | Use the explicit retained bytes and canonical provenance selected after prerequisite qualification. Node build metadata remains diagnostic; it cannot change genesis state. |

## Linked interface

Use separately compiled Rust libraries linked into the same executable by the
pinned builder. Calls remain in process. The facade uses owned bytes, primitive
tuples, strings, standard-library closures/futures and opaque owners. No Wasmtime,
Tokio, Malachite, libsql, Bitcoin, anyhow or generated WIT type crosses it. Type
aliases over standard-library types can be repeated in each graph; independently
compiled nominal structs cannot be assumed to have shared type identity.

The node selects a definition and admits a root before an executor operation.
The request carries the canonical base, application position, purpose and
node-created storage capability. An executor verifies the selected implementation
before using its own immutable policy. Child calls inherit that root. Public view
limits remain local limits and cannot replace canonical or trusted allowances.

Expose typed operations for recognition, materialization/execution, lifecycle,
committee derivation, view evaluation and simulation. Do not export a generic
closure accepting `Runtime` or an unselected constructor. Keep host failures and
export-level panics distinct from P1 deterministic outcomes and guest panic text.

## Scheduler and ownership

An erased `Future` is type-compatible across graphs but does not transfer Tokio
runtime context. Current `OwnerService::new` and guest/blocking work call
`tokio::spawn` and `spawn_blocking`; their Tokio instance belongs to the executor
graph. Conversely, a host callback may depend on node-local asynchronous I/O.
The production design must explicitly drive each side on its owning runtime.

Keep `OwnerService`, `RootKeeper`, canonical leases, child admission, task identity,
cancellation ordering, blocking-work registration and quarantine in the node.
Retained executors supply standard-library boxed futures and blocking closures
through node-created, root-bound capabilities. The node schedules and joins that
work using its own Tokio runtime. No Tokio handle, join error, cancellation token
or Wasmtime value crosses the linked boundary.

Guest completion contains an opaque bundle-owned payload and explicit
standard-library supervisor status. Only its originating bundle interprets the
payload. It retains the Store, values and graph-local errors until consumed or
dropped. Bundle-owned destructors preserve Store/table-before-lease release. The
node retains physical session authority and the opaque executor session until all
admitted children, blocking work and cleanup have completed.

Production entry points require these capabilities. Remove ownerless production
spawn and spawn-blocking fallbacks. Bundle-local synchronization may remain where
ordinary Future/Waker polling suffices, but the executor cannot assume its Tokio
runtime context exists. Timer, I/O or scheduler-dependent dependency paths require
an explicit host service. Do not introduce a second executor runtime implicitly.

Preserve one node-wide admission budget across retained executors, active views
and quarantined roots. An executor-local owner service cannot multiply capacity
by the number of bundles. Retain the accepted RootKeeper lifecycle rather than
adding a second independently authoritative cancellation state machine. A dropped
caller must not release its SQL session or permit a new canonical writer while
guest work, blocking work or callback-held cursors remain live.

Cancellation requests the existing node supervisor. Dropping a response future
does not establish cancellation completion. Preserve descendant-first abort/join,
blocking-work drain, commit authorization and quarantine. Executor cleanup
callbacks release graph-owned resources; they cannot authorize commit, reopen
admission or return a pooled SQL session independently.

Commit authorization precedes savepoint mutation and SQL commit. Root drain and
cleanup completion precede capability release. Failure to drain quarantines the
root and prevents competing canonical work; it is not a deterministic receipt.
The ownership adapter is security-sensitive implementation for a subsequent
bounded delegation after the native-stack assignment, not a change to that
agent's current task.

### Agreed capability signatures and cleanup contract

Use a bundle-origin opaque session owner retained by the node's root authority,
an opaque guest completion payload, and node-issued child capabilities. Only the
originating graph may interpret an opaque payload. The child capability captures
the existing task ancestry; callers cannot manufacture task IDs or admit work
under another root. A bundle label or caller-supplied integer is not authority.

The scheduling interface uses these agreed structural signatures, rather than
a new shared dependency crate:

```rust
use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

type SharedOwner = Arc<dyn Any + Send + Sync>;
type Payload = Box<dyn Any + Send>;
type HostError = (u8, String);
type HostFuture<T> = Pin<Box<dyn Future<Output = Result<T, HostError>> + Send>>;
type GuestCompletion = (bool, Payload);
type GuestFuture = Pin<Box<dyn Future<Output = GuestCompletion> + Send>>;
type GuestFactory = Box<dyn FnOnce(SharedOwner) -> GuestFuture + Send>;
type SubmitGuest =
    Arc<dyn Fn(SharedOwner, GuestFactory) -> HostFuture<GuestCompletion> + Send + Sync>;
type BlockingWork = Box<dyn FnOnce() -> Payload + Send>;
type SubmitBlocking =
    Arc<dyn Fn(SharedOwner, BlockingWork) -> HostFuture<Payload> + Send + Sync>;
type CheckCommit = Arc<dyn Fn(SharedOwner) -> Result<(), HostError> + Send + Sync>;
```

`SharedOwner` is an opaque capability or session handle, distinguished by the
operation receiving it. Only its issuing graph downcasts it. Scheduling callbacks
are minted for a root and reject tokens from another root, an expired root or a
different issuer before executing supplied work. The bundle receives a child token
from the node through `GuestFactory`; it never supplies a numeric parent or depth.
The existing one-outstanding-child rule and bounded admission apply before the
factory runs. Admission owns the produced future until it joins or is dropped.

`GuestCompletion.0` preserves the existing `host_panicked` supervisor signal.
The opaque payload owns the existing guest result, Wasmtime values and invocation
Store. A successful response transfers that payload to the parent bundle. A closed
receiver causes the node to drop the payload before releasing the child slot, as
the existing `GuestDelivery` lifecycle does. Factory panic, child task panic and
invalid payload identity are infrastructure failures and quarantine the root.
Guest deterministic errors remain within the opaque payload until the retained
executor classifies and serializes its operation result.

Closing-before-delivery preserves `closed_or_infrastructure`: a closing public
view/API parent must remain parked until the supervisor aborts and joins it. Do
not return an ordinary `HostError` that allows that parent to resume fee or
savepoint settlement. Canonical and simulation child closure remains a fatal
infrastructure outcome with quarantine. The node owns this behavior inside the
scheduling future; the bundle does not implement an independent closing state.

Host error tags distinguish ordinary infrastructure failure, exported-call panic
and interface misuse. Unknown tags fail closed as infrastructure errors. None is
a deterministic transaction rejection. Node-side join errors and their rendering
stay in the node; this interface does not export `JoinError`. Retain existing P1
guest error formatting separately, including its `host panic` representation.

Blocking registration precedes scheduling. The node's registry retains both the
work and its completion until work has actually terminated, even when the caller
abandons the returned future. Discarding a result drops its opaque payload through
the originating graph's destructor. No callback grants generic storage authority.

Root authority becomes a node-owned physical session plus a retained opaque
executor session and graph-local hooks. The hooks take the session owner and
return standard-library futures. Split hooks by responsibility:

1. Prepare the executor root with its immutable selection and admitted capability,
   checking that no previous root, live invocation or resource table remains.
2. For canonical drain, preserve the existing early checks after tracked work
   joins: empty semantic call stack, zero live Stores, no retained Store tables
   and expected resource-table ownership. Inspection cannot authorize commit.
   Do not apply that same early empty-stack requirement to canceled stateful or
   pooled roots: their existing restoration clears abandoned semantic state
   after rollback.
3. Perform retained savepoint settlement under the node's already decided commit
   authority, or rollback on cancellation/failure. Physical transaction operations
   still use the admitted node callbacks. Preserve existing error precedence.
4. Reset graph-owned stack/deposit/cache/table state and detach the root context
   according to the existing stateful versus pooled cleanup rules. The node also
   verifies physical autocommit before permitting pool return. For stateful/pooled
   restoration, only after the existing rollback and clearing steps require the
   full empty savepoint/call-stack, zero-invocation and table-ownership invariants.

Canonical roots preserve their separate drain, node commit and complete sequence.
Pooled/stateful roots preserve `restore` and its cancellation-versus-commit CAS.
Cleanup futures stay owned and driven by the supervisor if the requester times
out. Failed cleanup leaves authority quarantined; no destructor, response error
or caller timeout is evidence that a connection can be reused. Final method
names and tuple organization are routine implementation details, but these
ownership and failure contracts require planning agreement before production edits.

## Build route

Extend the current `tools/protocol-bundles/build.py` route to production executor
recipes. Today `identities` assumes proof-only Malachite and conflicting `itoa`
dependencies, and `qualify` directly compiles `protocol-bundles/proof/host.rs`.
Production execution and consensus recipes need explicit dependency requirements;
do not satisfy the old proof checker by adding unused dependencies to an executor.

Reuse locked resolution, metadata namespaces, native-library ownership checks,
exact compiler artifacts, source fingerprints and staged-input verification.
The node's final compile must consume those exact retained facade artifacts and
its own graph. Record the actual linker invocation and audit the final executable.
Do not add the retained crate as a normal Cargo dependency and thereby unify its
resolution with the node.

Bind compiler, target, features, local source, lockfiles, native binaries and
fastnum formatting environment. Retain explicit shared standard/platform ownership.
The node's native libraries must not satisfy an unnamespaced retained reference.
Docker and release entry points must invoke this route; proof-only CI is insufficient.

## Phase acceptance

1. Execute real P1 contracts through two independently resolved production bundles
   in one node, including conflicting dependency versions/features. Verify actual
   engine dispatch and final native-symbol ownership.
2. Compare the qualified pre-extraction P1 baseline with the linked implementation:
   recognition, malformed input, nested failures, fees/deposits, receipts, ordered
   state, lifecycle, committee derivation, simulation, views and canonical provenance.
3. Exercise node callback I/O, pending host work, callback failure/panic, caller
   cancellation, root shutdown, held cursors and cleanup on both sides of the graph
   boundary. Show that storage authority outlives retained work and cannot be reused
   early. Test node-wide capacity with both bundles resident.
4. Reject dependency-owned types at compile time, unselected entry and native-symbol
   fallback. Verify export panic classification separately from guest panic decoding,
   including vendored-path error text.
5. Run the required affected platform qualification against exact production source
   and artifacts, consolidate lead and two independent phase reviews, and pass CI
   through the real production builder before merge.

K3 and K7 still supply durable migration identity and actual height activation.
Two bundles or a deliberately different P2 used by an adapter test do not by
themselves establish the complete upgrade system.

## Planning review

The independent integration planning reviewer examined base `65677ded` through
`6bf63360` and supports node-owned scheduling with bundle-owned semantic futures
and opaque completion payloads. This replaces the initial executor-owned-driver
proposal. The reviewer traced RootKeeper, child ancestry, canonical drain, Tokio
fallbacks, storage callbacks and the proof-only linker. No builds or implementation
review were performed. The reviewer subsequently agreed the structural signatures
and cleanup contract at document SHA-256
`098f3e77f9d1d0d674a6b7148482d132a7dca8a99b0c0b7c35eb0b7fce38b7b3`
on 30 October 2026. That revision incorporates the two requested corrections:
closing API parents remain parked until supervised cancellation/join, and
canonical precommit drain checks remain distinct from pooled/stateful
post-rollback restoration checks. The lead accepts that same contract.

This agreement closes the consequential interface-planning question. It does
not waive prerequisite integration, implementation tests or consolidated phase
reviews, and does not establish production graph isolation or phase acceptance.
