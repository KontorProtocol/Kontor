# S1: Sequential contract execution amendment

Revision: S1-2, 2026-10-28. Proposed, awaiting exact-revision agreement.

This phase amends approved PLAN-1. It is one independently reviewed Kontor PR
before completing K2a. It does not replace F1-F3/K1-K11 or authorize production
implementation of S2 or the ownership correction. The lead and Interlink reviewer
must explicitly agree this revision before S1 implementation.

Base: main ca0e6a768a841a8dfee8a3f8cc3565f4570af97b, verified through GitHub.
Worktree: /home/wilfred/Documents/Kontor/sequential-contracts,
branch feat/sequential-contracts. Do not inherit the rejected direct-await change
from unfinished K2a at 6a5f42e63f0e0c721dd4012bc2389ad25166f884.

## S1: Synchronous contract ABI and sequential guest execution

One Kontor PR, implemented by the lead. Depends on reviewer agreement and current
main, not on the unfinished K2a extraction. No new dependency fork is expected;
confirm the pinned fork's supported synchronous-component/async-host path.

Scope:

- Change canonical built-in WIT, contract exports and all linked copies/fixtures
  to synchronous functions. Change validator rules for ordinary exports, init and
  fallback. Keep context, result, error and naming rules unless explicitly listed.
- Disable component guest async/concurrency and related guest-thread features in
  the engine. Enforce binary admission for arbitrary components and nested
  components, not just code produced by Kontor macros. Explicitly disable
  wasm_component_model_async, wasm_component_model_more_async_builtins,
  wasm_component_model_async_stackful, wasm_component_model_threading,
  wasm_component_model_error_context, wasm_threads,
  wasm_shared_everything_threads, wasm_stack_switching, and concurrency_support.
  Assert the resolved engine feature set and concurrency setting in tests.
  Inspect all engine creation,
  publication, native loading, cache, simulation and replay routes; require the
  same Runtime::new_engine constructor for these production routes. There is no
  production Component::deserialize path on the reviewed base; keep it absent
  or enforce the same engine identity and trusted artifact provenance if one is
  introduced. Test that an artifact produced with incompatible features cannot
  be loaded under the final engine; do not add an unsafe untrusted deserialize API.
- Use ordinary asynchronous host wrappers. Adapt Accessor-dependent code and
  fuel access to ordinary store access while preserving portable metering. Audit
  resource destructors: async plus store currently selects resource_concurrent
  even for synchronous WIT. Choose compatible drop flags/registration and add
  the metered linker's resource_async forwarding where needed.
- Preserve shared guest/native macro generation. Guest wrappers are synchronous;
  native wrappers retain async/await, pagination and their public API. Retain
  explicit import_test/interface_test selection for internal native callers too.
- Rebuild native contracts, test contracts and affected SDK outputs/provenance
  through ./tools/kontor build, followed by reproducibility checks. Cover custom
  WAT fixtures and docs as well as Rust-generated components.
- Do not add a guest concurrency scheduler or ban Rust source syntax as a proxy
  for the admitted binary capabilities. Do not introduce a direct-await change.
  Do not change stack sizes, other S2 capacity settings, or introduce a nested-call
  depth-cap value in S1; S2 owns that mechanism and its justified constant.

Invariants and acceptance:

- Normal, nested, fallback, init, view, paid and Core calls follow sequential
  guest call-return order, with no overlapping sibling guest host calls.
- Pending host I/O suspends the guest without blocking the host executor thread;
  independent node requests can progress. Native tests and client calls remain
  asynchronous. No guest continuation runs before its host call completes.
- Arbitrary async/concurrent components, including nested encodings, are rejected
  before execution through all admission/load routes. Existing core thread and
  nondeterministic-feature restrictions stay effective.
- User publication of unsupported components yields deterministic content
  rejection and the appropriate receipt, with cross-cell classification coverage.
  Native/built-in admission failure aborts startup. Incompatible stored bytes fail
  closed through infrastructure/halt handling, never a skip-and-continue outcome.
- Portable lifting/lowering charges, deterministic error classification, ordered
  effects, resources, nested rollback, fees and deposits remain accounted for.
  Record intentional regenerated-code fuel/ABI differences rather than pretending
  regenerated binaries are byte-equivalent to the old fixture.
- Run separate-process paid/view/Core separate-contract depth32 and depth64
  regressions through the actual S1 engine before S1 merge, including suspension,
  nested failure, receipts, fuel and cleanup assertions. Changing the host
  adapter/fiber path must not introduce the previously observed native stack abort.
  Preserve the spawned boundary; if the new path fails, resolve it before merge.
- Use the existing macro/runtime/validator/integration tests, meaningful negative
  controls and full affected workspace checks. Compile/run both environments and
  test async host suspension explicitly. Run reproducible artifact --check.
- Identify actual old development-artifact/cache incompatibility. Fail clearly
  or use explicit supported migration/rebuild procedures; do not silently execute
  incompatible bytes, delete development databases or claim existing production
  history needs preservation. Process-local compiled caches belong to their engine.

This phase does not fix the pre-existing native JIT stack divergence or detached
call cancellation. Those remain explicit blockers to freezing the final baseline.
All required reviews and exact-head CI apply to this PR. S1-only main is not a
qualified P1 baseline: do not deploy or create a new network genesis from that
intermediate state. S2 repeats S1's chain-depth regressions with Pulley.

## Superseded qualification and downstream obligations

This amendment replaces the earlier F1 carry-forward requirement that K2b execute
real canon-lift-async contracts. The final sequential protocol instead rejects
async-lift/async-lower and other guest-concurrency components, including nested
forms, while positively qualifying synchronous guests over asynchronous host I/O
in every retained bundle. Update implementation-plan.md and the private Site when
recording approval. Preserve all unrelated isolation, portable metering and
historical executor requirements. K1's old async/JIT experiment remains historical
prerequisite evidence, not final synchronous/Pulley baseline qualification.

S2 is a separate mandatory production-Pulley phase, subject to its own revised
exact-revision/hash plan agreement before production edits. Its unresolved source bounds, nested-call capacity, performance
criteria and any necessary Wasmtime-fork prerequisite do not authorize an S1-only
baseline. It must requalify the rebuilt synchronous binaries across all six
platform/profile cells with complete evidence, real runtime calls and strong
comparison negative controls before production adoption. S1 chain-depth probes
rerun under that production engine. No runtime/native-JIT fallback is permitted
in the final selected consensus, simulation or replay engine.

Before changing K2a's cancellation ownership, pass the separate OWNERSHIP-1 gate
with explicit agreement on its exact revision/hash before production edits:
an agreed state machine identifying root/nested task, callback and resource
owners; synchronous Drop and asynchronous drain behavior; storage-authority
fences; quiescence before rollback, resource/frame clearing, pool reuse or bundle
teardown; deepest-first release; flat polling and destruction of deep pending
chains; and fuel, signer, savepoint and completion ordering. Spawning crosses the
node host-service interface rather than adding Tokio types to the executor ABI.
Adapt cancellation tests to the S1 host API. S2's verified non-cancelled behavior
is the differential oracle, not the extraction compared against itself.

K2a freezes the final reviewed synchronous/Pulley prelaunch baseline and matching
native artifacts only after these gates pass. Earlier development artifacts stay
distinguishable as evidence and do not silently become executable P1 under a
changed engine. K2b extracts that baseline and all later phases remain required.

## Review and integration

The lead implements and reviews S1. An independent subagent and the independent
Interlink reviewer review the actual final base/head, behavior, tests and known
limitations. Resolve or justify findings, obtain follow-up review after material
changes, run all affected checks and current-head CI, merge on green, then verify
the actual merge. No required review is waived by reviewer unavailability. Update
operator/developer documentation and the owner-only dark design Site accurately.
