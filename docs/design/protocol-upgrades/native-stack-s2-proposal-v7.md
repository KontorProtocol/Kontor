# S2: deterministic native stack and Pulley capacity, proposal v7

Status: planning only, 2026-10-28; supersedes v1 through v6 after source review. This
document authorizes no production edit,
PR, merge, or network activation. The coordinator and independent reviewer must
agree an exact revision before S2 implementation. S1-2 is the synchronous
guest-ABI source at `18637a8a4de9389a03f14127fe9ba1b77d92f829`,
merged as `208480b7cd10d0bc1eebc3f1e6e35a577b84e6e6`. Fork PR A is the
reviewed Pulley logical-stack fix
at `8416d4673d0d4bf5b6cab35c75194c64817d8073`, merged as
`0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7`. Its exact-head fork CI
[run 40646035555](https://github.com/wilfreddenton/wasmtime/actions/runs/40646035555)
passed all ten jobs. S2 selects merged PR A's `.2` source. Fork PR B, the
version-only `.3` descendant, merged as `0dbc68b31c0bcf1a05c93122f1939fb8784e4e48`.
K1-REPIN is a
separate Kontor PR after A and B; it freezes distinct `.2`/`.3` bundles.
Actual execution through both bundles is qualified at K2b. Neither PR B nor
K1-REPIN is a prerequisite to S2's single-production-engine stack proof.
Keep the spawned guest-call owner from S1; cancellation ownership is the
separate OWNERSHIP-1/K2a gate.

## Source findings and invariants

- S1 disables guest component async, threading, stack switching, and Store
  concurrency in `core/indexer/src/runtime/mod.rs::new_engine`, while
  `core/indexer/src/runtime/call.rs::call_guest` still uses `tokio::spawn` and
  `Func::call_async`. A pending host callback suspends its guest. A child call
  creates a new Store via `invoke_unsettled`; each live child has its own
  `call_async` future and async fiber. S1's paid/view/Core depth-32 and
  depth-64 separate-process tests are in `call/tests/sequential_chains.rs`.
- The fork passes `Config::max_wasm_stack` to Pulley's `Vm::with_stack` through
  `crates/wasmtime/src/runtime/vm/interpreter.rs`. Fork PR A's
  `pulley/src/interp.rs` bounds execution by a checked, 16-byte-rounded
  logical length independent of backing capacity. A configured 524,288 bytes
  is already aligned, so its Pulley logical limit is exactly 524,288 bytes.
  The fork defaults are 524,288 bytes for `max_wasm_stack` and 2,097,152 bytes
  for `async_stack_size` (`crates/wasmtime/src/config.rs`). S2 must set both
  explicitly and attest them. The config documentation's
  `async_stack_size - max_wasm_stack` host allowance describes native compiled
  stack accounting; it is not a Pulley fiber capacity formula. Under Pulley,
  `runtime/vm/interpreter.rs::Interpreter::new` allocates a separate heap VM
  stack for each Store, while `runtime/fiber.rs::on_fiber` and
  `runtime/vm/instance/allocator/on_demand.rs` allocate a native async fiber
  from the 2 MiB setting. The Store may cache a fiber until teardown
  (`runtime/store/async_.rs`). Keep Wasmtime's nonzero and
  `max_wasm_stack <= async_stack_size` configuration checks, but measure
  native fiber headroom directly, including simultaneous child Stores.
- `Stack<CallFrame>::push` currently rejects a repeated contract ID, not a
  long chain of distinct contracts. `Runtime::_call` snapshots and records
  parent fuel before `invoke`. `invoke_unsettled` creates the child Store;
  `prepare_in_store` loads and instantiates its component; only then does
  `invoke_in_store` push the `CallFrame` and open a savepoint. The fork's
  `runtime/component/instance.rs` runs a core module start function on a
  fiber during `instantiate_async`, and S1's `preparation_fees.rs` tests a
  start trap. A start that calls an imported host function can therefore
  execute before the child's frame exists. A cap derived from
  `Stack<CallFrame>::len` would miss these live Stores. The same pre-frame
  window requires a separate host authorization decision. Wasmtime's
  [Instance API](https://docs.wasmtime.dev/api/wasmtime/struct.Instance.html)
  confirms that async instantiation can run a start function that calls an
  async host import.
  `call_fuel_limit` caps untrusted paid calls at 100,000 gas times the 1,000
  fuel multiplier, but Core uses `i64::MAX` fuel. Fuel therefore cannot serve
  as a universal bound on simultaneous Stores, fibers, or native frames.
- The old async-WIT Pulley matrix on diagnostic `f1f07c0d` matched all six
  platform/profile cells at plain depth 8187/8188 and wide depth 1722/1723,
  with a local depth-64 reentry success. It is evidence for the old fixture
  only (`tools/native-stack/qualification-results.md`). S1 changes the guest
  binary and its frame layout. The old 64 result does not select a cap.

## Deterministic nested-call bound

Define one protocol constant `MAX_LIVE_INVOCATIONS` across paid, public/system
view, Core, native contracts, and nested `foreign.call`. Add a shared
per-root invocation budget, distinct from `Stack<CallFrame>`. Acquire one
reservation **before** each invocation Store allocation with an atomic
compare-and-increment that cannot exceed the cap; the root Store gets
the first reservation. Put an `Arc<InvocationBudget>` and immutable depth in
the Store's Runtime data. Runtime clones within one invocation share that
budget context but do **not** own a reservation. `make_store` acquires a new,
unique `InvocationLease` for each root or child Store; its Drop releases
exactly one count. Nested Stores inherit the same root budget through their
parent Runtime, even during component start before a frame exists. This matches the existing
guest-memory inheritance: external Runtime has no limiter, `make_store`
creates the root limiter, and child Store Runtime clones call `new_child()`
on the same root budget (`runtime/mod.rs::make_store`). A failed Store
construction releases the new reservation only after any partially built
Store has finished dropping. A detached `tokio::spawn` guest task retains
its reservation while its Store is live. Never release on the outer caller
future's Drop. The invariant is physically live Stores, including preparation
and teardown, not only active guest frames.

The Runtime-held lease considered in v5 does **not** cover physical teardown.
In the pinned fork, `Store<T>::drop` drops `data_no_provenance` at
`crates/wasmtime/src/runtime/store.rs:2534` before it drops `StoreInner<T>`
at line 2535; `StoreOpaque::drop` then deallocates GC, module instances, and
allocator resources at lines 2540-2570. If Runtime holds the last lease Arc,
capacity is released before those allocations disappear. S2 must add an
owner-held lease that is dropped only after the whole Store is dropped. A
candidate wrapper has `store: Store<Runtime>` followed by
`lease: InvocationLease`, with fields declared in that order and no custom
Drop that releases the lease early. Rust drops struct fields in declaration
order, so `Store<Runtime>::drop` completes before `lease` is dropped. Add a
short code comment explaining this non-obvious field-order dependency and a
teardown-order test that fails if the fields are reversed.
Keep the wrapper intact through `invoke_unsettled`, `invoke_in_store`, and
`call_guest`; move the **whole wrapper** into the spawned task and return
it whole on join. If the outer future is cancelled, the detached task still
owns both the Store and lease. If the task result has no receiver,
dropping that result still drops the Store before the lease. Create
the wrapper immediately after `Store::new`, before fallible Store setup such
as `set_fuel`, so normal setup errors preserve the same drop order. While
`Store::new` runs, a local reservation guard remains live; if it unwinds,
that guard releases after its stack unwinds. Do not expose a raw production
Store that can outlive this owner. Audit all `make_store` callers and either
return the owner wrapper to them or keep a raw helper limited to diagnostics
and tests; current non-test runtime call search found `invoke_unsettled` as
the only production caller. Runtime clones may outlive the Store, but they
carry only the budget context. They neither release capacity early nor delay
its release. The unique owner lease covers the whole physical Store lifetime
and construction; it avoids scheduler-dependent false capacity rejection from
unrelated Runtime clone lifetimes.

Carry an immutable per-Store `invocation_depth` alongside the shared count,
zero on an external Runtime and one on the root Store. Increment it with a
checked `parent + 1` before instantiation. At the `invoke_unsettled` entry,
before allocating a Store, reject if either the parent's depth or the shared
reservation count has reached the cap. Make `make_store` fail closed if another
call site attempts an over-cap creation; audit its production callers so this
fallback cannot become a non-deterministic error-classification path. The
check applies regardless of `fuel_override` or the current `nested` flag.
S1's sequential guest policy should make root count equal to path depth in
non-cancelled execution; assert this in tests with pre-frame start callbacks
and host-I/O suspension. If a sibling can overlap, the count still bounds
memory, but its race-dependent admission would require a deterministic
scheduler before consensus use. Keep `Stack<CallFrame>` for its current
authorization/cycle semantics, without moving its cycle check or using its
length as the resource counter.

At the nested limit, return a deterministic `CallOutcome` with unchanged
inherited fuel before any child allocation. `_call` then updates the parent
Store's fuel and checkpoint on the existing child-result path. The depth
guard itself charges no new fuel; existing canonical lift/import charges
remain. Test exact fuel and receipt behavior before freezing the constant.
An early capacity error would take precedence over invalid target, malformed
expression, or cycle detection that currently occurs after Store creation.
That is a consequential error-order change, still requiring reviewer
agreement. Preserve the existing cycle guard and its order below capacity;
do not move it merely to match the new depth guard. If old precedence must
hold even at capacity, specify a separately metered preflight before Store
allocation and review its fuel effects. Test both capacity and below-cap
orders, plus a fuel-exhausted import. Do not infer `OpStatus::Trap` merely from
`ExecutionError::Deterministic`: `classify_result` maps a non-Trap
deterministic error to `Other`, while host import propagation can yield a
Wasmtime trap. Pin the actual nested receipt/status through runtime tests.
The result must not depend on host stack position, task
scheduling, allocator behavior, or platform. In the current WIT,
`foreign.call` returns `string`, so a host error traps the guest; test that
classification and cleanup rather than assuming catchability. Rejected calls
must create no child Store or savepoint and must leave the parent depth and
fuel checkpoint coherent. A flat sequential loop can issue many calls, so
this is a *live-depth* bound, not a total-work limit.

Before a frame is pushed, a core module start can reach host imports while
`Store<Runtime>` still carries the parent's top frame. Prefer a recursive
admission ban on **both** core `StartSection` and `ComponentStartSection` in
the encoded component, rather than a per-import `Preparing` allowlist. Use
`wasmparser::Parser::parse_all` so embedded modules and nested components are
visited; reject malformed payloads deterministically. Apply the shared rule
to native and user contracts before compilation or cache insertion on
publish and cold load. The current `component_policy::validate` runs only for
user publish, and `component_bytes_and_compiled` compiles and caches cold
loads without that check. User publish of inadmissible bytes is a
`Deterministic` content rejection. A cold load of already accepted stored or
native bytes that fails the new rule is an incompatible-state failure and
must propagate as `NonDeterministic`; recording it as a deterministic call
rejection could split nodes with different cached state. Cache insertion
must follow validation, and a cache hit must carry proof that its component
was validated under the current admission policy, or the cache must be
cleared before that policy takes effect. Test publish, cold load, native
prewarm, and cached reuse classifications separately. Preserve S1's
synchronous-component policy for user contracts.

This policy fits the merged first-party artifacts. A read-only inventory
decompressed all 5 native and 11 test `.wasm.br` modules from S1. A local
helper encoded each with the exact `wit-component` 0.262.0 API sequence in
`runtime/storage.rs`: `ComponentEncoder::default().module(bytes)?.validate(true).encode()?`.
`wasmparser` 0.262.0 `parse_all` found zero core starts and zero component
starts in every resulting component, across 46 embedded core modules. This
matches the runtime's encoder version and options; the helper did not run
the database-backed `Storage::decode_component_bytes` itself. Its pinned
source and lockfile are at `tools/native-stack/encoder-inventory`; it exits
nonzero on an encoded start. Reproduce by Brotli-decompressing each binary
and passing the resulting core module to the helper with `cargo run --locked
--offline --release --manifest-path tools/native-stack/encoder-inventory/Cargo.toml
-- path/to/module.wasm`. The installed
`wasm-tools` 1.244.0 check was only preliminary and is not the basis for this
inventory. The raw per-binary output plus compressed/decompressed SHA256
manifest is `tools/native-stack/encoder-inventory/inventory-s1-2026-10-28.tsv`;
the core-start negative-control output and fixture hash are in
`negative-control-s1-2026-10-28.txt` beside it. The merged binaries match
the S1 candidate byte-for-byte.

### Pre-frame guest-entry source audit

The call sequence in S1 is `invoke_unsettled` Store creation
(`core/indexer/src/runtime/call.rs:193-231`), `prepare_in_store` component
instantiation (`call.rs:299-348`), then frame push and savepoint
(`call.rs:248-255`). Between those points, `input::params` constructs host
`Val`s and charges fuel (`call/input.rs:17-61`); it does not call a guest
function. `prepare_in_store` also inserts host context resources
(`call.rs:394-508`), which are not guest-defined resources.

On the fork, `Instantiator::run` processes core `InstantiateModule` by
`Instance::new_raw` followed by `start_raw` on a fiber if startup is needed
(`crates/wasmtime/src/runtime/component/instance.rs:787-879`). Its remaining
global initializers configure lowered imports or extract table, memory,
realloc, callback, post-return, and resource function references
(`instance.rs:883-930,946-953`). Registration does not invoke those
functions. `Instance::new_raw` allocates the core instance and reports
`needs_startup` (`crates/wasmtime/src/runtime/instance.rs:295-342`). A core
Wasm start section is therefore the one module-controlled call path during
instantiation, subject to the generated startup case below. The component
translator has an unimplemented `ComponentStartSection` branch
(`crates/environ/src/component/translate.rs:1494-1497`), but ban that section
explicitly rather than relying on an engine rejection.

Wasmtime can synthesize a startup function for active data/element segments
even without a Wasm start section. The inspected compiler's
`translate_module_startup` initializes globals, passive elements, tables,
and memories, and invokes `translation.start_func` only when present
(`crates/cranelift/src/func_environ.rs:6088-6117`). Its initializer helpers
perform constant-expression evaluation, table operations, or memory copying
(`func_environ.rs:6142-6353`); these are generated VM operations, not a
call to an imported contract host function. The fork's Cranelift compiler
dispatches `FuncKey::ModuleStartup` through this translator for both native
and Pulley ISAs (`crates/cranelift/src/compiler.rs:436-453,662-685`); the
Pulley target branches only inside lower-level compilation. Test a start-free module
with active data and element segments plus a sentinel imported host function:
instantiation may execute generated startup, but the host sentinel must
remain uncalled. Include out-of-bounds initialization and fuel exhaustion,
which must trap or fail without attributing effects to the parent frame.

`ExtractRealloc` only records a function reference
(`component/instance.rs:896-899,946-953`). `input::params` builds dynamic
values before the frame; the selected export's argument lowering happens
inside `Func::call_async` through `call_guest` after frame push
(`call.rs:248-262,542-565`; fork `component/func.rs:288-310,465-507`).
Canonical realloc is invoked by `LowerContext::realloc` with `may_leave`
cleared (`component/func/options.rs:143-199`), so it cannot call imports or
intrinsics. A hostile realloc can still trap or consume fuel, and must be
charged to the framed child. Test it with a large string/list input.

Guest and host resource destructors are registered at instantiation
(`component/instance.rs:725-738,917-930`), not called. `ResourceAny` is
`Copy` and requires an explicit `resource_drop` to invoke a guest destructor
(`component/resources/any.rs:55-80,245-270,348-405`). S1's generated host
context resources have no destructor attached when converted to
`ResourceAny` (`component/resources/any.rs:108-115`). On a partially failed
instantiation, the component instance-count guard only decrements the count
(`component/instance.rs:1232-1260`); Store drop runs component cleanup only
for concurrent component state (`component/store.rs:128-166`). S1 disables
that concurrency (`core/indexer/src/runtime/mod.rs:327-336`). The ordinary
Store teardown deallocates instances (`crates/wasmtime/src/runtime/store.rs:2528-2570`),
with no explicit guest resource-drop call. Pin this with a failed
instantiation fixture that declares a guest destructor and a host context
sentinel, then assert that teardown invokes neither guest code nor host
resource destructor callback before a frame exists. Ordinary Rust `Drop`
must still release host resources during teardown; the negative fixture
does not forbid that cleanup. After frame push, an exported
function may explicitly drop an owned resource; test that host callback and
its cleanup under success and trap.

For a synchronous component call, Wasmtime's `Func::call_async` wraps
`call_impl` in the fiber (`component/func.rs:288-310`). `call_raw` lowers
arguments, calls the export, lifts results, invokes canonical post-return,
then exits the guest call (`component/func.rs:465-565`). `call_post_return`
clears `may_leave`, so post-return cannot call imports or intrinsics
(`component/func.rs:713-741`). Kontor pops the frame only after
`call_guest` returns (`core/indexer/src/runtime/call.rs:257-267`), so
post-return remains framed even on a trap. Test a component post-return that
attempts an import and verify the trap, fuel, and rollback classification.
If any other preparation or teardown path enters guest code before frame
push, the start ban alone is insufficient and this decision returns for review.

Negative controls must include a synchronous core-start fixture that calls
`foreign.call` and a start that calls a stateful host import, each rejected
at admission before instantiation or side effects. An invocation cold load
currently occurs after Store creation, so assert lease cleanup there. Test a
nested component start, a malformed component, post-frame host imports, and rejection through
publish, cold load, native prewarm, and cache reuse. Pin deterministic error
classification, fuel, savepoints, resource cleanup, and root reuse. The
start-ban decision requires exact-revision coordinator and independent-reviewer
agreement before implementation.

The reviewer and coordinator selected `MAX_LIVE_INVOCATIONS = 64`, **root
included**, conditional on six-cell native-fiber and memory margins. The
three-Store longest observed first-party path clears the requested eightfold
source-depth margin. The one local depth-64 success used the old async-WIT
fixture and proves neither the current stack nor memory margin. Before the
numeric value is approved for production:

1. Inventory the rebuilt first-party and test contracts' maximum intended
   cross-contract depth, including native Core hooks, pagination, fallback,
   callbacks, and realistic paid/view paths. Declare the supported legal depth
   and verify the candidate's eightfold margin from that inventory, including
   any source-enforced maximum. Check a maximum-gas paid
   chain and a representative Core chain. A cap below a supported realistic
   path is unacceptable even if the old probe passes.
2. Run exactly 63, 64, and 65 simultaneous-Store distinct-contract chains
   on every target/profile, counting the root and leaf. Require exact success
   at 63 and 64 and the same deterministic classified error at 65, with
   matching fuel, receipt,
   rollback, resource-table count, savepoint depth, and pooled reuse. Repeat
   after a nested failure, host I/O suspension, pre-frame start attempt, and
   a prior Pulley overflow. Count the root in all expected depths and assert
   exact reservation counts before prepare, during suspension, after teardown,
   and after failure. Include invalid target, malformed expression, exhausted
   fuel, and repeated-contract controls at and below the boundary. Test the
   owner wrapper's drop order with a teardown probe that observes the budget
   during Store destruction, not merely after return. Cover `set_fuel` or
   other fallible Store setup, failed preparation, successful nested return,
   panic/trap cleanup, a suspended spawned call whose outer future is
   dropped, and an unobserved task result. In each case the reservation must
   remain held until the Store has fully finished dropping. Audit all
   production Store creation paths for a raw-Store escape.

   The existing S1 `sequential_chains.rs::publish_chain` loops over
   `0..=depth` (`call/tests/sequential_chains.rs:54-104`), so its `depth=32`
   fixture has **33** simultaneous Stores, while `depth=64` has **65**.
   The current test expects `depth + 1` successful paid/Core receipts
   (`sequential_chains.rs:245-255`). Under a root-inclusive cap of 64, retain
   the old 33-Store success, add new 63- and 64-Store successes (fixture
   `depth=62` and `depth=63`), and make the unchanged old 65-Store fixture a
   designed over-cap rejection. Document that old success-to-rejection
   change explicitly in the implementation PR. The 65-Store case must not
   wait for the leaf's `testing::host_error` notification, because the guard
   rejects before leaf execution (`sequential_chains.rs:110-184`;
   `test-contracts/error-test/src/lib.rs:228-244`). Assert exact classified
   outcome, fuel, receipt rows/status, rollback, resource count, savepoint
   depth, and pool reuse instead. Keep the existing leaf-failure and host-I/O
   suspension paths on the 33-, 63-, and 64-Store successes. Name cases by
   simultaneous Store count so the fixture's `depth` argument cannot be
   mistaken for the protocol count.
3. Measure peak committed/reserved memory, live Store/fiber count, OS thread
   stack high-water, and each async fiber's native stack high-water with the
   rebuilt synchronous guest, in dev and release. Run adversarial but admitted
   host paths: canonical lift/lower, deeply nested canonical types, storage
   read/write, initialization, resource and instance teardown, guest reentry,
   native/Core, and maximum legal input sizes. Use child processes so
   a guard-page abort is reported as failure rather than killing the test
   runner. The cap must fit a declared per-invocation memory budget and retain
   a twofold margin, with peak native fiber use no more than half the usable
   fiber capacity, on all six cells under the chosen worst admitted path,
   including concurrent root
   requests at the declared node admission limit. Do not infer headroom from a
   single successful depth or from virtual Pulley stack size alone.

### Existing resource limits and the missing envelope

`core/indexer/src/runtime/guest_memory.rs::GuestMemoryLimits` already shares
a 512 MiB linear-memory/GC admission budget and 16,777,216 admitted table
elements across nested Stores in one root. It also caps each Store at 16
memories, 64 instances, eight tables, and 65,536 elements per table. These
limits do not count Pulley's stack allocation, Wasmtime async fibers, host
objects, compiled components, or table backing bytes. At candidate depth 64,
the configured 512 KiB Pulley stack plus 2 MiB async fiber implies 160 MiB
of nominal stack/fiber reservation for 64 simultaneously live Stores before
allocator and guard overhead. Distinguish virtual reservation, committed
pages, and observed RSS in every measurement.

The fork's `runtime/vm/table.rs::TableElementType::element_size` gives a
target-specific element stride. On the 64-bit targets, 16,777,216 funcref
slots at an eight-byte pointer-sized stride represent about 128 MiB of table
backing; GC refs use four-byte slots, about 64 MiB. Stack switching and its
continuation table type are disabled by S1. Thus a root can plausibly combine
the 512 MiB guest admission, 128 MiB table backing, and 160 MiB stack/fiber
reservation, an approximately 800 MiB subtotal before host data, Store and
instance metadata, database buffers, allocator overhead, and other roots.
These categories have different allocation and residency semantics, so 800
MiB is a planning subtotal, not a proven peak RSS or a sufficient process cap.
The final table-byte calculation must use the resolved target's element types
and allocator behavior, not just the slot count.

`runtime/pool.rs::new` sizes the read-only view pool from
`available_parallelism`, which varies by machine. `reactor/mod.rs` handles
simulation requests serially through `simulate_rx`, and canonical block and
batch execution await their ordered operations. Do not add an imaginary set
of independent simultaneous simulation roots. There is no fixed global
admission count for all root calls in the reviewed source. The final node
envelope must count one active consensus/reactor execution, its serial
simulation path, actual pooled views and other admitted API roots, then bound
or measure their overlap on the minimum supported hardware. A per-root depth
cap alone cannot certify process memory safety. If a fixed root-admission
bound is required, specify it as a separate reviewed node rule rather than
assuming the hardware-dependent pool size is a protocol constant.

The current `call_guest` spawns a task and awaits its JoinHandle. Dropping a
caller future can detach that task, leaving its Store and reservation live
after a view-pool object is returned or replaced. Therefore the pool's
`available_parallelism` limit is not a global live-Store or live-root bound
before OWNERSHIP-1. S2 may qualify **non-cancelled** execution and the lease's
correct survival through task detachment, but it cannot claim cancellation
quiescence or a finite process-wide admission envelope from this source.
Final production adoption still requires OWNERSHIP-1's cancellation, task
drain, storage-authority, and global admission gates. Keep a distinct
observation of detached tasks, Store count, and reservation count in tests;
do not silently count them as freed roots.

If 64 fails the inventory or resource envelope, choose a new constant and
rerun the full gate. If no constant can admit realistic calls within the
declared memory/headroom envelope, redesign the call owner and review it
before S2. Do not silently increase stack sizes or restrict guest WIT to make
the probe pass.

### First-party call-depth inventory

The merged S1 source has five native contracts. Direct cross-contract calls
found in their Rust source are:

| Caller | Direct target and source | Longest observed branch |
| --- | --- | ---: |
| NFT | `filestorage::create_agreement` in `native-contracts/nft/src/lib.rs::mint` | 2 |
| Staking | filestorage obligation/cleanup views and token issue, burn, or transfer in `native-contracts/staking/src/lib.rs` | 2 |
| Filestorage | staking stake query or slash, and token transfer/emission in `native-contracts/filestorage/src/lib.rs` and `rewards.rs` | 3 via `settle_expired_challenges -> staking::slash -> token::burn` |
| Token, system | no other contract call found in their native source; system calls its built-in host interface | 1 |

The staking-to-filestorage queries `has_storage_obligations` and
`is_bond_cleanup_pending` read filestorage state and do not call back into
staking. The longest **observed native first-party path** is therefore three
simultaneous invocation Stores, root included. Candidate 64 gives more than
an eightfold margin over this source path, but this static audit does not
bound arbitrary published user contracts or calls hidden in generated code.
`test-contracts/proxy/src/lib.rs` deliberately forwards `foreign.call` and
can form longer distinct-contract chains for qualification. Before approving
64, compare rebuilt native binaries and generated wrappers against this
source graph, inventory supported user composition, and test paid/view/Core
paths that actually occur in the node. Do not use the synthetic proxy's
unbounded source chain as a claimed realistic first-party need.

## Production engine and six-cell qualification

S2 pins merged fork PR A's `.2` commit and selects it as the one production
engine. Require the exact source, lockfile, and feature closure, with no
forbidden cache, profiling, or debug-builtins features. K1-REPIN later re-pins
the two independently resolved manifests to `.2` and `.3` in its own PR and
checks distinct package versions and normalized native prefixes. K2b later
qualifies actual execution through both bundles. Rebuild the synchronous stack-probe and
all affected native/test artifacts with the repository build command; record
source SHA, compressed component SHA, compiler, target, profile, lock, fork
commit, effective features, and resolved `Engine::is_pulley()`. Select
`pulley64` in the production `Runtime::new_engine` for every consensus,
simulation, replay, and API engine. Assert the resolved target is
`pulley64-unknown-unknown-elf`; remove the diagnostic environment toggle and
native-JIT fallback. Explicitly set and attest both stack sizes and the
16-byte logical rounding rule. Preserve the S1 guest-concurrency exclusions
and ordinary async host suspension.

Run the rebuilt probe in **exactly six** independent dev/release cells: Linux
x86-64, Linux ARM64, and macOS ARM64. Each cell must use the final production
`.2` production engine, without a test-only Pulley override. The cases are
paid, public view, system view, and Core plain
and wide recursion; a fixed large frame; nested distinct-contract chains;
host import followed by reentry; resource teardown; and Store reuse after
trap. Include the S1 paid/view/Core 33-Store success and the old 65-Store
fixture's designed rejection, plus new 63- and 64-Store successes.
For recursion, observe an actual success at depth `D` and the first
`StackOverflow` at `D+1` in every cell, with repeated samples near the
boundary. A binary-search claim alone is insufficient. If a case is intended
only as a bounded success, label it as such and do not use it to claim a
universal boundary. Capture process signal, timeout, and OOM as failures, not
as equivalent traps. Compare values, exact trap class, fuel, persisted paid
and Core receipts, absent view receipt, state markers, rollback, resource
count, savepoint count, and pool reuse. Keep raw logs and a SHA256 manifest.

Strengthen `tools/native-stack/qualify.py` and `compare.py` before the final
run. The comparator must require the exact six cell keys, one valid report per
key, successful upstream jobs, identical expected case sets and mandatory
fields, valid target/profile and binary provenance, identical component hash
and effective stack settings, and exact adjacent observations. Reject missing,
duplicate, truncated, stale, failed, or mislabeled reports. Compare each
observation rather than only the summary fields. Commit negative controls
that remove a cell/case/field, duplicate a key, alter a target or stack size,
shift one boundary, or substitute a process signal for a trap; each must make
comparison fail. These controls close the current comparator's `get()` and
glob-count gaps, which can otherwise let missing fields compare equally.

Run actual runtime paid/view/Core calls through the production entry points
in all six cells, including a maximum-gas paid call, native Core call, nested
success/failure, post-trap call, suspension, and cleanup. Assert receipt order,
status, gas/fuel, signer/payer, balances, deposit/collateral, state roots or
equivalent deterministic state, and exact rollback. Compare against the S1
synchronous baseline for intentional ABI-generated fuel changes. K2b performs
the later two-bundle execution comparison. Do not let the
stack-probe-only result stand in for real call accounting.

## Performance acceptance declared before measurement

Canonical block execution calls `execute_transaction` serially in block
order (`core/indexer/src/reactor/blocks.rs`), and each transaction walks its
inputs and ops serially (`reactor/executor.rs`). Decided batch application
also awaits each transaction in order (`reactor/batches.rs`). This ordering
preserves deterministic effects and makes a slow legal call hold up following
work. The configured 10-second propose timeout and its 80% GetValue fallback
are **proposal-distribution timers**, not a general VM service-time allowance;
do not define a Pulley budget as a percentage of either timer.

Before benchmarks, the operator and reviewer must declare: minimum validator
hardware and OS, its `available_parallelism` and view-pool size, admitted API
request overlap, representative and worst-admitted transaction/contract mixes,
arrival envelope (including bursts), maximum supported batch/block sizes,
acceptable replay catch-up lag, and a service deadline for applying a decided
batch or block. Use the **current validator hardware** as the first benchmark
reference, record its CPU, RAM, OS, storage, Rust profile, and concurrent view
load, then decide whether it is the minimum supported node. A faster CI runner
cannot substitute for that reference.

Construct a finite **declared operational** workload envelope `W_op` from
current and projected validator populations, realistic and stressful
contract mixes, and the available protocol bounds. Paid calls have the
100,000-gas ceiling, and file-storage
settlement loops cap selected work at 32 per call
(`native-contracts/filestorage/src/lib.rs::SETTLEMENT_WORK_LIMIT`). Core uses
`i64::MAX` fuel, while ordering reward distribution iterates all active
validator accounts (`native-contracts/staking/src/lib.rs`); its population is
a state dimension, not bounded by the paid gas cap. Inventory validator count,
files/agreements, pending settlements, state size, transaction/input/op count,
and all Core hooks before calling a benchmark the worst block in `W_op`.
No source-enforced maximum active-validator count was found in the staking
contract or its reactor caller. Ordering reward distribution is therefore
`O(N_active_validators)` in a state dimension outside the paid gas cap, and
`get_active_set` also enumerates the active set. S2 does not require a new
protocol validator cap and must preserve this existing Core behavior.
Report the observed population and the projected population range selected
by the operator. A benchmark of `W_op` supports a conditional operational
service claim only; it is not the worst legal block over all possible state.
Check the other dimensions for the same issue. The separate representative
envelope must include realistic native,
paid, view, and host-I/O calls, not just recursive probes.

On the same reference hardware and fixed block shape, measure first-party
native S1 and Pulley S2 full-block application times at increasing active
validator populations `N`, including ordering reward, active-set refresh,
storage, and competing admitted views. Preserve identical inputs and report
the observed distribution, not only an average. Define `N*` as the first
measured population where the predeclared 60-second service statistic for
the worst block in `W_op` is crossed. Report the measured bracket around
`N*` and uncertainty; if none crosses, report only `N*` greater than the
largest tested population. Do not interpolate an exact threshold from sparse
samples. Show both S1 and S2 curves and whether the operator's realistic or
projected population range reaches a crossing. If S2 crosses inside the
declared envelope, the performance gate remains open until the workload,
hardware, or implementation is revised and reviewed.

Derive the gate from the shared serial reactor: for each admitted block,
consensus-batch, or simulation class `i`, measure arrival rate `lambda_i` and
service time `S_i`; require `sum(lambda_i * E[S_i]) < 1` with an explicit
headroom factor under the declared mix. For a burst backlog `B` and recovery
horizon `R`, require
measured spare service rate sufficient to drain `B` within `R`. Measure
high-percentile end-to-end application latency for the declared batch/block
envelopes, including storage, host I/O, cold/warm loading, maximum-gas paid
calls, Core state dimensions, memory pressure, and competing admitted views.
Keep consensus batch arrival and Bitcoin anchor-block arrival as separate
streams with their actual ordering and queueing rules.

Reviewer and coordinator propose, as **draft targets** rather than source
facts: a declared `W_op` worst-envelope Bitcoin block applied within 60 seconds, a
six-block burst drained within 600 seconds, and replay throughput at least
10 times the representative arrival rate and at least once the declared worst
arrival rate. These become acceptance criteria only after `W_op`, the hardware,
arrival trace, measurement method, and backlog starting state are frozen
before the run. The unbounded Core state dimensions and detached-task root
admission gap prevent a universal worst-case or process-wide
performance claim. Scope the S2 gate to the declared
non-cancelled envelope.
Report native-S1 versus Pulley-S2 CPU time, wall time, RSS, and tail latency
as diagnostic deltas, but acceptance is the predeclared service and liveness
envelope. If the envelope is not yet declared, S2 performance approval remains
open; no arbitrary percentage threshold can close it.

## Review and phase gate

S2 may start production edits only after exact-revision coordinator and
independent-reviewer agreement on this plan or a replacement, with the
numeric depth cap, resource envelope, and performance assumptions resolved.
The implementation needs focused unit/integration tests, six-cell current-head
CI, exact-head review, and a separate merge decision. S2's non-cancelled
behavior becomes the differential oracle for later OWNERSHIP-1/K2a work. No
direct-await, guest async migration, or cancellation refactor is in S2 scope.

Open decisions: K1-REPIN identity for later phases; six-cell margin for the
selected root-inclusive cap of 64; start-section admission policy;
per-invocation/fiber and concurrent-root memory and stack headroom
budget; declared Core state/workload dimensions, validator hardware and arrival
trace, and service envelope. The depth guard adds no new fuel charge, but its
exact existing import charge, receipt/status, and error precedence require
review.
These are acceptance inputs,
not values inferred from the old async-WIT matrix.
