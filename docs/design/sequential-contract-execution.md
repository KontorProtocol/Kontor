# Sequential contract execution

S1 admits synchronous contract WIT and sequential guest call-return behavior.
The Wasmtime host remains asynchronous: a host import may await database or
other host work while the guest is suspended. The guest resumes after that
import returns. Independent node tasks can continue on the same host executor.

This is a prerequisite to protocol versioning. S1 alone is not a qualified P1
baseline and must not be deployed or used to establish a new network genesis.
The separate Pulley stack qualification and cancellation/ownership gates still
apply before freezing the final baseline.

## Contract and native APIs

Contract exports, including `init` and `fallback`, use WIT `func`, without
`async`. The canonical built-in imports also use synchronous WIT. Contract
code uses ordinary calls:

```rust
let value = other_contract::balance(&address, holder);
```

Native clients and tests retain asynchronous APIs. The shared macro generator
already selects `pub fn` or `pub async fn`, the guest foreign-call boundary or
native `execute_api`, and the corresponding `.await?`. `import` and `interface`
select the guest form. `import_test` and `interface_test`, including the testlib
aliases and internal native callers, select the native form. Pagination uses
the same explicit environment selection. This does not depend on `cfg(test)`
inside the proc-macro crate.

The binary capability policy is authoritative. It does not attempt to infer
execution semantics from Rust keywords or require every submitter to use the
SDK. The engine disables component async, additional async built-ins, stackful
async, component threading, error context, core threads, shared-everything
threads, stack switching, and concurrent Store execution. These restrictions
also apply to nested components. The publication policy rejects async function
types and unsupported canonical operations before compilation.

Host bindings use ordinary asynchronous `Access` wrappers. Resource destructors
retain asynchronous host cleanup but omit bindgen's Store flag, which would
select its concurrent destructor API. Portable lifting and lowering charges,
shared nested fuel, result conversion, savepoints and resource lifetimes remain
part of the execution semantics. The spawned guest-call boundary is retained;
S1 does not implement the separate cancellation/ownership correction.

## Artifacts and development state

Use `./tools/kontor build` to regenerate native/test contracts and the SDK with
the pinned reproducible toolchain. Use `./tools/kontor build --check` to compare
the generated outputs. Changing WIT changes encoded binaries and can change
instruction charges even where the source-level result remains the same.

Pre-S1 development artifacts contain async WIT. Rebuilding the node does not
rewrite contracts already stored in its database. An attempted new publication
of an unsupported component is a deterministic content rejection. Loading
incompatible stored bytes fails the operation as an infrastructure failure;
the node must not skip that operation and continue canonical execution.
Startup validates existing native artifacts as well as newly published ones,
so incompatible native bytes fail startup. Compiled caches are process-local;
an entry belonging to a different Wasmtime engine is rejected.

There is no automatic in-place migration or database deletion. Preserve old
development databases and their matching old executable when they are needed
for inspection. Any later authorized fresh development environment must use
rebuilt artifacts and a separate data directory (`--data-dir` / `DATA_DIR`).
Replaying old submissions into new state is not a compatibility workaround:
the old contract bytes still contain the unsupported ABI. A live deployment or
genesis reset requires the remaining protocol baseline gates and an explicit
network/state decision.

## Acceptance coverage

The S1 tests exercise resolved engine features, valid async components and
nested forms, rejection of locally serialized incompatible artifacts, cold
stored-byte loading, native restart, and cache engine identity. A single-thread
host test holds an import pending and demonstrates that another task runs while
the guest's next import cannot begin.

The resource-lifetime regression executes real guest storage iterators and
inspects their host table before dropping the Store. This distinguishes guest
destructor cleanup from invocation teardown. Failed invocations also verify
that their table and owned resources are released without invalidating parent
handles.

Separate-process paid, public-view and Core probes cover 32 and 64 child calls,
pending leaf host I/O, successful return, nested failure, rollback, receipts,
fuel, fees and reuse. Process isolation makes an abort a failing parent test;
bounded waits also reject a stalled child. These are regression checks of the
selected depths, not a proof that arbitrary native stacks or cancelled chains
are safe. The final Pulley phase must repeat the relevant qualification with
its exact engine, dependencies, artifacts and platform/profile matrix.
