# Pulley logical stack limit, fork prerequisite proposal v3

Status: frozen proposal for the lead's phased plan and independent review. This
document authorizes no source edit, dependency update, or production selection.
It addresses the Pulley virtual stack limit and the two fork identities needed
for K1's final proof pair. S2 retains separate nested call resource bounds,
native fiber headroom, workload performance, comparator hardening, and final
synchronous guest WIT qualification.

## Source and immutable identity

- Existing Kontor baseline: `wilfreddenton/wasmtime` commit
  `bfdee9ba9a483915dc95432708cf7db8281adbc1`, package version
  `51.0.0-dev`. PLAN-1 reserves this exact source and version in the existing
  development proof graph. Do not amend or retag it.
- Fork PR base: `wilfreddenton/wasmtime` commit
  `525ffedef9bc8babdd9c0b3bd703a5ba5793fcb8`, package version
  `51.0.0-kontor.1`. It descends from the baseline and contains the F1 native
  namespace work. PLAN-1 reserves this exact source and version in the other
  development proof graph. Do not amend or retag it.
- Proposed fix release, fork PR A: a new commit descended from the F1 base,
  with workspace package version `51.0.0-kontor.2` and native suffix
  `51_0_0_kontor_2`. Its Pulley logical-stack fix is the final P1 VM source.
- Proposed version-only release, separate fork PR B: a new commit descended
  from the reviewed fix release, with workspace package version
  `51.0.0-kontor.3` and native suffix `51_0_0_kontor_3`. It has the same fixed
  Pulley behavior and no implementation change. Its distinct immutable source
  identity is the final second proof graph's VM source.

The final K1 proof pair maps P1 to `.2` and the second graph to `.3`; both
select Pulley. The baseline `51.0.0-dev` and F1 `.1` identities remain reserved
development history, not the final retained P1 identity. S2/K2a must re-pin
and requalify K1's proof bundles with this new pair. Record the corresponding
PLAN-1 amendment when the phased plan is agreed. Each fork release is its own
reviewed PR because a phase is a PR. Work stays in `wilfreddenton/wasmtime`:
do not open an upstream Bytecode Alliance PR, issue, or comment.

The current Kontor manifests and the visible fork refs checked on 2026-10-28
contain only the baseline and `.1` identities; neither `.2` nor `.3` was
listed as a fork tag. This is a proposed reservation, not an assertion about
unobservable work. Recheck all retained manifests, fork refs, tags, and K1's
normalized-prefix guard immediately before publishing each release. If either
version has been claimed, choose new versions and freeze a new reviewed
proposal before publication.

Fork PR A changes only package versions inheriting Wasmtime's
`51.0.0-kontor.1` workspace identity, including `pulley-interpreter`, to
`51.0.0-kontor.2`, their matching internal dependency constraints, necessary
lock graph references, and the scoped logical-stack implementation and tests.
Fork PR B changes those same workspace-identity package versions from `.2` to
`.3`, matching internal constraints, and necessary lock graph references only.
Independently versioned Cranelift and third-party packages retain their
versions, sources, and checksums in both PRs. Record each new commit hash only
after implementation and review. Kontor's existing baseline and F1 development
bundle manifests and lockfiles stay immutable; S2/K2a produces the new final
proof pair. Neither fork PR selects Pulley in Kontor's production engine.

## Source finding and limited fix

In the pinned source, `crates/wasmtime/src/runtime/store.rs` constructs a
Pulley `Interpreter` per `Store` when the engine target is Pulley. Its
`runtime/vm/interpreter.rs` passes `config.max_wasm_stack` to
`Vm::with_stack`. In `pulley/src/interp.rs`, `Stack::new` rounds the request to
16 bytes and calls `TryVec::reserve_exact`, while `Stack::top` and `Stack::len`
use the vector's reported capacity. `set_sp` traps when a decrement crosses
the resulting base pointer.

For the pinned Rust 1.99.1 toolchain, `alloc::raw_vec::RawVecInner::grow_exact`
sets reported capacity to the requested `len + additional`, even if the
underlying allocator provides more bytes. The existing 512 KiB setting is
already 16-byte aligned. This explains the six matching Pulley reports. The
`Vec::try_reserve_exact` API nevertheless permits capacity behavior to change
with a toolchain or allocator implementation. A consensus stack limit should
depend on the configured logical size, not spare backing capacity.

The fork PR A implementation change is confined to the Pulley `Stack`
implementation and tests:

1. Compute a checked 16-byte-rounded logical length from the requested size.
   Return a structured allocation/range error if rounding overflows.
2. Reserve backing capacity of at least that logical length. Store the logical
   length separately from `TryVec::capacity()`.
3. Initialize the VM stack pointer at `base + logical_len`. Make `Stack::len`
   report `logical_len` so existing bounds and debug checks use the same
   endpoint. Every downward stack adjustment still traps below `base` before
   writing. Extra backing bytes must never become a runnable frame.
4. Preserve 16-byte alignment, Store ownership, trap classification, and
   existing host-call and unwinder behavior. Do not change the 512 KiB Wasm
   setting, 2 MiB async fiber setting, or host-call scheduling in either PR.

The result is an exact logical bound after the documented 16-byte rounding.
For a configured 512 KiB limit, the logical bound is exactly 512 KiB. Backing
allocation can be larger without changing the first `StackOverflow` point.

## Required test gate

The two fork PRs and S2 integration must pass the applicable gates below before
the final proof pair is retained:

1. Extend the existing `pulley/src/interp.rs` `simple_push_pop` unit test with
   deliberate backing overreservation. Construct a 16-byte logical stack,
   force `storage.reserve_exact(2)` while its vector length is zero so its
   reported capacity grows to at least 32 bytes, then rebase the test stack
   pointer after any relocation. Assert `top == base + 16`, four 4-byte pushes
   succeed, and the fifth traps as `StackOverflow`. This negative control must
   fail against the F1 base, where `top` follows backing capacity, and pass
   with the logical-length fix.
2. Check a 17-byte request rounds to a 32-byte logical limit and overflows
   only beyond that limit. Check the rounding-overflow error path. Verify
   repeated traps do not write below `base` or corrupt the next call.
3. Run Pulley interpreter and Wasmtime component tests with direct calls,
   indirect calls, a host import followed by guest reentry, canonical
   `cabi_realloc`, and resource teardown. Compare success, trap type, and
   follow-on Store reuse against the F1 base where the requested limit is
   unchanged.
4. Audit each new workspace lock and native definition. Packages inheriting
   Wasmtime's workspace identity, including `pulley-interpreter`, must use
   `.2` in PR A and `.3` in PR B, with matching internal constraints.
   Independently versioned packages must retain their versions, sources, and
   checksums, except for necessary lock graph references to the changed
   Wasmtime packages. The two native prefixes must be unique against each
   other and the development identities; K1 must reject duplicate versions or
   normalized suffixes. Record both commits, lock hashes, compiler identity,
   and source-diff inventories. PR B's diff must be limited to the version
   change, matching internal constraints, and necessary lock graph references.
   Keep forbidden cache, profiling, and debug-builtins features excluded under
   PLAN-1.
5. After S1 changes guest WIT, S2/K2a must rebuild the contract fixture and pass
   the strengthened six-cell Linux x86-64, Linux ARM64, and macOS ARM64 dev and
   release stack qualification on the new P1 and second proof bundles. Require
   both Pulley targets, all expected reports, cases, mandatory fields, target
   identifiers, true adjacent success/failure boundaries, real-call smoke,
   and successful upstream jobs. Include a deliberately truncated or failed
   report as a negative control. Compare values, receipts, fuel, rollback,
   and cleanup in addition to stack depth. Bundle identity and attestation
   must include the configured `max_wasm_stack` and the 16-byte rounding rule;
   a changed setting or rounding rule requires a new qualification.

The source proof for fork PR A is limited to virtual Pulley stack sizing.
Ordinary Wasm-to-Wasm dispatch uses Pulley's iterative interpreter loop, but
Wasm-to-host calls can reenter guest code through native frames. S2 must
separately bound reachable reentry and demonstrate native fiber headroom for
the final WIT. This proposal does not treat a passing six-cell matrix as a
universal proof for arbitrary guest programs.
