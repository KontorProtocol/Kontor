# Typed ABI error prototype

2026-09-17. This contains a tested proposal for the error boundary identified in
[the conversion-budget investigation](../abi-conversion-budget.md). The patches
are unapplied here. Kontor still uses the released Wasmtime 48.0.2 dependency.

The independent Kontor cleanup is applied in `7195abe4`: `ExecutionError`
exposes its immediate cause through `source()`, and an explicit nested-call
classification takes precedence over that cause. The regression checks three
wrapper levels and retains infrastructure handling for host, unknown engine,
and injected allocation failures. Previously `source()` skipped the immediate
cause, hiding it from standard error-chain inspection.

## Proposed change

[wasmtime.patch](wasmtime.patch) is against Wasmtime v48.0.2 and touches three
files. It exposes the existing `HostcallFuelExhausted` error, adds an
`InvalidStringEncoding` marker while retaining the underlying decoder error, and
uses the existing `Trap::StringOutOfBounds` / `Trap::UnalignedPointer` variants
for string pointer validation. It changes error reporting, not limits, gas
prices, allocation behavior, or successful conversion semantics.

[kontor.patch](kontor.patch) extends `decode_result` to accept the new explicit
error types as deterministic failures. Unknown engine errors and host failures
retain their infrastructure classification. No error-message matching or new
wrapper around every host function is needed. Apply it on top of the independent
cleanup at `7195abe4`, not directly to main.

## Validation and limits

The independent cleanup passed 163 runtime tests against released Wasmtime
48.0.2, with 12 manual tests ignored.

The isolated patched-dependency build passed 164 runtime tests, with 12 manual
tests ignored. The first broad run caught the missing immediate error source;
the final run includes its fix and verifies the allocation-error type survives
the nested error chain.

The focused suite passes seven tests, with one manual benchmark ignored:

- Sync and async component returns accept an eight-byte string with allowance
  eight, and reject allowance seven with the public allocation-limit type.
- Invalid UTF-8, invalid UTF-16, out-of-bounds string pointers, and unaligned
  UTF-16 pointers have the expected typed failures and deterministic handling.
- Existing Rust contracts exercise allocation-limit failures through zero, one,
  and two proxy calls. Writes roll back, typed errors survive nested calls,
  resource tables are released, and subsequent calls work.
- Actual async suspension still refreshes the experimental allowance before a
  subsequent host argument is converted.
- Host errors and panics remain infrastructure errors. Classifier tests inject
  `OutOfMemory`, unknown engine errors, DB-like host errors, and explicit
  infrastructure errors containing otherwise deterministic causes. They do not
  provoke a real machine allocation failure.

The malformed-string WAT fixtures use the Runtime Store and decoder directly;
they bypass contract publication. The write/rollback and proxy tests use the
existing Rust contract binaries. This is not an exhaustive conversion-error
audit: list/map pointer checks, discriminants, resource handles, and every
canonical ABI path are not changed by this patch. Ordinary Wasmtime traps retain
the existing Kontor classification policy.

This also does not settle conversion pricing or make the allocation allowance
a cross-platform gas unit. Dynamic limits remain test-only. Changing error
classification is consensus-visible and must be deployed consistently.

## Reproduce without changing the production pin

The tested checkout is `/tmp/kontor-typed-abi-errors`; the patched published
Wasmtime crate is `/tmp/kontor-wasmtime-typed-errors`. The local override reuses
Wasmtime's registry dependencies and changes only the top-level crate.

For a fresh reproduction, create a Kontor checkout at `7195abe4`, apply
`kontor.patch`, and copy the published Wasmtime 48.0.2 source to a writable
temporary directory. Apply `wasmtime.patch` there using `git apply -p3`
(the patch uses upstream `crates/wasmtime/` paths). From the Kontor checkout's
`core/` directory:

```sh
cargo test --release -p indexer --lib runtime:: \
  --config 'patch.crates-io.wasmtime.path="/tmp/kontor-wasmtime-typed-errors"'
```

Cargo adjusts that checkout's lockfile for the local override. Do not commit
that lockfile change or a temporary path dependency. The production checkout's
lockfile is unchanged.

## Integration recommendation

Take the small Wasmtime API proposal upstream first. The exact public API should
be settled with maintainers before committing Kontor to it. If a release cannot
be waited for, use a reviewed, revision-pinned fork with a removal condition;
avoid vendoring the entire crate or rewriting its registry source during builds.
The prepared Kontor patch can then be applied with the dependency update and
validated in Linux/macOS CI. Nothing has been posted upstream or pushed.

An [unsent issue draft](upstream-draft.md) accompanies the patches.
