# Contract conversion error compatibility

Kontor uses the released, pinned Wasmtime 48.0.2. No Wasmtime patch or fork is
required. The adapter in `runtime/call/error.rs` recognizes a narrow set of
conversion failures at the contract call boundary.

## Classification order

1. Preserve an explicit nested `ExecutionError` classification.
2. Keep actual Wasmtime `OutOfMemory` failures on the infrastructure path.
3. Preserve existing typed Wasmtime trap handling.
4. Exclude host errors wrapped by the generated `anyhow: true` bindings.
5. Recognize public UTF-8/UTF-16 and character decoder types at the root cause.
   Match the pinned allocation-limit, string/list bounds and alignment, return
   pointer, and guest allocator errors. Recognize invalid variant/enum/option/
   result tags using Wasmtime's complete message format and bounded integers.
6. Treat every other error as an infrastructure failure.

The host-origin check matters: a host function can return the same message or
Rust decoding error as Wasmtime's own conversion code. Those must not silently
turn into rejected contract calls. Explicit nested classifications take priority
so a deterministic child conversion failure remains deterministic in its parent.

Message matching applies only to the root cause, not formatted context or
substrings. The variable tag message must contain canonical decimal `u32` values
and, when the message includes a case count, an actually out-of-range tag.
Prefixes, suffixes, overflow, leading zeros, and inconsistent ranges do not match.
Matching runs on the failure path. Successful calls do not format errors.
The immediate underlying cause is preserved by `ExecutionError::source()`.

## Upgrade regressions

`call/tests/abi_errors.rs` triggers real failures in both synchronous and
asynchronous Wasmtime component exports, independently checking the expected
messages/public decoder types and the resulting Kontor classification. The test
messages do not import constants from the adapter. Changes to the Wasmtime
messages therefore fail tests instead of silently updating expectations.
Coverage includes invalid list pointers and lengths, indirect record return
pointers, enum/variant/option/result tags, Unicode characters, and guest allocator
results. Both sync and async exports exercise these paths, with valid controls,
memory-end boundaries, and nested classification propagation. Async record
returns exceed the 16-value flattening limit to exercise the indirect path.
Typed conversion tests also pin the distinct option/result and generated enum/
variant errors; host bindings use these same `Lift` implementations.

A separate fixture uses actual generated host bindings to return those same
messages and decoder types. It checks the host-origin marker and infrastructure
classification through three wrapper levels. Unknown engine errors, near matches,
misleading context, and an injected out-of-memory error remain infrastructure
failures. The test does not induce a physical host allocation failure.

Existing Rust contract tests cover direct and nested allocation-limit failures,
write rollback, resource release, subsequent successful calls, and actual async
suspension. Allocation-allowance probes are test-only; production limits and fuel
prices are unchanged.

Run from `core/`:

```sh
cargo test --release -p indexer --lib runtime::
```

On 2026-09-17, the real-conversion regression failed against the original
classifier. After expanding category coverage, the adapter passed 171 runtime
tests (12 manual tests ignored).

Any Wasmtime upgrade must pass these tests. Review changes to the conversion
errors or the host-binding wrapper before updating the adapter or expectations.
This is deliberately not an exhaustive conversion-error audit: unrecognized
map/fixed-list, resource, and engine errors retain the existing fallback. The tests
do not enumerate every host import signature or induce physical allocation failure.
Changing classification is consensus-visible and must be deployed consistently.

## Superseded approach

The tested dependency-patch proposal is retained in git history at `11bcd189`.
It was superseded by this adapter to avoid maintaining a Wasmtime fork. The
unapplied patch files and unsent upstream draft have been removed. The initial
hook and allocation-unit investigation remains in
[ABI conversion budget investigation](../abi-conversion-budget.md). Conversion
pricing and a deterministic dynamic guard remain separate work.
