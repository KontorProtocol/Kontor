# Contract conversion error compatibility

Kontor uses the released, pinned Wasmtime 48.0.2. No Wasmtime patch or fork is
required. The adapter in `runtime/call/error.rs` recognizes a narrow set of
conversion failures at the contract call boundary.

## Classification order

1. Preserve an explicit nested `ExecutionError` classification.
2. Keep actual Wasmtime `OutOfMemory` failures on the infrastructure path.
3. Preserve existing typed Wasmtime trap handling.
4. Exclude host errors wrapped by the generated `anyhow: true` bindings.
5. Recognize public UTF-8/UTF-16 decoder types at the root cause, and exactly
   match the pinned allocation-limit, string-bounds, and UTF-16-alignment errors.
6. Treat every other error as an infrastructure failure.

The host-origin check matters: a host function can return the same message or
Rust decoding error as Wasmtime's own conversion code. Those must not silently
turn into rejected contract calls. Explicit nested classifications take priority
so a deterministic child conversion failure remains deterministic in its parent.

Message matching applies only to the root cause, not formatted context or
substrings. It runs on the failure path. Successful calls do not format errors.
The immediate underlying cause is preserved by `ExecutionError::source()`.

## Upgrade regressions

`call/tests/abi_errors.rs` triggers real failures in both synchronous and
asynchronous Wasmtime component exports, independently checking the expected
messages/public decoder types and the resulting Kontor classification. The test
messages do not import constants from the adapter. Changes to the Wasmtime
messages therefore fail tests instead of silently updating expectations.

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
classifier, then the adapter passed 166 runtime tests (12 manual tests ignored).

Any Wasmtime upgrade must pass these tests. Review changes to the conversion
errors or the host-binding wrapper before updating the adapter or expectations.
This is deliberately not an exhaustive conversion-error audit: unrecognized
list/map, discriminant, resource, and engine errors retain the existing fallback.
Changing classification is consensus-visible and must be deployed consistently.

## Superseded approach

The tested dependency-patch proposal is retained in git history at `11bcd189`.
It was superseded by this adapter to avoid maintaining a Wasmtime fork. The
unapplied patch files and unsent upstream draft have been removed. The initial
hook and allocation-unit investigation remains in
[ABI conversion budget investigation](../abi-conversion-budget.md). Conversion
pricing and a deterministic dynamic guard remain separate work.
