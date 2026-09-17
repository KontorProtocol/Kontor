# ABI conversion budget investigation

2026-09-17, based on main `533854b0` (PR #577), Wasmtime 48.0.2.
This is an experiment, not an enabled protocol policy. Result encoding already
has the [bounded WAVE writer](contract-result-budget.md); this investigation
covers the earlier conversion between guest memory and owned host values.

The following measurements describe the initial experiment. The subsequent
[compatibility adapter](abi-errors/README.md) fixes the covered error
classifications without a Wasmtime patch. The dynamic allocation policy remains
test-only.

## Decision

Keep the production allocation allowance unchanged for now. Public call hooks
can refresh it from remaining fuel, including after suspension and in nested
Stores. However, the allowance is an allocation guard, not an execution charge:
it resets for each conversion, does not debit instruction fuel, and does not
expose consumption. Dividing remaining fuel by the existing output-byte price
rejects some otherwise affordable ordinary calls.

The next implementation prerequisite is a typed way to recognize conversion
limit failures without treating real host failures as contract failures. Then
define stable logical conversion units and their accounting. Do not price native
Rust allocation sizes as consensus work or match Wasmtime error strings.

## Integration experiment

`runtime/conversion_probe.rs` is compiled only for unit tests. Its policies
observe boundaries, impose a fixed allowance, or refresh an illustrative
`min(default_allowance, remaining_fuel / 10)` allowance. Ten is an experimental
factor borrowed from output pricing, not a proposed conversion price.

The Store factory installs the probe so each child Store receives it. Updating a
root Store alone does not cover child contracts. The probe refreshes at both
`CallingHost` and `ReturningFromWasm`: async component results can be lifted by
`task.return` before the final return hook. It never debits execution fuel.

Tests in `runtime/call/tests/conversion.rs` establish:

- Existing Rust contracts return 192-byte strings under a 1,024-unit allowance
  and reject 1,536-byte strings. Direct calls and one/two proxy levels agree.
- A procedure that writes a marker and map entry before returning an oversized
  result rolls both back. The call stack clears, the invocation's resource table
  is released, and a subsequent call succeeds.
- The rejected conversion currently returns `ExecutionError::NonDeterministic`.
  These are characterization tests of a known gap, not the desired behavior.
- With ample fuel, observing or updating the allowance leaves execution fuel
  totals unchanged across direct calls and both proxy depths.
- A separate WAT component calls an async host import twice. The host actually
  yields, spends fuel, and yields again. Refreshing the allowance rejects an
  oversized second argument before the second host body runs; an affordable
  second argument succeeds. This fixture uses the real Runtime Store and error
  decoder, but bypasses contract publication/admission.
- Existing injected host errors and panics remain infrastructure failures;
  instruction exhaustion remains a deterministic failure.

An ordinary `storage-state()` call returning `[0, 0, 0, 0]` succeeds with its
measured exact execution budget of 34,835. The illustrative dynamic policy
rejects the same call with 469 fuel left. Wasmtime's dynamic list lifting charges
`len * size_of::<Val>()` allocation units before lifting elements, not encoded
output bytes. `Val` is 48 bytes on this build. This counterexample rules out
simply reusing the WAVE byte rate for the guard.

## Error boundary

Wasmtime's allocation error is the private `HostcallFuelExhausted`, not a public
`Trap`. Kontor currently recognizes typed traps and explicitly deterministic
`ExecutionError`s. The limit therefore enters the infrastructure-error path.

Wasmtime 48.0.2 has its own error wrapper. Kontor's `bindgen! { anyhow: true }`
host wrappers call `ToWasmtimeResult`, which wraps host errors using
`Error::from_anyhow`. This preserves typed downcasts and offers a host-origin
marker through `is::<anyhow::Error>()`. It may avoid adding another wrapper to
every host implementation, but it is not a complete deterministic classifier:
native Wasmtime failures include actual host allocation failures too, and
nested calls can wrap engine errors as host errors. Absence of the anyhow marker
does not prove a guest fault.

Prefer a public typed conversion-error API in Wasmtime, starting with allocation
allowance exhaustion. Check malformed UTF-8 and invalid pointer failures at the
same boundary. Any proposal must keep real host allocation failures, DB errors,
and panics on the infrastructure path and preserve classification through
parent calls. The current integration tests do not cover malformed return
values; earlier standalone probes identified that adjacent gap.

Pinned source references:

- [Allocation allowance and private error](https://github.com/bytecodealliance/wasmtime/blob/v48.0.2/crates/wasmtime/src/runtime/component/func/options.rs)
- [Dynamic value lifting](https://github.com/bytecodealliance/wasmtime/blob/v48.0.2/crates/wasmtime/src/runtime/component/values.rs)
- [Error wrapper and anyhow interoperability](https://github.com/bytecodealliance/wasmtime/blob/v48.0.2/crates/core/src/error/error.rs)
- [Generated host wrappers](https://github.com/bytecodealliance/wasmtime/blob/v48.0.2/crates/wit-bindgen/src/lib.rs)

## Measured overhead

Local Linux release build, five rounds of 100 calls per policy, rotating policy
order. Values are median microseconds per call. Tracing is disabled; all three
cases use a binary compiled with Wasmtime's `call-hook` feature.

| Call | No installed hook | Observe | Refresh allowance |
| --- | ---: | ---: | ---: |
| Direct integer | 30.267 | 30.194 | 30.211 |
| Two proxies, integer | 172.575 | 175.654 | 175.009 |
| Direct four-number list | 89.870 | 90.466 | 90.374 |
| Two proxies, four-number list | 234.437 | 237.410 | 237.720 |
| Direct 1,536-byte string | 55.776 | 55.655 | 55.726 |
| Two proxies, 1,536-byte string | 204.110 | 206.672 | 206.975 |

Installing the hook adds approximately 0 to 2% in these cases, mostly in nested
calls. This does not measure enabling the feature versus a production build
without it. Hooks also run around fallible Wasmtime libcalls, so measure that
separately with compute-heavy and allocation-heavy guests before enabling it.
This is a feasibility comparison, not calibration or a cross-platform guarantee.

## Follow-through

1. Resolve the typed-error boundary, with an upstream API proposal or a narrowly
   scoped dependency change if necessary. Add malformed-result regressions and
   preserve nested rollback and infrastructure classification.
2. Specify logical conversion work (such as payload bytes and visited values)
   independently of host layouts. Establish what existing host tariffs already
   cover and how repeated conversion pays, including records with omitted fields.
   A refreshed guard alone does not charge repeated work.
3. Verify a pre-conversion guard against that policy, test exact boundaries and
   partial failures, then measure feature-enable overhead and platform parity.
   Only then enable it in production and calibrate prices.

Validation: 162 runtime tests passed, 12 manual tests ignored; the manual
`abi_hook_overhead` benchmark also passed. Production behavior is unchanged.
Reproduce from `core/`:

```sh
cargo test --release -p indexer --lib runtime::
cargo test --release -p indexer --lib runtime::call::tests::conversion::abi_hook_overhead -- --ignored --nocapture
```
