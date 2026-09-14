# Gas metering and congestion integration

Investigation baseline: main `8d30d38a`, 2026-09-14. Proposal reference:
[#445](https://github.com/KontorProtocol/Kontor/pull/445), head `dfd632b2`.
Tracks [#462](https://github.com/KontorProtocol/Kontor/issues/462) and the fee-pricing
slice of [#442](https://github.com/KontorProtocol/Kontor/issues/442).

## Current behavior

The runtime converts each user operation's signed gas limit to Wasmtime fuel
at 1,000 fuel/gas. Guest instructions and explicit host charges consume that
budget. Nested calls inherit the remaining budget; their work is already included
in the outer call. Trusted core work uses a separate, very large fuel ceiling.
Views have an operator-configured budget and do not execute as chain transactions.

Storage writes additionally consume `Fuel::Deposit`. This is a refundable
reservation against the operation's budget, not execution work. The runtime
tracks successfully consumed deposit gas across nested calls, including reverted
writes, and subtracts it before burning the execution fee. The stored result's
`gas` still includes that reservation. Nested procedures also insert result rows.
Summing those rows would both include collateral reservations and double-count
nested execution.

`gas_to_token_multiplier = 1e-9` has three callers: the upfront gas hold, execution
fee settlement, and the storage-floor view. Existing rows store integer
`deposited_gas`, so changing this multiplier reprices existing collateral as well
as fees. This is documented in the existing
[floor design](storage-deposit-floor-migration.md), not an accidental new behavior.
Congestion integration needs to separate those responsibilities deliberately.

The pricing proposal uses `price = phi_base * beta`, with `phi_base = 2.5e-7`
and beta initially zero. A zero execution price therefore needs to work without
making storage collateral free. The 250x ratio between the current and proposed
base constants is arithmetic, not independent evidence of correct calibration.
Runtime benchmarking cannot establish a KOR/USD price or the appropriate economic
markup.

Relevant code: `runtime/call.rs` (`prepare_call`, `handle_procedure`, `_call`),
`runtime/host_storage.rs` (`_set_primitive`), `runtime/host_files.rs`
(`storage_floor`), and `runtime/deposit.rs`.

## Measurement prerequisite implemented on this branch

Detailed `FuelGauge` profiling was enabled by default. Each host charge acquired
a mutex, updated per-type statistics and percentages, and appended a history
entry. `set_context` resets that history only when a transaction context is
present. Repeated system calls without one can accumulate entries. Profiling
also records attempted charges before fuel subtraction succeeds.

Normal runtimes now start with no gauge. Explicit cost probes still install a
gauge, so their host-operation counts remain available. This changes diagnostic
overhead, not fuel subtraction, fee settlement, state layout, or contracts.

The existing gauge is not suitable as a consensus utilization meter: in addition
to deposits and attempted charges, a captured interval can contain independent
gas-hold/release calls. Its start/end fields can be overwritten by those calls.
Build utilization from operation execution accounting, not diagnostic percentages.

Regression coverage compares profiling enabled/disabled across successful staking
writes, nested token calls, a contract error and fuel exhaustion, checking the
checkpoint, result gas/status, balances, collateral and burn. A manual benchmark alternates profiling
modes over seven warm samples of 100 staking top-ups, rolling back each sample.
It reports elapsed time, burned KOR and retained tracing events. It excludes native
compilation and bootstrap; it is not a block-capacity or full host-cost calibration.

Run from the repository root:

```sh
CARGO_BUILD_JOBS=4 RUST_LOG=warn cargo test --manifest-path core/Cargo.toml \
  --release -p indexer --lib runtime::fuel::profiling_tests::fuel_profiling_costs \
  -- --ignored --exact --nocapture
```

Measured on Linux aarch64 / Apple M2 in release mode with no concurrent build,
seven samples per mode:

| 100 warm staking top-ups | Profiling disabled | Profiling enabled |
|---|---:|---:|
| Median elapsed time | 849.004 ms | 851.105 ms |
| Sample range | 847.438–856.782 ms | 849.152–853.427 ms |
| Retained diagnostic events | 0 | 14,600 |
| Burned KOR | 0.0000211 | 0.0000211 |

The median difference is about 0.25%, within the observed timing variation. This
does not demonstrate a material throughput improvement for these DB-heavy calls.
It does eliminate unnecessary default event retention and tracing work. Other
workloads and machines may differ. Normal transaction-context resets also limit
retention; the table measures the full explicit profiling interval, not a claim
that all production calls accumulate indefinitely.

Validation: 495 library tests passed, 7 manual tests ignored; the profiling
benchmark was run explicitly. Core Clippy (`-p indexer --tests -- -D warnings`),
formatting and diff checks passed. No contract binary or storage format changed.

## Recommended implementation sequence

1. **Separate execution pricing from collateral pricing.** Keep the collateral
   conversion stable when congestion changes. Preserve the existing up-front
   collateral guarantee even when execution becomes cheaper than collateral.
   Simply changing the storage-floor caller to use another constant is insufficient.
2. **Expose deterministic operation usage.** Count executed fuel once at the outer
   call boundary, with deposits separately identified. Keep attempted work from
   deterministic failures; discard an abandoned block's totals on rollback.
   Track core work separately to understand node capacity without treating core
   maintenance or API views as user demand. Cover publishing, nested calls,
   out-of-fuel, failed preparation, and replay, not just successful procedures.
3. **Measure representative workloads and define capacity.** Include storage scans,
   writes/deletes, numeric operations, proof verification, BLS registration and
   ordinary contract calls. Choose a protocol-defined work target per Bitcoin
   block from measurements. Wall-clock time is observational only; nodes must not
   use their local elapsed time to decide utilization. A pricing target is distinct
   from a hard block limit, which would need its own ordering/admission semantics.
4. **Re-derive #445 against main and integrate pricing.** Use the prior Bitcoin
   block's committed utilization to select the next block's price, with one price
   for all its operations. Reorg/replay must restore price and usage together;
   optimistic execution needs the same Bitcoin-block boundary rule. Cache the
   resolved block price in the runtime, avoiding a contract view call per debit.
   Define bounds/rounding and signed fee authorization before applying prices.

One conservative way to preserve collateral funding in step 1 is to hold
`G * max(p_execution, p_collateral)` for a gas limit G, then burn only
`E * p_execution`, where E is execution gas and D is reserved deposit gas.
Because `E + D <= G`, the released balance is at least `D * p_collateral`.
This preserves the current proof even when execution price is zero. It can
over-reserve balance for operations that use little storage; it is a design option,
not an implemented or newly accepted fee policy. A distinct signed storage budget
is another possibility but requires broader transaction/SDK changes.

Open decisions before pricing activation: capacity target, handling utilization
above that target, beta bounds/minimum/rounding, and how a signed operation limits
its maximum KOR charge when the block price changes. Existing `Payment` specifies
a gas quantity, not a separate signed maximum price per gas.

## Closure

The profiling patch alone closes neither #462 nor #445. A replacement that includes
the pricing state machine and runtime consumers can supersede #445. #462 stays open
until calibration and integration are both completed or explicitly split into
linked follow-ups. Governance authorization remains #463.
