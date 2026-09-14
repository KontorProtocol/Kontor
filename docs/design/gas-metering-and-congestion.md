# Gas metering and congestion integration

Investigation baseline: main `8d30d38a`, 2026-09-14. Proposal reference:
[#445](https://github.com/KontorProtocol/Kontor/pull/445), head `dfd632b2`.
Tracks [#462](https://github.com/KontorProtocol/Kontor/issues/462) and the fee-pricing
slice of [#442](https://github.com/KontorProtocol/Kontor/issues/442).

## Behavior at the investigation baseline

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

`gas_to_token_multiplier = 1e-9` prices the upfront gas hold, execution
fee settlement, storage-floor view, and signer-footprint API. Existing rows store integer
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
  --release -p indexer --lib runtime::fuel::profiling_tests::fuel_accounting_costs \
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

Profiling-only validation: 495 library tests passed, 7 manual tests ignored; the profiling
benchmark was run explicitly. Core Clippy (`-p indexer --tests -- -D warnings`),
formatting and diff checks passed. That slice changed no contract binary or storage format.

## Recommended implementation sequence

1. **Separate execution pricing from collateral pricing (implemented on this branch).** Keep the collateral
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

The implementation preserves collateral funding in step 1 by holding
`G * max(p_execution, p_collateral)` for a gas limit G, then burn only
`E * p_execution`, where E is execution gas and D is reserved deposit gas.
Because `E + D <= G`, the released balance is at least `D * p_collateral`.
This preserves the current proof even when execution price is zero. It can
over-reserve balance for operations that use little storage. A distinct signed
storage budget would require broader transaction/SDK changes. With the current
equal prices the hold and final fees are unchanged.

Open decisions before pricing activation: capacity target, handling utilization
above that target, beta bounds/minimum/rounding, and how a signed operation limits
its maximum KOR charge when the block price changes. Existing `Payment` specifies
a gas quantity, not a separate signed maximum price per gas.

## Independent storage pricing decision, 2026-09-14

Execution and storage rates may evolve independently. Start with a stable storage
rate; future automatic adjustments should respond to persistent state demand,
not temporary execution congestion. Preserve reservations on untouched rows.
Repricing existing state or introducing rent requires separate lifecycle decisions.

The runtime now has one validated `Pricing` value with an execution price and a
storage reservation rate per byte. Defaults remain 1e-9 KOR per execution gas and
one reservation unit per byte. The existing `deposited_gas` denomination stays
fixed at 1e-9 KOR per unit; it is not a tunable price. Storage changes are expressed
as units charged to future writes, keeping the existing integer granularity.
Both the contract floor view and signer-footprint API use that same denomination.

Zero execution fees exposed a pre-existing settlement assumption: token `release`
always called `burn`, which rejects zero amounts. Release now skips a zero burn
and refunds escrow normally. Ordinary user burns still require a positive amount;
negative settlement burns still fail. The token binary is rebuilt for this change.

Writes record the current rate, as before. Replacing a row replaces its whole
reservation at the current rate; untouched rows retain theirs. Deletes free the
recorded reservation. The ordinary versioned rows and footprint rollback path
handle this without a new table, migration, or rescan on rate changes.

`Pricing` rejects negative execution prices and zero storage rates. Storage-byte
and fuel multiplication overflow fail deterministically before the write. Prices
remain protocol defaults in production: there is no node-local configuration,
contract-controlled setter, adaptive formula, or governance path added here.
A future protocol hook must resolve the agreed prices on startup and at block
boundaries, including rollback, before they can change on a running network.

Price-separation validation: 499 library tests passed (7 manual tests ignored),
including independent rates, prospective reservations, block rollback/replay,
zero-fee escrow/supply accounting, deterministic reservation overflow and the
hold/collateral arithmetic property. All six storage-deposit integration tests
passed. Core and native Clippy and formatting checks passed; the token binary
was rebuilt using the pinned contract build image.

Related designs consulted:

- [NEAR storage staking](https://docs.near.org/protocol/storage/storage-staking):
  balance reserved according to stored bytes, released when data is deleted.
- [Sui gas fees](https://docs.sui.io/develop/transaction-payment/gas-in-sui):
  separate computation and storage prices; storage prices change infrequently,
  with prepaid storage and deletion rebates.
- [Aptos fees](https://aptos.dev/network/blockchain/gas-txn-fee): execution/IO gas
  and storage fees denominated independently, with recorded storage refunds.
- [Stellar resource pricing](https://developers.stellar.org/docs/learn/fundamentals/fees-resource-limits-metering):
  dynamic storage pricing tied to ledger size, plus rent for storage lifetimes.

## Closure

The profiling and price-separation work closes neither #462 nor #445. A replacement that includes
the pricing state machine and runtime consumers can supersede #445. #462 stays open
until calibration and integration are both completed or explicitly split into
linked follow-ups. Governance authorization remains #463.

## Execution usage accounting

The next measurement slice records raw Wasmtime fuel, before gas rounding and
minimum billing. `ExecutionUsage` separates user fuel, system fuel and storage
reservation fuel. Reservations are subtracted even when the associated writes
revert. Failed host charges that never subtract fuel do not add their requested
cost. Guest traps, contract errors and initialization/preparation failures retain
fuel already consumed. Rejections before any metered execution report zero.

Sampling is at store boundaries. A parent is sampled before entering a nested
call; its checkpoint advances past the fuel inherited back from the child.
Every child is sampled independently, including failed preparation, and result
serialization is sampled after its charge. This avoids nested double counting
and missing child work. `FuelGauge` owns these totals and can optionally attach a detailed host
profile; both use the same measurement scope. Collection is enabled only within
explicit execution scopes, with constant-size counters when profiling is disabled.

This measures the work the existing fuel model covers, not all physical work.
In particular, parsing, signature verification outside Wasm, and publication's
validation/compilation are not separately priced by this change. Publishing
records its metered init, including initialization failures; malformed bytes can
therefore produce zero fuel despite host work. These gaps belong in the workload
and fuel-table calibration before treating fuel as a complete capacity model.

The existing fee path has two nested-call gaps: preparation failure does not
forward the child's remaining fuel, and procedure result charging occurs after
fuel is forwarded. Usage includes that work without changing fee settlement.
Measurements can consequently differ from charged gas by more than rounding,
and should not be reconstructed from result rows or burned KOR. Fixing the
billing behavior requires separate regression coverage and an explicit protocol
change; these measurements do not activate it implicitly.

Successful transaction execution persists one `transaction_execution_usage` row,
including deterministic failed operations. System fuel within it includes
hold/release work; nested views inherit their calling operation's category.
Infrastructure failures abort the surrounding transaction and persist no usage.
Block maintenance persists one `block_execution_usage` row. Both are additive,
off-checkpoint observations; missing rows on an existing database mean unknown,
not zero. No historical usage is synthesized from old gas/result records.

Transaction usage references the transaction row with `ON DELETE CASCADE`;
maintenance references the block with the same cascade. Savepoint rollback,
simulation and execution-history rollback discard observations together with the
execution. Optimistically executed transactions retain one observation on Bitcoin
confirmation, rather than being measured again. Joining to `transactions.height`
groups by execution anchor; joining to `confirmed_height` groups by Bitcoin
confirmation. Neither grouping is declared to be the eventual pricing window by
this change. The activation PR must settle that rule for optimistic execution.

Fees, signed gas limits, contract binaries and storage collateral remain unchanged.
This slice advances step 2 and does not close #462 or supersede #445.

Validation: nine focused accounting regressions pass, covering billing/checkpoint parity,
nested success and failed preparation, rejected charges, failed gas holds,
publish/init failure, traps, reverted deposits, transaction aggregation,
infrastructure failure, savepoint abandonment, confirmation rollback, execution
rollback/replay, overflow, consumed/rejected profile entries and explicit scopes
across context changes. The profiling parity test also compares disabled,
totals-only and detailed collection. The full indexer library suite passed with
511 tests and 9 intentionally ignored manual tests. Indexer Clippy (`--tests`, warnings
denied), formatting and diff checks passed. No contract or SDK rebuild is required
because this slice changes neither generated interfaces nor contract code.
## Consolidated gauge

`FuelGauge::new()` creates a totals-only scope; `FuelGauge::with_profiling()` adds
host-operation detail. Both return the same `FuelReport`, containing net execution
usage and an optional profile. The previous separate `UsageMeter` is removed.
Private `gross_user_fuel` includes reservations while accumulating; exported
`ExecutionUsage.user_fuel` always excludes them.

Host charging borrows the gauge directly from its Wasmtime store. It no longer
passes or clones a second gauge argument through every import, and charging is
synchronous because neither fuel subtraction nor short gauge updates await I/O.
Totals-only charging skips the profile lock. Detailed profiling records each
charge after the subtraction attempt, with separate consumed/rejected counts and
fuel; rejected requests never inflate consumed host fuel. The profile's consumed
host total includes deposit reservations, identified by the Deposit event/type.

Removed the old starting/ending fuel pair, host/guest percentage calculation,
per-charge percentage recomputation and automatic context-based gauge reset.
Reports cover explicit scopes, including internal calls and context changes;
optional profiles cannot use a different interval from their execution totals.
The existing contract cost probes now read those same reports. Fee settlement
and the refundable deposit meter retain their existing behavior.

The manual `fuel_accounting_costs` benchmark compares disabled collection,
totals-only collection and detailed profiling on warm staking top-ups (nested
token calls and storage writes). `fuel_persistence_costs` separately compares the
transaction path with collection disabled, totals only, and totals plus database
persistence. Both alternate mode order, roll back between samples and report
elapsed time and burned KOR. Timing is observational, never a consensus input or
CI assertion. Earlier profiling measurements above describe the previous gauge.

On local Linux aarch64, release mode, seven samples of 100 operations per mode
with no other test/compiler run in parallel produced these elapsed times:

| Probe | Mode | Median ms | Range ms |
| --- | --- | ---: | ---: |
| Warm contract calls | Disabled | 799.869 | 796.425–800.982 |
| Warm contract calls | Totals | 800.554 | 796.459–801.776 |
| Warm contract calls | Detailed profile | 801.166 | 796.685–804.542 |
| Transactions | Disabled | 800.926 | 799.849–802.756 |
| Transactions | Totals | 801.242 | 799.645–806.484 |
| Transactions | Totals + persistence | 801.480 | 800.688–804.709 |

Within-sample median overhead versus disabled was 0.10% for call totals, 0.11%
for detailed profiling, and 0.13% for transaction totals plus persistence.
Those differences are within the observed timing spread; this workload does not
resolve a meaningful slowdown. It also does not establish the overhead for
CPU-bound contracts or sustained database growth. Every sample burned exactly
0.0000283 KOR. Totals retained no diagnostic events; detailed profiles retained
14,700 events per sample. The persistence probe verified exactly 100 usage rows
in each persisted sample and zero in the other modes.
