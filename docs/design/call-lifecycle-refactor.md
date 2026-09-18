# Call lifecycle refactor: regression coverage

Implementation baseline: main `3749a368` (#568). Commit `b5ef4046` records three
failing fuel regressions before the refactor; `1b2b3113` adds preservation controls
and two resource-leak regressions.

## Behavior to preserve

The focused suite in `core/indexer/src/runtime/call/tests.rs` exercises the real
runtime using the existing error-test and proxy contract binaries. Its outcome
matrix runs direct calls and calls through one and two proxy layers.

| Behavior | Coverage |
| --- | --- |
| Successful views and procedures | Return values; persisted writes; no result row or fee for a direct view |
| Returned contract errors | Error remains a contract return; procedure result status is `ContractErr` |
| Guest panic, fuel exhaustion, host storage rejection | Deterministic failure; failed writes and footprint growth revert |
| Host errors and panics | Infrastructure classification; outer transaction rollback restores balances and supply (requires the existing `testing` feature) |
| Sponsored execution | Actor balance unchanged; outer result attributes actor and payer separately; payer debit equals burn after escrow refund |
| Storage reservations | Successful writes increase the payer's floor; failed writes restore it; reservations are excluded from execution fees |
| Call cleanup | No residual frames; caller's savepoint preserved; host-resource leaks are separately captured below |
| Runtime reuse | A succeeding call still works after each case and its transaction rollback |
| Unsigned nested views | No fees or procedure results; cannot call a procedure to gain write authority |
| Core execution | User gas limit and escrow do not apply; issuance changes supply without a fee burn |
| Reentrancy rejection | Proxy cycle rejected explicitly; parent frames/savepoint preserved; corrected chain works afterward |

These tests assert behavioral relationships, not exact historical fee snapshots.
They intentionally do not require infrastructure failures to write provisional
fees or result rows: those changes are discarded with the transaction.

Existing complementary coverage includes:

- `runtime/fuel/gauge/tests.rs`: deposits on reverted calls, preparation failures,
  transaction aggregation, infrastructure abort, confirmation, rollback/replay.
- `runtime/fuel/profiling_tests.rs`: profiling on/off preserves state and billing;
  Wasmtime initialization and host exhaustion retain their error classifications.
- `runtime/pricing/tests.rs`: zero-price settlement, storage collateral funding,
  overflow, independent rates and rollback/replay.
- `tests/contracts/error_classification.rs`: direct and proxied failures, failed
  writes and subsequent successful calls.
- `tests/contracts/storage_deposit.rs`: write-then-contract-error rollback,
  over-budget growth, overwrite/delete behavior and storage-floor enforcement.
- `tests/contracts/status_classification.rs` and `simulate_errors.rs`: persisted
  result statuses and transaction simulation behavior.
- `tests/contracts/native_token_sponsor_swap.rs` and `bls_publisher_pays.rs`:
  transaction-level sponsorship routing and fee attribution.

## Changes the refactor must make

The three red tests in `runtime/fuel/gauge/tests.rs` require charging failed child
preparation, including child result fuel in the parent's budget and bill, and
rejecting/rolling back an operation one fuel below its measured requirement.
They must become green without weakening these assertions.

The broader tests also exposed a host-resource leak on `scan-compound(false)`:
the direct failed call leaves four live entries behind even though its storage
changes roll back. `storage_traps_release_call_owned_host_resources` preserves
that finding as a separate red regression, with direct and nested cases. The
outcome matrix continues to check state, settlement and frame/savepoint cleanup.

A successful signed proxy call to `succeed()` also leaves one host resource behind.
`nested_success_releases_call_owned_host_resources` captures this independently.
Both cleanup regressions must become green without deleting resources belonging
to parent calls. The old direct-view slot-reuse test is superseded by the invocation-ownership test below.

This is a baseline for the scoped refactor, not proof of every possible failure.
Any additional preparation, cleanup or cancellation paths changed during the
refactor need focused coverage; existing tests do not inject arbitrary database
commit failures or task cancellation at every await point.

## Validation before refactoring

The focused call suite has four passing tests, including all 24 outcome/depth
combinations, and the two expected resource-cleanup failures. The full indexer
library run has 513 passing tests, exactly the five documented failures, and
nine ignored manual tests. No tests were filtered out. Clippy (`--tests`, warnings
denied), formatting and diff checks pass. No contract binaries changed.

```sh
REGTEST=1 cargo test --manifest-path core/Cargo.toml --locked --release \
  -p indexer --lib -j 2
```

At the test-only baseline this command exited unsuccessfully; all five regressions
are ordinary assertions, not ignored or expected-panic tests.

## Shared invocation lifecycle

Both `Runtime::execute` and the foreign-call host adapter now use `invoke`:

```text
choose budget and reserve the outer paid operation's tokens
  -> create store; prepare component, arguments and context
  -> push frame and open savepoint
  -> run guest, classify/serialize return, charge procedure result
  -> pop frame and commit or roll back
  -> record the call result
  -> measure final fuel and drop invocation resources
  -> outer paid operation: settle fee and refund unused reservation
  -> top-level: return result
     nested: copy final fuel to parent, then return result or error
```

Preparation failures retain their store until final fuel is measured and handed
back. Result charging precedes savepoint settlement: a procedure that exhausts
its budget serializing its result cannot commit its writes. The same ordering
applies at every nesting depth. Gas hold/release still execute in independent,
system-paid stores. Only the outer paid operation settles escrow; nested result
rows retain their existing attribution and rollback behavior.

`make_store` creates an invocation-local resource table. Parent and child share
storage, call frames, the deposit accumulator and gauge, but exchange signer
values and WAVE arguments/results rather than resource handles. The child table
can therefore be dropped in full without invalidating parent handles. Host import
clones share only their invocation's table. Return-resource decoding reads the
table from the store itself. This replaces selective context-handle deletion,
which missed resources abandoned on traps and even some successful proxy calls.

`invocation_tables_drop_resources_without_invalidating_parent_handles` exercises
successful execution, guest/host panics, storage traps, missing functions, missing
payment and failed gas holds at three call depths. It holds a weak reference to
the actual invocation table and a counted payload inside it, checking that both
table and owned payload are released while a parent's handle remains usable.
The earlier resource-count regressions also remain in place.

This changes consensus-visible fuel billing and the success boundary for nested
calls. Deploy it consistently across nodes. It adds no schema, contract ABI or
contract-binary changes. Dropping an in-flight future and arbitrary database
commit failures are still outside the regression matrix; the existing spawned
Wasm execution and infrastructure-error policy remain in place.

## Preparation fee settlement

Follow-up to #580, based on main `8a410e27`. Previously, top-level preparation
preceded token reservation, and a failed publication rolled back its init fee.
`runtime/fees.rs::with_payment` now owns the paid operation's outer savepoint:

```text
paid operation
  reserve tokens
  publication savepoint, when publishing
    insert and validate component
    invocation preparation
    guest savepoint: execute, then commit or roll back contract changes
    record call outcome
  commit publication, or remove it on failure
  burn consumed execution fee and refund remainder
commit paid operation
```

Deterministic preparation failures retain consumed fuel and pay for it. Failed
publication removes the contract, provenance and cached component without undoing
its fee. Infrastructure failures, including settlement write failures, roll back
the whole paid scope and clear speculative cached components. Storage-deposit
reservations remain refundable; the actor and sponsor remain distinct.

A signed operation with payment pays even when targeting a view and records its
outcome. Unsigned API views remain free. Nested calls reuse the outer budget and
reservation; core calls bypass user fees. Native token hold/release calls do not
produce result rows, so the SDK's highest result index identifies the user call.

Prices and the one-gas minimum are unchanged. Publication admission checks still
precede reservation, and component validation/compilation has no calibrated fuel
tariff yet. Invalid components rejected before init pay the minimum once reserved.
Preparation failures still use the existing transaction error reporting rather
than inventing a contract result when no function was resolved.

`call/tests/preparation_fees.rs` covers early failures, insufficient funds, gas
limit overflow, sponsorship, rollback/replay, failed init, injected settlement
failure and reuse of a rolled-back component ID. The original lifecycle matrix
now expects fees and a result for a paid direct view; the unsigned-view control
continues to require neither.

Validation: 593 library tests passed (16 manual tests ignored), followed by 34
focused call tests with host-failure injection enabled (two benchmarks ignored).
Twelve Bitcoin regtest integration tests passed, covering paid-view statuses,
simulation errors, ordinary sponsorship and BLS publisher sponsorship. Release
Clippy (`--lib --tests`, warnings denied), formatting and diff checks passed.

## Original refactor validation

All five regressions pass. The final library suite passed 518 tests, with nine
manual tests ignored. The focused integration suite passed 35 tests, including
real three-node Bitcoin regtest coverage for sponsorship, result statuses,
simulation errors and storage deposits. Clippy (`--tests`, warnings denied),
formatting and diff checks pass.

```sh
REGTEST=1 RUST_LOG=info cargo test --manifest-path core/Cargo.toml --locked \
  --release -p indexer --test integration -j 2 -- \
  error_classification storage_deposit status_classification simulate_errors \
  sponsor_swap bls_publisher_pays
```

The first integration attempt used `RUST_LOG=warn`, which hides the info-level
API-port announcement that the process-based harness requires. Setup timed out
before the affected cluster assertions could run. That attempt was stopped and
its child processes terminated; the corrected command above passed all 35 tests.
