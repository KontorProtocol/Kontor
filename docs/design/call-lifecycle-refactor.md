# Call lifecycle refactor: regression coverage

Implementation baseline: main `3749a368` (#568). No runtime behavior has changed
in this test-preparation work. Commit `b5ef4046` records three deliberately failing
fuel regressions before the refactor.

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

- `runtime/mod.rs::tests::call_context_resources_are_drained`: resource reuse
  after repeated successful direct views.
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
to parent calls. The original direct-view cleanup test remains in place.

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

This command intentionally exits unsuccessfully until the five regressions are
fixed; they are ordinary assertions, not ignored or expected-panic tests.
