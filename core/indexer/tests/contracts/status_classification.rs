//! Tests for `OpStatus` classification on persisted result rows. Submits ops
//! via simulate (which executes through the same `handle_procedure` path as
//! canonical execution but rolls back at the end), then asserts the
//! per-op `result.status` matches the expected category.
//!
//! Only proc-context functions produce contract_results rows (view-context
//! calls bypass `handle_procedure`). The error-test contract's
//! `contract-error` function is view-context, so there's no direct test for
//! the `ContractErr` status here — that's exercised indirectly when any
//! proc-context call returns `result<_, error>::Err`, which classifier
//! catches via the `"err("` prefix.

use indexer_types::{Inst, InstKind, OpStatus, PaymentIntent, TransactionHex};
use testlib::*;

interface!(
    name = "error_test",
    path = "../../test-contracts/error-test/wit"
);
interface!(name = "crypto", path = "../../test-contracts/crypto/wit");

async fn simulate_call(
    rt: &mut indexer::reg_tester::RegTester,
    ident: &mut indexer::reg_tester::Identity,
    contract: indexer_types::ContractAddress,
    expr: &str,
) -> Result<Vec<indexer_types::OpWithResult>> {
    let (_, _, reveal_tx_hex) = rt
        .compose_instruction(
            ident,
            Inst {
                payment: PaymentIntent::self_pay(10_000),
                kind: InstKind::Call {
                    contract,
                    expr: expr.to_string(),
                },
            },
        )
        .await?;
    rt.kontor_client()
        .await
        .transaction_simulate(TransactionHex { hex: reveal_tx_hex })
        .await
}

/// A normal successful proc-context call lands with `status: Ok`. Use
/// crypto's `set-hash` (proc-context, returns a value, succeeds) because
/// error-test's `succeed` is view-context and bypasses handle_procedure.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn status_classification_ok() -> Result<()> {
    let alice = runtime.identity().await?;
    let crypto = runtime.publish(&alice, "crypto").await?;
    let mut rt = runtime.reg_tester().unwrap();
    let mut ident = rt.identity().await?;

    let results = simulate_call(
        &mut rt,
        &mut ident,
        crypto.into(),
        "set-hash(\"status-test\")",
    )
    .await?;
    assert_eq!(results.len(), 1);
    let row = results[0]
        .result()
        .expect("set-hash should produce a result row");
    assert_eq!(row.status, OpStatus::Ok, "set-hash must yield Ok status");
    assert!(
        results[0].error_message().is_none(),
        "successful call has no error_message"
    );
    Ok(())
}

/// A wasm trap (div-by-zero) is `status: Trap`.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn status_classification_trap() -> Result<()> {
    let alice = runtime.identity().await?;
    let contract = runtime.publish(&alice, "error-test").await?;
    let mut rt = runtime.reg_tester().unwrap();
    let mut ident = rt.identity().await?;

    let results = simulate_call(&mut rt, &mut ident, contract.into(), "trap-div-zero()").await?;
    assert_eq!(results.len(), 1);
    let row = results[0]
        .result()
        .expect("trap-div-zero should still produce a result row");
    assert_eq!(
        row.status,
        OpStatus::Trap,
        "a non-fuel wasm trap must yield Trap status, got {:?}",
        row.status
    );
    assert!(
        results[0].error_message().is_some(),
        "trap should also surface an error_message via simulate"
    );
    Ok(())
}

/// Infinite-loop function exhausts fuel and produces `status: OutOfFuel`.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn status_classification_out_of_fuel() -> Result<()> {
    let alice = runtime.identity().await?;
    let contract = runtime.publish(&alice, "error-test").await?;
    let mut rt = runtime.reg_tester().unwrap();
    let mut ident = rt.identity().await?;

    let results = simulate_call(&mut rt, &mut ident, contract.into(), "trap-out-of-fuel()").await?;
    assert_eq!(results.len(), 1);
    let row = results[0]
        .result()
        .expect("trap-out-of-fuel should still produce a result row");
    assert_eq!(
        row.status,
        OpStatus::OutOfFuel,
        "fuel exhaustion must yield OutOfFuel status, got {:?}",
        row.status
    );
    Ok(())
}
