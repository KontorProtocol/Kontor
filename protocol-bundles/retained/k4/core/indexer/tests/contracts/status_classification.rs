//! Tests for `OpStatus` classification on persisted result rows. Submits ops
//! via simulate (which uses canonical execution but rolls back at the end),
//! then asserts the
//! per-op `result.status` matches the expected category.

use indexer_types::{Inst, InstKind, OpStatus, TransactionHex};
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
    let ComposeInstsResult { reveal_tx_hex, .. } = rt
        .compose_instruction(
            ident,
            Inst {
                gas_limit: 10_000,
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

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn status_classification_ok() -> Result<()> {
    let alice = runtime.identity().await?;
    let crypto = runtime.publish(&alice, "crypto").await?;
    let mut rt = runtime.reg_tester().unwrap();
    let mut ident = rt.identity().await?;

    let results = simulate_call(&mut rt, &mut ident, crypto, "set-hash(\"status-test\")").await?;
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

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn status_classification_paid_views() -> Result<()> {
    let alice = runtime.identity().await?;
    let contract = runtime.publish(&alice, "error-test").await?;
    let mut rt = runtime.reg_tester().unwrap();
    let mut ident = rt.identity().await?;
    for (expr, func, status) in [
        ("succeed()", "succeed", OpStatus::Ok),
        ("contract-error()", "contract-error", OpStatus::ContractErr),
    ] {
        let results = simulate_call(&mut rt, &mut ident, contract.clone(), expr).await?;
        assert_eq!(results.len(), 1);
        let row = results[0].result().expect("paid view outcome");
        // Fee settlement happens later, but must not replace the user's result.
        assert_eq!(row.func, func);
        assert_eq!(row.status, status);
        assert!(row.gas > 0);
        if status == OpStatus::Ok {
            assert_eq!(row.value.as_deref(), Some("42"));
        } else {
            assert!(row.value.as_ref().unwrap().starts_with("err("));
        }
    }
    Ok(())
}

/// A wasm trap (div-by-zero) is `status: Trap`.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn status_classification_trap() -> Result<()> {
    let alice = runtime.identity().await?;
    let contract = runtime.publish(&alice, "error-test").await?;
    let mut rt = runtime.reg_tester().unwrap();
    let mut ident = rt.identity().await?;

    let results = simulate_call(&mut rt, &mut ident, contract, "trap-div-zero()").await?;
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

    let results = simulate_call(&mut rt, &mut ident, contract, "trap-out-of-fuel()").await?;
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
