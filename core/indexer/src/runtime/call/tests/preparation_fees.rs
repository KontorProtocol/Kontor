use anyhow::Result;
use indexer_types::Payment;
use wasmtime::component::Component;

use super::{balance, call_chain, funded};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, ExecutionError, TransactionContext, native_provenance,
};
use crate::test_utils::test_runtime;

#[tokio::test]
async fn preparation_failures_burn_consumed_work_and_refund_the_payer() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let payer = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let missing = ContractAddress {
        name: "missing".into(),
        height: 1,
        tx_index: 0,
    };
    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().tx_index(3).build()),
            None,
            None,
        )
        .await;
    let id = runtime
        .storage
        .insert_contract(
            "start-trap",
            include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br"),
        )
        .await?;
    let component = Component::new(
        &runtime.engine,
        "(component (core module (func $start unreachable) (start $start)) (core instance (instantiate 0)))",
    )?;
    runtime.component_cache.put(id, component, 0).await;
    let start_trap = ContractAddress {
        name: "start-trap".into(),
        height: 1,
        tx_index: 3,
    };
    let payment = Payment {
        signer_id: payer.signer_id().unwrap(),
        gas_limit: 100_000,
    };
    for (target, expr, limit) in [
        (&missing, "init()", 100_000),
        (&chain[0], "(", 100_000),
        (&chain[0], "missing-function()", 100_000),
        (&chain[0], "primitive-entries(1)", 100_000),
        (&start_trap, "init()", 100_000),
        (&chain[0], "primitive-entries()", 1),
    ] {
        let mut expected = None;
        for _ in 0..2 {
            runtime.storage.savepoint().await?;
            let marker = runtime.storage.savepoint_stack.peek().await;
            let payer_before = balance(&mut runtime, HolderRef::from(&payer)).await?;
            let actor_before = balance(&mut runtime, HolderRef::from(&actor)).await?;
            let burned_before = balance(&mut runtime, HolderRef::Burner).await?;
            let supply_before = token::total_supply(&mut runtime).await?;
            let previous = runtime.start_usage();
            let result = runtime
                .execute(
                    Some(&actor),
                    Some(Payment {
                        gas_limit: limit,
                        ..payment.clone()
                    }),
                    target,
                    expr,
                )
                .await;
            let usage = runtime.finish_usage(previous)?;
            assert!(
                matches!(result, Err(ExecutionError::Deterministic(_))),
                "{expr}: {result:?}"
            );
            assert!(usage.user_fuel > 0, "{expr}");
            assert_eq!(usage.deposit_fuel, 0);
            let gas = usage
                .user_fuel
                .div_ceil(runtime.gas_to_fuel_multiplier)
                .max(1);
            assert!(gas <= limit);
            let fee = runtime.pricing.execution_fee(gas)?;
            assert!(fee > Decimal::default());
            assert_eq!(
                sub_decimal(
                    payer_before,
                    balance(&mut runtime, HolderRef::from(&payer)).await?
                )?,
                fee,
                "{expr}"
            );
            assert_eq!(
                sub_decimal(
                    balance(&mut runtime, HolderRef::Burner).await?,
                    burned_before
                )?,
                fee
            );
            assert_eq!(
                sub_decimal(supply_before, token::total_supply(&mut runtime).await?)?,
                fee
            );
            assert_eq!(
                balance(&mut runtime, HolderRef::from(&actor)).await?,
                actor_before
            );
            assert_eq!(
                balance(&mut runtime, HolderRef::Core).await?,
                Decimal::default()
            );
            assert_eq!(runtime.deposit.take().await, 0);
            assert!(runtime.stack.is_empty().await);
            assert_eq!(runtime.storage.savepoint_stack.peek().await, marker);
            if let Some(expected) = expected {
                assert_eq!(usage, expected);
            } else {
                expected = Some(usage);
            }
            runtime.storage.rollback().await?;
            assert_eq!(
                balance(&mut runtime, HolderRef::from(&payer)).await?,
                payer_before
            );
            assert_eq!(
                balance(&mut runtime, HolderRef::Burner).await?,
                burned_before
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn failed_publish_initialization_keeps_its_fee_outside_publication_rollback() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let payer = funded(&mut runtime).await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    let address = ContractAddress {
        name: "paid-init".into(),
        height: 1,
        tx_index: 0,
    };
    let payment = Payment {
        signer_id: payer.signer_id().unwrap(),
        gas_limit: 1,
    };
    let before = balance(&mut runtime, HolderRef::from(&payer)).await?;
    let burned = balance(&mut runtime, HolderRef::Burner).await?;
    let previous = runtime.start_usage();
    let result = runtime
        .publish(
            &actor,
            payment.clone(),
            &address.name,
            include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br"),
            &native_provenance()?,
        )
        .await;
    let usage = runtime.finish_usage(previous)?;
    assert!(matches!(result, Err(ExecutionError::Deterministic(_))));
    assert!(usage.user_fuel > 0);
    let fee = runtime.pricing.execution_fee(
        usage
            .user_fuel
            .div_ceil(runtime.gas_to_fuel_multiplier)
            .max(1),
    )?;
    assert_eq!(
        sub_decimal(
            before,
            balance(&mut runtime, HolderRef::from(&payer)).await?
        )?,
        fee
    );
    assert_eq!(
        sub_decimal(balance(&mut runtime, HolderRef::Burner).await?, burned)?,
        fee
    );
    assert_eq!(
        balance(&mut runtime, HolderRef::Core).await?,
        Decimal::default()
    );
    assert!(runtime.storage.contract_id(&address).await?.is_none());
    assert!(runtime.stack.is_empty().await);
    assert!(runtime.storage.savepoint_stack.is_empty().await);
    runtime
        .publish(
            &actor,
            Payment {
                gas_limit: 100_000,
                ..payment
            },
            &address.name,
            include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br"),
            &native_provenance()?,
        )
        .await?;
    assert_eq!(
        runtime.execute(None, None, &address, "succeed()").await?,
        "42"
    );
    Ok(())
}

#[tokio::test]
async fn an_unfunded_operation_never_starts_preparation() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let payer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    let before = balance(&mut runtime, HolderRef::from(&actor)).await?;
    let previous = runtime.start_usage();
    let result = runtime
        .execute(
            Some(&actor),
            Some(Payment {
                signer_id: payer.signer_id().unwrap(),
                gas_limit: 100_000,
            }),
            &ContractAddress {
                name: "missing".into(),
                height: 1,
                tx_index: 0,
            },
            "(",
        )
        .await;
    let usage = runtime.finish_usage(previous)?;
    assert!(format!("{:?}", result.unwrap_err()).contains("enough token"));
    assert_eq!(usage.user_fuel, 0);
    assert_eq!(usage.deposit_fuel, 0);
    assert_eq!(
        balance(&mut runtime, HolderRef::from(&actor)).await?,
        before
    );
    assert_eq!(
        balance(&mut runtime, HolderRef::Core).await?,
        Decimal::default()
    );
    assert!(runtime.storage.savepoint_stack.is_empty().await);
    Ok(())
}

#[tokio::test]
async fn settlement_failure_rolls_back_publication_and_cached_component() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    let address = ContractAddress {
        name: "settlement-failure".into(),
        height: 1,
        tx_index: 0,
    };
    let payment = Payment {
        signer_id: actor.signer_id().unwrap(),
        gas_limit: 100_000,
    };
    let conn = runtime.get_storage_conn();
    let before = balance(&mut runtime, HolderRef::from(&actor)).await?;
    let burned = balance(&mut runtime, HolderRef::Burner).await?;
    let supply = token::total_supply(&mut runtime).await?;
    let fuel_limit = runtime.call_fuel_limit(Some(&actor), Some(&payment), None)?;
    let provenance = native_provenance()?;
    let result = runtime.with_payment(&payment, fuel_limit, async |runtime| {
        let outcome = runtime.publish_unsettled(
            &actor, &payment, &address, actor.signer_id().unwrap(),
            include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br"),
            &provenance, fuel_limit,
        ).await?;
        assert!(outcome.result.is_ok());
        // Inject a real DB write failure only after successful initialization.
        conn.execute("CREATE TEMP TRIGGER reject_release BEFORE INSERT ON contract_state BEGIN SELECT RAISE(ABORT, 'injected settlement failure'); END", ()).await.map_err(anyhow::Error::from)?;
        Ok(outcome)
    }).await;
    assert!(
        matches!(result, Err(ExecutionError::NonDeterministic(_))),
        "settlement should fail with an infrastructure error"
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("settlement succeeded"),
    };
    assert!(format!("{error:?}").contains("injected settlement failure"));
    assert!(runtime.storage.contract_id(&address).await?.is_none());
    assert_eq!(
        balance(&mut runtime, HolderRef::from(&actor)).await?,
        before
    );
    assert_eq!(balance(&mut runtime, HolderRef::Burner).await?, burned);
    assert_eq!(
        balance(&mut runtime, HolderRef::Core).await?,
        Decimal::default()
    );
    assert_eq!(token::total_supply(&mut runtime).await?, supply);
    assert_eq!(runtime.deposit.take().await, 0);
    assert!(runtime.stack.is_empty().await);
    assert!(runtime.storage.savepoint_stack.is_empty().await);
    conn.execute("DROP TRIGGER IF EXISTS reject_release", ())
        .await?;
    runtime
        .publish(
            &actor,
            payment,
            &address.name,
            include_bytes!("../../../../../../test-contracts/binaries/counter.wasm.br"),
            &native_provenance()?,
        )
        .await?;
    assert_eq!(runtime.execute(None, None, &address, "get()").await?, "0");
    Ok(())
}

#[tokio::test]
async fn invalid_payment_limits_do_not_reserve_or_start_execution() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let before = balance(&mut runtime, HolderRef::from(&actor)).await?;
    let burned = balance(&mut runtime, HolderRef::Burner).await?;
    for gas_limit in [0, u64::MAX] {
        let previous = runtime.start_usage();
        let result = runtime
            .execute(
                Some(&actor),
                Some(Payment {
                    signer_id: actor.signer_id().unwrap(),
                    gas_limit,
                }),
                &ContractAddress {
                    name: "missing".into(),
                    height: 1,
                    tx_index: 0,
                },
                "init()",
            )
            .await;
        let usage = runtime.finish_usage(previous)?;
        assert!(
            matches!(result, Err(ExecutionError::Deterministic(_))),
            "{result:?}"
        );
        assert_eq!(usage.user_fuel, 0);
        assert_eq!(
            balance(&mut runtime, HolderRef::from(&actor)).await?,
            before
        );
        assert_eq!(balance(&mut runtime, HolderRef::Burner).await?, burned);
        assert_eq!(
            balance(&mut runtime, HolderRef::Core).await?,
            Decimal::default()
        );
        assert!(runtime.storage.savepoint_stack.is_empty().await);
    }
    Ok(())
}

#[tokio::test]
async fn paid_views_record_the_user_outcome_not_the_fee_refund() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let conn = runtime.get_storage_conn();
    conn.execute("DELETE FROM contract_results", ()).await?;
    let previous = runtime.start_usage();
    assert_eq!(
        runtime
            .execute_api(Some(&actor), &chain[0], "succeed()")
            .await?,
        "42"
    );
    let usage = runtime.finish_usage(previous)?;
    let mut rows = conn
        .query(
            "SELECT func, value, status, gas FROM contract_results ORDER BY result_index DESC",
            (),
        )
        .await?;
    let row = rows.next().await?.expect("paid view outcome");
    assert_eq!(row.get::<String>(0)?, "succeed");
    assert_eq!(row.get::<String>(1)?, "42");
    assert_eq!(row.get::<String>(2)?, "Ok");
    assert_eq!(
        row.get::<u64>(3)?,
        usage.user_fuel.div_ceil(runtime.gas_to_fuel_multiplier)
    );
    assert!(
        rows.next().await?.is_none(),
        "internal fee transfers leaked into results"
    );
    Ok(())
}
