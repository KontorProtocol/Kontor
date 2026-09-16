use anyhow::Result;
use futures_util::TryStreamExt;
use indexer_types::BlockRow;
use stdlib::KeyPath;

use crate::database::queries::{insert_block, live_deposit_gas_sum};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::fuel::{FuelDiscriminants, FuelGauge};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{ContractAddress, Decimal, Runtime, TransactionContext, from_wave_expr};
use crate::test_utils::{new_mock_block_hash, test_runtime};

async fn state(runtime: &mut Runtime, address: &ContractAddress) -> Result<(Vec<u64>, u64)> {
    let gauge = FuelGauge::with_profiling();
    runtime.gauge = Some(gauge.clone());
    let value = runtime
        .execute(None, None, address, "variant-state()")
        .await?;
    runtime.gauge = None;
    let report = gauge.report()?;
    let state: Vec<u64> = from_wave_expr(&value);
    assert_eq!(
        report.profile.unwrap().per_type[&FuelDiscriminants::Get].consumed_count,
        if state[1] == 0 { 3 } else { 4 },
        "variant reads must fetch only tags and the requested scalar payload"
    );
    Ok((state, report.usage.user_fuel))
}

async fn advance(runtime: &mut Runtime, height: u64) -> Result<()> {
    insert_block(
        &runtime.get_storage_conn(),
        BlockRow::builder()
            .height(height)
            .hash(new_mock_block_hash(height as u32))
            .build(),
    )
    .await?;
    runtime.set_context(height, None, None, None).await;
    Ok(())
}

#[tokio::test]
async fn explicit_variant_tags_preserve_empty_payloads_deposits_and_rollback() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    runtime
        .storage
        .insert_contract(
            "fib",
            include_bytes!("../../../../../test-contracts/binaries/fib.wasm.br"),
        )
        .await?;
    let address = ContractAddress {
        name: "fib".into(),
        height: 1,
        tx_index: 0,
    };
    let contract_id = runtime.storage.contract_id(&address).await?.unwrap();
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    let owner = signer.signer_id().unwrap();
    let core = Signer::Core(Box::new(Signer::Nobody));
    token::issue_to(
        &mut runtime,
        &core,
        HolderRef::from(&signer),
        Decimal::from("10000"),
    )
    .await??;
    runtime
        .execute_api(Some(&signer), &address, "init()")
        .await?;
    assert_eq!(state(&mut runtime, &address).await?.0, [0, 0, u64::MAX]);

    let choice = KeyPath::new().push_interned(4);
    let optional = KeyPath::new().push_interned(5);
    for expression in [
        "set-variant(1, 0, false)",
        "set-variant(0, 0, false)",
        "set-variant(1, 0, false)",
    ] {
        runtime
            .execute_api(Some(&signer), &address, expression)
            .await?;
    }
    assert_eq!(state(&mut runtime, &address).await?.0, [1, 1, 0]);
    for path in [&choice, &optional] {
        let rows: Vec<_> = runtime
            .storage
            .find_live_subtree(contract_id, path)
            .await?
            .try_collect()
            .await?;
        assert_eq!(rows.len(), 1, "empty payload needs only its root tag");
        assert_eq!(rows[0].path, path.as_ref());
    }

    runtime
        .execute_api(Some(&signer), &address, "set-variant(2, 128, false)")
        .await?;
    let before = state(&mut runtime, &address).await?;
    assert_eq!(before.0, [2, 1, 128]);
    let floor = runtime.storage.footprint().total_gas(owner).await?;
    advance(&mut runtime, 2).await?;
    runtime
        .execute_api(Some(&signer), &address, "mutate-variant(512)")
        .await?;
    assert_eq!(
        state(&mut runtime, &address).await?,
        before,
        "payload writes must not affect the tag or read fuel"
    );
    let rows: Vec<_> = runtime
        .storage
        .find_live_subtree(contract_id, &choice)
        .await?
        .try_collect()
        .await?;
    assert_eq!(rows.len(), 130);
    let before_failure = runtime.storage.footprint().total_gas(owner).await?;
    assert!(
        runtime
            .execute_api(Some(&signer), &address, "set-variant(1, 0, true)")
            .await
            .is_err()
    );
    assert_eq!(state(&mut runtime, &address).await?, before);
    assert_eq!(
        runtime.storage.footprint().total_gas(owner).await?,
        before_failure
    );
    assert_eq!(
        runtime
            .storage
            .find_live_subtree(contract_id, &choice)
            .await?
            .try_collect::<Vec<_>>()
            .await?
            .into_iter()
            .map(|row| row.path)
            .collect::<Vec<_>>(),
        rows.into_iter().map(|row| row.path).collect::<Vec<_>>()
    );

    runtime
        .execute_api(Some(&signer), &address, "set-variant(1, 0, false)")
        .await?;
    assert_eq!(state(&mut runtime, &address).await?.0, [1, 1, 0]);
    assert_eq!(
        runtime
            .storage
            .find_live_subtree(contract_id, &choice)
            .await?
            .try_collect::<Vec<_>>()
            .await?
            .len(),
        1
    );
    assert!(runtime.storage.footprint().total_gas(owner).await? < floor);
    assert_eq!(
        runtime.storage.footprint().total_gas(owner).await?,
        live_deposit_gas_sum(&runtime.get_storage_conn(), owner).await?
    );
    runtime
        .execute_api(Some(&signer), &address, "set-variant(0, 0, false)")
        .await?;
    assert_eq!(state(&mut runtime, &address).await?.0, [0, 0, u64::MAX]);

    runtime.storage.rollback_with_footprint(1).await?;
    runtime.set_context(1, None, None, None).await;
    assert_eq!(state(&mut runtime, &address).await?, before);
    assert_eq!(runtime.storage.footprint().total_gas(owner).await?, floor);
    runtime.storage.prune(0, 1).await?;
    runtime.get_storage_conn().execute_batch("VACUUM").await?;
    assert_eq!(state(&mut runtime, &address).await?, before);
    advance(&mut runtime, 2).await?;
    runtime
        .execute_api(Some(&signer), &address, "set-variant(0, 0, false)")
        .await?;
    let none = state(&mut runtime, &address).await?;
    runtime.storage.prune(1, 2).await?;
    assert_eq!(state(&mut runtime, &address).await?, none);
    assert_eq!(none.0, [0, 0, u64::MAX]);
    assert_eq!(
        runtime.storage.footprint().total_gas(owner).await?,
        live_deposit_gas_sum(&runtime.get_storage_conn(), owner).await?
    );
    Ok(())
}
