use anyhow::Result;
use indexer_types::{BlockRow, deserialize, serialize};
use stdlib::KeyPath;

use crate::database::queries::insert_block;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::fuel::{Fuel, FuelDiscriminants, FuelGauge};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, Integer, Runtime, TransactionContext, from_wave_expr,
};
use crate::test_utils::{new_mock_block_hash, test_runtime};

async fn stored(
    runtime: &mut Runtime,
    address: &ContractAddress,
    key: u64,
) -> Result<Option<Vec<String>>> {
    Ok(from_wave_expr(
        &runtime
            .execute(None, None, address, &format!("stored-numbers({key})"))
            .await?,
    ))
}

async fn index(
    runtime: &mut Runtime,
    address: &ContractAddress,
    integer: &str,
) -> Result<Vec<String>> {
    Ok(from_wave_expr(
        &runtime
            .execute(None, None, address, &format!("number-index(\"{integer}\")"))
            .await?,
    ))
}

#[tokio::test]
async fn scalar_numbers_preserve_indexes_deposits_and_rollback() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    runtime
        .storage
        .insert_contract(
            "arith",
            include_bytes!("../../../../../test-contracts/binaries/arith.wasm.br"),
        )
        .await?;
    let address = ContractAddress {
        name: "arith".into(),
        height: 1,
        tx_index: 0,
    };
    let contract_id = runtime.storage.contract_id(&address).await?.unwrap();
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    let signer_id = signer.signer_id().unwrap();
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
    assert_eq!(stored(&mut runtime, &address, 0).await?, None);

    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let inputs = [
        "0".into(),
        "1".into(),
        "-1".into(),
        max.into(),
        format!("-{max}"),
    ];
    for (key, integer) in inputs.iter().enumerate() {
        let decimal = Decimal::from_raw_units(Integer::from(integer.as_str())).to_string();
        runtime
            .execute_api(
                Some(&signer),
                &address,
                &format!("put-numbers({key}, \"{integer}\", \"{decimal}\")"),
            )
            .await?;
        assert_eq!(
            stored(&mut runtime, &address, key as u64).await?,
            Some(vec![integer.clone(), decimal.clone(), decimal])
        );
    }

    let path = KeyPath::new().push_interned(2).push_element(&3u64);
    let leaves = runtime
        .storage
        .find_live_subtree(contract_id, &path)
        .await?;
    assert_eq!(
        leaves.len(),
        1,
        "a numeric value must occupy one leaf, without limb/sign children"
    );
    assert_eq!(leaves[0].path, path.as_ref());
    let payload = runtime
        .storage
        .get(i64::MAX as u64, contract_id, &path)
        .await?
        .unwrap();
    let bytes: Vec<u8> = deserialize(&payload)?;
    assert_eq!(bytes, [vec![0], vec![255; 32]].concat());
    assert_eq!(leaves[0].size, serialize(&bytes)?.len() as u64);
    assert_eq!(leaves[0].depositor, Some(signer_id));
    assert_eq!(
        leaves[0].deposited_gas,
        Some((path.len() + payload.len()) as u64 * runtime.deposit_rate(contract_id, &path))
    );

    let gauge = FuelGauge::new();
    runtime.gauge = Some(gauge.clone());
    stored(&mut runtime, &address, 3).await?;
    let stats = gauge.per_type_stats().await;
    assert_eq!(stats[&FuelDiscriminants::Get].count, 3);
    assert_eq!(
        stats[&FuelDiscriminants::Get].total_fuel,
        3 * Fuel::Get(payload.len()).cost()
    );
    assert!(!stats.contains_key(&FuelDiscriminants::ExtendPathWithMatch));

    for (key, decimal) in [(5, "3"), (6, "-2")] {
        runtime
            .execute_api(
                Some(&signer),
                &address,
                &format!("put-numbers({key}, \"7\", \"{decimal}\")"),
            )
            .await?;
    }
    assert_eq!(index(&mut runtime, &address, "7").await?, ["7:-2", "7:3"]);
    let before = runtime.storage.footprint().total_gas(signer_id).await?;
    runtime.storage.savepoint().await?;
    runtime
        .execute_api(Some(&signer), &address, "change-integer(5, \"8\")")
        .await?;
    assert_eq!(index(&mut runtime, &address, "7").await?, ["7:-2"]);
    assert_eq!(index(&mut runtime, &address, "8").await?, ["8:3"]);
    runtime.storage.rollback().await?;
    assert_eq!(index(&mut runtime, &address, "7").await?, ["7:-2", "7:3"]);
    assert!(index(&mut runtime, &address, "8").await?.is_empty());
    assert_eq!(
        runtime.storage.footprint().total_gas(signer_id).await?,
        before
    );

    insert_block(
        &runtime.get_storage_conn(),
        BlockRow::builder()
            .height(2)
            .hash(new_mock_block_hash(2))
            .relevant(true)
            .build(),
    )
    .await?;
    runtime.set_context(2, None, None, None).await;
    runtime
        .execute_api(Some(&signer), &address, "remove-numbers(6)")
        .await?;
    assert_eq!(stored(&mut runtime, &address, 6).await?, None);
    assert_eq!(index(&mut runtime, &address, "7").await?, ["7:3"]);
    assert!(runtime.storage.footprint().total_gas(signer_id).await? < before);
    assert_eq!(
        from_wave_expr::<Option<String>>(
            &runtime
                .execute(None, None, &address, "optional-integer()")
                .await?
        ),
        None
    );
    runtime
        .execute_api(Some(&signer), &address, "put-numbers(5, \"8\", \"-4\")")
        .await?;
    assert!(index(&mut runtime, &address, "7").await?.is_empty());
    assert_eq!(index(&mut runtime, &address, "8").await?, ["8:-4"]);

    runtime.storage.rollback_with_footprint(1).await?;
    runtime.set_context(1, None, None, None).await;
    assert_eq!(index(&mut runtime, &address, "7").await?, ["7:-2", "7:3"]);
    assert!(index(&mut runtime, &address, "8").await?.is_empty());
    assert_eq!(
        stored(&mut runtime, &address, 6).await?,
        Some(vec!["7".into(), "-2".into(), "-2".into()])
    );
    assert_eq!(
        from_wave_expr::<Option<String>>(
            &runtime
                .execute(None, None, &address, "optional-integer()")
                .await?
        ),
        Some("7".into())
    );
    assert_eq!(
        from_wave_expr::<Vec<u64>>(
            &runtime
                .execute(None, None, &address, "number-keys()")
                .await?
        ),
        (0..7).collect::<Vec<_>>()
    );
    assert_eq!(
        runtime.storage.footprint().total_gas(signer_id).await?,
        before
    );
    Ok(())
}
