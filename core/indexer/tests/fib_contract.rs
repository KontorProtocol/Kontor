use anyhow::Result;
use clap::Parser;
use indexer::{
    config::Config,
    database::{
        queries::{get_contract_id_from_address, insert_block},
        types::BlockRow,
    },
    runtime::{
        ComponentCache, ContractAddress, Runtime, Storage, deserialize_cbor, load_native_contracts,
    },
    test_utils::{new_mock_block_hash, new_test_db},
};
use wasmtime::component::wasm_wave::{to_string as to_wave, value::Value};

#[tokio::test]
async fn test_fib_contract() -> Result<()> {
    let (_, writer, _test_db_dir) = new_test_db(&Config::parse()).await?;
    let conn = writer.connection();
    let height = 1;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(height)
            .hash(new_mock_block_hash(height as u32))
            .build(),
    )
    .await?;
    let storage = Storage::builder()
        .height(height)
        .conn(writer.connection())
        .build();
    let signer = "test_signer";
    let arith_contract_address = ContractAddress {
        name: "arith".to_string(),
        height: 0,
        tx_index: 0,
    };
    let component_cache = ComponentCache::new();
    let runtime = Runtime::new(storage.clone(), component_cache).await?;
    load_native_contracts(&runtime).await?;

    let result = runtime
        .execute(None, &arith_contract_address, "last-op()")
        .await?;
    assert_eq!(result, "some(id)");

    let fib_contract_address = ContractAddress {
        name: "fib".to_string(),
        height: 0,
        tx_index: 0,
    };
    let contract_id = get_contract_id_from_address(&conn, &fib_contract_address)
        .await?
        .unwrap();
    assert_eq!(
        deserialize_cbor::<u64>(&storage.get(contract_id, "cache.0.value").await?.unwrap())?,
        0
    );
    let n = 8;
    let expr = format!("fib({})", to_wave(&Value::from(n))?);
    let result = runtime
        .execute(Some(signer), &fib_contract_address, &expr)
        .await?;
    assert_eq!(result, "21");
    assert_eq!(
        deserialize_cbor::<u64>(&storage.get(contract_id, "cache.8.value").await?.unwrap())?,
        21
    );

    let result = runtime
        .execute(None, &arith_contract_address, "last-op()")
        .await?;
    assert_eq!(result, "some(sum({y: 8}))");

    Ok(())
}
