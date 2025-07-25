use anyhow::Result;
use clap::Parser;
use indexer::{
    config::Config,
    database::{
        load_native_contracts,
        queries::{
            get_contract_id_from_address, get_latest_contract_state_value, insert_block,
            insert_transaction,
        },
        types::{BlockRow, TransactionRow},
    },
    runtime::{ComponentCache, ContractAddress, Runtime, Storage, deserialize_cbor},
    test_utils::{new_mock_block_hash, new_test_db},
};
use wasmtime::component::wasm_wave::{to_string as to_wave, value::Value};

#[tokio::test]
async fn test_fib_contract() -> Result<()> {
    let (_, writer, _test_db_dir) = new_test_db(&Config::parse()).await?;
    let conn = writer.connection();
    load_native_contracts(&conn).await?;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(new_mock_block_hash(1))
            .build(),
    )
    .await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .txid("1".to_string())
            .height(1)
            .tx_index(1)
            .build(),
    )
    .await?;
    let storage = Storage::builder().conn(writer.connection()).build();
    let signer = "test_signer".to_string();
    let eval_contract_address = ContractAddress {
        name: "eval".to_string(),
        height: 0,
        tx_index: 0,
    };
    let component_cache = ComponentCache::new();
    let runtime = Runtime::new(
        storage,
        component_cache,
        signer,
        eval_contract_address.clone(),
    )
    .await?;
    runtime.execute(None, "init()").await?;

    let result = runtime.execute(None, "last-op()").await?;
    assert_eq!(result, "some(id)");

    let fib_contract_address = ContractAddress {
        name: "fib".to_string(),
        height: 0,
        tx_index: 0,
    };
    let contract_id = get_contract_id_from_address(&conn, &fib_contract_address)
        .await?
        .unwrap();
    let runtime = runtime.with_contract_address(fib_contract_address).await?;

    runtime.execute(None, "init()").await?;
    assert_eq!(
        deserialize_cbor::<u64>(
            &get_latest_contract_state_value(&writer.connection(), contract_id, "cache.0.value")
                .await?
                .unwrap(),
        )
        .unwrap(),
        0
    );
    let n = 8;
    let expr = format!("fib({})", to_wave(&Value::from(n))?);
    let result = runtime.execute(None, &expr).await?;
    assert_eq!(result, "21");
    assert_eq!(
        deserialize_cbor::<u64>(
            &get_latest_contract_state_value(&writer.connection(), contract_id, "cache.8.value")
                .await?
                .unwrap(),
        )
        .unwrap(),
        21
    );

    let runtime = runtime.with_contract_address(eval_contract_address).await?;
    let result = runtime.execute(None, "last-op()").await?;
    assert_eq!(result, "some(sum({y: 8}))");

    Ok(())
}
