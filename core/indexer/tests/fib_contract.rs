use anyhow::Result;
use clap::Parser;
use indexer::{
    config::Config,
    database::{
        queries::{get_latest_contract_state_value, insert_block, insert_transaction},
        types::{BlockRow, TransactionRow},
    },
    runtime::{ComponentCache, Runtime, Storage, deserialize_cbor},
    test_utils::{new_mock_block_hash, new_test_db},
};
use wasmtime::component::wasm_wave::{to_string as to_wave, value::Value};

#[tokio::test]
async fn test_fib_contract() -> Result<()> {
    let (_, writer, _test_db_dir) = new_test_db(&Config::parse()).await?;
    let conn = writer.connection();
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
    let contract_id = "fib";
    let component_cache = ComponentCache::new();
    let runtime = Runtime::new(storage, component_cache, signer, contract_id.to_string())?;

    runtime.clone().execute(None, "init()").await?;
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
    Ok(())
}
