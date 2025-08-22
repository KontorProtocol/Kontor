use anyhow::Result;
use clap::Parser;
use indexer::{
    config::Config,
    database::{queries::insert_block, types::BlockRow},
    runtime::{ComponentCache, ContractAddress, Runtime, Storage, load_native_contracts},
    test_utils::{new_mock_block_hash, new_test_db},
};
use wasmtime::component::wasm_wave::{to_string as to_wave, value::Value};

#[tokio::test]
async fn test_fib_contract() -> Result<()> {
    let (_, writer, _test_db_dir) = new_test_db(&Config::parse()).await?;
    let conn = writer.connection();
    let height = 1;
    let tx_id = 1;
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
        .tx_id(tx_id)
        .conn(writer.connection())
        .build();
    let crypto_contract_address = ContractAddress {
        name: "crypto".to_string(),
        height: 0,
        tx_index: 0,
    };
    let component_cache = ComponentCache::new();
    let runtime = Runtime::new(storage.clone(), component_cache).await?;
    load_native_contracts(&runtime).await?;

    let expr = format!("hash({})", to_wave(&Value::from("foo"))?);
    let result = runtime
        .execute(None, &crypto_contract_address, &expr)
        .await?;
    assert_eq!(
        result,
        r#""2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae""#
    );

    let expr = format!(
        "hash-with-salt({}, {})",
        to_wave(&Value::from("foo"))?,
        to_wave(&Value::from("bar"))?
    );
    let result = runtime
        .execute(None, &crypto_contract_address, &expr)
        .await?;
    assert_eq!(
        result,
        r#""c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2""#
    );

    let result = runtime
        .execute(None, &crypto_contract_address, "generate-id()")
        .await?;
    assert_eq!(
        result,
        r#""26eab58ebc163556b05d60d774a7cf9d726e6ebf3e8e945d9088424a3c255271""#
    );

    let result = runtime
        .execute(None, &crypto_contract_address, "generate-id()")
        .await?;
    assert_eq!(
        result,
        r#""d793e0c6d5bf864ccb0e64b1aaa6b9bc0fb02b2c64faa5b8aabb97f9f54a5b90""#
    );

    Ok(())
}
