use anyhow::Result;
use clap::Parser;
use indexer::{
    config::Config,
    database::{
        queries::insert_block,
        types::BlockRow,
    },
    runtime::{
        ComponentCache, ContractAddress, Runtime, Storage, load_native_contracts,
    },
    test_utils::{new_mock_block_hash, new_test_db},
};
use wasmtime::component::wasm_wave::{to_string as to_wave, value::Value};

#[tokio::test]
async fn test_token_contract() -> Result<()> {
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
    let minter = "test_minter";
    let holder = "test_holder";

    let component_cache = ComponentCache::new();
    let runtime = Runtime::new(storage.clone(), component_cache).await?;
    load_native_contracts(&runtime).await?;

    let contract = ContractAddress {
        name: "token".to_string(),
        height: 0,
        tx_index: 0,
    };

    let expr = format!( "mint({})", to_wave(&Value::from(1000))?);
    let result = runtime.execute(Some(minter), &contract, &expr).await?;
    assert_eq!(result, "()");

    // attempt transfer from non-existent account
    // TODO provide nice error message; currently it blows up with cryptic wasm trace
//    let expr = format!( "transfer({}, {})",
//        to_wave(&Value::from(minter))?,
//        to_wave(&Value::from(123))?
//    );
//    let _ = runtime.execute(Some(holder), &contract, &expr).await?;

    let expr = format!( "transfer({}, {})",
        to_wave(&Value::from(holder))?,
        to_wave(&Value::from(42))?
    );
    let result = runtime.execute(Some(minter), &contract, &expr).await?;
    assert_eq!(result, "()");

    let expr = format!("balance({})", to_wave(&Value::from(holder))?);
    let result = runtime.execute(Some(minter), &contract, &expr).await?;
    assert_eq!(result, "some(42)");

    let expr = format!("balance({})", to_wave(&Value::from(minter))?);
    let result = runtime.execute(Some(minter), &contract, &expr).await?;
    assert_eq!(result, "some(958)");

    // TODO provide nice error message; currently it blows up with cryptic wasm trace
    // let expr = format!("balance({})", to_wave(&Value::from("foo"))?);
    // let _ = runtime.execute(Some(minter), &contract, &expr).await?;

    Ok(())
}
