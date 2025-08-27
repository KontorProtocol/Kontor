use anyhow::Result;
use clap::Parser;
use indexer::{
    config::Config,
    database::{queries::insert_block, types::BlockRow},
    runtime::{ComponentCache, ContractAddress, Error, Runtime, Storage, load_native_contracts},
    test_utils::{new_mock_block_hash, new_test_db},
};
use stdlib::import;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
    test = true,
);

#[tokio::test]
async fn test_token_contract() -> Result<()> {
    let (_, writer, _test_db_dir) = new_test_db(&Config::try_parse_from([""])?).await?;
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

    token::mint(&runtime, minter, "900").await;
    token::mint(&runtime, minter, "100").await;

    let result = token::balance(&runtime, minter).await;
    assert_eq!(result, Some("1000".to_string()));

    let result = token::transfer(&runtime, holder, minter, "123").await;
    assert_eq!(
        result,
        Err(Error::Message("insufficient funds".to_string()))
    );

    token::transfer(&runtime, minter, holder, "40").await?;
    token::transfer(&runtime, minter, holder, "2.00001").await?;

    let result = token::balance(&runtime, holder).await;
    assert_eq!(result, Some("42.00001".to_string()));

    let result = token::balance(&runtime, minter).await;
    assert_eq!(result, Some("957.99999".to_string()));

    let result = token::balance(&runtime, "foo").await;
    assert_eq!(result, None);

    let result = token::balance_log10(&runtime, holder).await;
    assert_eq!(result, Some("1.6232493938".to_string()));

    Ok(())
}
