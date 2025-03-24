use anyhow::Result;
use bitcoin::BlockHash;
use clap::Parser;
use kontor::{
    bitcoin_client,
    bitcoin_follower::reconciler::get_last_matching_block_height,
    block::Block,
    config::Config,
    database::{queries::insert_block, types::BlockRow},
    utils::{MockTransaction, new_mock_block_hash, new_test_db},
};
use tokio_util::sync::CancellationToken;

fn new_minimal_block(height: u64, hash: BlockHash, prev_hash: BlockHash) -> Block<MockTransaction> {
    Block {
        height,
        hash,
        prev_hash,
        transactions: vec![],
    }
}

#[tokio::test]
async fn test_no_reorg() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let bitcoin = bitcoin_client::Client::new_from_config(Config::try_parse()?)?;
    let (reader, writer, _temp_dir) = new_test_db().await?;

    let height = 100; // Adjust to a known height on your chain
    let prev_height = height - 1;
    let hash = new_mock_block_hash(100); // Fake, doesn't need to match
    let prev_hash = bitcoin.get_block_hash(prev_height).await?; // Real, must match DB
    let block = new_minimal_block(height, hash, prev_hash);

    insert_block(
        &writer.connection(),
        BlockRow {
            height: prev_height,
            hash: prev_hash,
        },
    )
    .await?;

    let result = get_last_matching_block_height(
        cancel_token,
        &reader,
        &bitcoin,
        block.height,
        block.prev_hash,
    )
    .await?;
    assert_eq!(
        result, prev_height,
        "Should return height-1 when prev_hash matches DB at height-1"
    );
    Ok(())
}

#[tokio::test]
async fn test_single_block_reorg() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let bitcoin = bitcoin_client::Client::new_from_config(Config::try_parse()?)?;
    let (reader, writer, _temp_dir) = new_test_db().await?;

    let height = 100; // Adjust to a known height
    let prev_height = height - 1;
    let prev_prev_height = height - 2;
    let hash = new_mock_block_hash(100); // Fake, doesn't need to match
    let prev_hash = bitcoin.get_block_hash(prev_prev_height).await?; // Real, must match DB at height-2
    let db_prev_hash = new_mock_block_hash(1000); // Fake, non-matching
    let block = new_minimal_block(height, hash, prev_hash);

    let conn = writer.connection();
    insert_block(
        &conn,
        BlockRow {
            height: prev_height,
            hash: db_prev_hash,
        },
    )
    .await?;
    insert_block(
        &conn,
        BlockRow {
            height: prev_prev_height,
            hash: prev_hash,
        },
    )
    .await?;

    let result = get_last_matching_block_height(
        cancel_token,
        &reader,
        &bitcoin,
        block.height,
        block.prev_hash,
    )
    .await?;
    assert_eq!(
        result, prev_prev_height,
        "Should return height-2 when prev_hash matches height-2"
    );
    Ok(())
}

#[tokio::test]
async fn test_multi_block_reorg() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let bitcoin = bitcoin_client::Client::new_from_config(Config::try_parse()?)?;
    let (reader, writer, _temp_dir) = new_test_db().await?;

    let height = 100; // Adjust to a known height
    let prev_height = height - 1;
    let prev_prev_height = height - 2;
    let prev_prev_prev_height = height - 3;
    let hash = new_mock_block_hash(100); // Fake, doesn't need to match
    let prev_hash = bitcoin.get_block_hash(prev_prev_prev_height).await?; // Real, must match DB at height-3
    let db_prev_hash = new_mock_block_hash(1000); // Fake, non-matching
    let db_prev_prev_hash = new_mock_block_hash(1001); // Fake, non-matching
    let block = new_minimal_block(height, hash, prev_hash);

    let conn = writer.connection();
    insert_block(
        &conn,
        BlockRow {
            height: prev_height,
            hash: db_prev_hash,
        },
    )
    .await?;
    insert_block(
        &conn,
        BlockRow {
            height: prev_prev_height,
            hash: db_prev_prev_hash,
        },
    )
    .await?;
    insert_block(
        &conn,
        BlockRow {
            height: prev_prev_prev_height,
            hash: prev_hash,
        },
    )
    .await?;

    let result = get_last_matching_block_height(
        cancel_token,
        &reader,
        &bitcoin,
        block.height,
        block.prev_hash,
    )
    .await?;
    assert_eq!(
        result, prev_prev_prev_height,
        "Should return height-3 when prev_hash matches height-3"
    );
    Ok(())
}
