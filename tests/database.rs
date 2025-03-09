use anyhow::Result;
use clap::Parser;
use kontor::{
    bitcoin_client::Client, config::Config, database::types::BlockRow, utils::new_test_db,
};

#[tokio::test]
async fn test_database() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let height = 800000;
    let hash = client.get_block_hash(height).await?;
    let block = BlockRow { height, hash };

    let (reader, writer, _temp_dir) = new_test_db().await?;

    writer.insert_block(block).await?;
    let block_at_height = reader.get_block_at_height(height).await?.unwrap();
    assert_eq!(block_at_height.height, height);
    assert_eq!(block_at_height.hash, hash);
    let last_block = reader.get_block_latest().await?.unwrap();
    assert_eq!(last_block.height, height);
    assert_eq!(last_block.hash, hash);

    Ok(())
}
