use anyhow::Result;
use kontor::{
    bitcoin_client::Client,
    config::Config,
    database::{reader::Reader, types::BlockRow, writer::Writer},
};

#[tokio::test]
async fn test_database() -> Result<()> {
    use tempfile::TempDir;

    let client = Client::new_from_config(Config::load()?)?;
    let height = 800000;
    let hash = client.get_block_hash(height).await?;
    let block = BlockRow { height, hash };

    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("test_db.db");
    let writer = Writer::new(db_path.as_path()).await?;
    let reader = Reader::new(db_path.as_path()).await?;

    writer.insert_block(block).await?;
    let block_at_height = reader.get_block_at_height(height).await?.unwrap();
    assert_eq!(block_at_height.height, height);
    assert_eq!(block_at_height.hash, hash);
    let last_block = reader.get_last_block().await?.unwrap();
    assert_eq!(last_block.height, height);
    assert_eq!(last_block.hash, hash);

    Ok(())
}
