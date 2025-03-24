use anyhow::Result;
use clap::Parser;
use kontor::{
    bitcoin_client::Client,
    config::Config,
    database::{
        queries::{insert_block, select_block_at_height, select_block_latest},
        types::BlockRow,
    },
    utils::{new_test_conn, new_test_db},
};

#[tokio::test]
async fn test_database() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let height = 800000;
    let hash = client.get_block_hash(height).await?;
    let block = BlockRow { height, hash };

    let (reader, writer, _temp_dir) = new_test_db().await?;

    insert_block(&writer.connection(), block).await?;
    let block_at_height = select_block_at_height(&*reader.connection().await?, height)
        .await?
        .unwrap();
    assert_eq!(block_at_height.height, height);
    assert_eq!(block_at_height.hash, hash);
    let last_block = select_block_latest(&*reader.connection().await?)
        .await?
        .unwrap();
    assert_eq!(last_block.height, height);
    assert_eq!(last_block.hash, hash);

    Ok(())
}

#[tokio::test]
async fn test_transaction() -> Result<()> {
    let (conn, _temp_dir) = new_test_conn().await?;
    let tx = conn.transaction().await?;
    let height = 800000;
    let client = Client::new_from_config(Config::try_parse()?)?;
    let hash = client.get_block_hash(height).await?;
    let block = BlockRow { height, hash };
    insert_block(&tx, block).await?;
    assert!(select_block_latest(&tx).await?.is_some());
    tx.commit().await?;
    Ok(())
}
