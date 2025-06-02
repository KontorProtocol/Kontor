use anyhow::Result;
use bitcoin::BlockHash;
use clap::Parser;
use kontor::{
    config::Config,
    database::{
        checkpoint_queries::create_checkpoint_from_state, queries::insert_block, types::BlockRow,
    },
    utils::new_test_db,
};
use libsql::params;
use std::str::FromStr;

#[tokio::test]
async fn test_create_checkpoint_from_state() -> Result<()> {
    // Setup
    let config = Config::try_parse()?;
    let (_reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();

    // Insert a block first (required due to foreign key constraint)
    let height = 100;
    let block_hash = "0000000000000000000392ff974088ed040eaf4047067d04e12a131c70e732bb";
    let block = BlockRow {
        height,
        hash: BlockHash::from_str(block_hash).unwrap(),
    };
    insert_block(&conn, block).await?;

    // Insert some contract state data - make sure this is the latest row
    conn.execute(
        "INSERT INTO contract_state (contract_id, tx_id, height, path, value, deleted) 
         VALUES (?, ?, ?, ?, ?, ?)",
        params![
            "test_contract",
            1,
            height,
            "/test/path",
            hex::decode("deadbeef").unwrap(),
            false
        ],
    )
    .await?;

    // Create a checkpoint from the state
    let checkpoint_hash = create_checkpoint_from_state(&conn, height).await?;

    // Verify the checkpoint was created
    let mut rows = conn
        .query(
            "SELECT height, hash FROM checkpoints WHERE height = ?",
            params![height],
        )
        .await?;

    let row = rows.next().await?.unwrap();
    let stored_height: u64 = row.get(0)?;
    let stored_hash: String = row.get(1)?;

    // Assertions
    assert_eq!(stored_height, height);
    assert_eq!(stored_hash, checkpoint_hash);

    // For the second test, we need to insert a new block first
    let block_hash2 = "000000000000000000033df156e7b5f6d6b25e3765f9c944a3b5a7c5bd1b4a89";
    let height2 = height + 1;
    let block2 = BlockRow {
        height: height2,
        hash: BlockHash::from_str(block_hash2).unwrap(),
    };
    insert_block(&conn, block2).await?;

    // Then insert a new contract state with a higher ID (to be the latest)
    conn.execute(
        "INSERT INTO contract_state (contract_id, tx_id, height, path, value, deleted) 
         VALUES (?, ?, ?, ?, ?, ?)",
        params![
            "test_contract2",
            2,
            height2,
            "/test/path2",
            hex::decode("face1234").unwrap(),
            false
        ],
    )
    .await?;

    // Create another checkpoint
    let checkpoint_hash2 = create_checkpoint_from_state(&conn, height2).await?;

    // Verify the second checkpoint
    let mut rows = conn
        .query(
            "SELECT height, hash FROM checkpoints WHERE height = ?",
            params![height2],
        )
        .await?;

    let row = rows.next().await?.unwrap();
    let stored_height2: u64 = row.get(0)?;
    let stored_hash2: String = row.get(1)?;

    // Assertions for second checkpoint
    assert_eq!(stored_height2, height2);
    assert_eq!(stored_hash2, checkpoint_hash2);

    // Verify the hash is different from the first checkpoint
    assert_ne!(checkpoint_hash, checkpoint_hash2);

    Ok(())
}
