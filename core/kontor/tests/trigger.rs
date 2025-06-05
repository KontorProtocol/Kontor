use std::str::FromStr;

use anyhow::Result;
use clap::Parser;
use kontor::{
    config::Config,
    database::{queries::insert_block, types::BlockRow},
    utils::new_test_db,
};
use libsql::params;

#[tokio::test]
async fn test_checkpoint_trigger() -> Result<()> {
    let config = Config::try_parse()?;
    let (_reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();

    // 1. Insert a block at height 5
    let block5 = BlockRow {
        height: 5,
        hash: bitcoin::BlockHash::from_str(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )?,
    };
    insert_block(&conn, block5).await?;

    // 2. Insert a contract_state entry to trigger the first checkpoint
    conn.execute(
        "INSERT INTO contract_state (contract_id, tx_id, height, path, value, deleted) 
         VALUES ('contract1', 1, 5, '/path/1', X'DEADBEEF', 0)",
        params![],
    )
    .await?;

    // 3. Verify the first checkpoint was created
    let mut rows = conn
        .query(
            "SELECT id, height, hash FROM checkpoints ORDER BY id",
            params![],
        )
        .await?;

    let row = rows.next().await?.expect("Should have one checkpoint");
    let id1: i64 = row.get(0)?;
    let height1: i64 = row.get(1)?;
    let hash1: String = row.get(2)?;

    assert_eq!(height1, 5, "First checkpoint should be at height 5");
    tracing::info!(
        "First checkpoint: id={}, height={}, hash={}",
        id1,
        height1,
        hash1
    );

    // 4. Insert another contract_state entry at the same height
    conn.execute(
        "INSERT INTO contract_state (contract_id, tx_id, height, path, value, deleted) 
         VALUES ('contract1', 1, 5, '/path/2', X'CAFEBABE', 0)",
        params![],
    )
    .await?;

    // 5. Verify the checkpoint was updated (same id, same height, different hash)
    let mut rows = conn
        .query(
            "SELECT id, height, hash FROM checkpoints ORDER BY id",
            params![],
        )
        .await?;

    let row = rows.next().await?.expect("Should have one checkpoint");
    let id2: i64 = row.get(0)?;
    let height2: i64 = row.get(1)?;
    let hash2: String = row.get(2)?;

    assert_eq!(id2, id1, "Should be the same checkpoint id");
    assert_eq!(height2, 5, "Height should still be 5");
    assert_ne!(hash2, hash1, "Hash should be different");
    tracing::info!(
        "Updated checkpoint: id={}, height={}, hash={}",
        id2,
        height2,
        hash2
    );

    // 6. Insert a block and contract_state at height 9 (same interval)
    let block9 = BlockRow {
        height: 9,
        hash: bitcoin::BlockHash::from_str(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26e",
        )?,
    };
    insert_block(&conn, block9).await?;

    conn.execute(
        "INSERT INTO contract_state (contract_id, tx_id, height, path, value, deleted) 
         VALUES ('contract1', 2, 9, '/path/3', X'BADDCAFE', 0)",
        params![],
    )
    .await?;

    // 7. Verify the checkpoint was updated (same id, new height, different hash)
    let mut rows = conn
        .query(
            "SELECT id, height, hash FROM checkpoints ORDER BY id",
            params![],
        )
        .await?;

    let row = rows.next().await?.expect("Should have one checkpoint");
    let id3: i64 = row.get(0)?;
    let height3: i64 = row.get(1)?;
    let hash3: String = row.get(2)?;

    assert_eq!(id3, id1, "Should still be the same checkpoint id");
    assert_eq!(height3, 9, "Height should now be 9");
    assert_ne!(hash3, hash2, "Hash should be different");
    tracing::info!(
        "Updated checkpoint: id={}, height={}, hash={}",
        id3,
        height3,
        hash3
    );

    // 8. Insert a block and contract_state at height 10 (new interval)
    let block10 = BlockRow {
        height: 10,
        hash: bitcoin::BlockHash::from_str(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26d",
        )?,
    };
    insert_block(&conn, block10).await?;

    conn.execute(
        "INSERT INTO contract_state (contract_id, tx_id, height, path, value, deleted) 
         VALUES ('contract1', 3, 10, '/path/4', X'DEADBEEF', 0)",
        params![],
    )
    .await?;

    // 9. Verify a new checkpoint was created
    let mut rows = conn
        .query(
            "SELECT id, height, hash FROM checkpoints ORDER BY id",
            params![],
        )
        .await?;

    // First checkpoint should still exist
    let row = rows.next().await?.expect("Should have first checkpoint");
    assert_eq!(row.get::<i64>(0)?, id1, "First checkpoint ID should match");

    // Second checkpoint should be created
    let row = rows.next().await?.expect("Should have second checkpoint");
    let id4: i64 = row.get(0)?;
    let height4: i64 = row.get(1)?;
    let hash4: String = row.get(2)?;

    assert_ne!(id4, id1, "Should be a new checkpoint id");
    assert_eq!(height4, 10, "Height should be 10");
    tracing::info!(
        "New checkpoint: id={}, height={}, hash={}",
        id4,
        height4,
        hash4
    );

    // 10. Test direct update of a checkpoint height
    let block15 = BlockRow {
        height: 15,
        hash: bitcoin::BlockHash::from_str(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26c",
        )?,
    };
    insert_block(&conn, block15).await?;

    conn.execute(
        "INSERT INTO contract_state (contract_id, tx_id, height, path, value, deleted) 
         VALUES ('contract1', 4, 15, '/path/5', X'CAFEBABE', 0)",
        params![],
    )
    .await?;

    // Verify the second checkpoint was updated
    let mut rows = conn
        .query(
            "SELECT id, height FROM checkpoints WHERE id = ?",
            params![id4],
        )
        .await?;

    let row = rows
        .next()
        .await?
        .expect("Should have updated second checkpoint");
    let height5: i64 = row.get(1)?;
    assert_eq!(
        height5, 15,
        "Second checkpoint height should be updated to 15"
    );

    // 11. Test crossing multiple intervals
    let block25 = BlockRow {
        height: 25,
        hash: bitcoin::BlockHash::from_str(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26b",
        )?,
    };
    insert_block(&conn, block25).await?;

    conn.execute(
        "INSERT INTO contract_state (contract_id, tx_id, height, path, value, deleted) 
         VALUES ('contract1', 5, 25, '/path/6', X'DEADBEEF', 0)",
        params![],
    )
    .await?;

    // Verify a new checkpoint was created
    let mut rows = conn
        .query("SELECT COUNT(*) FROM checkpoints", params![])
        .await?;

    let count: i64 = rows
        .next()
        .await?
        .expect("Should have one checkpoint")
        .get(0)?;
    assert_eq!(count, 3, "Should now have 3 checkpoints");

    // Get the newest checkpoint
    let mut rows = conn
        .query(
            "SELECT height FROM checkpoints ORDER BY id DESC LIMIT 1",
            params![],
        )
        .await?;

    let row = rows.next().await?.expect("Should have third checkpoint");
    let height6: i64 = row.get(0)?;
    assert_eq!(height6, 25, "Third checkpoint height should be 25");

    // 12. Test transaction rollback doesn't affect checkpoints
    {
        let tx = conn.transaction().await?;

        let block35 = BlockRow {
            height: 35,
            hash: bitcoin::BlockHash::from_str(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26a",
            )?,
        };
        insert_block(&tx, block35).await?;

        tx.execute(
            "INSERT INTO contract_state (contract_id, tx_id, height, path, value, deleted) 
             VALUES ('contract1', 6, 35, '/path/7', X'DEADBEEF', 0)",
            params![],
        )
        .await?;

        // Don't commit the transaction - let it roll back
    }

    // Verify checkpoint count is still 3
    let mut rows = conn
        .query("SELECT COUNT(*) FROM checkpoints", params![])
        .await?;

    let count: i64 = rows
        .next()
        .await?
        .expect("Should have one checkpoint")
        .get(0)?;
    assert_eq!(count, 3, "Should still have 3 checkpoints after rollback");

    // 13. Test transaction commit creates checkpoint
    {
        let tx = conn.transaction().await?;

        let block35 = BlockRow {
            height: 35,
            hash: bitcoin::BlockHash::from_str(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26a",
            )?,
        };
        insert_block(&tx, block35).await?;

        tx.execute(
            "INSERT INTO contract_state (contract_id, tx_id, height, path, value, deleted) 
             VALUES ('contract1', 6, 35, '/path/7', X'DEADBEEF', 0)",
            params![],
        )
        .await?;

        tx.commit().await?;
    }

    // Verify checkpoint count is now 4
    let mut rows = conn
        .query("SELECT COUNT(*) FROM checkpoints", params![])
        .await?;

    let count: i64 = rows
        .next()
        .await?
        .expect("Should have one checkpoint")
        .get(0)?;
    assert_eq!(
        count, 4,
        "Should have 4 checkpoints after committed transaction"
    );

    tracing::info!("All checkpoint trigger tests passed!");
    Ok(())
}
