use anyhow::Result;
use bitcoin::BlockHash;
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

use indexer::{
    bitcoin_follower::event::BitcoinEvent,
    database::queries,
    reactor,
    test_utils::{gen_random_blocks, new_random_blockchain, new_test_db},
};

/// Poll until a processed block at `height` has the expected `hash`.
async fn await_block_hash(conn: &libsql::Connection, height: i64, hash: BlockHash) {
    loop {
        if let Ok(Some(block)) = queries::select_processed_block_at_height(conn, height).await
            && block.hash == hash
        {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn send_block_and_wait(
    tx: &mpsc::Sender<BitcoinEvent>,
    conn: &libsql::Connection,
    block: &indexer_types::Block,
    target_height: u64,
) {
    let hash = block.hash;
    let height = block.height as i64;
    tx.send(BitcoinEvent::BlockInsert {
        target_height,
        block: block.clone(),
    })
    .await
    .unwrap();
    await_block_hash(conn, height, hash).await;
}

#[tokio::test]
async fn test_reactor_fetching() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = &writer.connection();

    let blocks = new_random_blockchain(5);

    let (event_tx, event_rx) = mpsc::channel(10);
    let handle = reactor::run(1, cancel_token.clone(), writer, event_rx, None, None, None);

    let target = 5;
    for block in &blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    for (i, expected) in blocks.iter().enumerate() {
        let block = queries::select_processed_block_at_height(conn, (i + 1) as i64)
            .await?
            .unwrap();
        assert_eq!(block.hash, expected.hash);
    }

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn test_reactor_rollback_and_reinsert() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = &writer.connection();

    let blocks = new_random_blockchain(3);

    let (event_tx, event_rx) = mpsc::channel(10);
    let handle = reactor::run(1, cancel_token.clone(), writer, event_rx, None, None, None);

    // Insert blocks 1-3
    let target = 3;
    for block in &blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    let initial_block_3_hash = blocks[2].hash;

    // Rollback to height 2 (remove block 3), then insert new blocks 3-5
    event_tx
        .send(BitcoinEvent::Rollback { to_height: 2 })
        .await?;

    let new_blocks = gen_random_blocks(2, 5, Some(blocks[1].hash));
    let target = 5;
    for block in &new_blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    // Block 3 should have a different hash now
    let block = queries::select_processed_block_at_height(conn, 3)
        .await?
        .unwrap();
    assert_eq!(block.hash, new_blocks[0].hash);
    assert_ne!(block.hash, initial_block_3_hash);

    // Blocks 4-5 should exist with new hashes
    let block = queries::select_processed_block_at_height(conn, 5)
        .await?
        .unwrap();
    assert_eq!(block.hash, new_blocks[2].hash);

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn test_reactor_deep_rollback() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = &writer.connection();

    let blocks = new_random_blockchain(4);

    let (event_tx, event_rx) = mpsc::channel(10);
    let handle = reactor::run(1, cancel_token.clone(), writer, event_rx, None, None, None);

    // Insert blocks 1-4
    let target = 4;
    for block in &blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    // Roll back to height 1 (remove blocks 2-4)
    event_tx
        .send(BitcoinEvent::Rollback { to_height: 1 })
        .await?;

    // Insert new chain from block 1
    let new_blocks = gen_random_blocks(1, 4, Some(blocks[0].hash));
    let target = 4;
    for block in &new_blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    // Block 1 should be preserved
    let block = queries::select_processed_block_at_height(conn, 1)
        .await?
        .unwrap();
    assert_eq!(block.hash, blocks[0].hash);

    // Block 2 should have new hash
    let block = queries::select_processed_block_at_height(conn, 2)
        .await?
        .unwrap();
    assert_eq!(block.hash, new_blocks[0].hash);

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn test_reactor_rollback_then_extend() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = &writer.connection();

    let blocks = new_random_blockchain(2);

    let (event_tx, event_rx) = mpsc::channel(10);
    let handle = reactor::run(1, cancel_token.clone(), writer, event_rx, None, None, None);

    // Insert blocks 1-2
    let target = 2;
    for block in &blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    // Extend with blocks 3-4
    let more_blocks = gen_random_blocks(2, 4, Some(blocks[1].hash));
    let target = 4;
    for block in &more_blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    let block = queries::select_processed_block_at_height(conn, 4)
        .await?
        .unwrap();
    assert_eq!(block.hash, more_blocks[1].hash);

    // Roll back to height 1, insert entirely new chain
    event_tx
        .send(BitcoinEvent::Rollback { to_height: 1 })
        .await?;

    let new_blocks = gen_random_blocks(1, 4, Some(blocks[0].hash));
    let target = 4;
    for block in &new_blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    // Verify block 2 has new hash
    let block = queries::select_processed_block_at_height(conn, 2)
        .await?
        .unwrap();
    assert_eq!(block.hash, new_blocks[0].hash);

    // Verify block 4 has new hash
    let block = queries::select_processed_block_at_height(conn, 4)
        .await?
        .unwrap();
    assert_eq!(block.hash, new_blocks[2].hash);

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}
