use anyhow::{Result, anyhow};
use clap::Parser;
use libsql::Connection;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

use bitcoin::{BlockHash, hashes::Hash};

use indexer::{
    bitcoin_follower::{
        ctrl::CtrlChannel,
        events::{BlockId, Event},
    },
    block::{Block, Tx},
    config::Config,
    database::{queries, types::BlockRow},
    reactor,
    retry::{new_backoff_unlimited, retry},
    test_utils::{MockTransaction, new_test_db},
};

fn gen_block<T: Tx>(height: u64, hash: &BlockHash, prev_hash: &BlockHash) -> Block<T> {
    Block {
        height,
        hash: *hash,
        prev_hash: *prev_hash,
        transactions: vec![],
    }
}

fn gen_blocks<T: Tx>(start: u64, end: u64, prev_hash: BlockHash) -> Vec<Block<T>> {
    let mut blocks = vec![];
    let mut prev = prev_hash;

    for _i in start..end {
        let hash = BlockHash::from_byte_array([(_i + 1) as u8; 32]);
        let block = gen_block(_i + 1, &hash, &prev);
        blocks.push(block.clone());

        prev = hash;
    }

    blocks
}

fn new_block_chain<T: Tx>(n: u64) -> Vec<Block<T>> {
    gen_blocks(0, n, BlockHash::from_byte_array([0x00; 32]))
}

fn block_row<T: Tx>(height: u64, b: &Block<T>) -> BlockRow {
    BlockRow {
        height,
        hash: b.hash,
    }
}

async fn select_block_at_height(
    conn: &Connection,
    height: u64,
    cancel_token: CancellationToken,
) -> Result<BlockRow> {
    retry(
        async || match queries::select_block_at_height(conn, height).await {
            Ok(Some(row)) => Ok(row),
            Ok(None) => Err(anyhow!("Block at height not found: {}", height)),
            Err(e) => Err(e.into()),
        },
        "read block at height",
        new_backoff_unlimited(),
        cancel_token.clone(),
    )
    .await
}

#[tokio::test]
async fn test_reactor_rollback_event() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (ctrl, mut ctrl_rx) = CtrlChannel::create();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let handle = reactor::run::<MockTransaction>(
        91,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 91);
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 91,
                hash: BlockHash::from_byte_array([0x10; 32]),
                prev_hash: BlockHash::from_byte_array([0x00; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x20; 32]),
                prev_hash: BlockHash::from_byte_array([0x10; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 93,
                hash: BlockHash::from_byte_array([0x30; 32]),
                prev_hash: BlockHash::from_byte_array([0x20; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    sleep(Duration::from_millis(10)).await; // short delay to hopefully avoid a read retry
    let conn = &*reader.connection().await?;
    let block = select_block_at_height(conn, 92, cancel_token.clone()).await?;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x20; 32]));

    assert!(
        tx.send(Event::BlockRemove(BlockId::Height(91)))
            .await
            .is_ok()
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 92);
    assert_eq!(
        start.last_hash,
        Some(BlockHash::from_byte_array([0x10; 32]))
    );
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x21; 32]),
                prev_hash: BlockHash::from_byte_array([0x10; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 93,
                hash: BlockHash::from_byte_array([0x31; 32]),
                prev_hash: BlockHash::from_byte_array([0x21; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    sleep(Duration::from_millis(10)).await; // short delay to hopefully avoid a read retry

    let block = select_block_at_height(conn, 92, cancel_token.clone()).await?;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x21; 32]));

    let block = select_block_at_height(conn, 93, cancel_token.clone()).await?;
    assert_eq!(block.height, 93);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x31; 32]));

    assert!(!handle.is_finished());

    cancel_token.cancel();
    let _ = handle.await;

    Ok(())
}

#[tokio::test]
async fn test_reactor_unexpected_block() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (ctrl, mut ctrl_rx) = CtrlChannel::create();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let handle = reactor::run::<MockTransaction>(
        81,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 81);
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 82, // skipping 81
                hash: BlockHash::from_byte_array([0x01; 32]),
                prev_hash: BlockHash::from_byte_array([0x00; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    cancel_token.cancelled().await;
    assert!(cancel_token.is_cancelled());

    let _ = handle.await;

    Ok(())
}

#[tokio::test]
async fn test_reactor_rollback_due_to_hash_mismatch() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (ctrl, mut ctrl_rx) = CtrlChannel::create();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let handle = reactor::run::<MockTransaction>(
        91,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 91);
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 91,
                hash: BlockHash::from_byte_array([0x01; 32]),
                prev_hash: BlockHash::from_byte_array([0x00; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x02; 32]),
                prev_hash: BlockHash::from_byte_array([0x01; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    sleep(Duration::from_millis(10)).await; // short delay to hopefully avoid a read retry

    let conn = &*reader.connection().await?;
    let block = select_block_at_height(conn, 92, cancel_token.clone()).await?;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x02; 32]));

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 93,
                hash: BlockHash::from_byte_array([0x03; 32]),
                prev_hash: BlockHash::from_byte_array([0x12; 32]), // not matching
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 92);
    assert_eq!(
        start.last_hash,
        Some(BlockHash::from_byte_array([0x01; 32]))
    );

    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x12; 32]),
                prev_hash: BlockHash::from_byte_array([0x01; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    sleep(Duration::from_millis(10)).await; // short delay to hopefully avoid a read retry
    let block = select_block_at_height(conn, 92, cancel_token.clone()).await?;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x12; 32]));

    assert!(!handle.is_finished());

    cancel_token.cancel();
    let _ = handle.await;

    Ok(())
}

#[tokio::test]
async fn test_reactor_rollback_due_to_reverting_height() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (ctrl, mut ctrl_rx) = CtrlChannel::create();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let handle = reactor::run::<MockTransaction>(
        91,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 91);
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 91,
                hash: BlockHash::from_byte_array([0x01; 32]),
                prev_hash: BlockHash::from_byte_array([0x00; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x02; 32]),
                prev_hash: BlockHash::from_byte_array([0x01; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 93,
                hash: BlockHash::from_byte_array([0x03; 32]),
                prev_hash: BlockHash::from_byte_array([0x02; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,                                   // lower height
                hash: BlockHash::from_byte_array([0x12; 32]), // new hash
                prev_hash: BlockHash::from_byte_array([0x01; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    // we're re-requesting the block we just received, which is wasteful but
    // it doesn't seem worth having a special code-path for what should be
    // an exceptional case.

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 92);
    assert_eq!(
        start.last_hash,
        Some(BlockHash::from_byte_array([0x01; 32]))
    );
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x12; 32]),
                prev_hash: BlockHash::from_byte_array([0x01; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    let conn = &*reader.connection().await?;
    sleep(Duration::from_millis(10)).await; // short delay to hopefully avoid a read retry
    let block = select_block_at_height(conn, 92, cancel_token.clone()).await?;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x12; 32]));

    assert!(!handle.is_finished());

    cancel_token.cancel();
    let _ = handle.await;

    Ok(())
}

#[tokio::test]
async fn test_reactor_rollback_hash_event() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (ctrl, mut ctrl_rx) = CtrlChannel::create();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let blocks = new_block_chain::<MockTransaction>(5);
    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, block_row(1, &blocks[1 - 1]))
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, block_row(2, &blocks[2 - 1]))
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, block_row(3, &blocks[3 - 1]))
            .await
            .is_ok()
    );

    let handle = reactor::run::<MockTransaction>(
        4,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 4);
    assert_eq!(start.last_hash, Some(blocks[3 - 1].hash));
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockRemove(BlockId::Hash(blocks[2 - 1].hash)))
            .await
            .is_ok()
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 2);
    assert_eq!(start.last_hash, Some(blocks[1 - 1].hash));
    assert!(!handle.is_finished());
    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}
