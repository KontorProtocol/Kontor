use anyhow::Result;
use clap::Parser;
use tokio_util::sync::CancellationToken;

use bitcoin::{BlockHash, hashes::Hash};

use indexer::{
    bitcoin_follower::{
        ctrl::CtrlChannel,
        events::{BlockId, Event},
    },
    block::Block,
    config::Config,
    database::queries,
    reactor,
    test_utils::{MockTransaction, await_block_at_height, new_numbered_blockchain, new_test_db},
};

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

    let conn = &*reader.connection().await?;
    let block = await_block_at_height(conn, 92).await;
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

    let block = await_block_at_height(conn, 92).await;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x21; 32]));

    let block = await_block_at_height(conn, 93).await;
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

    let conn = &*reader.connection().await?;
    let block = await_block_at_height(conn, 92).await;
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

    let block = await_block_at_height(conn, 92).await;
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
    let block = await_block_at_height(conn, 92).await;
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

    let blocks = new_numbered_blockchain(5);
    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, (&blocks[1 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[2 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[3 - 1]).into())
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
