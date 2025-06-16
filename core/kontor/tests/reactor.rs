use anyhow::Result;
use clap::Parser;
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

use bitcoin::{BlockHash, hashes::Hash};

use kontor::{
    bitcoin_follower::{
        events::{Event, Signal},
        queries::select_block_at_height,
    },
    block::Block,
    config::Config,
    reactor,
    utils::{MockTransaction, new_test_db},
};

#[tokio::test]
async fn test_reactor_rollback_event() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (tx, rx) = mpsc::channel(1);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let handle = reactor::run::<MockTransaction>(
        91,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl_tx,
        rx,
    );

    assert_eq!(ctrl_rx.recv().await.unwrap(), Signal::Seek((91, None)));

    assert!(
        tx.send(Event::Block((
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
        tx.send(Event::Block((
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
        tx.send(Event::Block((
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

    assert!(tx.send(Event::Rollback(91)).await.is_ok());

    assert_eq!(
        ctrl_rx.recv().await.unwrap(),
        Signal::Seek((92, Some(BlockHash::from_byte_array([0x10; 32]))))
    );

    assert!(
        tx.send(Event::Block((
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
        tx.send(Event::Block((
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
    //
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
    let (tx, rx) = mpsc::channel(1);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let _handle = reactor::run::<MockTransaction>(
        81,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl_tx,
        rx,
    );

    assert_eq!(ctrl_rx.recv().await.unwrap(), Signal::Seek((81, None)));

    assert!(
        tx.send(Event::Block((
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

    // TODO re-enable these checks once we have tightened up the handling of
    // spurious blocks (currently the reactor will simply ignore them
    // cancel_token.cancelled().await;
    // assert!(cancel_token.is_cancelled());

    // let _ = handle.await;

    Ok(())
}

#[tokio::test]
async fn test_reactor_rollback_due_to_hash_mismatch() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (tx, rx) = mpsc::channel(1);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let handle = reactor::run::<MockTransaction>(
        91,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl_tx,
        rx,
    );

    assert_eq!(ctrl_rx.recv().await.unwrap(), Signal::Seek((91, None)));

    assert!(
        tx.send(Event::Block((
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
        tx.send(Event::Block((
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
        tx.send(Event::Block((
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

    let conn = &*reader.connection().await?;
    let block = select_block_at_height(conn, 92, cancel_token.clone()).await?;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x02; 32]));

    assert_eq!(
        ctrl_rx.recv().await.unwrap(),
        Signal::Seek((92, Some(BlockHash::from_byte_array([0x01; 32]))))
    );

    assert!(
        tx.send(Event::Block((
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
    let (tx, rx) = mpsc::channel(1);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let handle = reactor::run::<MockTransaction>(
        91,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl_tx,
        rx,
    );

    assert_eq!(ctrl_rx.recv().await.unwrap(), Signal::Seek((91, None)));

    assert!(
        tx.send(Event::Block((
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
        tx.send(Event::Block((
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
        tx.send(Event::Block((
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
        tx.send(Event::Block((
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

    assert_eq!(
        ctrl_rx.recv().await.unwrap(),
        Signal::Seek((92, Some(BlockHash::from_byte_array([0x01; 32]))))
    );

    assert!(
        tx.send(Event::Block((
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
