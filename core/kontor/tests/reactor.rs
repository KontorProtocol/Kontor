use anyhow::Result;
use clap::Parser;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use bitcoin::{hashes::Hash, BlockHash};

use kontor::{
    bitcoin_follower::{events::Event, queries::select_block_at_height},
    block::Block,
    config::Config,
    reactor,
    utils::{new_test_db, MockTransaction},
};

#[tokio::test]
async fn test_reactor_rollback_event() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (tx, rx) = mpsc::channel(1);
    let (ctrl_tx, _rx) = mpsc::channel(1);
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let handle = reactor::run::<MockTransaction>(
        91,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl_tx,
        rx,
    );

    assert!(tx
        .send(Event::Block((
            100,
            Block {
                height: 91,
                hash: BlockHash::from_byte_array([0x10; 32]),
                prev_hash: BlockHash::from_byte_array([0x00; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok());

    assert!(tx
        .send(Event::Block((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x20; 32]),
                prev_hash: BlockHash::from_byte_array([0x10; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok());

    assert!(tx
        .send(Event::Block((
            100,
            Block {
                height: 93,
                hash: BlockHash::from_byte_array([0x30; 32]),
                prev_hash: BlockHash::from_byte_array([0x20; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok());

    let conn = &*reader.connection().await?;
    let block = select_block_at_height(conn, 92, cancel_token.clone()).await?;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x20; 32]));

    assert!(tx.send(Event::Rollback(91)).await.is_ok());

    assert!(tx
        .send(Event::Block((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x21; 32]),
                prev_hash: BlockHash::from_byte_array([0x10; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok());

    assert!(tx
        .send(Event::Block((
            100,
            Block {
                height: 93,
                hash: BlockHash::from_byte_array([0x31; 32]),
                prev_hash: BlockHash::from_byte_array([0x21; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok());

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
    let (ctrl_tx, _rx) = mpsc::channel(1);
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let handle = reactor::run::<MockTransaction>(
        81,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl_tx,
        rx,
    );

    assert!(tx
        .send(Event::Block((
            100,
            Block {
                height: 82, // skipping 81
                hash: BlockHash::from_byte_array([0x01; 32]),
                prev_hash: BlockHash::from_byte_array([0x00; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok());

    cancel_token.cancelled().await;
    assert!(cancel_token.is_cancelled());

    let _ = handle.await;

    Ok(())
}

#[tokio::test]
async fn test_reactor_deduced_rollback() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (tx, rx) = mpsc::channel(1);
    let (ctrl_tx, _rx) = mpsc::channel(1);
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let handle = reactor::run::<MockTransaction>(
        91,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl_tx,
        rx,
    );

    assert!(tx
        .send(Event::Block((
            100,
            Block {
                height: 91,
                hash: BlockHash::from_byte_array([0x01; 32]),
                prev_hash: BlockHash::from_byte_array([0x00; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok());

    assert!(tx
        .send(Event::Block((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x02; 32]),
                prev_hash: BlockHash::from_byte_array([0x01; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok());

    assert!(tx
        .send(Event::Block((
            100,
            Block {
                height: 93,
                hash: BlockHash::from_byte_array([0x03; 32]),
                prev_hash: BlockHash::from_byte_array([0x04; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok());

    let conn = &*reader.connection().await?;
    let block = select_block_at_height(conn, 92, cancel_token.clone()).await?;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x02; 32]));

    // TODO verify that the reactor deduced the need for a rollback

    assert!(!handle.is_finished());

    cancel_token.cancel();
    let _ = handle.await;

    Ok(())
}
