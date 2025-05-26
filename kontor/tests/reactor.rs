use anyhow::Result;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use bitcoin::{BlockHash, hashes::Hash};

use kontor::{
    bitcoin_follower::{events::Event, queries::select_block_at_height},
    block::Block,
    reactor,
    utils::{MockTransaction, new_test_db},
};

#[tokio::test]
async fn test_reactor_rollback() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (tx, rx) = mpsc::channel(1);
    let (reader, writer, _temp_dir) = new_test_db().await?;

    let handle =
        reactor::run::<MockTransaction>(cancel_token.clone(), reader.clone(), writer.clone(), rx);

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

    let conn = &*reader.connection().await?;
    let block = select_block_at_height(conn, 92, cancel_token.clone()).await?;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x20; 32]));

    assert!(tx.send(Event::Rollback(91)).await.is_ok());

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
