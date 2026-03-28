use anyhow::Result;
use indexer::{
    consensus::Height,
    database::queries::{get_transaction_by_txid, insert_block},
    reactor::block_handler::{batch_handler, block_handler},
    test_utils::{new_mock_block_hash, new_mock_transaction, test_runtime},
};
use indexer_types::{Block, BlockRow};

#[tokio::test]
async fn batch_then_block_deduplicates_transaction() -> Result<()> {
    let (mut runtime, _db_dir, _) = test_runtime().await?;
    let conn = runtime.get_storage_conn();

    let mock_tx = new_mock_transaction(42);
    let txid_str = mock_tx.txid.to_string();

    // Execute via batch_handler at consensus height 1, anchored at block 1
    let cert = vec![0u8; 8];
    batch_handler(
        &mut runtime,
        1,
        new_mock_block_hash(1),
        Height::new(1),
        &cert,
        std::slice::from_ref(&mock_tx),
        &[], // no raw bitcoin txs needed for this test
    )
    .await?;

    // Verify tx exists with batch_height set but no confirmed_height
    let row = get_transaction_by_txid(&conn, &txid_str)
        .await?
        .expect("Transaction should exist after batch");
    assert!(row.batch_height.is_some(), "batch_height should be set");
    assert!(
        row.confirmed_height.is_none(),
        "confirmed_height should be None before block confirmation"
    );

    // Process a block at height 2 containing the same transaction
    insert_block(
        &conn,
        BlockRow::builder()
            .height(2)
            .hash(new_mock_block_hash(2))
            .relevant(true)
            .build(),
    )
    .await?;

    let block = Block {
        height: 2,
        hash: new_mock_block_hash(2),
        prev_hash: new_mock_block_hash(1),
        transactions: vec![mock_tx],
    };
    block_handler(&mut runtime, &block).await?;

    // Verify: still one transaction row, now with confirmed_height set
    let row = get_transaction_by_txid(&conn, &txid_str)
        .await?
        .expect("Transaction should still exist");
    assert_eq!(
        row.confirmed_height,
        Some(2),
        "confirmed_height should be set to block height"
    );
    assert_eq!(row.tx_index, Some(0), "tx_index should be set from block");
    assert!(
        row.batch_height.is_some(),
        "batch_height should still be set"
    );

    Ok(())
}
