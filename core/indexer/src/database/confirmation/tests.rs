use anyhow::{Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, Network, OutPoint, ScriptBuf, TxOut, Witness};
use indexer_types::{BlockRow, TransactionRow};
use libsql::{Builder, Connection, params};
use tempfile::TempDir;

use super::{
    backfill_confirmation_positions, get_confirmation_position, initialize_confirmation_metadata,
    set_confirmation_position,
};
use crate::database::connection::new_connection;
use crate::database::queries::{
    confirm_transaction, get_transaction_by_txid, insert_batch, insert_block, insert_transaction,
    rollback_to_height,
};
use crate::test_utils::{new_mock_block_hash, new_mock_transaction};

async fn legacy_projection(conn: &Connection, txid: &str) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(
        get_transaction_by_txid(conn, txid).await?,
    )?)
}

#[tokio::test]
async fn migration_preserves_legacy_rows_without_inventing_raw_positions() -> Result<()> {
    let db = Builder::new_local(":memory:").build().await?;
    let conn = db.connect()?;
    conn.execute_batch(
        "CREATE TABLE transactions (
           id INTEGER PRIMARY KEY, txid TEXT NOT NULL UNIQUE, height INTEGER NOT NULL,
           confirmed_height INTEGER, tx_index INTEGER, batch_height INTEGER);
         INSERT INTO transactions VALUES (1, 'confirmed', 4, 7, 0, 2);
         INSERT INTO transactions VALUES (2, 'pending', 4, NULL, NULL, 3);",
    )
    .await?;
    let confirmed = legacy_projection(&conn, "confirmed").await?;
    let pending = legacy_projection(&conn, "pending").await?;
    initialize_confirmation_metadata(&conn).await?;
    assert_eq!(get_confirmation_position(&conn, "confirmed").await?, None);
    assert_eq!(get_confirmation_position(&conn, "pending").await?, None);
    set_confirmation_position(&conn, "confirmed", 7, 9).await?;
    initialize_confirmation_metadata(&conn).await?;
    assert_eq!(
        get_confirmation_position(&conn, "confirmed").await?,
        Some(9)
    );
    assert_eq!(legacy_projection(&conn, "confirmed").await?, confirmed);
    assert_eq!(legacy_projection(&conn, "pending").await?, pending);
    assert!(
        set_confirmation_position(&conn, "pending", 4, 0)
            .await
            .is_err()
    );
    assert!(
        set_confirmation_position(&conn, "missing", 7, 0)
            .await
            .is_err()
    );
    assert!(
        set_confirmation_position(&conn, "confirmed", 8, 0)
            .await
            .is_err()
    );
    assert_eq!(
        get_confirmation_position(&conn, "confirmed").await?,
        Some(9)
    );
    set_confirmation_position(&conn, "confirmed", 7, u32::MAX).await?;
    assert_eq!(
        get_confirmation_position(&conn, "confirmed").await?,
        Some(u32::MAX)
    );
    for invalid in [-1_i64, i64::from(u32::MAX) + 1] {
        assert!(
            conn.execute(
                "UPDATE transactions SET confirmed_bitcoin_tx_index = ? WHERE txid = 'confirmed'",
                params![invalid],
            )
            .await
            .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn legacy_confirmation_changes_invalidate_position_and_rollback_atomically() -> Result<()> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "positions.db").await?;
    for height in 1..=3 {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(new_mock_block_hash(height as u32))
                .relevant(true)
                .build(),
        )
        .await?;
    }
    insert_batch(&conn, 1, 1, &new_mock_block_hash(1).to_string(), &[], true).await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(1)
            .batch_height(1)
            .txid("batched".into())
            .build(),
    )
    .await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(3)
            .confirmed_height(3)
            .tx_index(1)
            .txid("block-only".into())
            .build(),
    )
    .await?;
    confirm_transaction(&conn, "batched", 2, 0).await?;
    set_confirmation_position(&conn, "batched", 2, 7).await?;
    let before = legacy_projection(&conn, "batched").await?;
    conn.execute_batch("SAVEPOINT confirmation_test").await?;
    confirm_transaction(&conn, "batched", 3, 1).await?;
    assert_eq!(get_confirmation_position(&conn, "batched").await?, None);
    set_confirmation_position(&conn, "batched", 3, 11).await?;
    conn.execute_batch("ROLLBACK TO confirmation_test; RELEASE confirmation_test")
        .await?;
    assert_eq!(get_confirmation_position(&conn, "batched").await?, Some(7));
    assert_eq!(legacy_projection(&conn, "batched").await?, before);

    set_confirmation_position(&conn, "block-only", 3, 12).await?;
    rollback_to_height(&conn, 1).await?;
    let surviving = get_transaction_by_txid(&conn, "batched")
        .await?
        .context("batch execution must survive confirmation rollback")?;
    assert_eq!(surviving.height, 1);
    assert_eq!(surviving.batch_height, Some(1));
    assert_eq!(surviving.confirmed_height, None);
    assert_eq!(surviving.tx_index, None);
    assert_eq!(get_confirmation_position(&conn, "batched").await?, None);
    assert!(
        get_transaction_by_txid(&conn, "block-only")
            .await?
            .is_none()
    );
    insert_block(
        &conn,
        BlockRow::builder()
            .height(2)
            .hash(new_mock_block_hash(22))
            .relevant(true)
            .build(),
    )
    .await?;
    confirm_transaction(&conn, "batched", 2, 1).await?;
    set_confirmation_position(&conn, "batched", 2, 13).await?;
    assert_eq!(get_confirmation_position(&conn, "batched").await?, Some(13));
    let reconfirmed = get_transaction_by_txid(&conn, "batched").await?.unwrap();
    assert_eq!(reconfirmed.height, surviving.height);
    assert_eq!(reconfirmed.batch_height, surviving.batch_height);
    assert_eq!(reconfirmed.tx_index, Some(1));
    Ok(())
}

fn backfill_block() -> Block {
    let mut block = genesis_block(Network::Regtest);
    for index in 1..=2 {
        let mut tx = block.txdata[0].clone();
        tx.input[0].previous_output = OutPoint {
            txid: new_mock_transaction(index).txid,
            vout: 0,
        };
        tx.lock_time = LockTime::from_consensus(index);
        block.txdata.push(tx);
    }
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    block
}

#[tokio::test]
async fn backfill_requires_canonical_body_and_rolls_back_partial_writes() -> Result<()> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "backfill.db").await?;
    let block = backfill_block();
    let ids: Vec<_> = block
        .txdata
        .iter()
        .skip(1)
        .map(|tx| tx.compute_txid().to_string())
        .collect();
    insert_block(
        &conn,
        BlockRow::builder()
            .height(7)
            .hash(block.block_hash())
            .relevant(true)
            .build(),
    )
    .await?;
    for (ordinal, txid) in ids.iter().enumerate() {
        insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(7)
                .confirmed_height(7)
                .tx_index(ordinal as u32)
                .txid(txid.clone())
                .build(),
        )
        .await?;
    }
    let before = [
        legacy_projection(&conn, &ids[0]).await?,
        legacy_projection(&conn, &ids[1]).await?,
    ];
    let mut wrong_header = block.clone();
    wrong_header.header.nonce ^= 1;
    assert!(
        backfill_confirmation_positions(&conn, 7, &wrong_header)
            .await
            .is_err()
    );
    let mut wrong_body = block.clone();
    wrong_body.txdata[1].output[0].value = Amount::ZERO;
    assert!(
        backfill_confirmation_positions(&conn, 7, &wrong_body)
            .await
            .is_err()
    );
    let mut wrong_witness = block.clone();
    wrong_witness.txdata[1].input[0].witness.push([1; 32]);
    assert!(
        backfill_confirmation_positions(&conn, 7, &wrong_witness)
            .await
            .is_err()
    );
    assert!(
        backfill_confirmation_positions(&conn, 8, &block)
            .await
            .is_err()
    );
    for txid in &ids {
        assert_eq!(get_confirmation_position(&conn, txid).await?, None);
    }

    conn.execute_batch(
        "CREATE TRIGGER reject_second_confirmation_position
         BEFORE UPDATE OF confirmed_bitcoin_tx_index ON transactions WHEN NEW.id = 2
         BEGIN SELECT RAISE(ABORT, 'injected metadata failure'); END;",
    )
    .await?;
    assert!(
        backfill_confirmation_positions(&conn, 7, &block)
            .await
            .is_err()
    );
    for txid in &ids {
        assert_eq!(get_confirmation_position(&conn, txid).await?, None);
    }
    conn.execute_batch("DROP TRIGGER reject_second_confirmation_position")
        .await?;

    let report = backfill_confirmation_positions(&conn, 7, &block).await?;
    assert_eq!((report.updated, report.already_known), (2, 0));
    assert_eq!(get_confirmation_position(&conn, &ids[0]).await?, Some(1));
    assert_eq!(get_confirmation_position(&conn, &ids[1]).await?, Some(2));
    let report = backfill_confirmation_positions(&conn, 7, &block).await?;
    assert_eq!((report.updated, report.already_known), (0, 2));
    assert_eq!(legacy_projection(&conn, &ids[0]).await?, before[0]);
    assert_eq!(legacy_projection(&conn, &ids[1]).await?, before[1]);

    set_confirmation_position(&conn, &ids[0], 7, 0).await?;
    assert!(
        backfill_confirmation_positions(&conn, 7, &block)
            .await
            .is_err()
    );
    assert_eq!(get_confirmation_position(&conn, &ids[0]).await?, Some(0));
    set_confirmation_position(&conn, &ids[0], 7, 1).await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(7)
            .confirmed_height(7)
            .tx_index(2)
            .txid("absent-from-block".into())
            .build(),
    )
    .await?;
    assert!(
        backfill_confirmation_positions(&conn, 7, &block)
            .await
            .is_err()
    );
    assert_eq!(
        get_confirmation_position(&conn, "absent-from-block").await?,
        None
    );
    Ok(())
}

#[tokio::test]
async fn backfill_requires_the_committed_witness_data() -> Result<()> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "witness-backfill.db").await?;
    let mut block = backfill_block();
    block.txdata[1].input[0].witness.push([42; 32]);
    block.txdata[0].input[0].witness.push([0; 32]);
    let commitment = Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(&commitment.to_byte_array());
    block.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    assert!(block.check_merkle_root());
    assert!(block.check_witness_commitment());
    insert_block(
        &conn,
        BlockRow::builder()
            .height(7)
            .hash(block.block_hash())
            .relevant(true)
            .build(),
    )
    .await?;
    let txid = block.txdata[1].compute_txid().to_string();
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(7)
            .confirmed_height(7)
            .tx_index(0)
            .txid(txid.clone())
            .build(),
    )
    .await?;
    let mut stripped = block.clone();
    for transaction in &mut stripped.txdata {
        for input in &mut transaction.input {
            input.witness = Witness::new();
        }
    }
    assert!(
        stripped.check_witness_commitment(),
        "pinned library skips witness-free bodies"
    );
    assert!(
        backfill_confirmation_positions(&conn, 7, &stripped)
            .await
            .is_err()
    );
    assert_eq!(get_confirmation_position(&conn, &txid).await?, None);
    let mut tampered = block.clone();
    tampered.txdata[1].input[0].witness.push([43; 32]);
    assert!(!tampered.check_witness_commitment());
    assert!(
        backfill_confirmation_positions(&conn, 7, &tampered)
            .await
            .is_err()
    );
    let result = backfill_confirmation_positions(&conn, 7, &block).await?;
    assert_eq!((result.updated, result.already_known), (1, 0));
    assert_eq!(get_confirmation_position(&conn, &txid).await?, Some(1));
    Ok(())
}
