use std::collections::HashMap;

use bitcoin::Block;
use libsql::{Connection, Error, TransactionBehavior, params};
use serde::Serialize;

use super::queries::{Error as QueryError, select_block_at_height};

pub async fn initialize_confirmation_metadata(conn: &Connection) -> Result<(), Error> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let mut columns = tx.query("PRAGMA table_info(transactions)", ()).await?;
    let mut exists = false;
    while let Some(column) = columns.next().await? {
        if column.get::<String>(1)? == "confirmed_bitcoin_tx_index" {
            exists = true;
        }
    }
    drop(columns);
    if !exists {
        tx.execute(
            "ALTER TABLE transactions ADD COLUMN confirmed_bitcoin_tx_index INTEGER
             CHECK (confirmed_bitcoin_tx_index BETWEEN 0 AND 4294967295)",
            (),
        )
        .await?;
    }
    // Retained executors can clear or replace confirmation height using their
    // original SQL. Their writes must also invalidate this node-owned metadata.
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_transactions_confirmation_height
         ON transactions (confirmed_height) WHERE confirmed_height IS NOT NULL;
         CREATE TRIGGER IF NOT EXISTS invalidate_confirmation_position
         AFTER UPDATE OF confirmed_height ON transactions
         WHEN NEW.confirmed_height IS NULL OR NEW.confirmed_height IS NOT OLD.confirmed_height
         BEGIN
           UPDATE transactions SET confirmed_bitcoin_tx_index = NULL WHERE id = NEW.id;
         END;",
    )
    .await?;
    tx.commit().await
}

pub async fn set_confirmation_position(
    conn: &Connection,
    txid: &str,
    height: u64,
    raw_index: u32,
) -> Result<(), QueryError> {
    let changed = conn
        .execute(
            "UPDATE transactions SET confirmed_bitcoin_tx_index = ?
             WHERE txid = ? AND confirmed_height = ?",
            params![raw_index, txid, height],
        )
        .await?;
    if changed != 1 {
        return Err(QueryError::InvalidData(format!(
            "confirmation position requires transaction {txid} confirmed at height {height}"
        )));
    }
    Ok(())
}

pub async fn get_confirmation_position(
    conn: &Connection,
    txid: &str,
) -> Result<Option<u32>, QueryError> {
    let mut rows = conn
        .query(
            "SELECT confirmed_bitcoin_tx_index FROM transactions WHERE txid = ?",
            params![txid],
        )
        .await?;
    Ok(match rows.next().await? {
        Some(row) => row.get(0)?,
        None => None,
    })
}

#[derive(Debug, Serialize)]
pub struct ConfirmationBackfill {
    pub height: u64,
    pub block_hash: String,
    pub updated: u64,
    pub already_known: u64,
}

pub async fn backfill_confirmation_positions(
    conn: &Connection,
    height: u64,
    block: &Block,
) -> Result<ConfirmationBackfill, QueryError> {
    let witness_commitment_present = block.txdata.first().is_some_and(|tx| {
        tx.output.iter().any(|output| {
            let script = output.script_pubkey.as_bytes();
            script.len() >= 38 && script.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
        })
    });
    // rust-bitcoin accepts witness-free bodies before inspecting commitment
    // outputs. A committed SegWit block must include its witness data here.
    let stripped_witness = witness_commitment_present
        && block
            .txdata
            .iter()
            .all(|tx| tx.input.iter().all(|input| input.witness.is_empty()));
    if block.weight().to_wu() > 4_000_000
        || !block.txdata.first().is_some_and(|tx| tx.is_coinbase())
        || block.txdata.iter().skip(1).any(|tx| tx.is_coinbase())
        || !block.check_merkle_root()
        || !block.check_witness_commitment()
        || stripped_witness
    {
        return Err(QueryError::InvalidData(
            "invalid confirmation block body".into(),
        ));
    }
    let mut positions = HashMap::with_capacity(block.txdata.len());
    for (index, transaction) in block.txdata.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| {
            QueryError::InvalidData("Bitcoin transaction position exceeds u32".into())
        })?;
        if positions
            .insert(transaction.compute_txid().to_string(), index)
            .is_some()
        {
            return Err(QueryError::InvalidData(
                "duplicate transaction in confirmation block".into(),
            ));
        }
    }
    // Hold the writer lock while checking canonical identity and updating rows.
    // A reorg cannot replace the checked block between those two operations.
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let stored = select_block_at_height(&tx, height)
        .await?
        .ok_or_else(|| QueryError::InvalidData(format!("no canonical block at height {height}")))?;
    let hash = block.block_hash();
    if stored.hash != hash {
        return Err(QueryError::InvalidData(format!(
            "confirmation block differs from canonical height {height}"
        )));
    }
    let mut rows = tx
        .query(
            "SELECT txid, confirmed_bitcoin_tx_index FROM transactions
         WHERE confirmed_height = ? ORDER BY id",
            params![height],
        )
        .await?;
    let mut missing = Vec::new();
    let mut already_known = 0;
    while let Some(row) = rows.next().await? {
        let txid: String = row.get(0)?;
        let index = *positions.get(&txid).ok_or_else(|| {
            QueryError::InvalidData(format!(
                "confirmed transaction {txid} is absent from canonical block {hash}"
            ))
        })?;
        match row.get::<Option<u32>>(1)? {
            None => missing.push((txid, index)),
            Some(known) if known == index => already_known += 1,
            Some(_) => {
                return Err(QueryError::InvalidData(format!(
                    "stored confirmation position differs for {txid}"
                )));
            }
        }
    }
    drop(rows);
    for (txid, index) in &missing {
        set_confirmation_position(&tx, txid, height, *index).await?;
    }
    tx.commit().await?;
    Ok(ConfirmationBackfill {
        height,
        block_hash: hash.to_string(),
        updated: missing.len() as u64,
        already_known,
    })
}

#[cfg(test)]
mod tests;
