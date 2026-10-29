use libsql::{Connection, Error, TransactionBehavior, params};

use super::queries::Error as QueryError;

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
        "CREATE TRIGGER IF NOT EXISTS invalidate_confirmation_position
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

#[cfg(test)]
mod tests;
