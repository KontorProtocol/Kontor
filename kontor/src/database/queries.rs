use anyhow::Result;
use bitcoin::BlockHash;
use libsql::{Connection, de::from_row, params};

use super::types::{BlockRow, ContractStateRow};

pub async fn insert_block(conn: &Connection, block: BlockRow) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO blocks (height, hash) VALUES (?, ?)",
        (block.height, block.hash.to_string()),
    )
    .await?;
    Ok(())
}

pub async fn rollback_to_height(conn: &Connection, height: u64) -> Result<u64> {
    // CASCADE
    let num_rows = conn
        .execute("DELETE FROM blocks WHERE height > ?", [height])
        .await?;

    Ok(num_rows)
}

pub async fn select_block_latest(conn: &Connection) -> Result<Option<BlockRow>> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;
    Ok(match rows.next().await? {
        Some(row) => Some(from_row::<BlockRow>(&row)?),
        None => None,
    })
}

pub async fn select_block_at_height(conn: &Connection, height: u64) -> Result<Option<BlockRow>> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks WHERE height = ?",
            params![height],
        )
        .await?;
    Ok(match rows.next().await? {
        Some(row) => Some(from_row::<BlockRow>(&row)?),
        None => None,
    })
}

pub async fn select_block_with_hash(
    conn: &Connection,
    hash: &BlockHash,
) -> Result<Option<BlockRow>> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks WHERE hash = ?",
            params![hash.to_string()],
        )
        .await?;
    Ok(match rows.next().await? {
        Some(row) => Some(from_row::<BlockRow>(&row)?),
        None => None,
    })
}

// Contract state
pub async fn insert_contract_state(
    conn: &Connection,
    contract_id: &str,
    tx_id: i64,
    height: u64,
    path: &str,
    value: Option<Vec<u8>>,
    deleted: bool,
) -> Result<i64> {
    conn.execute(
        "INSERT OR REPLACE INTO contract_state (contract_id, tx_id, height, path, value, deleted)
         VALUES (?, ?, ?, ?, ?, ?)",
        params![contract_id, tx_id, height, path, value, deleted],
    )
    .await?;

    Ok(conn.last_insert_rowid())
}

pub async fn get_latest_contract_state(
    conn: &Connection,
    contract_id: &str,
    path: &str,
) -> Result<Option<ContractStateRow>> {
    // rust template strings
    let mut rows = conn
        .query(
            r#"
SELECT id, contract_id, tx_id, height, path, value, deleted 
FROM contract_state WHERE contract_id = ? AND path = ? 
ORDER BY height DESC LIMIT 1
"#,
            params![contract_id, path],
        )
        .await?;

    if let Some(row) = rows.next().await? {
        Ok(Some(ContractStateRow {
            id: Some(row.get(0)?),
            contract_id: row.get(1)?,
            tx_id: row.get(2)?,
            height: row.get(3)?,
            path: row.get(4)?,
            value: row.get(5)?,
            deleted: row.get(6)?,
        }))
    } else {
        Ok(None)
    }
}

// MAKE QUERY FROM DOC

// do we want this?
// pub async fn get_contract_state_at_height(
//     conn: &Connection,
//     contract_id: &str,
//     height: u64,
// ) -> Result<Option<ContractStateRow>> {
//     // DOUBLE CHECK NOTION DOC -- finding height exactly then getting rest of row
//     // format these
//     let mut rows = conn
//         .query(
//             "SELECT id, contract_id, tx_id, height, path, value, deleted
//          FROM contract_state
//          WHERE contract_id = ? AND height <= ? // deleted is false
//          HAVING height = MAX(height)",
//             params![contract_id, height],
//         )
//         .await?;

//     if let Some(row) = rows.next().await? {
//         Ok(Some(ContractStateRow {
//             id: Some(row.get(0)?),
//             contract_id: row.get(1)?,
//             tx_id: row.get(2)?,
//             height: row.get(3)?,
//             path: row.get(4)?,
//             value: row.get(5)?,
//             deleted: row.get(6)?,
//         }))
//     } else {
//         Ok(None)
//     }
// }

// Transactions
pub async fn insert_transaction(conn: &Connection, height: u64, txid: &str) -> Result<i64> {
    conn.execute(
        "INSERT INTO transactions (height, txid) VALUES (?, ?)",
        params![height, txid],
    )
    .await?;

    Ok(conn.last_insert_rowid())
}

pub async fn get_transaction_by_id(
    conn: &Connection,
    id: i64,
) -> Result<Option<(i64, u64, String)>> {
    let mut rows = conn
        .query(
            "SELECT id, height, txid FROM transactions WHERE id = ?",
            params![id],
        )
        .await?;

    if let Some(row) = rows.next().await? {
        Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?)))
    } else {
        Ok(None)
    }
}

pub async fn get_transaction_by_txid(
    conn: &Connection,
    txid: &str,
) -> Result<Option<(i64, u64, String)>> {
    let mut rows = conn
        .query(
            "SELECT id, height, txid FROM transactions WHERE txid = ?",
            params![txid],
        )
        .await?;

    if let Some(row) = rows.next().await? {
        Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?)))
    } else {
        Ok(None)
    }
}

// do we want this?
pub async fn get_transactions_at_height(
    conn: &Connection,
    height: u64,
) -> Result<Vec<(i64, String)>> {
    let mut rows = conn
        .query(
            "SELECT id, txid FROM transactions WHERE height = ?",
            params![height],
        )
        .await?;

    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push((row.get(0)?, row.get(1)?));
    }

    Ok(results)
}
