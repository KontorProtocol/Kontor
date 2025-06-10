// queries.rs - All pagination queries
use bitcoin::BlockHash;
use libsql::{Connection, de::from_row, params};
use thiserror::Error as ThisError;

use super::types::{BlockCursor, TransactionCursor};
use crate::database::types::{BlockRow, ContractStateRow, TransactionRow};

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("LibSQL error: {0}")]
    LibSQL(#[from] libsql::Error),
    #[error("Row deserialization error: {0}")]
    RowDeserialization(#[from] serde::de::value::Error),
}

async fn collect_rows<T>(mut rows: libsql::Rows) -> Result<Vec<T>, Error>
where
    T: for<'de> serde::Deserialize<'de>,
{
    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push(from_row(&row)?);
    }
    Ok(results)
}

async fn count_table(conn: &Connection, table: &str) -> Result<u64, Error> {
    let query = format!("SELECT COUNT(*) as count FROM {}", table);
    let mut rows = conn.query(&query, params![]).await?;

    let row = rows
        .next()
        .await?
        .ok_or_else(|| Error::LibSQL(libsql::Error::QueryReturnedNoRows))?;
    Ok(row.get::<u64>(0)?)
}

async fn get_latest_height(conn: &Connection) -> Result<u64, Error> {
    let mut rows = conn
        .query(
            "SELECT height FROM blocks ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;

    match rows.next().await? {
        Some(row) => Ok(row.get::<u64>(0)?),
        None => Ok(0),
    }
}

// OFFSET PAGINATION QUERIES
pub async fn select_blocks_paginated(
    conn: &Connection,
    offset: u64,
    limit: u64,
) -> Result<Vec<BlockRow>, Error> {
    let rows = conn
        .query(
            "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT ? OFFSET ?",
            params![limit, offset],
        )
        .await?;

    collect_rows(rows).await
}

pub async fn count_blocks(conn: &Connection) -> Result<u64, Error> {
    count_table(conn, "blocks").await
}

pub async fn select_transactions_paginated(
    conn: &Connection,
    offset: u64,
    limit: u64,
) -> Result<Vec<TransactionRow>, Error> {
    let rows = conn
        .query(
            "SELECT id, txid, height FROM transactions ORDER BY height DESC, id DESC LIMIT ? OFFSET ?",
            params![limit, offset],
        )
        .await?;

    collect_rows(rows).await
}

pub async fn count_transactions(conn: &Connection) -> Result<u64, Error> {
    count_table(conn, "transactions").await
}

pub async fn select_blocks_cursor(
    conn: &Connection,
    cursor: Option<BlockCursor>,
    limit: u64,
) -> Result<(Vec<BlockRow>, u64), Error> {
    // Validate cursor if provided
    if let Some(ref cursor) = cursor {
        let height_exists = conn
            .query(
                "SELECT 1 FROM blocks WHERE height = ?",
                params![cursor.height],
            )
            .await?
            .next()
            .await?
            .is_some();

        if !height_exists {
            // Height was rolled back - start from latest
            return Box::pin(select_blocks_cursor(conn, None, limit)).await;
        }
    }

    let results = match cursor {
        None => {
            // Get latest blocks - no cursor, so no WHERE clause
            let rows = conn
                .query(
                    "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT ?",
                    params![limit + 1],
                )
                .await?;
            collect_rows(rows).await?
        }
        Some(cursor) => {
            // Get blocks before cursor height
            let rows = conn
                .query(
                    "SELECT height, hash FROM blocks WHERE height < ? ORDER BY height DESC LIMIT ?",
                    params![cursor.height, limit + 1],
                )
                .await?;
            collect_rows(rows).await?
        }
    };

    let latest_height = get_latest_height(conn).await?;
    Ok((results, latest_height))
}

pub async fn select_transactions_cursor(
    conn: &Connection,
    cursor: Option<TransactionCursor>,
    limit: u64,
) -> Result<(Vec<TransactionRow>, u64), Error> {
    // Validate cursor if provided
    if let Some(ref cursor) = cursor {
        let height_exists = conn
            .query(
                "SELECT 1 FROM blocks WHERE height = ?",
                params![cursor.height],
            )
            .await?
            .next()
            .await?
            .is_some();

        if !height_exists {
            // Height was rolled back - start from latest
            return Box::pin(select_transactions_cursor(conn, None, limit)).await;
        }
    }

    let results = match cursor {
        None => {
            // Get latest transactions - no cursor, so no WHERE clause
            let rows = conn
                .query(
                    "SELECT id, txid, height FROM transactions ORDER BY height DESC, id DESC LIMIT ?",
                    params![limit + 1],
                )
                .await?;
            collect_rows(rows).await?
        }
        Some(cursor) => {
            // Get transactions before cursor
            let rows = conn
                .query(
                    "SELECT id, txid, height FROM transactions 
                     WHERE (height < ? OR (height = ? AND id < ?)) 
                     ORDER BY height DESC, id DESC LIMIT ?",
                    params![cursor.height, cursor.height, cursor.id, limit + 1],
                )
                .await?;
            collect_rows(rows).await?
        }
    };

    let latest_height = get_latest_height(conn).await?;
    Ok((results, latest_height))
}

pub async fn insert_block(conn: &Connection, block: BlockRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT OR REPLACE INTO blocks (height, hash) VALUES (?, ?)",
        (block.height, block.hash.to_string()),
    )
    .await?;
    Ok(conn.last_insert_rowid())
}

pub async fn rollback_to_height(conn: &Connection, height: u64) -> Result<u64, Error> {
    let num_rows = conn
        .execute("DELETE FROM blocks WHERE height > ?", [height])
        .await?;

    Ok(num_rows)
}

pub async fn select_block_latest(conn: &Connection) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn select_block_at_height(
    conn: &Connection,
    height: u64,
) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks WHERE height = ?",
            params![height],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn select_block_with_hash(
    conn: &Connection,
    hash: &BlockHash,
) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks WHERE hash = ?",
            params![hash.to_string()],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn insert_contract_state(conn: &Connection, row: ContractStateRow) -> Result<i64, Error> {
    conn.execute(
        r#"
            INSERT OR REPLACE INTO contract_state (
                contract_id,
                tx_id,
                height,
                path,
                value,
                deleted
            ) VALUES (?, ?, ?, ?, ?, ?)
        "#,
        params![
            row.contract_id,
            row.tx_id,
            row.height,
            row.path,
            row.value,
            row.deleted
        ],
    )
    .await?;

    Ok(conn.last_insert_rowid())
}

pub async fn get_latest_contract_state(
    conn: &Connection,
    contract_id: &str,
    path: &str,
) -> Result<Option<ContractStateRow>, Error> {
    let mut rows = conn
        .query(
            r#"
                SELECT
                    id,
                    contract_id,
                    tx_id,
                    height,
                    path,
                    value,
                    deleted
                FROM contract_state
                WHERE contract_id = ? AND path = ?
                ORDER BY height DESC
                LIMIT 1
            "#,
            params![contract_id, path],
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn insert_transaction(conn: &Connection, row: TransactionRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT INTO transactions (height, txid) VALUES (?, ?)",
        params![row.height, row.txid],
    )
    .await?;

    Ok(conn.last_insert_rowid())
}

pub async fn get_transaction_by_id(
    conn: &Connection,
    id: i64,
) -> Result<Option<TransactionRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT id, height, txid FROM transactions WHERE id = ?",
            params![id],
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_transaction_by_txid(
    conn: &Connection,
    txid: &str,
) -> Result<Option<TransactionRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT id, txid, height FROM transactions WHERE txid = ?",
            params![txid],
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_transactions_at_height(
    conn: &Connection,
    height: u64,
) -> Result<Vec<TransactionRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT id, txid, height FROM transactions WHERE height = ?",
            params![height],
        )
        .await?;

    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push(from_row(&row)?);
    }
    Ok(results)
}
