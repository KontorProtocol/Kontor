use bitcoin::BlockHash;
use futures_util::{Stream, stream};
use libsql::{Connection, de::from_row, named_params, params};
use thiserror::Error as ThisError;

use crate::{
    database::types::{ContractRow, PaginationMeta, TransactionCursor, TransactionRow},
    runtime::ContractAddress,
};

use super::types::{BlockRow, ContractStateRow};
use libsql::Transaction;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("LibSQL error: {0}")]
    LibSQL(#[from] libsql::Error),
    #[error("Row deserialization error: {0}")]
    RowDeserialization(#[from] serde::de::value::Error),
    #[error("Invalid cursor format")]
    InvalidCursor,
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

pub async fn select_block_by_height_or_hash(
    conn: &Connection,
    identifier: &str,
) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks WHERE height = ? OR hash = ?",
            params![identifier, identifier],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn select_block_at_height(
    conn: &Connection,
    height: i64,
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

const BASE_CONTRACT_STATE_QUERY: &str = include_str!("sql/base_contract_state_query.sql");

fn base_contract_state_query() -> String {
    BASE_CONTRACT_STATE_QUERY
        .replace("{{path_operator}}", "=")
        .replace("{{path_prefix}}", "")
        .replace("{{path_suffix}}", "")
}

pub async fn get_latest_contract_state(
    conn: &Connection,
    contract_id: i64,
    path: &str,
) -> Result<Option<ContractStateRow>, Error> {
    let mut rows = conn
        .query(
            &format!(
                r#"
                SELECT
                    id,
                    contract_id,
                    tx_id,
                    height,
                    path,
                    value,
                    deleted
                {}
                "#,
                base_contract_state_query()
            ),
            ((":contract_id", contract_id), (":path", path)),
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_latest_contract_state_value(
    conn: &Connection,
    contract_id: i64,
    path: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query(
            &format!(
                r#"
                SELECT value
                {}
                "#,
                base_contract_state_query()
            ),
            ((":contract_id", contract_id), (":path", path)),
        )
        .await?;

    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}

pub async fn delete_contract_state(
    conn: &Connection,
    height: i64,
    tx_id: i64,
    contract_id: i64,
    path: &str,
) -> Result<bool, Error> {
    Ok(
        match get_latest_contract_state(conn, contract_id, path).await? {
            Some(mut row) => {
                row.deleted = true;
                row.height = height;
                row.tx_id = tx_id;
                insert_contract_state(conn, row).await?;
                true
            }
            None => false,
        },
    )
}

fn base_exists_contract_state_query() -> String {
    BASE_CONTRACT_STATE_QUERY
        .replace("{{path_operator}}", "LIKE")
        .replace("{{path_prefix}}", "")
        .replace("{{path_suffix}}", "|| '%'")
}

pub async fn exists_contract_state(
    conn: &Connection,
    contract_id: i64,
    path: &str,
) -> Result<bool, Error> {
    let mut rows = conn
        .query(
            &format!(
                r#"
                SELECT value
                {}
                "#,
                base_exists_contract_state_query()
            ),
            ((":contract_id", contract_id), (":path", path)),
        )
        .await?;
    Ok(rows.next().await?.is_some())
}

const PATH_PREFIX_FILTER_QUERY: &str = include_str!("sql/path_prefix_filter_query.sql");

pub async fn path_prefix_filter_contract_state(
    conn: &Connection,
    contract_id: i64,
    path: String,
) -> Result<impl Stream<Item = Result<String, libsql::Error>> + Send + 'static, Error> {
    let rows = conn
        .query(
            PATH_PREFIX_FILTER_QUERY,
            ((":contract_id", contract_id), (":path", path.clone())),
        )
        .await?;
    let stream = stream::unfold(rows, |mut rows| async move {
        match rows.next().await {
            Ok(Some(row)) => match row.get::<String>(0) {
                Ok(segment) => Some((Ok(segment), rows)),
                Err(e) => Some((Err(e), rows)),
            },
            Ok(None) => None,
            Err(e) => Some((Err(e), rows)),
        }
    });

    Ok(stream)
}

fn base_matching_path_contract_state_query() -> String {
    BASE_CONTRACT_STATE_QUERY
        .replace("{{path_operator}}", "REGEXP")
        .replace("{{path_prefix}}", "")
        .replace("{{path_suffix}}", "")
}

pub async fn matching_path(
    conn: &Connection,
    contract_id: i64,
    regexp: &str,
) -> Result<Option<String>, Error> {
    let mut rows = conn
        .query(
            &format!(
                r#"
                SELECT path
                {}
                "#,
                base_matching_path_contract_state_query()
            ),
            ((":contract_id", contract_id), (":path", regexp)),
        )
        .await?;
    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}

pub async fn contract_has_state(conn: &Connection, contract_id: i64) -> Result<bool, Error> {
    let mut rows = conn
        .query(
            "SELECT COUNT(*) FROM contract_state WHERE contract_id = ?",
            params![contract_id],
        )
        .await?;
    Ok(rows
        .next()
        .await?
        .map(|r| r.get::<i64>(0))
        .transpose()?
        .expect("Query must return at least one row")
        > 0)
}

pub async fn insert_contract(conn: &Connection, row: ContractRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT OR IGNORE INTO contracts (name, height, tx_index, bytes) VALUES (?, ?, ?, ?)",
        params![row.name.clone(), row.height, row.tx_index, row.bytes],
    )
    .await?;
    Ok(get_contract_id_from_address(
        conn,
        &ContractAddress {
            name: row.name,
            height: row.height,
            tx_index: row.tx_index,
        },
    )
    .await?
    .expect("Contract was just inserted"))
}

pub async fn get_contract_bytes_by_address(
    conn: &Connection,
    address: &ContractAddress,
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query(
            r#"
        SELECT bytes FROM contracts
        WHERE name = :name
        AND height = :height
        AND tx_index = :tx_index
        "#,
            (
                (":name", address.name.clone()),
                (":height", address.height),
                (":tx_index", address.tx_index),
            ),
        )
        .await?;
    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}

pub async fn get_contract_id_from_address(
    conn: &Connection,
    address: &ContractAddress,
) -> Result<Option<i64>, Error> {
    let mut rows = conn
        .query(
            r#"
        SELECT id FROM contracts
        WHERE name = :name
        AND height = :height
        AND tx_index = :tx_index
        "#,
            (
                (":name", address.name.clone()),
                (":height", address.height),
                (":tx_index", address.tx_index),
            ),
        )
        .await?;
    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}

pub async fn get_contract_bytes_by_id(
    conn: &Connection,
    id: i64,
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query("SELECT bytes FROM contracts WHERE id = ?", params![id])
        .await?;
    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}

pub async fn insert_transaction(conn: &Connection, row: TransactionRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT INTO transactions (height, txid, tx_index) VALUES (?, ?, ?)",
        params![row.height, row.txid, row.tx_index],
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
            "SELECT id, txid, height, tx_index FROM transactions WHERE id = ?",
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
            "SELECT id, txid, height, tx_index FROM transactions WHERE txid = ?",
            params![txid],
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_transactions_at_height(
    conn: &Connection,
    height: i64,
) -> Result<Vec<TransactionRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT id, txid, height, tx_index FROM transactions WHERE height = ?",
            params![height],
        )
        .await?;

    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push(from_row(&row)?);
    }
    Ok(results)
}

pub async fn get_transactions_paginated(
    tx: &Transaction,
    height: Option<i64>,
    cursor: Option<String>,
    offset: Option<i64>,
    limit: i64,
) -> Result<(Vec<TransactionRow>, PaginationMeta), Error> {
    let mut where_clauses = Vec::new();

    // Build height filter
    if height.is_some() {
        where_clauses.push("t.height = :height");
    }

    let cursor_decoded = cursor
        .as_ref()
        .map(|c| TransactionCursor::decode(c).map_err(|_| Error::InvalidCursor))
        .transpose()?;

    if cursor_decoded.is_some() {
        where_clauses.push("(t.height, t.tx_index) < (:cursor_height, :cursor_tx_index)");
    }

    let (cursor_height, cursor_tx_index) = cursor_decoded
        .as_ref()
        .map_or((None, None), |c| (Some(c.height), Some(c.tx_index)));

    // Build WHERE clause
    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    // Get total count first
    let count_query = format!("SELECT COUNT(*) FROM transactions t {}", where_sql);
    let mut count_rows = tx
        .query(
            &count_query,
            named_params! {
                ":height": height,
                ":cursor_height": cursor_height,
                ":cursor_tx_index": cursor_tx_index,
            },
        )
        .await?;

    let total_count = count_rows
        .next()
        .await?
        .map_or(0, |r| r.get::<i64>(0).unwrap_or(0));

    // Build OFFSET clause
    let offset_clause = cursor
        .is_none()
        .then_some(offset)
        .flatten()
        .map_or(String::from(""), |_| "OFFSET :offset".to_string());

    let query = format!(
        r#"
         SELECT t.txid, t.height, t.tx_index
         FROM transactions t
         {where_sql}
         ORDER BY t.height DESC, t.tx_index DESC
         LIMIT :limit
         {offset_clause}
         "#,
        where_sql = where_sql,
        offset_clause = offset_clause
    );

    // Execute main query with ALL named parameters
    let mut rows = tx
        .query(
            &query,
            named_params! {
                ":height": height,
                ":cursor_height": cursor_height,
                ":cursor_tx_index": cursor_tx_index,
                ":offset": offset,
                ":limit": (limit + 1),
            },
        )
        .await?;

    let mut transactions: Vec<TransactionRow> = Vec::new();
    while let Some(row) = rows.next().await? {
        transactions.push(from_row(&row)?);
    }

    let has_more = transactions.len() > limit as usize;

    if has_more {
        transactions.pop();
    }

    let next_cursor = transactions
        .last()
        .filter(|_| offset.is_none() && has_more)
        .map(|last_tx| {
            TransactionCursor {
                height: last_tx.height,
                tx_index: last_tx.tx_index,
            }
            .encode()
        });

    let next_offset = (cursor.is_none() && has_more).then(|| offset.unwrap_or(0) + limit);

    let pagination = PaginationMeta {
        next_cursor,
        next_offset,
        has_more,
        total_count,
    };

    Ok((transactions, pagination))
}
