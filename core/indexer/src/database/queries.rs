use bitcoin::BlockHash;
use futures_util::{Stream, stream};
use libsql::{Connection, de::from_row, named_params, params};
use thiserror::Error as ThisError;

use crate::{
    database::types::{
        CheckpointRow, ContractListRow, ContractResultRow, ContractRow, OpResultId, PaginationMeta,
        TransactionCursor, TransactionRow,
    },
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
    #[error("Out of fuel")]
    OutOfFuel,
}

pub async fn insert_block(conn: &Connection, block: BlockRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT OR REPLACE INTO blocks (height, hash) VALUES (?, ?)",
        (block.height, block.hash.to_string()),
    )
    .await?;
    Ok(conn.last_insert_rowid())
}

pub async fn insert_processed_block(conn: &Connection, block: BlockRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT OR REPLACE INTO blocks (height, hash, processed) VALUES (?, ?, 1)",
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
            "SELECT height, hash FROM blocks WHERE processed = 1 ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn set_block_processed(conn: &Connection, height: i64) -> Result<(), Error> {
    conn.execute(
        "UPDATE blocks SET processed = 1 WHERE height = ?",
        params![height],
    )
    .await?;
    Ok(())
}

pub async fn delete_unprocessed_blocks(conn: &Connection) -> Result<u64, Error> {
    Ok(conn
        .execute("DELETE FROM blocks WHERE processed = 0", params![])
        .await?)
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

pub async fn select_processed_block_at_height(
    conn: &Connection,
    height: i64,
) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks WHERE height = ? AND processed = 1",
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

pub async fn insert_contract_state(conn: &Connection, row: ContractStateRow) -> Result<u64, Error> {
    Ok(conn
        .execute(
            r#"
            INSERT OR REPLACE INTO contract_state (
                contract_id,
                height,
                tx_index,
                size,
                path,
                value,
                deleted
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
            params![
                row.contract_id,
                row.height,
                row.tx_index,
                row.size(),
                row.path,
                row.value,
                row.deleted
            ],
        )
        .await?)
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
                    contract_id,
                    height,
                    tx_index,
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
    fuel: u64,
    contract_id: i64,
    path: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query(
            &format!(
                r#"
                SELECT
                  CASE
                    WHEN size <= :fuel THEN value
                    ELSE null
                  END AS value
                {}
                "#,
                base_contract_state_query()
            ),
            (
                (":contract_id", contract_id),
                (":path", path),
                (":fuel", fuel),
            ),
        )
        .await?;

    let row = rows.next().await?;
    if let Some(row) = row {
        return match row.get::<Option<Vec<u8>>>(0)? {
            Some(v) => Ok(Some(v)),
            None => Err(Error::OutOfFuel),
        };
    }
    Ok(None)
}

pub async fn delete_contract_state(
    conn: &Connection,
    height: i64,
    tx_index: i64,
    contract_id: i64,
    path: &str,
) -> Result<bool, Error> {
    Ok(
        match get_latest_contract_state(conn, contract_id, path).await? {
            Some(mut row) => {
                row.deleted = true;
                row.height = height;
                row.tx_index = tx_index;
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
                SELECT 1
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

const MATCHING_PATH_CONTRACT_STATE_QUERY: &str = include_str!("sql/matching_path_query.sql");

pub async fn matching_path(
    conn: &Connection,
    contract_id: i64,
    base_path: &str,
    regexp: &str,
) -> Result<Option<String>, Error> {
    let mut rows = conn
        .query(
            MATCHING_PATH_CONTRACT_STATE_QUERY,
            (
                (":contract_id", contract_id),
                (":base_path", base_path),
                (":path", regexp),
            ),
        )
        .await?;
    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}

const DELETE_MATCHING_PATHS_QUERY: &str = include_str!("sql/delete_matching_paths.sql");

pub async fn delete_matching_paths(
    conn: &Connection,
    contract_id: i64,
    height: i64,
    path_regexp: &str,
) -> Result<u64, Error> {
    Ok(conn
        .execute(
            DELETE_MATCHING_PATHS_QUERY,
            (
                (":contract_id", contract_id),
                (":height", height),
                (":path_regexp", path_regexp),
            ),
        )
        .await?)
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
        r#"
            INSERT OR REPLACE INTO contracts (
                id,
                name,
                height,
                tx_index,
                size,
                bytes
            ) SELECT
                COALESCE(MAX(id), 1) + 1,
                ?,
                ?,
                ?,
                ?,
                ?
            FROM contracts
            "#,
        params![
            row.name.clone(),
            row.height,
            row.tx_index,
            row.size(),
            row.bytes
        ],
    )
    .await?;

    Ok(conn.last_insert_rowid())
}

pub async fn get_contracts(conn: &Connection) -> Result<Vec<ContractListRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT id, name, height, tx_index, size FROM contracts ORDER BY id DESC",
            params![],
        )
        .await?;
    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push(from_row(&row)?);
    }
    Ok(results)
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

pub async fn get_contract_address_from_id(
    conn: &Connection,
    id: i64,
) -> Result<Option<ContractAddress>, Error> {
    let mut rows = conn
        .query(
            r#"
        SELECT name, height, tx_index FROM contracts
        WHERE id = ?
        "#,
            params![id],
        )
        .await?;

    let row = rows.next().await?;
    if let Some(row) = row {
        let name = row.get(0)?;
        let height = row.get(1)?;
        let tx_index = row.get(2)?;
        Ok(Some(ContractAddress {
            name,
            height,
            tx_index,
        }))
    } else {
        Ok(None)
    }
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

pub async fn insert_transaction(conn: &Connection, row: TransactionRow) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO transactions (height, txid, tx_index) VALUES (?, ?, ?)",
        params![row.height, row.txid, row.tx_index],
    )
    .await?;
    Ok(())
}

pub async fn get_transaction_by_txid(
    conn: &Connection,
    txid: &str,
) -> Result<Option<TransactionRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT txid, height, tx_index FROM transactions WHERE txid = ?",
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
            "SELECT txid, height, tx_index FROM transactions WHERE height = ?",
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
        where_clauses.push("(t.height, t.tx_index) < (:cursor_height, :cursor_index)");
    }

    let (cursor_height, cursor_index) = cursor_decoded
        .as_ref()
        .map_or((None, None), |c| (Some(c.height), Some(c.index)));

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
                ":cursor_index": cursor_index,
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
                ":cursor_index": cursor_index,
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
                index: last_tx.tx_index,
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

pub async fn get_op_result(
    conn: &Connection,
    op_result_id: &OpResultId,
) -> Result<Option<ContractResultRow>, Error> {
    let mut rows = conn
        .query(
            r#"
            SELECT
                c.contract_id,
                c.func_name,
                c.height,
                c.tx_index,
                c.input_index,
                c.op_index,
                c.result_index,
                c.gas,
                c.value
            FROM contract_results c
            JOIN transactions t ON c.height = t.height AND c.tx_index = t.tx_index
            WHERE t.txid = :txid AND c.input_index = :input_index AND c.op_index = :op_index
            ORDER BY c.result_index DESC
            LIMIT 1
            "#,
            named_params! {
                ":txid": op_result_id.txid.clone(),
                ":input_index": op_result_id.input_index,
                ":op_index": op_result_id.op_index,
            },
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_contract_result(
    conn: &Connection,
    height: i64,
    tx_index: i64,
    input_index: i64,
    op_index: i64,
    result_index: i64,
) -> Result<Option<ContractResultRow>, Error> {
    let mut rows = conn
        .query(
            r#"
            SELECT
                contract_id,
                func_name,
                height,
                tx_index,
                input_index,
                op_index,
                result_index,
                gas,
                value
            FROM contract_results
            WHERE height = :height
              AND tx_index = :tx_index
              AND input_index = :input_index
              AND op_index = :op_index
              AND result_index = :result_index
            "#,
            named_params! {
                ":height": height,
                ":tx_index": tx_index,
                ":input_index": input_index,
                ":op_index": op_index,
                ":result_index": result_index,
            },
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn insert_contract_result(
    conn: &Connection,
    row: ContractResultRow,
) -> Result<i64, Error> {
    conn.execute(
        r#"
            INSERT OR REPLACE INTO contract_results (
                contract_id,
                size,
                func_name,
                height,
                tx_index,
                input_index,
                op_index,
                result_index,
                gas,
                value
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
        params![
            row.contract_id,
            row.size(),
            row.func_name,
            row.height,
            row.tx_index,
            row.input_index,
            row.op_index,
            row.result_index,
            row.gas,
            row.value
        ],
    )
    .await?;

    Ok(conn.last_insert_rowid())
}

pub async fn get_checkpoint_by_id(
    conn: &libsql::Connection,
    id: i64,
) -> Result<Option<CheckpointRow>, Error> {
    let mut row = conn
        .query(
            "SELECT id, height, hash FROM checkpoints WHERE id = ?",
            params![id],
        )
        .await?;
    Ok(row.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_checkpoint_latest(
    conn: &libsql::Connection,
) -> Result<Option<CheckpointRow>, Error> {
    let mut row = conn
        .query(
            "SELECT id, height, hash FROM checkpoints ORDER BY id DESC LIMIT 1",
            params![],
        )
        .await?;
    Ok(row.next().await?.map(|r| from_row(&r)).transpose()?)
}
