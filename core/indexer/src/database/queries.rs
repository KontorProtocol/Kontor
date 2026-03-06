use bitcoin::BlockHash;
use futures_util::{Stream, stream};
use indexer_types::{BlockRow, ContractListRow, PaginationMeta, TransactionRow};
use libsql::{Connection, Value, de::from_row, named_params, params};
use serde::de::DeserializeOwned;
use thiserror::Error as ThisError;

use crate::{
    database::types::{
        BlockQuery, CheckpointRow, ContractResultPublicRow, ContractResultRow, ContractRow,
        FileMetadataRow, HasRowId, OpResultId, OrderDirection, ResultQuery, TransactionQuery,
    },
    runtime::ContractAddress,
};

use super::types::ContractStateRow;

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
    #[error("Contract not found: {0}")]
    ContractNotFound(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub async fn insert_block(conn: &Connection, block: BlockRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT OR REPLACE INTO blocks (height, hash, relevant) VALUES (?, ?, ?)",
        (block.height, block.hash.to_string(), block.relevant),
    )
    .await?;
    Ok(conn.last_insert_rowid())
}

pub async fn insert_processed_block(conn: &Connection, block: BlockRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT OR REPLACE INTO blocks (height, hash, relevant, processed) VALUES (?, ?, ?, 1)",
        (block.height, block.hash.to_string(), block.relevant),
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
            "SELECT height, hash, relevant FROM blocks WHERE processed = 1 ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn select_recent_blocks(conn: &Connection, limit: i64) -> Result<Vec<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash, relevant FROM blocks WHERE processed = 1 ORDER BY height DESC LIMIT ?",
            params![limit],
        )
        .await?;
    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push(from_row(&row)?);
    }
    Ok(results)
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

pub async fn select_processed_block_by_height_or_hash(
    conn: &Connection,
    identifier: &str,
) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash, relevant FROM blocks WHERE (height = ? OR hash = ?) AND processed = 1",
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
            "SELECT height, hash, relevant FROM blocks WHERE height = ?",
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
            "SELECT height, hash, relevant FROM blocks WHERE height = ? AND processed = 1",
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
            "SELECT height, hash, relevant FROM blocks WHERE hash = ?",
            params![hash.to_string()],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_blocks_paginated(
    conn: &Connection,
    query: BlockQuery,
) -> Result<(Vec<BlockRow>, PaginationMeta), Error> {
    let var = "b";
    let mut where_clauses = vec!["processed = 1".to_string()];
    let mut params = vec![];
    if let Some(relevant) = query.relevant {
        where_clauses.push("b.relevant = :relevant".to_string());
        params.push((":relevant".to_string(), Value::from(relevant)));
    }
    get_paginated(
        conn,
        var,
        "b.height, b.hash, b.relevant",
        &format!("blocks {}", var),
        where_clauses,
        params,
        query.order,
        query.cursor,
        query.offset,
        query.limit,
    )
    .await
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
    tx_index: Option<i64>,
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
                name,
                height,
                tx_index,
                size,
                bytes
            ) VALUES (
                ?,
                ?,
                ?,
                ?,
                ?
            )
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

pub fn filter_cursor(cursor: Option<i64>) -> Option<i64> {
    cursor.filter(|&c| c >= 0)
}

pub fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.map_or(20, |l| l.clamp(0, 1000))
}

pub async fn get_paginated<T>(
    conn: &Connection,
    var: &str,
    selects: &str,
    from: &str,
    mut where_clauses: Vec<String>,
    mut params: Vec<(String, Value)>,
    order: OrderDirection,
    cursor: Option<i64>,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<(Vec<T>, PaginationMeta), Error>
where
    T: DeserializeOwned + HasRowId,
{
    let cursor = filter_cursor(cursor);
    let limit = clamp_limit(limit);

    if let Some(cursor) = cursor {
        where_clauses.push(format!(
            "{}.{} {} :cursor",
            var,
            T::id_name(),
            if order == OrderDirection::Desc {
                "<"
            } else {
                ">"
            }
        ));
        params.push((":cursor".to_string(), Value::Integer(cursor)));
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    // Get total count first
    let total_count = conn
        .query(
            &format!(
                "SELECT COUNT(DISTINCT {}.{}) FROM {} {}",
                var,
                T::id_name(),
                from,
                where_sql
            ),
            params.clone(),
        )
        .await?
        .next()
        .await?
        .map_or(0, |r| r.get::<i64>(0).unwrap_or(0));

    // Build OFFSET clause
    let mut offset_clause = "";
    if cursor.is_none()
        && let Some(offset) = offset
    {
        offset_clause = "OFFSET :offset";
        params.push((":offset".to_string(), Value::Integer(offset)));
    }

    params.push((":limit".to_string(), Value::Integer(limit + 1)));

    // Execute main query with ALL named parameters
    let mut rows = conn
        .query(
            &format!(
                r#"
                SELECT {selects}
                FROM {from}
                {where_sql}
                ORDER BY {var}.{id_name} {order}
                LIMIT :limit
                {offset_clause}
                "#,
                selects = selects,
                from = from,
                where_sql = where_sql,
                var = var,
                id_name = T::id_name(),
                order = order,
                offset_clause = offset_clause
            ),
            params,
        )
        .await?;

    let mut results: Vec<T> = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push(from_row(&row)?);
    }

    let has_more = results.len() > limit as usize;

    if has_more {
        results.pop();
    }

    let next_cursor = results
        .last()
        .filter(|_| offset.is_none())
        .map(|last_tx| last_tx.id());

    let next_offset = cursor
        .is_none()
        .then(|| offset.unwrap_or(0) + results.len() as i64);

    let pagination = PaginationMeta {
        next_cursor,
        next_offset,
        has_more,
        total_count,
    };

    Ok((results, pagination))
}

pub async fn get_transactions_paginated(
    conn: &Connection,
    query: TransactionQuery,
) -> Result<(Vec<TransactionRow>, PaginationMeta), Error> {
    let mut params: Vec<(String, Value)> = Vec::new();
    let var = "t";
    let mut selects = "t.id, t.txid, t.height, t.tx_index".to_string();
    let mut from = "transactions t JOIN blocks b USING (height)".to_string();
    let mut where_clauses = vec!["b.processed = 1".to_string()];
    if let Some(address) = &query.contract {
        let contract_id = get_contract_id_from_address(conn, address)
            .await?
            .ok_or(Error::ContractNotFound(address.to_string()))?;
        selects = format!("DISTINCT {}", selects);
        from = format!("{} JOIN contract_state c USING (height, tx_index)", from);
        where_clauses.push(format!("c.contract_id = {}", contract_id));
    }

    if let Some(height) = query.height {
        where_clauses.push("t.height = :height".to_string());
        params.push((":height".to_string(), Value::Integer(height)));
    }

    get_paginated(
        conn,
        var,
        &selects,
        &from,
        where_clauses,
        params,
        query.order,
        query.cursor,
        query.offset,
        query.limit,
    )
    .await
}

pub async fn get_results_paginated(
    conn: &Connection,
    query: ResultQuery,
) -> Result<(Vec<ContractResultPublicRow>, PaginationMeta), Error> {
    let mut params: Vec<(String, Value)> = Vec::new();
    let var = "r";
    let selects = r#"
        DISTINCT
        r.id,
        r.height,
        r.tx_index,
        r.input_index,
        r.op_index,
        r.result_index,
        r.func,
        r.gas,
        r.value,
        c.name as contract_name,
        c.height as contract_height,
        c.tx_index as contract_tx_index,
        t.txid
    "#;
    let from = r#"
        contract_results r
        JOIN blocks b USING (height)
        LEFT JOIN transactions t ON r.height = t.height AND r.tx_index = t.tx_index
        JOIN contracts c ON r.contract_id = c.id
    "#;
    let mut where_clauses = vec!["b.processed = 1".to_string()];
    if let Some(address) = &query.contract {
        let contract_id = get_contract_id_from_address(conn, address)
            .await?
            .ok_or(Error::ContractNotFound(address.to_string()))?;
        where_clauses.push(format!("r.contract_id = {}", contract_id));
    }

    if let Some(func) = &query.func {
        where_clauses.push(format!("r.func = '{}'", func));
    }

    if let Some(height) = query.height {
        where_clauses.push("r.height = :height".to_string());
        params.push((":height".to_string(), Value::Integer(height)));
    }

    if let Some(height) = query.start_height {
        where_clauses.push(format!(
            "r.height {} :start_height",
            if query.order == OrderDirection::Desc {
                "<="
            } else {
                ">="
            }
        ));
        params.push((":start_height".to_string(), Value::Integer(height)));
    }

    get_paginated(
        conn,
        var,
        selects,
        from,
        where_clauses,
        params,
        query.order,
        query.cursor,
        query.offset,
        query.limit,
    )
    .await
}

pub async fn get_op_result(
    conn: &Connection,
    op_result_id: &OpResultId,
) -> Result<Option<ContractResultPublicRow>, Error> {
    let mut rows = conn
        .query(
            r#"
            SELECT
                r.id,
                r.func,
                r.height,
                r.tx_index,
                r.input_index,
                r.op_index,
                r.result_index,
                r.gas,
                r.value,
                c.name as contract_name,
                c.height as contract_height,
                c.tx_index as contract_tx_index,
                t.txid
            FROM contract_results r
            JOIN blocks b USING (height)
            LEFT JOIN transactions t ON r.height = t.height AND r.tx_index = t.tx_index
            JOIN contracts c ON r.contract_id = c.id
            WHERE b.processed = 1 AND t.txid = :txid AND r.input_index = :input_index AND r.op_index = :op_index
            ORDER BY r.result_index DESC
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
    tx_index: Option<i64>,
    input_index: Option<i64>,
    op_index: Option<i64>,
    result_index: i64,
) -> Result<Option<ContractResultRow>, Error> {
    let mut rows = conn
        .query(
            r#"
            SELECT
                id,
                contract_id,
                func,
                height,
                tx_index,
                input_index,
                op_index,
                result_index,
                gas,
                value
            FROM contract_results
            WHERE height = :height
              AND tx_index IS :tx_index
              AND input_index IS :input_index
              AND op_index IS :op_index
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
                func,
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
            row.func,
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

pub async fn get_checkpoint_by_height(
    conn: &libsql::Connection,
    height: i64,
) -> Result<Option<CheckpointRow>, Error> {
    let mut row = conn
        .query(
            "SELECT height, hash FROM checkpoints WHERE height = ?",
            params![height],
        )
        .await?;
    Ok(row.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_checkpoint_latest(
    conn: &libsql::Connection,
) -> Result<Option<CheckpointRow>, Error> {
    let mut row = conn
        .query(
            "SELECT height, hash FROM checkpoints ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;
    Ok(row.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn select_all_file_metadata(conn: &Connection) -> Result<Vec<FileMetadataRow>, Error> {
    let mut rows = conn
        .query(
            r#"SELECT
            id,
            file_id,
            object_id,
            nonce,
            root,
            padded_len,
            original_size,
            filename,
            height,
            historical_root
            FROM file_metadata
            ORDER BY id ASC"#,
            params![],
        )
        .await?;

    let mut entries = Vec::new();
    while let Some(row) = rows.next().await? {
        entries.push(from_row(&row)?);
    }
    Ok(entries)
}

pub async fn select_file_metadata_by_file_id(
    conn: &Connection,
    file_id: &str,
) -> Result<Option<FileMetadataRow>, Error> {
    let mut rows = conn
        .query(
            r#"SELECT
            id,
            file_id,
            object_id,
            nonce,
            root,
            padded_len,
            original_size,
            filename,
            height,
            historical_root
            FROM file_metadata
            WHERE file_id = ?
            LIMIT 1"#,
            params![file_id],
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn insert_file_metadata(
    conn: &Connection,
    entry: &FileMetadataRow,
) -> Result<i64, Error> {
    // Convert Option<[u8; 32]> to Value (Null or Blob)
    let historical_root_value: Value = match &entry.historical_root {
        Some(root) => Value::Blob(root.to_vec()),
        None => Value::Null,
    };

    conn.execute(
        r#"INSERT INTO
        file_metadata
        (file_id,
        object_id,
        nonce,
        root,
        padded_len,
        original_size,
        filename,
        height,
        historical_root)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        params![
            entry.file_id.clone(),
            entry.object_id.clone(),
            entry.nonce.clone(),
            entry.root,
            entry.padded_len,
            entry.original_size,
            entry.filename.clone(),
            entry.height,
            historical_root_value,
        ],
    )
    .await?;
    Ok(conn.last_insert_rowid())
}
