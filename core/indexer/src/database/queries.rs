use bitcoin::BlockHash;
use futures_util::{Stream, stream};
use indexer_types::{BlockRow, ContractListRow, PaginationMeta, TransactionRow};
use libsql::{Connection, Value, de::from_row, named_params, params};
use serde::de::DeserializeOwned;
use thiserror::Error as ThisError;

use crate::{
    database::types::{
        BatchQueryResult, BlockQuery, CheckpointRow, ContractResultPublicRow, ContractResultRow,
        ContractRow, FileMetadataRow, HasRowId, Identity, OpResultId, OrderDirection, ResultQuery,
        SignerEntry, SignerRow, TransactionQuery,
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
        "INSERT INTO blocks (height, hash, relevant) VALUES (?, ?, ?)",
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
            "SELECT height, hash, relevant FROM blocks ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn select_recent_blocks(conn: &Connection, limit: i64) -> Result<Vec<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash, relevant FROM blocks ORDER BY height DESC LIMIT ?",
            params![limit],
        )
        .await?;
    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push(from_row(&row)?);
    }
    Ok(results)
}

pub async fn select_block_by_height_or_hash(
    conn: &Connection,
    identifier: &str,
) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash, relevant FROM blocks WHERE height = ? OR hash = ?",
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
    let mut where_clauses = vec![];
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
                tx_id,
                size,
                path,
                value,
                deleted
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
            params![
                row.contract_id,
                row.height,
                row.tx_id,
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
                    tx_id,
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
    tx_id: Option<i64>,
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
            INSERT INTO contracts (
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

pub async fn insert_transaction(conn: &Connection, row: TransactionRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT INTO transactions (height, txid, confirmed_height, tx_index, batch_height) VALUES (?, ?, ?, ?, ?)",
        params![row.height, row.txid, row.confirmed_height, row.tx_index, row.batch_height],
    )
    .await?;
    Ok(conn.last_insert_rowid())
}

pub async fn insert_batch(
    conn: &Connection,
    consensus_height: i64,
    anchor_height: i64,
    anchor_hash: &str,
    certificate: &[u8],
    is_block: bool,
) -> Result<(), Error> {
    conn.execute(
        "INSERT OR IGNORE INTO batches (consensus_height, anchor_height, anchor_hash, certificate, is_block) VALUES (?, ?, ?, ?, ?)",
        params![consensus_height, anchor_height, anchor_hash, certificate, is_block as i64],
    )
    .await?;
    Ok(())
}

pub async fn delete_batches_above_anchor(conn: &Connection, max_anchor: i64) -> Result<u64, Error> {
    let rows = conn
        .execute(
            "DELETE FROM batches WHERE anchor_height > ?",
            params![max_anchor],
        )
        .await?;
    Ok(rows)
}

pub async fn select_latest_consensus_height(conn: &Connection) -> Result<Option<i64>, Error> {
    Ok(conn
        .query("SELECT MAX(consensus_height) FROM batches", ())
        .await?
        .next()
        .await?
        .and_then(|row| row.get(0).ok()))
}

pub async fn select_batch(
    conn: &Connection,
    consensus_height: i64,
) -> Result<Option<BatchQueryResult>, Error> {
    let results = query_batches(
        conn,
        &format!("WHERE b.consensus_height = {consensus_height}"),
    )
    .await?;
    Ok(results.into_iter().next())
}

pub async fn select_min_batch_height(conn: &Connection) -> Result<Option<i64>, Error> {
    let mut rows = conn
        .query("SELECT MIN(consensus_height) FROM batches", params![])
        .await?;

    let Some(row) = rows.next().await? else {
        return Ok(None);
    };

    Ok(row.get::<Option<i64>>(0)?)
}

pub async fn select_batches_from_anchor(
    conn: &Connection,
    from_anchor: i64,
) -> Result<Vec<BatchQueryResult>, Error> {
    query_batches(conn, &format!("WHERE b.anchor_height >= {from_anchor}")).await
}

pub async fn select_batches_in_range(
    conn: &Connection,
    start: i64,
    end: i64,
) -> Result<Vec<BatchQueryResult>, Error> {
    query_batches(
        conn,
        &format!("WHERE b.consensus_height >= {start} AND b.consensus_height <= {end}"),
    )
    .await
}

async fn query_batches(
    conn: &Connection,
    where_clause: &str,
) -> Result<Vec<BatchQueryResult>, Error> {
    let sql = format!(
        "SELECT b.consensus_height, b.anchor_height, b.anchor_hash, b.is_block, b.certificate, \
                t.txid \
         FROM batches b \
         LEFT JOIN transactions t ON t.batch_height = b.consensus_height \
         {where_clause} \
         ORDER BY b.consensus_height, t.id"
    );
    let mut rows = conn.query(&sql, ()).await?;

    let mut results: Vec<BatchQueryResult> = Vec::new();
    while let Some(row) = rows.next().await? {
        let consensus_height: i64 = row.get(0)?;
        let txid: Option<String> = row.get(5)?;

        if results
            .last()
            .is_some_and(|r| r.consensus_height == consensus_height)
        {
            if let Some(txid) = txid {
                results.last_mut().unwrap().txids.push(txid);
            }
        } else {
            results.push(BatchQueryResult {
                consensus_height,
                anchor_height: row.get(1)?,
                anchor_hash: row.get(2)?,
                is_block: row.get::<i64>(3)? != 0,
                certificate: row.get(4)?,
                txids: txid.into_iter().collect(),
            });
        }
    }

    Ok(results)
}

pub async fn confirm_transaction(
    conn: &Connection,
    txid: &str,
    confirmed_height: i64,
    tx_index: i64,
) -> Result<(), Error> {
    conn.execute(
        "UPDATE transactions SET confirmed_height = ?, tx_index = ? WHERE txid = ?",
        params![confirmed_height, tx_index, txid],
    )
    .await?;
    delete_unconfirmed_batch_tx(conn, txid).await?;
    Ok(())
}

pub async fn insert_unconfirmed_batch_tx(
    conn: &Connection,
    txid: &str,
    batch_height: i64,
    raw_tx: &[u8],
) -> Result<(), Error> {
    conn.execute(
        "INSERT OR IGNORE INTO unconfirmed_batch_txs (txid, batch_height, raw_tx) VALUES (?, ?, ?)",
        params![txid, batch_height, raw_tx],
    )
    .await?;
    Ok(())
}

pub async fn delete_unconfirmed_batch_tx(conn: &Connection, txid: &str) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM unconfirmed_batch_txs WHERE txid = ?",
        params![txid],
    )
    .await?;
    Ok(())
}

pub async fn select_unconfirmed_batch_txs(
    conn: &Connection,
    batch_height: i64,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut rows = conn
        .query(
            "SELECT raw_tx FROM unconfirmed_batch_txs WHERE batch_height = ?",
            params![batch_height],
        )
        .await?;
    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        let raw_tx: Vec<u8> = row.get(0)?;
        results.push(raw_tx);
    }
    Ok(results)
}

pub async fn select_unconfirmed_batch_tx(
    conn: &Connection,
    txid: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query(
            "SELECT raw_tx FROM unconfirmed_batch_txs WHERE txid = ?",
            params![txid],
        )
        .await?;
    Ok(rows
        .next()
        .await?
        .map(|row| row.get::<Vec<u8>>(0))
        .transpose()?)
}

pub async fn get_transaction_by_txid(
    conn: &Connection,
    txid: &str,
) -> Result<Option<TransactionRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT id, txid, height, confirmed_height, tx_index, batch_height FROM transactions WHERE txid = ?",
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
            "SELECT id, txid, height, confirmed_height, tx_index, batch_height FROM transactions WHERE height = ?",
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
    let mut selects =
        "t.id, t.txid, t.height, t.confirmed_height, t.tx_index, t.batch_height".to_string();
    let mut from = "transactions t".to_string();
    let mut where_clauses = vec![];
    if let Some(address) = &query.contract {
        let contract_id = get_contract_id_from_address(conn, address)
            .await?
            .ok_or(Error::ContractNotFound(address.to_string()))?;
        selects = format!("DISTINCT {}", selects);
        from = format!("{} JOIN contract_state c ON c.tx_id = t.id", from);
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
        t.tx_index,
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
        LEFT JOIN transactions t ON r.tx_id = t.id
        JOIN contracts c ON r.contract_id = c.id
    "#;
    let mut where_clauses = vec![];
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
                r.height,
                t.tx_index,
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
            FROM contract_results r
            LEFT JOIN transactions t ON r.tx_id = t.id
            JOIN contracts c ON r.contract_id = c.id
            WHERE t.txid = :txid AND r.input_index = :input_index AND r.op_index = :op_index
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
    tx_id: Option<i64>,
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
                tx_id,
                input_index,
                op_index,
                result_index,
                gas,
                value
            FROM contract_results
            WHERE tx_id IS :tx_id
              AND input_index IS :input_index
              AND op_index IS :op_index
              AND result_index = :result_index
            "#,
            named_params! {
                ":tx_id": tx_id,
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
            INSERT INTO contract_results (
                contract_id,
                size,
                func,
                height,
                tx_id,
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
            row.tx_id,
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

/// Return the subset of `txids` that already exist in the transactions table.
pub async fn select_existing_txids(
    conn: &Connection,
    txids: &[String],
) -> Result<std::collections::HashSet<String>, Error> {
    if txids.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let placeholders: Vec<&str> = txids.iter().map(|_| "?").collect();
    let sql = format!(
        "SELECT txid FROM transactions WHERE txid IN ({})",
        placeholders.join(", ")
    );
    let params: Vec<libsql::Value> = txids
        .iter()
        .map(|t| libsql::Value::from(t.clone()))
        .collect();
    let mut rows = conn
        .query(&sql, libsql::params::Params::Positional(params))
        .await?;
    let mut result = std::collections::HashSet::new();
    while let Some(row) = rows.next().await? {
        let txid: String = row.get(0)?;
        result.insert(txid);
    }
    Ok(result)
}

// ─────────────────────────────────────────────────────────────────
// Identity DAO
// ─────────────────────────────────────────────────────────────────

impl Identity {
    pub async fn x_only_pubkey(&self, conn: &Connection) -> Result<String, Error> {
        let mut rows = conn
            .query(
                "SELECT x_only_pubkey FROM signers WHERE id = ?",
                params![self.signer_id],
            )
            .await?;
        let row = rows
            .next()
            .await?
            .ok_or_else(|| Error::InvalidData(format!("unknown signer_id {}", self.signer_id)))?;
        Ok(row.get(0)?)
    }

    pub async fn bls_pubkey(&self, conn: &Connection) -> Result<Option<Vec<u8>>, Error> {
        let mut rows = conn
            .query(
                "SELECT bls_pubkey FROM bls_keys WHERE signer_id = ? ORDER BY height DESC LIMIT 1",
                params![self.signer_id],
            )
            .await?;
        Ok(rows.next().await?.map(|row| row.get(0)).transpose()?)
    }

    pub async fn next_nonce(&self, conn: &Connection) -> Result<i64, Error> {
        let mut rows = conn
            .query(
                "SELECT next_nonce FROM nonces WHERE signer_id = ? ORDER BY height DESC LIMIT 1",
                params![self.signer_id],
            )
            .await?;
        Ok(rows
            .next()
            .await?
            .map(|row| row.get(0))
            .transpose()?
            .unwrap_or(0))
    }
}

// ─────────────────────────────────────────────────────────────────
// Signer Registry
// ─────────────────────────────────────────────────────────────────

pub async fn get_or_create_identity(
    conn: &Connection,
    x_only_pubkey: &str,
    height: i64,
) -> Result<Identity, Error> {
    let mut rows = conn
        .query(
            "SELECT id FROM signers WHERE x_only_pubkey = ?",
            params![x_only_pubkey],
        )
        .await?;

    if let Some(row) = rows.next().await? {
        return Ok(Identity {
            signer_id: row.get(0)?,
        });
    }

    conn.execute(
        "INSERT INTO signers (x_only_pubkey, height) VALUES (?, ?)",
        params![x_only_pubkey, height],
    )
    .await?;

    let signer_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO nonces (signer_id, next_nonce, height) VALUES (?, 0, ?)",
        params![signer_id, height],
    )
    .await?;

    Ok(Identity { signer_id })
}

pub async fn ensure_signer(
    conn: &Connection,
    x_only_pubkey: &str,
    height: i64,
) -> Result<SignerRow, Error> {
    let mut rows = conn
        .query(
            "SELECT id, x_only_pubkey, height FROM signers WHERE x_only_pubkey = ?",
            params![x_only_pubkey],
        )
        .await?;

    if let Some(row) = rows.next().await? {
        return Ok(SignerRow {
            signer_id: row.get(0)?,
            x_only_pubkey: row.get(1)?,
            height: row.get(2)?,
        });
    }

    conn.execute(
        "INSERT INTO signers (x_only_pubkey, height) VALUES (?, ?)",
        params![x_only_pubkey, height],
    )
    .await?;

    let signer_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO nonces (signer_id, next_nonce, height) VALUES (?, 0, ?)",
        params![signer_id, height],
    )
    .await?;

    Ok(SignerRow {
        signer_id,
        x_only_pubkey: x_only_pubkey.to_string(),
        height,
    })
}

pub async fn advance_nonce(
    conn: &Connection,
    signer_id: i64,
    caller_nonce: i64,
    height: i64,
) -> Result<i64, Error> {
    let mut rows = conn
        .query(
            "SELECT next_nonce FROM nonces WHERE signer_id = ? ORDER BY height DESC LIMIT 1",
            params![signer_id],
        )
        .await?;

    let stored_nonce: i64 = rows
        .next()
        .await?
        .ok_or_else(|| Error::InvalidData(format!("no nonce for signer_id {signer_id}")))?
        .get(0)?;

    if caller_nonce < stored_nonce {
        return Err(Error::InvalidData(format!(
            "nonce too low for signer_id {signer_id}: got {caller_nonce}, expected >= {stored_nonce}"
        )));
    }

    let next_nonce = caller_nonce + 1;
    conn.execute(
        "INSERT OR REPLACE INTO nonces (signer_id, next_nonce, height) VALUES (?, ?, ?)",
        params![signer_id, next_nonce, height],
    )
    .await?;

    Ok(next_nonce)
}

pub async fn register_bls_key(
    conn: &Connection,
    signer_id: i64,
    bls_pubkey: &[u8],
    height: i64,
) -> Result<(), Error> {
    conn.execute(
        "INSERT OR REPLACE INTO bls_keys (signer_id, bls_pubkey, height) VALUES (?, ?, ?)",
        params![signer_id, bls_pubkey.to_vec(), height],
    )
    .await?;
    Ok(())
}

pub async fn get_signer_entry(
    conn: &Connection,
    x_only_pubkey: &str,
) -> Result<Option<SignerEntry>, Error> {
    let mut rows = conn
        .query(
            r#"SELECT
                s.id,
                s.x_only_pubkey,
                b.bls_pubkey,
                n.next_nonce
            FROM signers s
            LEFT JOIN (
                SELECT signer_id, bls_pubkey
                FROM bls_keys
                WHERE signer_id = (SELECT id FROM signers WHERE x_only_pubkey = ?)
                ORDER BY height DESC LIMIT 1
            ) b ON b.signer_id = s.id
            LEFT JOIN (
                SELECT signer_id, next_nonce
                FROM nonces
                WHERE signer_id = (SELECT id FROM signers WHERE x_only_pubkey = ?)
                ORDER BY height DESC LIMIT 1
            ) n ON n.signer_id = s.id
            WHERE s.x_only_pubkey = ?"#,
            params![x_only_pubkey, x_only_pubkey, x_only_pubkey],
        )
        .await?;

    Ok(rows
        .next()
        .await?
        .map(|row| {
            Ok::<_, Error>(SignerEntry {
                signer_id: row.get(0)?,
                x_only_pubkey: row.get(1)?,
                bls_pubkey: row.get::<Option<Vec<u8>>>(2)?,
                next_nonce: row.get::<Option<i64>>(3)?.unwrap_or(0),
            })
        })
        .transpose()?)
}

pub async fn get_signer_entry_by_id(
    conn: &Connection,
    signer_id: i64,
) -> Result<Option<SignerEntry>, Error> {
    let mut rows = conn
        .query(
            r#"SELECT
                s.id,
                s.x_only_pubkey,
                b.bls_pubkey,
                n.next_nonce
            FROM signers s
            LEFT JOIN (
                SELECT signer_id, bls_pubkey
                FROM bls_keys WHERE signer_id = ?
                ORDER BY height DESC LIMIT 1
            ) b ON b.signer_id = s.id
            LEFT JOIN (
                SELECT signer_id, next_nonce
                FROM nonces WHERE signer_id = ?
                ORDER BY height DESC LIMIT 1
            ) n ON n.signer_id = s.id
            WHERE s.id = ?"#,
            params![signer_id, signer_id, signer_id],
        )
        .await?;

    Ok(rows
        .next()
        .await?
        .map(|row| {
            Ok::<_, Error>(SignerEntry {
                signer_id: row.get(0)?,
                x_only_pubkey: row.get(1)?,
                bls_pubkey: row.get::<Option<Vec<u8>>>(2)?,
                next_nonce: row.get::<Option<i64>>(3)?.unwrap_or(0),
            })
        })
        .transpose()?)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::database::types::{OrderDirection, TransactionQuery};
    use anyhow::Result;
    use bitcoin::hashes::Hash;
    use futures_util::{StreamExt, TryStreamExt};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::test_utils::{new_mock_block_hash, new_mock_transaction, new_test_db};

    fn calculate_row_hash(state: &ContractStateRow) -> String {
        let value_part = hex::encode(&state.value).to_uppercase();
        let input = format!(
            "{}{}{}{}",
            state.contract_id,
            state.path,
            value_part,
            if state.deleted { "1" } else { "0" }
        );
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize()).to_uppercase()
    }

    fn calculate_combined_hash(state: &ContractStateRow, prev_hash: &str) -> String {
        let row_hash = calculate_row_hash(state);
        let combined = format!("{}{}", row_hash, prev_hash);
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        hex::encode(hasher.finalize()).to_uppercase()
    }

    async fn setup_test_data(conn: &libsql::Connection) -> Result<()> {
        // Insert blocks
        for height in [800000, 800001, 800002] {
            let hash = format!(
                "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba{:02}",
                height % 100
            )
            .parse()?;
            let block = BlockRow::builder().height(height).hash(hash).build();
            insert_block(conn, block).await?;
        }

        insert_contract(
            conn,
            ContractRow::builder()
                .name("token".to_string())
                .height(800000)
                .tx_index(1)
                .bytes(vec![])
                .build(),
        )
        .await?;

        // Insert transactions across multiple heights
        // Height 800000: 5 transactions (tx_index 0-4)
        let mut tx_ids_800000 = Vec::new();
        for i in 0..5 {
            let tx = TransactionRow::builder()
                .height(800000)
                .txid(format!(
                    "tx800000_{:02}_abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456",
                    i
                ))
                .tx_index(i)
                .build();
            tx_ids_800000.push(insert_transaction(conn, tx).await?);
        }

        // tx_index=0 modifies the token contract
        insert_contract_state(
            conn,
            ContractStateRow::builder()
                .contract_id(1)
                .tx_id(tx_ids_800000[0])
                .height(800000)
                .path("foo".to_string())
                .build(),
        )
        .await?;

        // Height 800001: 3 transactions (tx_index 0-2)
        let mut tx_ids_800001 = Vec::new();
        for i in 0..3 {
            let tx = TransactionRow::builder()
                .height(800001)
                .txid(format!(
                    "tx800001_{:02}_fedcba0987654321fedcba0987654321fedcba0987654321fedcba098765",
                    i
                ))
                .tx_index(i)
                .build();
            tx_ids_800001.push(insert_transaction(conn, tx).await?);
        }

        // tx_index=1 modifies the token contract (two state changes — tests DISTINCT)
        insert_contract_state(
            conn,
            ContractStateRow::builder()
                .contract_id(1)
                .tx_id(tx_ids_800001[1])
                .height(800001)
                .path("bar".to_string())
                .build(),
        )
        .await?;
        insert_contract_state(
            conn,
            ContractStateRow::builder()
                .contract_id(1)
                .tx_id(tx_ids_800001[1])
                .height(800001)
                .path("biz".to_string())
                .build(),
        )
        .await?;

        // Height 800002: 2 transactions (tx_index 0-1)
        let mut tx_ids_800002 = Vec::new();
        for i in 0..2 {
            let tx = TransactionRow::builder()
                .height(800002)
                .txid(format!(
                    "tx800002_{:02}_123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
                    i
                ))
                .tx_index(i)
                .build();
            tx_ids_800002.push(insert_transaction(conn, tx).await?);
        }

        // tx_index=0 modifies the token contract
        insert_contract_state(
            conn,
            ContractStateRow::builder()
                .contract_id(1)
                .tx_id(tx_ids_800002[0])
                .height(800002)
                .path("baz".to_string())
                .build(),
        )
        .await?;

        Ok(())
    }

    async fn count_checkpoints(conn: &Connection) -> i64 {
        let stmt = conn
            .prepare("SELECT COUNT(*) FROM checkpoints")
            .await
            .unwrap();
        let mut rows = stmt.query(libsql::params![]).await.unwrap();
        rows.next()
            .await
            .unwrap()
            .map(|r| r.get(0).unwrap())
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn test_checkpoint_trigger() {
        let (_reader, writer, _temp) = new_test_db().await.unwrap();
        let conn = writer.connection();

        for height in 1..=200 {
            let block = BlockRow::builder()
                .height(height)
                .hash(bitcoin::BlockHash::from_byte_array([height as u8; 32]))
                .build();
            insert_block(&conn, block).await.unwrap();
        }

        let cs1 = ContractStateRow::builder()
            .contract_id(1)
            .height(10)
            .path("/test/path1".to_string())
            .value(b"test value 1".to_vec())
            .build();
        insert_contract_state(&conn, cs1.clone()).await.unwrap();
        let cp1 = get_checkpoint_by_height(&conn, 10).await.unwrap().unwrap();
        assert_eq!(cp1.height, 10);
        assert_eq!(
            cp1.hash.to_lowercase(),
            calculate_row_hash(&cs1).to_lowercase()
        );
        assert_eq!(count_checkpoints(&conn).await, 1);

        let cs2 = ContractStateRow::builder()
            .contract_id(1)
            .height(20)
            .path("/test/path2".to_string())
            .build();
        insert_contract_state(&conn, cs2.clone()).await.unwrap();
        let cp2 = get_checkpoint_by_height(&conn, 20).await.unwrap().unwrap();
        assert_eq!(cp2.height, 20);
        assert_eq!(
            cp2.hash.to_lowercase(),
            calculate_combined_hash(&cs2, &cp1.hash).to_lowercase()
        );
        assert_eq!(count_checkpoints(&conn).await, 2);

        let cs3 = ContractStateRow::builder()
            .contract_id(2)
            .height(60)
            .path("/test/path3".to_string())
            .value(b"test value 3".to_vec())
            .build();
        insert_contract_state(&conn, cs3.clone()).await.unwrap();
        let cp3 = get_checkpoint_by_height(&conn, 60).await.unwrap().unwrap();
        assert_eq!(
            cp3.hash.to_lowercase(),
            calculate_combined_hash(&cs3, &cp2.hash).to_lowercase()
        );
        assert_eq!(count_checkpoints(&conn).await, 3);

        let cs4 = ContractStateRow::builder()
            .contract_id(2)
            .height(75)
            .path("/test/path4".to_string())
            .value(b"test value 4".to_vec())
            .build();
        insert_contract_state(&conn, cs4.clone()).await.unwrap();
        let cp4 = get_checkpoint_by_height(&conn, 75).await.unwrap().unwrap();
        assert_eq!(
            cp4.hash.to_lowercase(),
            calculate_combined_hash(&cs4, &cp3.hash).to_lowercase()
        );
        assert_eq!(count_checkpoints(&conn).await, 4);

        let cs5 = ContractStateRow::builder()
            .contract_id(3)
            .height(120)
            .path("/test/path5".to_string())
            .value(b"test value 5".to_vec())
            .build();
        insert_contract_state(&conn, cs5.clone()).await.unwrap();
        let cp5 = get_checkpoint_by_height(&conn, 120).await.unwrap().unwrap();
        assert_eq!(
            cp5.hash.to_lowercase(),
            calculate_combined_hash(&cs5, &cp4.hash).to_lowercase()
        );
        assert_eq!(count_checkpoints(&conn).await, 5);

        let cs6 = ContractStateRow::builder()
            .contract_id(4)
            .height(190)
            .path("/test/path6".to_string())
            .build();
        insert_contract_state(&conn, cs6.clone()).await.unwrap();
        let cp6 = get_checkpoint_by_height(&conn, 190).await.unwrap().unwrap();
        assert_eq!(
            cp6.hash.to_lowercase(),
            calculate_combined_hash(&cs6, &cp5.hash).to_lowercase()
        );
        assert_eq!(count_checkpoints(&conn).await, 6);

        let cs7 = ContractStateRow::builder()
            .contract_id(4)
            .height(199)
            .path("/test/path7".to_string())
            .value(b"test value 7".to_vec())
            .build();
        insert_contract_state(&conn, cs7.clone()).await.unwrap();
        let cp7 = get_checkpoint_by_height(&conn, 199).await.unwrap().unwrap();
        assert_eq!(
            cp7.hash.to_lowercase(),
            calculate_combined_hash(&cs7, &cp6.hash).to_lowercase()
        );
        assert_eq!(count_checkpoints(&conn).await, 7);

        let cp_latest = get_checkpoint_latest(&conn).await.unwrap().unwrap();
        assert_eq!(cp7, cp_latest);

        // Same height insertion updates checkpoint
        let cs8 = ContractStateRow::builder()
            .contract_id(4)
            .height(199)
            .path("/test/path7".to_string())
            .value(b"test value 7".to_vec())
            .build();
        insert_contract_state(&conn, cs8.clone()).await.unwrap();
        assert_eq!(count_checkpoints(&conn).await, 7);
        assert_eq!(
            calculate_combined_hash(&cs8, &cp7.hash).to_lowercase(),
            get_checkpoint_latest(&conn)
                .await
                .unwrap()
                .unwrap()
                .hash
                .to_lowercase()
        );
    }

    #[tokio::test]
    async fn test_database() -> Result<()> {
        let height: i64 = 800000;
        let hash = new_mock_block_hash(height as u32);
        let block = BlockRow::builder().height(height).hash(hash).build();

        let (reader, writer, _temp_dir) = new_test_db().await?;

        insert_block(&writer.connection(), block).await?;
        let block_at_height = select_block_at_height(&*reader.connection().await?, height)
            .await?
            .unwrap();
        assert_eq!(block_at_height.height, height);
        assert_eq!(block_at_height.hash, hash);
        let last_block = select_block_latest(&*reader.connection().await?)
            .await?
            .unwrap();
        assert_eq!(last_block.height, height);
        assert_eq!(last_block.hash, hash);

        Ok(())
    }

    #[tokio::test]
    async fn test_transaction() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let tx = writer.connection().transaction().await?;
        let height = 800000;
        let hash = new_mock_block_hash(height as u32);
        let block = BlockRow::builder().height(height).hash(hash).build();
        insert_block(&tx, block).await?;
        assert!(select_block_latest(&tx).await?.is_some());
        tx.commit().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_crypto_extension() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        let mut rows = conn
            .query("SELECT hex(crypto_sha256('abc'))", params![])
            .await?;
        let row = rows.next().await?.unwrap();
        let hash = row.get_str(0)?;
        assert_eq!(
            hash,
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_contract_state_operations() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();

        // First insert a block to satisfy foreign key constraints
        let height = 800000;
        let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
        let block = BlockRow::builder().height(height).hash(hash).build();
        insert_block(&conn, block).await?;

        // Insert a transaction for the contract state
        let tx = TransactionRow::builder()
            .height(height)
            .txid("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string())
            .tx_index(0)
            .confirmed_height(height)
            .build();
        let tx_id = insert_transaction(&conn, tx.clone()).await?;

        // Test contract state insertion and retrieval
        let contract_id = 123;
        let path = "test.path";
        let value = vec![1, 2, 3, 4];

        assert!(!contract_has_state(&conn, contract_id).await?);

        let contract_state = ContractStateRow::builder()
            .contract_id(contract_id)
            .tx_id(tx_id)
            .height(height)
            .path(path.to_string())
            .value(value.clone())
            .build();

        // Insert contract state
        let id = insert_contract_state(&conn, contract_state.clone()).await?;
        assert!(id > 0, "Contract state insertion should succeed");

        // check existence
        assert!(contract_has_state(&conn, contract_id).await?);
        assert!(exists_contract_state(&conn, contract_id, "test.").await?);

        assert_eq!(
            matching_path(&conn, contract_id, "test", r"^test.(path|foo|bar)(\..*|$)")
                .await?
                .unwrap(),
            path
        );

        // Get latest contract state
        let retrieved_state = get_latest_contract_state(&conn, contract_id, path).await?;
        assert!(
            retrieved_state.is_some(),
            "Contract state should be retrieved"
        );

        // Get latest contract state value
        let fuel = 1000;
        let retrieved_value =
            get_latest_contract_state_value(&conn, 1000, contract_id, path).await?;
        assert!(
            retrieved_value.is_some(),
            "Contract state value should be retrieved"
        );

        let retrieved_state = retrieved_state.unwrap();
        assert_eq!(retrieved_state.contract_id, contract_id);
        assert_eq!(retrieved_state.path, path);
        assert_eq!(retrieved_state.value, value);
        assert_eq!(retrieved_value.unwrap(), value);
        assert!(!retrieved_state.deleted);
        assert_eq!(retrieved_state.height, height);
        assert_eq!(retrieved_state.tx_id, contract_state.tx_id);

        // Test with a newer version of the same contract state
        let height2 = 800001;
        let hash2 = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?;
        let block2 = BlockRow::builder().height(height2).hash(hash2).build();
        insert_block(&conn, block2).await?;

        let txid2 = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let tx2 = TransactionRow::builder()
            .height(height2)
            .txid(txid2.to_string())
            .tx_index(2)
            .confirmed_height(height2)
            .build();
        let tx_id2 = insert_transaction(&conn, tx2.clone()).await?;

        let updated_value = vec![5, 6, 7, 8];
        let updated_contract_state = ContractStateRow::builder()
            .contract_id(contract_id)
            .tx_id(tx_id2)
            .height(height2)
            .path(path.to_string())
            .value(updated_value.clone())
            .build();
        insert_contract_state(&conn, updated_contract_state).await?;

        // Verify we get the latest version
        let latest_state = get_latest_contract_state(&conn, contract_id, path)
            .await?
            .unwrap();
        let latest_value = get_latest_contract_state_value(&conn, fuel, contract_id, path)
            .await?
            .unwrap();
        assert_eq!(latest_state.height, height2);
        assert_eq!(latest_state.value, updated_value);
        assert_eq!(latest_value, updated_value);

        // Delete the contract state
        let deleted =
            delete_contract_state(&conn, height2, Some(tx_id2), contract_id, path).await?;
        assert!(deleted);

        let count = conn
            .query(
                "SELECT COUNT(*) FROM contract_state WHERE contract_id = :contract_id AND path = :path",
                ((":contract_id", contract_id), (":path", path)),
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get::<u64>(0)
            .unwrap();
        assert_eq!(count, 2);

        // Verify the contract state is deleted
        let latest_state = get_latest_contract_state(&conn, contract_id, path).await?;
        assert!(latest_state.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_transaction_operations() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();

        // Insert a block first
        let height = 800000;
        let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
        let block = BlockRow::builder().height(height).hash(hash).build();
        insert_block(&conn, block).await?;

        let tx1 = TransactionRow::builder()
            .height(height)
            .txid("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string())
            .tx_index(0)
            .confirmed_height(height)
            .build();
        let tx2 = TransactionRow::builder()
            .height(height)
            .txid("123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0".to_string())
            .tx_index(1)
            .confirmed_height(height)
            .build();
        let tx3 = TransactionRow::builder()
            .height(height)
            .txid("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string())
            .tx_index(2)
            .confirmed_height(height)
            .build();

        // Insert multiple transactions at the same height

        insert_transaction(&conn, tx1.clone()).await?;
        insert_transaction(&conn, tx2.clone()).await?;
        insert_transaction(&conn, tx3.clone()).await?;

        // Test get_transaction_by_txid
        let result = get_transaction_by_txid(&conn, tx2.txid.as_str())
            .await?
            .unwrap();
        assert_eq!(tx2.txid, result.txid);
        assert_eq!(tx2.height, result.height);
        assert_eq!(tx2.tx_index, result.tx_index);

        // Test get_transactions_at_height
        let txs_at_height = get_transactions_at_height(&conn, height).await?;
        assert_eq!(txs_at_height.len(), 3);

        // Verify all transactions are included - now using TransactionRow objects
        let txids = txs_at_height
            .iter()
            .map(|tx| tx.txid.clone())
            .collect::<HashSet<_>>();

        assert!(txids.contains(&tx1.txid));
        assert!(txids.contains(&tx2.txid));
        assert!(txids.contains(&tx3.txid));

        // Insert transactions at a different height
        let height2 = 800001;
        let hash2 = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?;
        let block2 = BlockRow::builder().height(height2).hash(hash2).build();
        insert_block(&conn, block2).await?;

        let tx4_txid =
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string();
        let tx4 = TransactionRow::builder()
            .height(height2)
            .txid(tx4_txid.clone())
            .tx_index(0)
            .build();

        insert_transaction(&conn, tx4).await?;

        // Verify get_transactions_at_height returns only transactions at the specified height
        let txs_at_height1 = get_transactions_at_height(&conn, height).await?;
        assert_eq!(txs_at_height1.len(), 3);

        let txs_at_height2 = get_transactions_at_height(&conn, height2).await?;
        assert_eq!(txs_at_height2.len(), 1);

        // Check the transaction details
        let tx4 = &txs_at_height2[0];
        assert_eq!(tx4.tx_index, Some(0));
        assert_eq!(tx4.txid, tx4_txid);
        assert_eq!(tx4.height, height2);

        Ok(())
    }

    #[tokio::test]
    async fn test_select_block_by_height_or_hash() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();

        // Insert test blocks
        let block1 = BlockRow::builder()
            .height(800000)
            .hash("000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?)
            .build();
        let block2 = BlockRow::builder()
            .height(800001)
            .hash("000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?)
            .build();
        let block3 = BlockRow::builder()
            .height(123456)
            .hash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".parse()?)
            .build();

        insert_block(&conn, block1.clone()).await?;
        insert_block(&conn, block2.clone()).await?;
        insert_block(&conn, block3.clone()).await?;

        // Test 1: Find by height (as string)
        let result = select_block_by_height_or_hash(&conn, "800000").await?;
        assert!(result.is_some());
        let found_block = result.unwrap();
        assert_eq!(found_block.height, 800000);
        assert_eq!(found_block.hash, block1.hash);

        // Test 2: Find by hash
        let result = select_block_by_height_or_hash(
            &conn,
            "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05",
        )
        .await?;
        assert!(result.is_some());
        let found_block = result.unwrap();
        assert_eq!(found_block.height, 800001);
        assert_eq!(found_block.hash, block2.hash);

        // Test 3: Find by different height
        let result = select_block_by_height_or_hash(&conn, "123456").await?;
        assert!(result.is_some());
        let found_block = result.unwrap();
        assert_eq!(found_block.height, 123456);
        assert_eq!(found_block.hash, block3.hash);

        // Test 4: Find by different hash
        let result = select_block_by_height_or_hash(
            &conn,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )
        .await?;
        assert!(result.is_some());
        let found_block = result.unwrap();
        assert_eq!(found_block.height, 123456);
        assert_eq!(found_block.hash, block3.hash);

        // Test 5: Non-existent height
        let result = select_block_by_height_or_hash(&conn, "999999").await?;
        assert!(result.is_none());

        // Test 6: Non-existent hash
        let result = select_block_by_height_or_hash(&conn, "nonexistenthash123456789").await?;
        assert!(result.is_none());

        // Test 7: Invalid height format (non-numeric string that's not a hash)
        let result = select_block_by_height_or_hash(&conn, "invalid_height").await?;
        assert!(result.is_none());

        // Test 8: Empty string
        let result = select_block_by_height_or_hash(&conn, "").await?;
        assert!(result.is_none());

        // Test 9: Height 0 (edge case)
        let block_zero = BlockRow::builder()
            .height(0)
            .hash("0000000000000000000000000000000000000000000000000000000000000000".parse()?)
            .build();
        insert_block(&conn, block_zero.clone()).await?;

        let result = select_block_by_height_or_hash(&conn, "0").await?;
        assert!(result.is_some());
        let found_block = result.unwrap();
        assert_eq!(found_block.height, 0);
        assert_eq!(found_block.hash, block_zero.hash);

        // Test 10: Very large height
        let large_height = u64::MAX;
        let result = select_block_by_height_or_hash(&conn, &large_height.to_string()).await?;
        assert!(result.is_none());

        // Test 11: Partial hash match (should not match)
        let result = select_block_by_height_or_hash(&conn, "000000000000000000015d76").await?;
        assert!(result.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_contracts() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        insert_block(
            &conn,
            BlockRow::builder()
                .hash(new_mock_block_hash(0))
                .height(0)
                .build(),
        )
        .await?;
        insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(0)
                .tx_index(1)
                .txid(new_mock_transaction(1).txid.to_string())
                .build(),
        )
        .await?;
        let row = ContractRow::builder()
            .bytes("value".as_bytes().to_vec())
            .height(0)
            .tx_index(1)
            .name("test".to_string())
            .build();
        insert_contract(&conn, row.clone()).await?;
        let address = ContractAddress {
            height: 0,
            tx_index: 1,
            name: "test".to_string(),
        };
        let bytes = get_contract_bytes_by_address(&conn, &address)
            .await?
            .unwrap();
        assert_eq!(bytes, row.bytes);
        let id = get_contract_id_from_address(&conn, &address)
            .await?
            .unwrap();
        let bytes = get_contract_bytes_by_id(&conn, id).await?.unwrap();
        assert_eq!(bytes, row.bytes);
        let rows = get_contracts(&conn).await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], ContractListRow { id, ..row.into() });
        Ok(())
    }

    #[tokio::test]
    async fn test_contracts_gapless() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        let insert = async |conn: &Connection, i: i64| {
            insert_block(
                conn,
                BlockRow::builder()
                    .hash(new_mock_block_hash(i as u32))
                    .height(i)
                    .build(),
            )
            .await
            .unwrap();
            let row = ContractRow::builder()
                .bytes("value".as_bytes().to_vec())
                .height(i)
                .tx_index(1)
                .name("test".to_string())
                .build();
            insert_contract(conn, row.clone()).await.unwrap();
        };
        for i in 1i64..=5 {
            insert(&conn, i).await;
        }
        let query = "SELECT id FROM contracts ORDER BY height ASC";
        let get_ids = async |conn: &Connection| {
            conn.query(query, params![])
                .await
                .unwrap()
                .into_stream()
                .map(|row| row.unwrap().get::<i64>(0).unwrap())
                .collect::<Vec<_>>()
                .await
        };
        assert_eq!(get_ids(&conn).await, vec![1, 2, 3, 4, 5]);
        rollback_to_height(&conn, 3).await?;
        assert_eq!(get_ids(&conn).await, vec![1, 2, 3]);
        for i in 4i64..=5 {
            insert(&conn, i).await;
        }
        assert_eq!(get_ids(&conn).await, vec![1, 2, 3, 4, 5]);
        Ok(())
    }

    #[tokio::test]
    async fn test_map_keys() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();

        let height = 800000;
        let block1 = BlockRow::builder()
            .height(height)
            .hash("000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?)
            .build();

        insert_block(&conn, block1.clone()).await?;

        // Insert transactions to satisfy FK constraints
        let tx_id1 = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(height)
                .txid(
                    "aaaa000000000000000000000000000000000000000000000000000000000001".to_string(),
                )
                .tx_index(0)
                .confirmed_height(height)
                .build(),
        )
        .await?;
        let tx_id2 = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(height)
                .txid(
                    "aaaa000000000000000000000000000000000000000000000000000000000002".to_string(),
                )
                .tx_index(1)
                .confirmed_height(height)
                .build(),
        )
        .await?;
        let tx_id3 = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(height)
                .txid(
                    "aaaa000000000000000000000000000000000000000000000000000000000003".to_string(),
                )
                .tx_index(2)
                .confirmed_height(height)
                .build(),
        )
        .await?;

        let contract_id = 123;
        let path = "test.path";
        let value = vec![1, 2, 3, 4];

        let contract_state = ContractStateRow::builder()
            .contract_id(contract_id)
            .tx_id(tx_id1)
            .height(height)
            .path(format!("{}.key0.foo", path))
            .value(value.clone())
            .build();

        insert_contract_state(&conn, contract_state).await?;

        let contract_state = ContractStateRow::builder()
            .contract_id(contract_id)
            .tx_id(tx_id1)
            .height(height)
            .path(format!("{}.key0.bar", path))
            .value(value.clone())
            .build();

        insert_contract_state(&conn, contract_state).await?;

        let contract_state = ContractStateRow::builder()
            .contract_id(contract_id)
            .tx_id(tx_id2)
            .height(height)
            .path(format!("{}.key2", path))
            .value(value.clone())
            .build();
        insert_contract_state(&conn, contract_state).await?;

        let contract_state = ContractStateRow::builder()
            .contract_id(contract_id)
            .tx_id(tx_id3)
            .height(height)
            .path(format!("{}.key1", path))
            .value(value.clone())
            .build();
        insert_contract_state(&conn, contract_state).await?;

        let stream =
            path_prefix_filter_contract_state(&conn, contract_id, "test.path".to_string()).await?;
        let paths = stream.try_collect::<Vec<String>>().await?;
        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0], "key0");
        assert_eq!(paths[1], "key1");
        assert_eq!(paths[2], "key2");

        let result = delete_matching_paths(
            &conn,
            contract_id,
            height,
            &format!(r"^{}.({})(\..*|$)", "test.path", ["key0"].join("|")),
        )
        .await?;
        assert_eq!(result, 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_contract_result_operations() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();

        // Insert a block first
        let height = 800000;
        let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
        let block = BlockRow::builder().height(height).hash(hash).build();
        insert_block(&conn, block).await?;

        let contract_id = insert_contract(
            &conn,
            ContractRow::builder()
                .name("token".to_string())
                .height(height)
                .tx_index(1)
                .bytes(vec![])
                .build(),
        )
        .await?;

        let txid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let tx1 = TransactionRow::builder()
            .height(height)
            .txid(txid.to_string())
            .tx_index(0)
            .confirmed_height(height)
            .build();

        let tx_id = insert_transaction(&conn, tx1.clone()).await?;

        let result = ContractResultRow::builder()
            .id(1)
            .tx_id(tx_id)
            .input_index(0)
            .op_index(0)
            .height(height)
            .contract_id(contract_id)
            .value("".to_string())
            .gas(100)
            .build();

        insert_contract_result(&conn, result.clone()).await?;

        let row = get_contract_result(
            &conn,
            result.tx_id,
            result.input_index,
            result.op_index,
            result.result_index,
        )
        .await?;
        assert_eq!(Some(result.clone()), row);

        let row =
            get_op_result(&conn, &OpResultId::builder().txid(txid.to_string()).build()).await?;
        assert!(row.is_some());
        assert_eq!(result.id, row.unwrap().id);

        Ok(())
    }

    #[tokio::test]
    async fn test_file_metadata_operations() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();

        // Insert a block first to satisfy foreign key constraints
        let height = 800000;
        let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
        let block = BlockRow::builder().height(height).hash(hash).build();
        insert_block(&conn, block).await?;

        // Insert a transaction
        let txid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let tx = TransactionRow::builder()
            .height(height)
            .txid(txid.to_string())
            .tx_index(0)
            .build();
        insert_transaction(&conn, tx.clone()).await?;

        // Initially, no file metadata entries should exist
        let entries = select_all_file_metadata(&conn).await?;
        assert!(entries.is_empty());

        // Insert a file metadata entry
        let file_id = "file_abc123".to_string();
        let root = [1u8; 32]; // 32 bytes for FieldElement
        let padded_len = 1024u64;
        let original_size = 100u64;
        let filename = "file_abc123.dat".to_string();

        let object_id = "obj_abc123".to_string();
        let nonce = vec![3u8; 32];

        let entry1 = FileMetadataRow::builder()
            .file_id(file_id.clone())
            .object_id(object_id.clone())
            .nonce(nonce.clone())
            .root(root)
            .padded_len(padded_len)
            .original_size(original_size)
            .filename(filename.clone())
            .height(height)
            .build();

        let id1 = insert_file_metadata(&conn, &entry1).await?;
        assert!(id1 > 0, "Insert should return a valid ID");

        // Verify entry was inserted
        let entries = select_all_file_metadata(&conn).await?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id1);
        assert_eq!(entries[0].file_id, file_id);
        assert_eq!(entries[0].object_id, object_id);
        assert_eq!(entries[0].nonce, nonce);
        assert_eq!(entries[0].root, root);
        assert_eq!(entries[0].padded_len, padded_len);
        assert_eq!(entries[0].original_size, original_size);
        assert_eq!(entries[0].filename, filename);
        assert_eq!(entries[0].height, height);

        // Insert another file metadata entry at a different height
        let height2 = 800001;
        let hash2 = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?;
        let block2 = BlockRow::builder().height(height2).hash(hash2).build();
        insert_block(&conn, block2).await?;

        let txid2 = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let tx2 = TransactionRow::builder()
            .height(height2)
            .txid(txid2.to_string())
            .tx_index(0)
            .build();
        insert_transaction(&conn, tx2.clone()).await?;

        let file_id2 = "file_def456".to_string();
        let object_id2 = "obj_def456".to_string();
        let nonce2 = vec![4u8; 32];
        let root2 = [2u8; 32];
        let padded_len2 = 2048u64;
        let original_size2 = 200u64;
        let filename2 = "file_def456.dat".to_string();

        let entry2 = FileMetadataRow::builder()
            .file_id(file_id2.clone())
            .object_id(object_id2)
            .nonce(nonce2)
            .root(root2)
            .padded_len(padded_len2)
            .original_size(original_size2)
            .filename(filename2)
            .height(height2)
            .build();

        let id2 = insert_file_metadata(&conn, &entry2).await?;
        assert!(id2 > id1, "Second entry should have a higher ID");

        // Verify both entries exist and are ordered by ID
        let entries = select_all_file_metadata(&conn).await?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, id1);
        assert_eq!(entries[0].file_id, file_id);
        assert_eq!(entries[1].id, id2);
        assert_eq!(entries[1].file_id, file_id2);

        // Test rollback deletes file metadata entries (ON DELETE CASCADE)
        rollback_to_height(&conn, height as u64).await?;

        let entries = select_all_file_metadata(&conn).await?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id1);

        Ok(())
    }

    #[tokio::test]
    async fn test_insert_and_select_batch() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();

        let height: i64 = 100;
        let hash = new_mock_block_hash(height as u32);
        insert_block(&conn, BlockRow::builder().height(height).hash(hash).build()).await?;

        insert_batch(&conn, 1, height, &hash.to_string(), b"cert1", false).await?;

        // Insert two batch transactions
        insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(height)
                .batch_height(1)
                .txid("aa".repeat(32))
                .build(),
        )
        .await?;
        insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(height)
                .batch_height(1)
                .txid("bb".repeat(32))
                .build(),
        )
        .await?;

        let result = select_batch(&conn, 1).await?;
        assert!(result.is_some());
        let batch = result.unwrap();
        assert_eq!(batch.anchor_height, height);
        assert_eq!(batch.anchor_hash, hash.to_string());
        assert_eq!(batch.certificate, b"cert1");
        assert_eq!(batch.txids.len(), 2);
        assert_eq!(batch.txids[0], "aa".repeat(32));
        assert_eq!(batch.txids[1], "bb".repeat(32));

        // Non-existent batch
        assert!(select_batch(&conn, 999).await?.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_select_min_batch_height() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();

        assert!(select_min_batch_height(&conn).await?.is_none());

        let height: i64 = 100;
        let hash = new_mock_block_hash(height as u32);
        insert_block(&conn, BlockRow::builder().height(height).hash(hash).build()).await?;

        insert_batch(&conn, 5, height, &hash.to_string(), b"cert5", false).await?;
        insert_batch(&conn, 3, height, &hash.to_string(), b"cert3", false).await?;
        insert_batch(&conn, 8, height, &hash.to_string(), b"cert8", false).await?;

        assert_eq!(select_min_batch_height(&conn).await?, Some(3));

        Ok(())
    }

    #[tokio::test]
    async fn test_select_batches_from_anchor() -> Result<()> {
        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();

        // Create blocks at heights 100 and 200
        for h in [100i64, 200] {
            let hash = new_mock_block_hash(h as u32);
            insert_block(&conn, BlockRow::builder().height(h).hash(hash).build()).await?;
        }

        let hash100 = new_mock_block_hash(100);
        let hash200 = new_mock_block_hash(200);

        // Batch at anchor 100
        insert_batch(&conn, 1, 100, &hash100.to_string(), b"cert1", false).await?;
        insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(100)
                .batch_height(1)
                .txid("aa".repeat(32))
                .build(),
        )
        .await?;

        // Batch at anchor 200
        insert_batch(&conn, 2, 200, &hash200.to_string(), b"cert2", false).await?;
        insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(200)
                .batch_height(2)
                .txid("bb".repeat(32))
                .build(),
        )
        .await?;
        insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(200)
                .batch_height(2)
                .txid("cc".repeat(32))
                .build(),
        )
        .await?;

        // Query from anchor 200 — should only return the second batch
        let results = select_batches_from_anchor(&conn, 200).await?;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].consensus_height, 2);
        assert_eq!(results[0].anchor_height, 200);
        assert_eq!(results[0].txids.len(), 2);

        // Query from anchor 100 — should return both
        let results = select_batches_from_anchor(&conn, 100).await?;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].consensus_height, 1);
        assert_eq!(results[0].txids.len(), 1);
        assert_eq!(results[1].consensus_height, 2);
        assert_eq!(results[1].txids.len(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_select_existing_txids() -> Result<()> {
        use crate::database::queries::select_existing_txids;

        let (_reader, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();

        // Create a block
        insert_block(
            &conn,
            BlockRow::builder()
                .height(100)
                .hash(new_mock_block_hash(100))
                .build(),
        )
        .await?;

        // Insert some transactions
        let txid_a = "aa".repeat(32);
        let txid_b = "bb".repeat(32);
        let txid_c = "cc".repeat(32);

        insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(100)
                .confirmed_height(100)
                .tx_index(0)
                .txid(txid_a.clone())
                .build(),
        )
        .await?;
        insert_batch(
            &conn,
            1,
            100,
            &new_mock_block_hash(100).to_string(),
            b"cert",
            false,
        )
        .await?;
        insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(100)
                .batch_height(1)
                .txid(txid_b.clone())
                .build(),
        )
        .await?;

        // Query with mix of existing and non-existing txids
        let result =
            select_existing_txids(&conn, &[txid_a.clone(), txid_b.clone(), txid_c.clone()]).await?;

        assert!(result.contains(&txid_a), "confirmed tx should be found");
        assert!(result.contains(&txid_b), "batched tx should be found");
        assert!(!result.contains(&txid_c), "unknown tx should not be found");
        assert_eq!(result.len(), 2);

        // Empty input returns empty result
        let empty = select_existing_txids(&conn, &[]).await?;
        assert!(empty.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_get_blocks_query() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        insert_block(
            &conn,
            BlockRow::builder()
                .height(100)
                .hash(new_mock_block_hash(100))
                .build(),
        )
        .await?;

        insert_block(
            &conn,
            BlockRow::builder()
                .height(101)
                .hash(new_mock_block_hash(101))
                .build(),
        )
        .await?;

        insert_block(
            &conn,
            BlockRow::builder()
                .height(102)
                .hash(new_mock_block_hash(102))
                .build(),
        )
        .await?;

        let (blocks, meta) =
            get_blocks_paginated(&conn, BlockQuery::builder().limit(1).build()).await?;

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 102);
        assert!(meta.has_more);
        assert_eq!(meta.next_cursor, Some(blocks[0].height));
        assert_eq!(meta.total_count, 3);

        let (blocks, meta) = get_blocks_paginated(
            &conn,
            BlockQuery::builder()
                .maybe_cursor(meta.next_cursor)
                .limit(1)
                .build(),
        )
        .await?;

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 101);
        assert!(meta.has_more);
        assert_eq!(meta.next_cursor, Some(blocks[0].height));

        let (blocks, meta) = get_blocks_paginated(
            &conn,
            BlockQuery::builder()
                .maybe_cursor(meta.next_cursor)
                .limit(1)
                .build(),
        )
        .await?;

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 100);
        assert!(!meta.has_more);
        assert_eq!(meta.next_cursor, Some(blocks[0].height));

        Ok(())
    }

    #[tokio::test]
    async fn test_get_blocks_query_relevant() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        insert_block(
            &conn,
            BlockRow::builder()
                .height(100)
                .hash(new_mock_block_hash(100))
                .relevant(true)
                .build(),
        )
        .await?;

        insert_block(
            &conn,
            BlockRow::builder()
                .height(101)
                .hash(new_mock_block_hash(101))
                .build(),
        )
        .await?;

        let (blocks, meta) =
            get_blocks_paginated(&conn, BlockQuery::builder().relevant(true).build()).await?;

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 100);
        assert!(!meta.has_more);
        assert_eq!(meta.next_cursor, Some(blocks[0].height));
        assert_eq!(meta.total_count, 1);

        let (blocks, meta) =
            get_blocks_paginated(&conn, BlockQuery::builder().relevant(false).build()).await?;

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 101);
        assert!(!meta.has_more);
        assert_eq!(meta.next_cursor, Some(blocks[0].height));
        assert_eq!(meta.total_count, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_results_query() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();

        insert_block(
            &conn,
            BlockRow::builder()
                .height(1)
                .hash(new_mock_block_hash(1))
                .build(),
        )
        .await?;

        let contract_1_id = insert_contract(
            &conn,
            ContractRow::builder()
                .name("token".to_string())
                .height(1)
                .tx_index(1)
                .bytes(vec![])
                .build(),
        )
        .await?;

        let contract_2_id = insert_contract(
            &conn,
            ContractRow::builder()
                .name("storage".to_string())
                .height(1)
                .tx_index(2)
                .bytes(vec![])
                .build(),
        )
        .await?;

        let tx_id_1_3 = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(1)
                .txid(new_mock_transaction(1003).txid.to_string())
                .tx_index(3)
                .build(),
        )
        .await?;

        let tx_id_1_4 = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(1)
                .txid(new_mock_transaction(1004).txid.to_string())
                .tx_index(4)
                .build(),
        )
        .await?;

        insert_contract_result(
            &conn,
            ContractResultRow::builder()
                .contract_id(contract_1_id)
                .height(1)
                .tx_id(tx_id_1_3)
                .input_index(0)
                .op_index(0)
                .gas(100)
                .build(),
        )
        .await?;

        insert_contract_result(
            &conn,
            ContractResultRow::builder()
                .contract_id(contract_2_id)
                .func("foo".to_string())
                .height(1)
                .tx_id(tx_id_1_4)
                .input_index(0)
                .op_index(0)
                .gas(100)
                .build(),
        )
        .await?;

        insert_block(
            &conn,
            BlockRow::builder()
                .height(2)
                .hash(new_mock_block_hash(2))
                .build(),
        )
        .await?;

        let tx_id_2_1 = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(2)
                .txid(new_mock_transaction(2001).txid.to_string())
                .tx_index(1)
                .build(),
        )
        .await?;

        let tx_id_2_2 = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(2)
                .txid(new_mock_transaction(2002).txid.to_string())
                .tx_index(2)
                .build(),
        )
        .await?;

        insert_contract_result(
            &conn,
            ContractResultRow::builder()
                .contract_id(contract_1_id)
                .height(2)
                .tx_id(tx_id_2_1)
                .input_index(0)
                .op_index(0)
                .gas(100)
                .build(),
        )
        .await?;

        insert_contract_result(
            &conn,
            ContractResultRow::builder()
                .contract_id(contract_2_id)
                .height(2)
                .tx_id(tx_id_2_2)
                .input_index(0)
                .op_index(0)
                .gas(100)
                .build(),
        )
        .await?;

        // contract result with NULL tx_id (no associated transaction)
        insert_contract_result(
            &conn,
            ContractResultRow::builder()
                .contract_id(contract_2_id)
                .height(2)
                .result_index(1)
                .gas(100)
                .build(),
        )
        .await?;

        let (_, meta) = get_results_paginated(
            &conn,
            ResultQuery::builder()
                .order(OrderDirection::Asc)
                .limit(1)
                .build(),
        )
        .await?;
        assert_eq!(meta.total_count, 5);

        // NULL tx_id result is included with txid: None
        let (results, _) = get_results_paginated(
            &conn,
            ResultQuery::builder()
                .height(2)
                .order(OrderDirection::Asc)
                .limit(10)
                .build(),
        )
        .await?;
        assert_eq!(results.len(), 3);

        // contract filtering
        let (results, meta) = get_results_paginated(
            &conn,
            ResultQuery::builder()
                .contract(ContractAddress {
                    name: "token".to_string(),
                    height: 1,
                    tx_index: 1,
                })
                .order(OrderDirection::Asc)
                .limit(1)
                .build(),
        )
        .await?;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].contract_name, "token");
        assert_eq!(results[0].contract_height, 1);
        assert_eq!(results[0].contract_tx_index, 1);
        assert_eq!(meta.total_count, 2);

        // func filtering
        let (results, meta) = get_results_paginated(
            &conn,
            ResultQuery::builder()
                .contract(ContractAddress {
                    name: "storage".to_string(),
                    height: 1,
                    tx_index: 2,
                })
                .func("foo".to_string())
                .order(OrderDirection::Asc)
                .limit(1)
                .build(),
        )
        .await?;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].func, "foo".to_string());
        assert_eq!(results[0].contract_name, "storage");
        assert_eq!(results[0].contract_height, 1);
        assert_eq!(results[0].contract_tx_index, 2);
        assert_eq!(meta.total_count, 1);
        assert_eq!(meta.next_cursor, Some(results[0].id));

        // height filtering
        let (results, meta) = get_results_paginated(
            &conn,
            ResultQuery::builder()
                .height(2)
                .contract(ContractAddress {
                    name: "token".to_string(),
                    height: 1,
                    tx_index: 1,
                })
                .order(OrderDirection::Asc)
                .limit(1)
                .build(),
        )
        .await?;
        assert_eq!(results[0].height, 2);
        assert_eq!(meta.total_count, 1);

        // start height
        let (results, meta) = get_results_paginated(
            &conn,
            ResultQuery::builder()
                .start_height(2)
                .contract(ContractAddress {
                    name: "token".to_string(),
                    height: 1,
                    tx_index: 1,
                })
                .order(OrderDirection::Asc)
                .limit(1)
                .build(),
        )
        .await?;
        assert_eq!(results[0].height, 2);
        assert_eq!(meta.total_count, 1);
        assert!(!meta.has_more);

        Ok(())
    }

    #[tokio::test]
    async fn test_transaction_query_contract_address() -> Result<()> {
        let x = serde_json::from_str::<TransactionQuery>(r#"{"contract": "token_1_0"}"#).unwrap();
        assert_eq!(
            x,
            TransactionQuery::builder()
                .contract(ContractAddress {
                    name: "token".to_string(),
                    height: 1,
                    tx_index: 0
                })
                .build()
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_basic_pagination_no_filters() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;

        // Test first page with limit 3
        let (transactions, meta) =
            get_transactions_paginated(&conn, TransactionQuery::builder().limit(3).build()).await?;

        assert_eq!(transactions.len(), 3);
        assert!(meta.has_more);
        assert_eq!(meta.total_count, 10); // 5 + 3 + 2 = 10 total
        assert!(meta.next_offset.is_some());
        assert_eq!(meta.next_offset, Some(3));
        assert!(meta.next_cursor.is_some());
        let cursor = meta.next_cursor.unwrap();
        assert_eq!(cursor, 8);

        // Verify ordering (DESC by height, then DESC by tx_index)
        assert_eq!(transactions[0].height, 800002);
        assert_eq!(transactions[0].tx_index, Some(1));
        assert_eq!(transactions[1].height, 800002);
        assert_eq!(transactions[1].tx_index, Some(0));
        assert_eq!(transactions[2].height, 800001);
        assert_eq!(transactions[2].tx_index, Some(2));

        Ok(())
    }

    #[tokio::test]
    async fn test_offset_pagination() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;
        // First page
        let (page1, meta1) =
            get_transactions_paginated(&conn, TransactionQuery::builder().limit(3).build()).await?;
        assert_eq!(page1.len(), 3);
        assert_eq!(meta1.next_offset, Some(3));
        assert!(meta1.has_more);
        assert!(meta1.next_cursor.is_some());

        // Second page using offset
        let (page2, meta2) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder().offset(3).limit(3).build(),
        )
        .await?;
        assert_eq!(page2.len(), 3);
        assert_eq!(meta2.next_offset, Some(6));
        assert!(meta2.has_more);
        assert!(meta2.next_cursor.is_none()); // offset pagination

        // Third page
        let (page3, meta3) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder().offset(6).limit(3).build(),
        )
        .await?;
        assert_eq!(page3.len(), 3);
        assert_eq!(meta3.next_offset, Some(9));
        assert!(meta3.has_more);

        // Fourth page (last page)
        let (page4, meta4) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder().offset(9).limit(3).build(),
        )
        .await?;
        assert_eq!(page4.len(), 1); // Only 1 transaction left
        assert_eq!(meta4.next_offset, Some(10)); // For polling - points past last item
        assert!(!meta4.has_more);

        // Verify no overlap between pages
        let all_txids: Vec<String> = [&page1, &page2, &page3, &page4]
            .iter()
            .flat_map(|page| page.iter().map(|tx| tx.txid.clone()))
            .collect();
        let unique_txids: std::collections::HashSet<String> = all_txids.iter().cloned().collect();
        assert_eq!(all_txids.len(), unique_txids.len()); // No duplicates

        Ok(())
    }

    #[tokio::test]
    async fn test_cursor_pagination() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;

        // First page with cursor pagination
        let (page1, meta1) =
            get_transactions_paginated(&conn, TransactionQuery::builder().limit(3).build()).await?;

        assert_eq!(page1.len(), 3);
        assert!(meta1.has_more);
        assert!(meta1.next_cursor.is_some());
        assert!(meta1.next_offset.is_some());

        let cursor = meta1.next_cursor.unwrap();
        assert_eq!(cursor, 8);

        let (page2, meta2) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .maybe_cursor(meta1.next_cursor)
                .limit(3)
                .build(),
        )
        .await?;

        assert_eq!(page2.len(), 3);
        assert!(meta2.has_more);
        assert!(meta2.next_cursor.is_some());
        assert!(meta2.next_offset.is_none());

        let cursor = meta2.next_cursor.unwrap();
        assert_eq!(cursor, 5);

        let (page3, meta3) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .maybe_cursor(meta2.next_cursor)
                .limit(3)
                .build(),
        )
        .await?;

        assert_eq!(page3.len(), 3);
        assert!(meta3.has_more);
        assert!(meta3.next_cursor.is_some());

        let cursor = meta3.next_cursor.unwrap();
        assert_eq!(cursor, 2);

        let (page4, meta4) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .maybe_cursor(meta3.next_cursor)
                .limit(3)
                .build(),
        )
        .await?;

        assert_eq!(page4.len(), 1);
        assert!(!meta4.has_more);
        assert_eq!(meta4.next_cursor, Some(page4[0].id));

        // Verify no overlap
        let all_txids: Vec<String> = [&page1, &page2, &page3, &page4]
            .iter()
            .flat_map(|page| page.iter().map(|tx| tx.txid.clone()))
            .collect();
        let unique_txids: std::collections::HashSet<String> = all_txids.iter().cloned().collect();
        assert_eq!(all_txids.len(), unique_txids.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_height_filter() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;
        // Filter by height 800001 (should have 3 transactions)
        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder().height(800001).limit(10).build(),
        )
        .await?;

        assert_eq!(transactions.len(), 3);
        assert_eq!(meta.total_count, 3);
        assert!(!meta.has_more);
        assert_eq!(meta.next_offset, Some(3));

        // Verify all transactions are from height 800001
        for tx in &transactions {
            assert_eq!(tx.height, 800001);
        }

        // Verify ordering within height (DESC by tx_index)
        assert_eq!(transactions[0].tx_index, Some(2));
        assert_eq!(transactions[1].tx_index, Some(1));
        assert_eq!(transactions[2].tx_index, Some(0));

        Ok(())
    }

    #[tokio::test]
    async fn test_height_filter_with_pagination() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;

        // Filter by height 800000 with limit 2 (should have 5 total, return 2)
        let (page1, meta1) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder().height(800000).limit(2).build(),
        )
        .await?;

        assert_eq!(page1.len(), 2);
        assert_eq!(meta1.total_count, 5);
        assert!(meta1.has_more);
        assert_eq!(meta1.next_offset, Some(2));

        // Get second page
        let (page2, meta2) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .height(800000)
                .offset(2)
                .limit(2)
                .build(),
        )
        .await?;

        assert_eq!(page2.len(), 2);
        assert!(meta2.has_more);
        assert_eq!(meta2.next_offset, Some(4));

        // Get final page
        let (page3, meta3) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .height(800000)
                .offset(4)
                .limit(2)
                .build(),
        )
        .await?;

        assert_eq!(page3.len(), 1); // Last transaction
        assert!(!meta3.has_more);
        assert_eq!(meta3.next_offset, Some(5));

        Ok(())
    }

    #[tokio::test]
    async fn test_cursor_and_offset_conflict() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;

        // When both cursor and offset are provided, cursor takes precedence
        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .cursor(9)
                .offset(5)
                .limit(3)
                .build(),
        )
        .await?;

        // Should use cursor pagination (ignore offset)
        assert!(meta.next_cursor.is_none());
        assert!(meta.next_offset.is_none());

        // Should return transactions with (height, tx_index) < (800001, 1)
        for tx in &transactions {
            assert!(tx.height == 800001);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_empty_result_set() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;

        // Query for non-existent height
        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder().height(999999).limit(10).build(),
        )
        .await?;

        assert_eq!(transactions.len(), 0);
        assert_eq!(meta.total_count, 0);
        assert!(!meta.has_more);
        assert_eq!(meta.next_offset, Some(0));
        assert!(meta.next_cursor.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_large_limit() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;

        // Request more than available
        let (transactions, meta) =
            get_transactions_paginated(&conn, TransactionQuery::builder().limit(100).build())
                .await?;

        assert_eq!(transactions.len(), 10); // All available transactions
        assert!(!meta.has_more);
        assert_eq!(meta.next_offset, Some(10));
        assert_eq!(meta.total_count, 10);

        Ok(())
    }

    #[tokio::test]
    async fn test_zero_limit() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;

        let (transactions, meta) =
            get_transactions_paginated(&conn, TransactionQuery::builder().limit(0).build()).await?;

        assert_eq!(transactions.len(), 0);
        assert!(meta.has_more); // There are transactions available
        assert_eq!(meta.next_offset, Some(0)); // Next offset should be 0
        assert_eq!(meta.total_count, 10);

        Ok(())
    }

    #[tokio::test]
    async fn test_cursor_boundary_conditions() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;

        // Cursor pointing to the very first transaction
        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder().cursor(10).limit(10).build(),
        )
        .await?;

        assert_eq!(transactions.len(), 9);
        assert!(!meta.has_more);

        // Cursor pointing beyond all transactions
        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder().cursor(11).limit(10).build(),
        )
        .await?;

        assert_eq!(transactions.len(), 10);
        assert!(!meta.has_more);

        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder().cursor(0).limit(10).build(),
        )
        .await?;

        assert_eq!(transactions.len(), 0);
        assert!(!meta.has_more);

        Ok(())
    }

    #[tokio::test]
    async fn test_cursor_contract_address_querying() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;

        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .contract(ContractAddress {
                    name: "token".to_string(),
                    height: 800000,
                    tx_index: 1,
                })
                .limit(1)
                .build(),
        )
        .await?;

        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].height, 800002);
        assert_eq!(transactions[0].tx_index, Some(0));
        assert!(meta.has_more);
        assert_eq!(meta.next_cursor, Some(transactions[0].id));
        assert_eq!(meta.total_count, 3);

        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .maybe_cursor(meta.next_cursor)
                .contract(ContractAddress {
                    name: "token".to_string(),
                    height: 800000,
                    tx_index: 1,
                })
                .limit(1)
                .build(),
        )
        .await?;

        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].height, 800001);
        assert_eq!(transactions[0].tx_index, Some(1));
        assert!(meta.has_more);
        assert_eq!(meta.next_cursor, Some(transactions[0].id));

        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .maybe_cursor(meta.next_cursor)
                .contract(ContractAddress {
                    name: "token".to_string(),
                    height: 800000,
                    tx_index: 1,
                })
                .limit(1)
                .build(),
        )
        .await?;

        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].height, 800000);
        assert_eq!(transactions[0].tx_index, Some(0));
        assert!(!meta.has_more);
        assert_eq!(meta.next_cursor, Some(transactions[0].id));

        Ok(())
    }

    #[tokio::test]
    async fn test_cursor_contract_address_querying_asc() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_test_data(&conn).await?;

        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .contract(ContractAddress {
                    name: "token".to_string(),
                    height: 800000,
                    tx_index: 1,
                })
                .limit(1)
                .order(OrderDirection::Asc)
                .build(),
        )
        .await?;

        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].height, 800000);
        assert_eq!(transactions[0].tx_index, Some(0));
        assert!(meta.has_more);
        assert_eq!(meta.next_cursor, Some(transactions[0].id));
        assert_eq!(meta.total_count, 3);

        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .maybe_cursor(meta.next_cursor)
                .contract(ContractAddress {
                    name: "token".to_string(),
                    height: 800000,
                    tx_index: 1,
                })
                .limit(1)
                .order(OrderDirection::Asc)
                .build(),
        )
        .await?;

        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].height, 800001);
        assert_eq!(transactions[0].tx_index, Some(1));
        assert!(meta.has_more);
        assert_eq!(meta.next_cursor, Some(transactions[0].id));

        let (transactions, meta) = get_transactions_paginated(
            &conn,
            TransactionQuery::builder()
                .maybe_cursor(meta.next_cursor)
                .contract(ContractAddress {
                    name: "token".to_string(),
                    height: 800000,
                    tx_index: 1,
                })
                .limit(1)
                .order(OrderDirection::Asc)
                .build(),
        )
        .await?;

        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].height, 800002);
        assert_eq!(transactions[0].tx_index, Some(0));
        assert!(!meta.has_more);
        assert_eq!(meta.next_cursor, Some(transactions[0].id));

        Ok(())
    }

    async fn setup_block(conn: &Connection, height: i64) -> Result<()> {
        insert_block(
            conn,
            BlockRow {
                height,
                hash: new_mock_block_hash(height as u32),
                relevant: true,
            },
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_ensure_signer_creates_new() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_block(&conn, 1).await?;

        let row = ensure_signer(&conn, "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233", 1).await?;
        assert_eq!(row.x_only_pubkey, "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233");
        assert_eq!(row.height, 1);
        assert!(row.signer_id > 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_ensure_signer_returns_existing() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_block(&conn, 1).await?;
        setup_block(&conn, 2).await?;

        let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        let row1 = ensure_signer(&conn, pubkey, 1).await?;
        let row2 = ensure_signer(&conn, pubkey, 2).await?;
        assert_eq!(row1.signer_id, row2.signer_id);
        assert_eq!(row1.height, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_advance_nonce() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_block(&conn, 1).await?;
        setup_block(&conn, 2).await?;

        let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        let row = ensure_signer(&conn, pubkey, 1).await?;

        let next = advance_nonce(&conn, row.signer_id, 0, 1).await?;
        assert_eq!(next, 1);

        let next = advance_nonce(&conn, row.signer_id, 1, 2).await?;
        assert_eq!(next, 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_advance_nonce_gap() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_block(&conn, 1).await?;

        let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        let row = ensure_signer(&conn, pubkey, 1).await?;

        let next = advance_nonce(&conn, row.signer_id, 5, 1).await?;
        assert_eq!(next, 6);

        Ok(())
    }

    #[tokio::test]
    async fn test_advance_nonce_replay_rejected() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_block(&conn, 1).await?;
        setup_block(&conn, 2).await?;

        let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        let row = ensure_signer(&conn, pubkey, 1).await?;

        advance_nonce(&conn, row.signer_id, 0, 1).await?;
        let result = advance_nonce(&conn, row.signer_id, 0, 2).await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_register_bls_key() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_block(&conn, 1).await?;

        let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        let row = ensure_signer(&conn, pubkey, 1).await?;

        let bls_key = vec![1u8; 48];
        register_bls_key(&conn, row.signer_id, &bls_key, 1).await?;

        let entry = get_signer_entry(&conn, pubkey).await?.unwrap();
        assert_eq!(entry.bls_pubkey, Some(bls_key));

        Ok(())
    }

    #[tokio::test]
    async fn test_get_signer_entry() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_block(&conn, 1).await?;

        let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        let row = ensure_signer(&conn, pubkey, 1).await?;

        let entry = get_signer_entry(&conn, pubkey).await?.unwrap();
        assert_eq!(entry.signer_id, row.signer_id);
        assert_eq!(entry.x_only_pubkey, pubkey);
        assert_eq!(entry.bls_pubkey, None);
        assert_eq!(entry.next_nonce, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_signer_entry_by_id() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_block(&conn, 1).await?;

        let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        let row = ensure_signer(&conn, pubkey, 1).await?;

        let entry = get_signer_entry_by_id(&conn, row.signer_id).await?.unwrap();
        assert_eq!(entry.x_only_pubkey, pubkey);
        assert_eq!(entry.next_nonce, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_signer_rollback() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_block(&conn, 1).await?;
        setup_block(&conn, 2).await?;
        setup_block(&conn, 3).await?;

        let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        let row = ensure_signer(&conn, pubkey, 1).await?;
        advance_nonce(&conn, row.signer_id, 0, 2).await?;
        register_bls_key(&conn, row.signer_id, &vec![1u8; 48], 3).await?;

        // Rollback to height 2 — should remove bls_key (height 3) but keep nonce (height 2)
        rollback_to_height(&conn, 2).await?;

        let entry = get_signer_entry(&conn, pubkey).await?.unwrap();
        assert_eq!(entry.bls_pubkey, None);
        assert_eq!(entry.next_nonce, 1);

        // Rollback to height 0 — should remove everything
        rollback_to_height(&conn, 0).await?;
        let entry = get_signer_entry(&conn, pubkey).await?;
        assert!(entry.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_identity_dao() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_block(&conn, 1).await?;

        let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        let identity = get_or_create_identity(&conn, pubkey, 1).await?;

        assert_eq!(identity.x_only_pubkey(&conn).await?, pubkey);
        assert_eq!(identity.bls_pubkey(&conn).await?, None);
        assert_eq!(identity.next_nonce(&conn).await?, 0);

        let bls_key = vec![1u8; 48];
        register_bls_key(&conn, identity.signer_id, &bls_key, 1).await?;
        assert_eq!(identity.bls_pubkey(&conn).await?, Some(bls_key));

        advance_nonce(&conn, identity.signer_id, 0, 1).await?;
        assert_eq!(identity.next_nonce(&conn).await?, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_or_create_identity_idempotent() -> Result<()> {
        let (_, writer, _temp_dir) = new_test_db().await?;
        let conn = writer.connection();
        setup_block(&conn, 1).await?;
        setup_block(&conn, 2).await?;

        let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        let id1 = get_or_create_identity(&conn, pubkey, 1).await?;
        let id2 = get_or_create_identity(&conn, pubkey, 2).await?;
        assert_eq!(id1.signer_id, id2.signer_id);

        Ok(())
    }
}
