use crate::{
    bitcoin_client::types::TestMempoolAcceptResult,
    database::{
        queries::{
            count_blocks, count_transactions, get_transaction_by_txid, select_block_at_height,
            select_block_latest, select_blocks_cursor, select_blocks_paginated,
            select_transactions_cursor, select_transactions_paginated,
        },
        types::{
            BlockCursor, BlockRow, CursorQuery, CursorResponse, PaginatedResponse, PaginationQuery,
            TransactionCursor, TransactionRow,
        },
    },
};
use axum::extract::{Path, Query, State};

use super::{
    Env,
    compose::{
        CommitInputs, CommitOutputs, ComposeInputs, ComposeOutputs, ComposeQuery, RevealInputs,
        RevealOutputs, RevealQuery, compose, compose_commit, compose_reveal,
    },
    error::HttpError,
    result::Result,
};

use serde::Deserialize;

#[derive(Deserialize)]
pub struct TxsQuery {
    txs: String,
}

pub async fn get_block(State(env): State<Env>, Path(height): Path<u64>) -> Result<BlockRow> {
    match select_block_at_height(&*env.reader.connection().await?, height).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound(format!("block at height: {}", height)).into()),
    }
}

pub async fn get_block_latest(State(env): State<Env>) -> Result<BlockRow> {
    match select_block_latest(&*env.reader.connection().await?).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound("No blocks written".to_owned()).into()),
    }
}

pub async fn test_mempool_accept(
    Query(query): Query<TxsQuery>,
    State(env): State<Env>,
) -> Result<Vec<TestMempoolAcceptResult>> {
    let txs: Vec<String> = query.txs.split(',').map(|s| s.to_string()).collect();

    let results = env.bitcoin.test_mempool_accept(&txs).await?;
    Ok(results.into())
}

pub async fn get_compose(
    Query(query): Query<ComposeQuery>,
    State(env): State<Env>,
) -> Result<ComposeOutputs> {
    let inputs = ComposeInputs::from_query(query, &env.bitcoin)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;

    let outputs = compose(inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
}

pub async fn get_compose_commit(
    Query(query): Query<ComposeQuery>,
    State(env): State<Env>, // TODO
) -> Result<CommitOutputs> {
    let inputs = ComposeInputs::from_query(query, &env.bitcoin)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let commit_inputs = CommitInputs::from(inputs);

    let outputs =
        compose_commit(commit_inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
}

pub async fn get_compose_reveal(
    Query(query): Query<RevealQuery>,
    State(env): State<Env>,
) -> Result<RevealOutputs> {
    let inputs = RevealInputs::from_query(query, &env.bitcoin)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let outputs = compose_reveal(inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
}

// OFFSET PAGINATION HANDLERS
pub async fn get_blocks_paginated(
    Query(pagination): Query<PaginationQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<BlockRow>> {
    pagination
        .validate()
        .map_err(HttpError::BadRequest)?;

    let conn = &*env.reader.connection().await?;
    let total = count_blocks(conn).await?;
    let blocks = select_blocks_paginated(conn, pagination.offset, pagination.limit).await?;

    Ok(PaginatedResponse {
        data: blocks,
        total,
        offset: pagination.offset,
        limit: pagination.limit,
        has_more: pagination.offset + pagination.limit < total,
    }
    .into())
}

pub async fn get_transactions_paginated(
    Query(pagination): Query<PaginationQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<TransactionRow>> {
    pagination
        .validate()
        .map_err(HttpError::BadRequest)?;

    let conn = &*env.reader.connection().await?;
    let total = count_transactions(conn).await?;
    let transactions =
        select_transactions_paginated(conn, pagination.offset, pagination.limit).await?;

    Ok(PaginatedResponse {
        data: transactions,
        total,
        offset: pagination.offset,
        limit: pagination.limit,
        has_more: pagination.offset + pagination.limit < total,
    }
    .into())
}

// CURSOR PAGINATION HANDLERS
pub async fn get_blocks_cursor(
    Query(query): Query<CursorQuery>,
    State(env): State<Env>,
) -> Result<CursorResponse<BlockRow>> {
    query.validate().map_err(HttpError::BadRequest)?;

    let cursor = match query.cursor {
        Some(c) => Some(BlockCursor::decode(&c).map_err(HttpError::BadRequest)?),
        None => None,
    };

    let conn = &*env.reader.connection().await?;
    let (mut blocks, latest_height) = select_blocks_cursor(conn, cursor, query.limit).await?;

    // Check if there are more results
    let has_more = blocks.len() > query.limit as usize;
    if has_more {
        blocks.pop(); // Remove the extra item
    }

    let next_cursor = if has_more && !blocks.is_empty() {
        let last = &blocks[blocks.len() - 1];
        Some(
            BlockCursor {
                height: last.height,
            }
            .encode(),
        )
    } else {
        None
    };

    Ok(CursorResponse {
        data: blocks,
        next_cursor,
        has_more,
        latest_height,
    }
    .into())
}

pub async fn get_transactions_cursor(
    Query(query): Query<CursorQuery>,
    State(env): State<Env>,
) -> Result<CursorResponse<TransactionRow>> {
    query.validate().map_err(HttpError::BadRequest)?;

    let cursor = match query.cursor {
        Some(c) => Some(TransactionCursor::decode(&c).map_err(HttpError::BadRequest)?),
        None => None,
    };

    let conn = &*env.reader.connection().await?;
    let (mut transactions, latest_height) =
        select_transactions_cursor(conn, cursor, query.limit).await?;

    // Check if there are more results
    let has_more = transactions.len() > query.limit as usize;
    if has_more {
        transactions.pop(); // Remove the extra item
    }

    let next_cursor = if has_more && !transactions.is_empty() {
        let last = &transactions[transactions.len() - 1];
        Some(
            TransactionCursor {
                height: last.height,
                id: last.id.expect("Transaction ID should be present"),
            }
            .encode(),
        )
    } else {
        None
    };

    Ok(CursorResponse {
        data: transactions,
        next_cursor,
        has_more,
        latest_height,
    }
    .into())
}

pub async fn get_transaction_by_txid_handler(
    Path(txid): Path<String>,
    State(env): State<Env>,
) -> Result<TransactionRow> {
    if let Some(tx) =
        get_transaction_by_txid(&*env.reader.connection().await?, &txid)
            .await?
    {
        Ok(tx.into())
    } else {
        Err(HttpError::NotFound(format!("transaction: {}", txid)).into())
    }
}
