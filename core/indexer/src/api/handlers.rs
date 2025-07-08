use axum::extract::{Path, Query, State};

use crate::{
    bitcoin_client::types::TestMempoolAcceptResult,
    database::{
        queries::{
            get_transaction_by_txid, get_transactions_paginated, select_block_by_height_or_hash,
            select_block_latest,
        },
        types::{BlockRow, TransactionListResponse, TransactionQuery, TransactionRow},
    },
};

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
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, ToSchema, IntoParams)]
pub struct TxsQuery {
    txs: String,
}

#[utoipa::path(
    get,
    path = "/api/blocks/{identifier}",
    params(
        ("identifier" = String, Path, description = "Block height or hash")
    ),
    responses(
        (status = 200, description = "Block found", body = BlockRow),
        (status = 404, description = "Block not found")
    )
)]
pub async fn get_block(State(env): State<Env>, Path(identifier): Path<String>) -> Result<BlockRow> {
    match select_block_by_height_or_hash(&*env.reader.connection().await?, &identifier).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound(format!("block at height or hash: {}", identifier)).into()),
    }
}

#[utoipa::path(
    get,
    path = "/api/blocks/latest",
    responses(
        (status = 200, description = "Latest block found", body = BlockRow),
        (status = 404, description = "No blocks written")
    )
)]
pub async fn get_block_latest(State(env): State<Env>) -> Result<BlockRow> {
    match select_block_latest(&*env.reader.connection().await?).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound("No blocks written".to_owned()).into()),
    }
}

#[utoipa::path(
    get,
    path = "/api/test_mempool_accept",
    params(
        TxsQuery
    ),
    responses(
        (status = 200, description = "Transactions tested", body = Vec<TestMempoolAcceptResult>)
    )
)]
pub async fn test_mempool_accept(
    Query(query): Query<TxsQuery>,
    State(env): State<Env>,
) -> Result<Vec<TestMempoolAcceptResult>> {
    let txs: Vec<String> = query.txs.split(',').map(|s| s.to_string()).collect();

    let results = env.bitcoin.test_mempool_accept(&txs).await?;
    Ok(results.into())
}

#[utoipa::path(
    get,
    path = "/compose",
    params(
        ComposeQuery
    ),
    responses(
        (status = 200, description = "Composed transaction", body = ComposeOutputs),
        (status = 400, description = "Bad request")
    )
)]
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

#[utoipa::path(
    get,
    path = "/compose/commit",
    params(
        ComposeQuery
    ),
    responses(
        (status = 200, description = "Composed commit transaction", body = CommitOutputs),
        (status = 400, description = "Bad request")
    )
)]
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

#[utoipa::path(
    get,
    path = "/compose/reveal",
    params(
        RevealQuery
    ),
    responses(
        (status = 200, description = "Composed reveal transaction", body = RevealOutputs),
        (status = 400, description = "Bad request")
    )
)]
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

// Shared implementation for transaction queries
pub async fn get_transactions(
    Query(query): Query<TransactionQuery>,
    State(env): State<Env>,
    path: Option<Path<i64>>,
) -> Result<TransactionListResponse> {
    let limit = query.limit.map_or(20, |l| l.clamp(1, 1000));
    if query.cursor.is_some() && query.offset.is_some() {
        return Err(HttpError::BadRequest(
            "Cannot specify both cursor and offset parameters".to_string(),
        )
        .into());
    }
    // Extract height from optional path
    let height = path.map(|Path(h)| h);
    // Start a transaction
    let conn = env.reader.connection().await?;
    let tx = conn.transaction().await?;
    let (transactions, pagination) =
        get_transactions_paginated(&tx, height, query.cursor, query.offset, limit).await?;
    // Commit the transaction
    tx.commit().await?;
    Ok(TransactionListResponse {
        transactions,
        pagination,
    }
    .into())
}

// Wrapper functions for OpenAPI documentation
#[utoipa::path(
    get,
    path = "/api/transactions",
    params(
        TransactionQuery
    ),
    responses(
        (status = 200, description = "List of transactions", body = TransactionListResponse),
        (status = 400, description = "Bad request")
    )
)]
pub async fn get_transactions_root(
    query: Query<TransactionQuery>,
    state: State<Env>,
) -> Result<TransactionListResponse> {
    get_transactions(query, state, None).await
}

#[utoipa::path(
    get,
    path = "/api/blocks/{height}/transactions",
    params(
        ("height" = i64, Path, description = "Block height"),
        TransactionQuery
    ),
    responses(
        (status = 200, description = "List of transactions for block", body = TransactionListResponse),
        (status = 400, description = "Bad request")
    )
)]
pub async fn get_transactions_for_block(
    path: Path<i64>,
    query: Query<TransactionQuery>,
    state: State<Env>,
) -> Result<TransactionListResponse> {
    get_transactions(query, state, Some(path)).await
}

#[utoipa::path(
    get,
    path = "/api/transactions/{txid}",
    params(
        ("txid" = String, Path, description = "Transaction ID")
    ),
    responses(
        (status = 200, description = "Transaction found", body = TransactionRow),
        (status = 404, description = "Transaction not found")
    )
)]
pub async fn get_transaction(
    Path(txid): Path<String>,
    State(env): State<Env>,
) -> Result<TransactionRow> {
    match get_transaction_by_txid(&*env.reader.connection().await?, &txid).await? {
        Some(transaction) => Ok(transaction.into()),
        None => Err(HttpError::NotFound(format!("transaction: {}", txid)).into()),
    }
}
