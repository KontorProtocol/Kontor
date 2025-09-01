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
        CommitInputs, CommitOutputs, ComposeAddressQuery, ComposeInputs, ComposeOutputs,
        ComposeQuery, RevealInputs, RevealOutputs, RevealQuery, compose, compose_commit,
        compose_reveal,
    },
    error::HttpError,
    result::Result,
};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as base64_engine;
use serde::Deserialize;
use serde::Serialize;
use serde_json;

#[derive(Deserialize)]
pub struct TxsQuery {
    txs: String,
}

pub async fn get_block(State(env): State<Env>, Path(identifier): Path<String>) -> Result<BlockRow> {
    match select_block_by_height_or_hash(&*env.reader.connection().await?, &identifier).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound(format!("block at height or hash: {}", identifier)).into()),
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
    Query(query): Query<ComposeAddressesB64Query>,
    State(env): State<Env>,
) -> Result<ComposeOutputs> {
    // Hard cap addresses payload
    if query.addresses.len() > 64 * 1024 {
        return Err(HttpError::BadRequest("addresses too large".to_string()).into());
    }
    let decoded_addresses: Vec<ComposeAddressQuery> =
        decode_addresses_b64(&query.addresses).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    let cq = ComposeQuery {
        addresses: decoded_addresses,
        script_data: query.script_data,
        sat_per_vbyte: query.sat_per_vbyte,
        change_output: query.change_output,
        envelope: query.envelope,
        chained_script_data: query.chained_script_data,
    };

    let inputs = ComposeInputs::from_query(cq, &env.bitcoin)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;

    let outputs = compose(inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
}

pub async fn get_compose_commit(
    Query(query): Query<ComposeAddressesB64Query>,
    State(env): State<Env>, // TODO
) -> Result<CommitOutputs> {
    if query.addresses.len() > 64 * 1024 {
        return Err(HttpError::BadRequest("addresses too large".to_string()).into());
    }
    let decoded_addresses: Vec<ComposeAddressQuery> =
        decode_addresses_b64(&query.addresses).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    let cq = ComposeQuery {
        addresses: decoded_addresses,
        script_data: query.script_data,
        sat_per_vbyte: query.sat_per_vbyte,
        change_output: query.change_output,
        envelope: query.envelope,
        chained_script_data: query.chained_script_data,
    };

    let inputs = ComposeInputs::from_query(cq, &env.bitcoin)
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

#[derive(Deserialize, Serialize)]
pub struct ComposeAddressesB64Query {
    pub addresses: String, // base64-encoded JSON Vec<ComposeAddressQuery>
    pub script_data: String,
    pub sat_per_vbyte: u64,
    pub change_output: Option<bool>,
    pub envelope: Option<u64>,
    pub chained_script_data: Option<String>,
}

fn decode_addresses_b64(s: &str) -> anyhow::Result<Vec<ComposeAddressQuery>> {
    let bytes = base64_engine
        .decode(s)
        .map_err(|e| anyhow::anyhow!("invalid base64 in addresses: {}", e))?;
    let addrs: Vec<ComposeAddressQuery> = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid JSON in addresses: {}", e))?;
    Ok(addrs)
}

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

pub async fn get_transaction(
    Path(txid): Path<String>,
    State(env): State<Env>,
) -> Result<TransactionRow> {
    match get_transaction_by_txid(&*env.reader.connection().await?, &txid).await? {
        Some(transaction) => Ok(transaction.into()),
        None => Err(HttpError::NotFound(format!("transaction: {}", txid)).into()),
    }
}
