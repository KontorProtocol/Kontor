use std::str::FromStr;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bitcoin::consensus::encode;
use indexer_types::{OpWithResult, PaginatedResponse, TransactionHex, TransactionRow};

use super::validate_query;
use crate::api::{Env, error::HttpError, result::Result};
use crate::block::{filter_map, inspect};
use crate::database::queries::{get_transaction_by_txid, get_transactions_paginated};
use crate::database::types::TransactionQuery;

pub async fn get_transactions(
    Query(query): Query<TransactionQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<TransactionRow>> {
    validate_query(query.cursor, query.offset)?;
    let (results, pagination) =
        get_transactions_paginated(&*env.reader.connection().await?, query).await?;
    Ok(PaginatedResponse {
        results,
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

pub async fn post_transaction_hex_inspect(
    State(env): State<Env>,
    Json(TransactionHex { hex }): Json<TransactionHex>,
) -> Result<Vec<OpWithResult>> {
    let btx = encode::deserialize_hex::<bitcoin::Transaction>(&hex)
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let tx = filter_map((0, btx))
        .ok_or_else(|| HttpError::BadRequest("Not a valid Kontor transaction".to_string()))?;
    let conn = env.reader.connection().await?;
    Ok(inspect(&conn, &tx).await?.into())
}

pub async fn get_transaction_inspect(
    State(env): State<Env>,
    Path(txid): Path<String>,
) -> Result<Vec<OpWithResult>> {
    let txid = bitcoin::Txid::from_str(&txid)
        .map_err(|e| HttpError::BadRequest(format!("Invalid txid: {}", e)))?;
    let btx = env.bitcoin.get_raw_transaction(&txid).await?;
    let tx = filter_map((0, btx))
        .ok_or_else(|| HttpError::BadRequest("Not a valid Kontor transaction".to_string()))?;
    let conn = env.reader.connection().await?;
    Ok(inspect(&conn, &tx).await?.into())
}

pub async fn post_simulate(
    State(env): State<Env>,
    Json(TransactionHex { hex }): Json<TransactionHex>,
) -> Result<Vec<OpWithResult>> {
    let btx = encode::deserialize_hex::<bitcoin::Transaction>(&hex)
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let tx = filter_map((0, btx))
        .ok_or_else(|| HttpError::BadRequest("Not a valid Kontor transaction".to_string()))?;
    let (ret_tx, ret_rx) = tokio::sync::oneshot::channel();
    env.simulate_tx.send((tx, ret_tx)).await?;
    Ok(ret_rx
        .await?
        .map_err(|e| HttpError::BadRequest(e.to_string()))?
        .into())
}
