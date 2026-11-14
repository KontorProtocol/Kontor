use std::str::FromStr;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bitcoin::consensus::encode;
use bitcoin::hex::HexSliceToBytesIter;
use indexer_types::{
    InspectedOp, OpWithResult, PaginatedResponse, TransactionHex, TransactionInfo,
};
use libsql::TransactionBehavior;

use super::validate_query;
use crate::api::{
    Env, confirmation,
    error::{Error as ApiError, HttpError},
    result::Result,
};
use crate::block::{filter_map_for_network, inspect};
use crate::database::queries::{get_transaction_by_txid, get_transactions_paginated};
use crate::database::types::TransactionQuery;
use crate::protocol_info::SimulationReport;

pub async fn get_transactions(
    Query(query): Query<TransactionQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<TransactionInfo>> {
    validate_query(query.cursor, query.offset)?;
    let conn = env.reader.connection().await?;
    let snapshot = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .await?;
    let (rows, pagination) = get_transactions_paginated(&snapshot, query).await?;
    let results = confirmation::transactions(&snapshot, rows).await?;
    snapshot.commit().await?;
    Ok(PaginatedResponse {
        results,
        pagination,
    }
    .into())
}

pub async fn get_transaction(
    Path(txid): Path<String>,
    State(env): State<Env>,
) -> Result<TransactionInfo> {
    let conn = env.reader.connection().await?;
    let snapshot = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .await?;
    let row = get_transaction_by_txid(&snapshot, &txid).await?;
    let result = confirmation::transactions(&snapshot, row.into_iter().collect())
        .await?
        .pop();
    snapshot.commit().await?;
    match result {
        Some(transaction) => Ok(transaction.into()),
        None => Err(HttpError::NotFound(format!("transaction: {}", txid)).into()),
    }
}

pub async fn post_transaction_hex_inspect(
    State(env): State<Env>,
    Json(TransactionHex { hex }): Json<TransactionHex>,
) -> Result<Vec<InspectedOp>> {
    let btx = encode::deserialize_hex::<bitcoin::Transaction>(&hex)
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let tx = filter_map_for_network((0, btx), env.config.network)
        .ok_or_else(|| HttpError::BadRequest("Not a valid Kontor transaction".to_string()))?;
    let conn = env.reader.connection().await?;
    let snapshot = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .await?;
    let ops = inspect(&snapshot, &tx).await?;
    let result = confirmation::inspection(&snapshot, ops).await?;
    snapshot.commit().await?;
    Ok(result.into())
}

pub async fn get_transaction_inspect(
    State(env): State<Env>,
    Path(txid): Path<String>,
) -> Result<Vec<InspectedOp>> {
    let txid = bitcoin::Txid::from_str(&txid)
        .map_err(|e| HttpError::BadRequest(format!("Invalid txid: {}", e)))?;
    let btx = env.bitcoin.get_raw_transaction(&txid).await?;
    let tx = filter_map_for_network((0, btx), env.config.network)
        .ok_or_else(|| HttpError::BadRequest("Not a valid Kontor transaction".to_string()))?;
    let conn = env.reader.connection().await?;
    let snapshot = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .await?;
    let ops = inspect(&snapshot, &tx).await?;
    let result = confirmation::inspection(&snapshot, ops).await?;
    snapshot.commit().await?;
    Ok(result.into())
}

pub async fn post_simulate(
    State(env): State<Env>,
    Json(TransactionHex { hex }): Json<TransactionHex>,
) -> Result<Vec<OpWithResult>> {
    Ok(simulate(&env, hex).await?.operations.into())
}

pub async fn post_simulate_context(
    State(env): State<Env>,
    Json(TransactionHex { hex }): Json<TransactionHex>,
) -> Result<SimulationReport> {
    Ok(simulate(&env, hex).await?.into())
}

async fn simulate(env: &Env, hex: String) -> std::result::Result<SimulationReport, ApiError> {
    let raw = HexSliceToBytesIter::new(&hex)
        .map_err(encode::FromHexError::from)
        .and_then(|bytes| {
            bytes
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| {
                    // P1 may report an earlier consensus error before reaching a bad
                    // hex suffix. Preserve that error precedence for rejected syntax;
                    // valid hex never decodes a Bitcoin transaction before admission.
                    encode::deserialize_hex::<bitcoin::Transaction>(&hex)
                        .expect_err("invalid hex cannot decode a transaction")
                })
        })
        .map_err(|error| HttpError::BadRequest(error.to_string()))?;
    let (ret_tx, ret_rx) = tokio::sync::oneshot::channel();
    env.simulate_tx.send((raw, ret_tx)).await?;
    Ok(ret_rx
        .await?
        .map_err(|e| HttpError::BadRequest(e.to_string()))?
        .map_err(HttpError::BadRequest)?)
}
