use std::str::FromStr;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bitcoin::consensus::encode;
use indexer_types::{
    BroadcastQuery, BroadcastResult, OpWithResult, PaginatedResponse, TransactionHex,
    TransactionRow,
};

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

/// Relay a package of raw Bitcoin transactions (dependency order — e.g.
/// `[commit, reveal]`) to bitcoind via `submitpackage`. Lets SDK clients
/// — browser ones especially — broadcast without their own bitcoind RPC
/// access. Returns the last tx's txid; a rejected package is a 400 with
/// the reason.
pub async fn post_transaction_broadcast(
    State(env): State<Env>,
    Json(BroadcastQuery { transactions }): Json<BroadcastQuery>,
) -> Result<BroadcastResult> {
    let last = transactions
        .last()
        .ok_or_else(|| HttpError::BadRequest("no transactions provided".to_string()))?;
    // Deserialize the last tx up front: validates the hex and gives the
    // txid to return (submitpackage keys its results by wtxid).
    let last_txid = encode::deserialize_hex::<bitcoin::Transaction>(last)
        .map_err(|e| HttpError::BadRequest(format!("invalid transaction hex: {e}")))?
        .compute_txid();

    // `submitpackage` (Bitcoin Core 30) only accepts child-with-parents
    // topology — a single child plus its direct parents. The 2-tx
    // commit-reveal pair fits; the marketplace swap's 4-tx
    // `[attachCommit, attachReveal, buyerCommit, swapReveal]` DAG
    // (swapReveal has two independent roots: attachReveal's parent +
    // buyerCommit) does not. For larger packages we fall back to
    // tx-by-tx relay; each Kontor tx funds its own fee (compose sizes
    // each), so a successful parent followed by a failing child orphans
    // the parent in mempool until it expires — recoverable, but the
    // caller sees a half-broadcast state.
    if transactions.len() <= 2 {
        let result = env
            .bitcoin
            .submit_package(&transactions)
            .await
            .map_err(|e| HttpError::BadRequest(format!("broadcast failed: {e}")))?;
        if result.package_msg != "success" {
            let detail = result
                .tx_results
                .values()
                .find_map(|r| r.error.clone())
                .unwrap_or(result.package_msg);
            return Err(HttpError::BadRequest(format!("package rejected: {detail}")).into());
        }
    } else {
        for raw in &transactions {
            env.bitcoin
                .send_raw_transaction(raw)
                .await
                .map_err(|e| HttpError::BadRequest(format!("broadcast failed: {e}")))?;
        }
    }

    Ok(BroadcastResult {
        txid: last_txid.to_string(),
    }
    .into())
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
