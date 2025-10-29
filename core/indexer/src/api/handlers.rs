use anyhow::Context;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use wit_component::WitPrinter;

use crate::{
    bitcoin_client::types::TestMempoolAcceptResult,
    database::{
        queries::{
            get_contract_id_from_address, get_transaction_by_txid, get_transactions_paginated,
            select_block_by_height_or_hash, select_block_latest,
        },
        types::{BlockRow, TransactionListResponse, TransactionQuery, TransactionRow},
    },
    reactor::results::ResultEvent,
    runtime::ContractAddress,
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

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct TxsQuery {
    txs: String,
}

#[derive(Deserialize, Serialize)]
pub struct Info {
    pub available: bool,
    pub height: i64,
}

pub async fn get_index(State(env): State<Env>) -> Result<Info> {
    let height = select_block_latest(&*env.reader.connection().await?)
        .await?
        .map(|b| b.height)
        .unwrap_or((env.config.starting_block_height - 1) as i64);
    Ok(Info {
        available: true,
        height,
    }
    .into())
}

pub async fn stop(State(env): State<Env>) -> Result<Info> {
    env.cancel_token.cancel();
    let height = select_block_latest(&*env.reader.connection().await?)
        .await?
        .map(|b| b.height)
        .unwrap_or_default();
    Ok(Info {
        available: false,
        height,
    }
    .into())
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

pub async fn post_compose(
    State(env): State<Env>,
    Json(query): Json<ComposeQuery>,
) -> Result<ComposeOutputs> {
    if query.instructions.len() > 400 * 1024 {
        return Err(HttpError::BadRequest("instructions too large".to_string()).into());
    }

    let inputs = ComposeInputs::from_query(query, env.config.network, &env.bitcoin)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;

    let outputs = compose(inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
}

pub async fn post_compose_commit(
    State(env): State<Env>,
    Json(query): Json<ComposeQuery>,
) -> Result<CommitOutputs> {
    if query.instructions.len() > 400 * 1024 {
        return Err(HttpError::BadRequest("instructions too large".to_string()).into());
    }

    let inputs = ComposeInputs::from_query(query, env.config.network, &env.bitcoin)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let commit_inputs = CommitInputs::from(inputs);

    let outputs =
        compose_commit(commit_inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
}

pub async fn post_compose_reveal(
    State(env): State<Env>,
    Json(query): Json<RevealQuery>,
) -> Result<RevealOutputs> {
    let inputs = RevealInputs::from_query(query, env.config.network, &env.bitcoin)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let outputs = compose_reveal(inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewExpr {
    pub expr: String,
}

fn extract_contract_address(s: &str) -> anyhow::Result<ContractAddress> {
    let address_parts = s.split("_").collect::<Vec<_>>();
    if address_parts.len() != 3 {
        return Err(HttpError::BadRequest("Invalid contract address format".to_string()).into());
    }
    let name = address_parts[0].to_string();
    if let Ok(height) = address_parts[1].parse::<i64>()
        && let Ok(tx_index) = address_parts[2].parse::<i64>()
    {
        Ok(ContractAddress {
            name,
            height,
            tx_index,
        })
    } else {
        Err(HttpError::BadRequest("Invalid parts in contract address".to_string()).into())
    }
}

pub async fn post_view(
    Path(address): Path<String>,
    State(env): State<Env>,
    Json(ViewExpr { expr }): Json<ViewExpr>,
) -> Result<ResultEvent> {
    let contract_address = extract_contract_address(&address)?;
    let result = env.runtime.execute(None, &contract_address, &expr).await;
    Ok(match result {
        Ok(value) => ResultEvent::Ok { value },
        Err(e) => ResultEvent::Err {
            message: format!("{:?}", e),
        },
    }
    .into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitResponse {
    pub wit: String,
}

pub async fn get_wit(Path(address): Path<String>, State(env): State<Env>) -> Result<WitResponse> {
    let contract_address = extract_contract_address(&address)?;
    let contract_id =
        get_contract_id_from_address(&*env.reader.connection().await?, &contract_address)
            .await?
            .ok_or(HttpError::NotFound("Contract not found".to_string()))?;
    let bs = env.runtime.get_component_bytes(contract_id).await?;
    let decoded = wit_component::decode(&bs).context("Failed to decode component")?;
    let mut printer = WitPrinter::default();
    printer
        .print(decoded.resolve(), decoded.package(), &[])
        .context("Failed to print component")?;
    let wit = format!("{}", printer.output);
    Ok(WitResponse { wit }.into())
}
