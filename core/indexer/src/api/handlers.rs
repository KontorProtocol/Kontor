use std::str::FromStr;

use anyhow::anyhow;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use bitcoin::consensus::encode;
use libsql::Connection;

use crate::{
    block::filter_map,
    built_info,
    database::{
        queries::{
            self, get_checkpoint_latest, get_transaction_by_txid, get_transactions_paginated,
            select_block_by_height_or_hash, select_block_latest,
        },
        types::{
            BlockRow, ContractListRow, OpResultId, TransactionListResponse, TransactionQuery,
            TransactionRow,
        },
    },
    reactor::{
        results::{ResultEvent, ResultEventMetadata},
        types::Op,
    },
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Info {
    pub version: String,
    pub target: String,
    pub available: bool,
    pub height: i64,
    pub checkpoint: Option<String>,
}

async fn get_info(env: &Env) -> anyhow::Result<Info> {
    let conn = env.reader.connection().await?;
    let height = select_block_latest(&conn)
        .await?
        .map(|b| b.height)
        .unwrap_or((env.config.starting_block_height - 1) as i64);
    let checkpoint = get_checkpoint_latest(&conn).await?.map(|c| c.hash);
    Ok(Info {
        version: built_info::PKG_VERSION.to_string(),
        target: built_info::TARGET.to_string(),
        available: *env.available.read().await,
        height,
        checkpoint,
    })
}

pub async fn get_index(State(env): State<Env>) -> Result<Info> {
    Ok(get_info(&env).await?.into())
}

pub async fn stop(State(env): State<Env>) -> Result<Info> {
    env.cancel_token.cancel();
    Ok(get_info(&env).await?.into())
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
) -> Result<TransactionListResponse> {
    let limit = query.limit.map_or(20, |l| l.clamp(1, 1000));

    if query.cursor.is_some() && query.offset.is_some() {
        return Err(HttpError::BadRequest(
            "Cannot specify both cursor and offset parameters".to_string(),
        )
        .into());
    }

    // Start a transaction
    let conn = env.reader.connection().await?;
    let tx = conn.transaction().await?;

    let (transactions, pagination) =
        get_transactions_paginated(&tx, query.height, query.cursor, query.offset, limit).await?;

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
pub struct TransactionHex {
    pub hex: String,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct OpWithResult {
    pub op: Op,
    pub result: Option<ResultEvent>,
}

async fn inspect(conn: &Connection, btx: bitcoin::Transaction) -> Result<Vec<OpWithResult>> {
    let mut ops = Vec::new();
    if let Some(tx) = filter_map((0, btx)) {
        for op in tx.ops {
            let id = OpResultId::builder()
                .txid(tx.txid.to_string())
                .input_index(op.metadata().input_index)
                .op_index(0)
                .build();
            let result = ResultEvent::get_by_op_result_id(conn, &id).await?;
            ops.push(OpWithResult { op, result });
        }
    }
    Ok(ops.into())
}

pub async fn post_transaction_hex_inspect(
    State(env): State<Env>,
    Json(TransactionHex { hex }): Json<TransactionHex>,
) -> Result<Vec<OpWithResult>> {
    let btx = encode::deserialize_hex::<bitcoin::Transaction>(&hex)
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let conn = env.reader.connection().await?;
    inspect(&conn, btx).await
}

pub async fn get_transaction_inspect(
    State(env): State<Env>,
    Path(txid): Path<String>,
) -> Result<Vec<OpWithResult>> {
    let txid = bitcoin::Txid::from_str(&txid)
        .map_err(|e| HttpError::BadRequest(format!("Invalid txid: {}", e)))?;
    let btx = env.bitcoin.get_raw_transaction(&txid).await?;
    let conn = env.reader.connection().await?;
    inspect(&conn, btx).await
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

pub async fn post_contract(
    Path(address): Path<String>,
    State(env): State<Env>,
    Json(ViewExpr { expr }): Json<ViewExpr>,
) -> Result<ResultEvent> {
    if !*env.available.read().await {
        return Err(HttpError::ServiceUnavailable("Indexer is not available".to_string()).into());
    }
    let contract_address = extract_contract_address(&address)?;
    let func_name = expr
        .split("(")
        .next()
        .ok_or(anyhow!("Invalid wave expression"))?;
    let result = env
        .runtime
        .lock()
        .await
        .execute(None, &contract_address, &expr)
        .await;
    let metadata = ResultEventMetadata::builder()
        // height is meaningless for view expressions
        .height(0)
        .contract_address(contract_address)
        .func_name(func_name.to_string())
        .gas(0)
        .build();
    Ok(match result {
        Ok(value) => ResultEvent::Ok {
            metadata,
            value: value.clone(),
        },
        Err(e) => ResultEvent::Err {
            metadata,
            message: format!("{:?}", e),
        },
    }
    .into())
}

pub async fn get_contracts(State(env): State<Env>) -> Result<Vec<ContractListRow>> {
    let conn = env.reader.connection().await?;
    Ok(queries::get_contracts(&conn).await?.into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractResponse {
    pub wit: String,
}

pub async fn get_contract(
    Path(address): Path<String>,
    State(env): State<Env>,
) -> Result<ContractResponse> {
    if !*env.available.read().await {
        return Err(HttpError::ServiceUnavailable("Indexer is not available".to_string()).into());
    }
    let contract_address = extract_contract_address(&address)?;
    let runtime = env.runtime.lock().await;
    let contract_id = runtime
        .storage
        .contract_id(&contract_address)
        .await?
        .ok_or(HttpError::NotFound("Contract not found".to_string()))?;

    let wit = runtime.storage.component_wit(contract_id).await?;
    Ok(ContractResponse { wit }.into())
}
