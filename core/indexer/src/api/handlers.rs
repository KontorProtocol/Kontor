use std::str::FromStr;

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
            self, get_blocks_paginated, get_checkpoint_latest, get_op_result,
            get_results_paginated, get_transaction_by_txid, get_transactions_paginated,
            select_block_by_height_or_hash, select_block_latest,
        },
        types::{
            BlockQuery, BlockRow, ContractListRow, ContractResultPublicRow, OpResultId,
            PaginatedResponse, ResultQuery, TransactionQuery, TransactionRow,
        },
    },
    reactor::types::Op,
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

pub fn validate_query(
    cursor: Option<i64>,
    offset: Option<i64>,
) -> std::result::Result<(), HttpError> {
    if cursor.is_some() && offset.is_some() {
        return Err(HttpError::BadRequest(
            "Cannot specify both cursor and offset parameters".to_string(),
        ));
    }
    Ok(())
}

pub async fn get_blocks(
    Query(query): Query<BlockQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<BlockRow>> {
    validate_query(query.cursor, query.offset)?;
    let (results, pagination) =
        get_blocks_paginated(&*env.reader.connection().await?, query).await?;
    Ok(PaginatedResponse {
        results,
        pagination,
    }
    .into())
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHex {
    pub hex: String,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct OpWithResult {
    pub op: Op,
    pub result: Option<ResultRow>,
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
            let result = get_op_result(conn, &id).await?.map(Into::into);
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ViewResult {
    Ok { value: String },
    Err { message: String },
}

pub async fn post_contract(
    Path(address): Path<String>,
    State(env): State<Env>,
    Json(ViewExpr { expr }): Json<ViewExpr>,
) -> Result<ViewResult> {
    if !*env.available.read().await {
        return Err(HttpError::ServiceUnavailable("Indexer is not available".to_string()).into());
    }
    let contract_address = address
        .parse::<ContractAddress>()
        .map_err(|_| HttpError::BadRequest("Invalid contract address".to_string()))?;
    let result = env
        .runtime
        .lock()
        .await
        .execute(None, &contract_address, &expr)
        .await;
    Ok(match result {
        Ok(value) => ViewResult::Ok { value },
        Err(e) => ViewResult::Err {
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
    let contract_address = address
        .parse::<ContractAddress>()
        .map_err(|_| HttpError::BadRequest("Invalid contract address".to_string()))?;
    let runtime = env.runtime.lock().await;
    let contract_id = runtime
        .storage
        .contract_id(&contract_address)
        .await?
        .ok_or(HttpError::NotFound("Contract not found".to_string()))?;

    let wit = runtime.storage.component_wit(contract_id).await?;
    Ok(ContractResponse { wit }.into())
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResultRow {
    pub id: i64,
    pub height: i64,
    pub tx_index: i64,
    pub input_index: i64,
    pub op_index: i64,
    pub result_index: i64,
    pub func: String,
    pub gas: i64,
    pub value: Option<String>,
    pub contract: String,
}

impl From<ContractResultPublicRow> for ResultRow {
    fn from(row: ContractResultPublicRow) -> Self {
        ResultRow {
            id: row.id,
            height: row.height,
            tx_index: row.tx_index,
            input_index: row.input_index,
            op_index: row.op_index,
            result_index: row.result_index,
            func: row.func,
            gas: row.gas,
            value: row.value,
            contract: ContractAddress {
                name: row.contract_name,
                height: row.contract_height as u64,
                tx_index: row.tx_index as u64,
            }
            .to_string(),
        }
    }
}

pub async fn get_results(
    Query(query): Query<ResultQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<ResultRow>> {
    validate_query(query.cursor, query.offset)?;
    if query.start_height.is_some() && query.height.is_some() {
        return Err(HttpError::BadRequest(
            "start_height and height cannot be used together".to_string(),
        )
        .into());
    }

    if query.func.is_some() && query.contract.is_none() {
        return Err(HttpError::BadRequest("func requires contract".to_string()).into());
    }

    let (results, pagination) =
        get_results_paginated(&*env.reader.connection().await?, query).await?;
    Ok(PaginatedResponse {
        results: results.into_iter().map(Into::into).collect(),
        pagination,
    }
    .into())
}

pub async fn get_result(
    Path(id): Path<String>,
    State(env): State<Env>,
) -> Result<Option<ResultRow>> {
    let id = id
        .parse::<OpResultId>()
        .map_err(|_| HttpError::BadRequest("Invalid ID".to_string()))?;
    Ok(get_op_result(&*env.reader.connection().await?, &id)
        .await?
        .map(Into::into)
        .into())
}
