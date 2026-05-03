use axum::{
    Json,
    extract::{Path, Query, State},
};
use indexer_types::{
    ContractListRow, ContractResponse, PaginatedResponse, ViewExpr, ViewResult,
};

use super::validate_query;
use crate::api::{Env, error::HttpError, result::Result};
use crate::database::queries;
use crate::database::types::ContractQuery;
use crate::runtime::ContractAddress;

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
        .runtime_pool
        .get()
        .await?
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

pub async fn get_contracts(
    Query(query): Query<ContractQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<ContractListRow>> {
    validate_query(query.cursor, query.offset)?;
    let (results, pagination) =
        queries::get_contracts_paginated(&*env.reader.connection().await?, query).await?;
    Ok(PaginatedResponse {
        results,
        pagination,
    }
    .into())
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
    let runtime = env.runtime_pool.get().await?;
    let contract_id = runtime
        .storage
        .contract_id(&contract_address)
        .await?
        .ok_or(HttpError::NotFound("Contract not found".to_string()))?;

    let wit = runtime.storage.component_wit(contract_id).await?;
    Ok(ContractResponse { wit }.into())
}
