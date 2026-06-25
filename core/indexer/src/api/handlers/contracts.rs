use axum::{
    Json,
    extract::{Path, Query, State},
};
use indexer_types::{
    ContractListRow, ContractProvenanceResponse, ContractResponse, PaginatedResponse,
    ProvenanceEntry, ViewExpr, ViewResult,
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
    let contract_address = address
        .parse::<ContractAddress>()
        .map_err(|_| HttpError::BadRequest("Invalid contract address".to_string()))?;
    let result = env
        .runtime_pool
        .get()
        .await?
        .execute(None, None, &contract_address, &expr)
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

pub async fn get_contract_provenance(
    Path(address): Path<String>,
    State(env): State<Env>,
) -> Result<ContractProvenanceResponse> {
    let contract_address = address
        .parse::<ContractAddress>()
        .map_err(|_| HttpError::BadRequest("Invalid contract address".to_string()))?;
    let conn = env.reader.connection().await?;
    let contract_id = queries::get_contract_id_from_address(&conn, &contract_address)
        .await?
        .ok_or(HttpError::NotFound("Contract not found".to_string()))?;
    let entries = queries::get_contract_provenance_log(&conn, contract_id)
        .await?
        .into_iter()
        .map(|row| {
            let provenance = postcard::from_bytes(&row.provenance)?;
            Ok::<_, anyhow::Error>(ProvenanceEntry {
                height: row.height,
                tx_index: row.tx_index,
                provenance,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(ContractProvenanceResponse { entries }.into())
}
