use axum::{
    Json,
    extract::{Path, State},
};
use indexer_types::{ContractListRow, ContractResponse, ViewExpr, ViewResult};

use crate::api::{Env, error::HttpError, result::Result};
use crate::database::queries;
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

pub async fn get_contracts(State(env): State<Env>) -> Result<Vec<ContractListRow>> {
    let conn = env.reader.connection().await?;
    Ok(queries::get_contracts(&conn).await?.into())
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
