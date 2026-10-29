use axum::extract::{Path, Query, State};
use indexer_types::{PaginatedResponse, ResultInfo};
use libsql::TransactionBehavior;

use super::validate_query;
use crate::api::{Env, confirmation, error::HttpError, result::Result};
use crate::database::queries::{get_op_result, get_results_paginated};
use crate::database::types::{OpResultId, ResultQuery};

pub async fn get_results(
    Query(query): Query<ResultQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<ResultInfo>> {
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

    let conn = env.reader.connection().await?;
    let snapshot = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .await?;
    let (rows, pagination) = get_results_paginated(&snapshot, query).await?;
    let results =
        confirmation::results(&snapshot, rows.into_iter().map(Into::into).collect()).await?;
    snapshot.commit().await?;
    Ok(PaginatedResponse {
        results,
        pagination,
    }
    .into())
}

pub async fn get_result(
    Path(id): Path<String>,
    State(env): State<Env>,
) -> Result<Option<ResultInfo>> {
    let id = id
        .parse::<OpResultId>()
        .map_err(|_| HttpError::BadRequest("Invalid ID".to_string()))?;
    let conn = env.reader.connection().await?;
    let snapshot = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .await?;
    let row = get_op_result(&snapshot, &id).await?;
    let result = confirmation::results(&snapshot, row.into_iter().map(Into::into).collect())
        .await?
        .pop();
    snapshot.commit().await?;
    Ok(result.into())
}
