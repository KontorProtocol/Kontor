use axum::extract::{Path, Query, State};
use indexer_types::{PaginatedResponse, ResultRow};

use super::validate_query;
use crate::api::{Env, error::HttpError, result::Result};
use crate::database::queries::{get_op_result, get_results_paginated};
use crate::database::types::{OpResultId, ResultQuery};

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
