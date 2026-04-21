use axum::extract::{Path, Query, State};
use indexer_types::{BlockRow, PaginatedResponse, TransactionRow};

use super::validate_query;
use crate::api::{Env, error::HttpError, result::Result};
use crate::database::queries::{
    get_blocks_paginated, get_transactions_paginated, select_block_by_height_or_hash,
    select_block_latest,
};
use crate::database::types::{BlockQuery, TransactionQuery};

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

pub async fn get_block_transactions(
    Path(identifier): Path<String>,
    Query(mut query): Query<TransactionQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<TransactionRow>> {
    validate_query(query.cursor, query.offset)?;
    let conn = env.reader.connection().await?;
    let block = select_block_by_height_or_hash(&conn, &identifier)
        .await?
        .ok_or_else(|| HttpError::NotFound(format!("block at height or hash: {}", identifier)))?;
    query.height = Some(block.height);
    let (results, pagination) = get_transactions_paginated(&conn, query).await?;
    Ok(PaginatedResponse {
        results,
        pagination,
    }
    .into())
}
