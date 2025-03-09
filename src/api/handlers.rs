use axum::extract::{Path, State};

use crate::database::types::BlockRow;

use super::{
    context::Context,
    error::{Error, HttpError},
    response::Response,
};

pub async fn get_block(
    State(context): State<Context>,
    Path(height): Path<u64>,
) -> Result<Response<BlockRow>, Error> {
    match context.reader.get_block_at_height(height).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound(format!("block at height: {}", height)).into()),
    }
}

pub async fn get_block_latest(State(context): State<Context>) -> Result<Response<BlockRow>, Error> {
    match context.reader.get_block_latest().await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound("No blocks written".to_owned()).into()),
    }
}
