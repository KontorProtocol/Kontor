use axum::extract::{Path, State};

use crate::database::{
    queries::{select_block_at_height, select_block_latest},
    types::BlockRow,
};

use super::{
    Env,
    error::{Error, HttpError},
    response::Response,
};

pub async fn get_block(
    State(env): State<Env>,
    Path(height): Path<u64>,
) -> Result<Response<BlockRow>, Error> {
    match select_block_at_height(&*env.reader.connection().await?, height).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound(format!("block at height: {}", height)).into()),
    }
}

pub async fn get_block_latest(State(env): State<Env>) -> Result<Response<BlockRow>, Error> {
    match select_block_latest(&*env.reader.connection().await?).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound("No blocks written".to_owned()).into()),
    }
}
