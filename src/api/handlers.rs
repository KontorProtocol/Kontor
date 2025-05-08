use axum::extract::{Path, Query, State};

use crate::database::{
    queries::{select_block_at_height, select_block_latest},
    types::BlockRow,
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

pub async fn get_block(State(env): State<Env>, Path(height): Path<u64>) -> Result<BlockRow> {
    match select_block_at_height(&*env.reader.connection().await?, height).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound(format!("block at height: {}", height)).into()),
    }
}

pub async fn get_block_latest(State(env): State<Env>) -> Result<BlockRow> {
    match select_block_latest(&*env.reader.connection().await?).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound("No blocks written".to_owned()).into()),
    }
}

pub async fn get_compose(
    Query(query): Query<ComposeQuery>,
    State(env): State<Env>,
) -> Result<ComposeOutputs> {
    let inputs = ComposeInputs::from_query(query, &env.bitcoin).await?;

    let outputs = compose(inputs)?;

    Ok(outputs.into())
}

pub async fn get_compose_commit(
    Query(query): Query<ComposeQuery>,
    State(env): State<Env>, // TODO
) -> Result<CommitOutputs> {
    let inputs = ComposeInputs::from_query(query, &env.bitcoin).await?;
    let commit_inputs = CommitInputs::from(inputs);

    let outputs = compose_commit(commit_inputs)?;

    Ok(outputs.into())
}

pub async fn get_compose_reveal(
    Query(query): Query<RevealQuery>,
    State(env): State<Env>,
) -> Result<RevealOutputs> {
    let inputs = RevealInputs::from_query(query, &env.bitcoin).await?;
    let outputs = compose_reveal(inputs)?;

    Ok(outputs.into())
}
