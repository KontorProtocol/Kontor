use axum::{Json, extract::State};
use indexer_types::{CommitOutputs, ComposeOutputs, ComposeQuery, RevealOutputs, RevealQuery};

use crate::api::compose::{
    CommitInputs, ComposeInputs, compose, compose_commit, compose_reveal, reveal_inputs_from_query,
};
use crate::api::{Env, error::HttpError, result::Result};

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
    let inputs = reveal_inputs_from_query(query, env.config.network)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let outputs = compose_reveal(inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
}
