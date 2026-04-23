use axum::{Json, extract::State};
use indexer_types::{CommitOutputs, ComposeOutputs, ComposeQuery, RevealOutputs, RevealQuery};

use crate::api::compose::{
    CommitInputs, ComposeInputs, compose, compose_commit, compose_reveal, reveal_inputs_from_query,
};
use crate::api::{Env, error::HttpError, result::Result};

/// Resolve the default `sat_per_vbyte` for a compose request that omitted
/// the field. Returns `ServiceUnavailable` when the indexer hasn't
/// finished its initial mempool sync — the published `fastest_fee` would
/// just be `Fees::floor(1)` at that point, which is meaningless. Clients
/// can still call compose with an explicit `sat_per_vbyte` during this
/// window; this only fails the implicit-default path.
async fn default_sat_per_vbyte(env: &Env) -> std::result::Result<u64, HttpError> {
    if !*env.available.read().await {
        return Err(HttpError::ServiceUnavailable(
            "fee data not yet available; specify sat_per_vbyte explicitly or retry once the indexer is ready".to_string(),
        ));
    }
    Ok(env.fees_rx.borrow().fastest)
}

pub async fn post_compose(
    State(env): State<Env>,
    Json(query): Json<ComposeQuery>,
) -> Result<ComposeOutputs> {
    if query.instructions.len() > 400 * 1024 {
        return Err(HttpError::BadRequest("instructions too large".to_string()).into());
    }

    let default_fee = match query.sat_per_vbyte {
        Some(v) => v,
        None => default_sat_per_vbyte(&env).await?,
    };
    let inputs = ComposeInputs::from_query(query, env.config.network, &env.bitcoin, default_fee)
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

    let default_fee = match query.sat_per_vbyte {
        Some(v) => v,
        None => default_sat_per_vbyte(&env).await?,
    };
    let inputs = ComposeInputs::from_query(query, env.config.network, &env.bitcoin, default_fee)
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
    let default_fee = match query.sat_per_vbyte {
        Some(v) => v,
        None => default_sat_per_vbyte(&env).await?,
    };
    let inputs = reveal_inputs_from_query(query, env.config.network, default_fee)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let outputs = compose_reveal(inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
}
