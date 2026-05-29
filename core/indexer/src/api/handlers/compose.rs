use axum::{Json, extract::State};
use indexer_types::{CommitOutputs, ComposeOutputs, Reveal, RevealOutputs};

use crate::api::compose::{compose, compose_commit, compose_reveal};
use crate::api::{Env, error::HttpError, result::Result};

/// Resolve the default `sat_per_vbyte` for a compose request that omitted
/// the field. By the time the request gets here the `require_available`
/// middleware has ensured the indexer is ready and `fees_rx` carries a
/// real estimate (not just the `Fees::floor(1)` startup placeholder).
fn default_sat_per_vbyte(env: &Env) -> u64 {
    env.fees_rx.borrow().fastest
}

pub async fn post_compose(
    State(env): State<Env>,
    Json(mut reveal): Json<Reveal>,
) -> Result<ComposeOutputs> {
    if reveal.sat_per_vbyte.is_none() {
        reveal.sat_per_vbyte = Some(default_sat_per_vbyte(&env));
    }
    let (commits, reveal_outputs) = compose(reveal, env.config.network, &env.bitcoin)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    Ok(ComposeOutputs {
        commits,
        reveal: reveal_outputs,
    }
    .into())
}

pub async fn post_compose_commit(
    State(env): State<Env>,
    Json(mut reveal): Json<Reveal>,
) -> Result<CommitOutputs> {
    if reveal.sat_per_vbyte.is_none() {
        reveal.sat_per_vbyte = Some(default_sat_per_vbyte(&env));
    }
    let outputs = compose_commit(reveal, env.config.network, &env.bitcoin)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    Ok(outputs.into())
}

pub async fn post_compose_reveal(
    State(env): State<Env>,
    Json(mut reveal): Json<Reveal>,
) -> Result<RevealOutputs> {
    if reveal.sat_per_vbyte.is_none() {
        reveal.sat_per_vbyte = Some(default_sat_per_vbyte(&env));
    }
    let outputs = compose_reveal(reveal).map_err(|e| HttpError::BadRequest(e.to_string()))?;
    Ok(outputs.into())
}
