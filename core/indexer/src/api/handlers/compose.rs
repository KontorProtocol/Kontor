use axum::{Json, extract::State};
use indexer_types::{CommitOutputs, ComposeOutputs, Reveal, RevealOutputs};

use crate::api::compose::{compose, compose_commit, compose_reveal};
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
    Json(mut reveal): Json<Reveal>,
) -> Result<ComposeOutputs> {
    if reveal.sat_per_vbyte.is_none() {
        reveal.sat_per_vbyte = Some(default_sat_per_vbyte(&env).await?);
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
        reveal.sat_per_vbyte = Some(default_sat_per_vbyte(&env).await?);
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
        let default_fee = default_sat_per_vbyte(&env).await?;
        reveal.sat_per_vbyte = Some(default_fee);
    }
    let outputs = compose_reveal(reveal).map_err(|e| HttpError::BadRequest(e.to_string()))?;
    Ok(outputs.into())
}
