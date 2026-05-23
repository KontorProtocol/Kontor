use axum::{Json, extract::State};
use indexer_types::{
    CommitOutputs, CommitOutputsV2, ComposeOutputs, ComposeQuery, Reveal, RevealOutputs,
    RevealQuery,
};

use crate::api::compose::{
    CommitInputs, ComposeInputs, compose, compose_commit, compose_commit_v2, compose_reveal,
    compose_reveal_v2, compose_v2, reveal_inputs_from_query,
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

// ============================================================================
// New Reveal-centric compose API endpoints
//
// `compose_v2` takes a Reveal and builds whatever needs building. If any
// participants have CommitSource::Build, those commits are built first;
// then the reveal PSBT is built from the resulting all-Existing Reveal.
// `compose_commit_v2` builds only the commits (split flow). `compose_reveal_v2`
// builds only the reveal (all participants must be Existing).
//
// All three accept a `Reveal` as the JSON body. The handlers consult
// the env-level default sat_per_vbyte if the Reveal omits it.
// ============================================================================

#[derive(serde::Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct ComposeV2Response {
    pub commits: Vec<indexer_types::CommitTx>,
    pub reveal: RevealOutputs,
}

pub async fn post_compose_v2(
    State(env): State<Env>,
    Json(mut reveal): Json<Reveal>,
) -> Result<ComposeV2Response> {
    let default_fee = match reveal.sat_per_vbyte {
        Some(v) => v,
        None => default_sat_per_vbyte(&env).await?,
    };
    if reveal.sat_per_vbyte.is_none() {
        reveal.sat_per_vbyte = Some(default_fee);
    }
    let (commits, reveal_outputs) =
        compose_v2(reveal, env.config.network, &env.bitcoin, default_fee)
            .await
            .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    Ok(ComposeV2Response {
        commits,
        reveal: reveal_outputs,
    }
    .into())
}

pub async fn post_compose_commit_v2(
    State(env): State<Env>,
    Json(mut reveal): Json<Reveal>,
) -> Result<CommitOutputsV2> {
    let default_fee = match reveal.sat_per_vbyte {
        Some(v) => v,
        None => default_sat_per_vbyte(&env).await?,
    };
    if reveal.sat_per_vbyte.is_none() {
        reveal.sat_per_vbyte = Some(default_fee);
    }
    let outputs = compose_commit_v2(reveal, env.config.network, &env.bitcoin, default_fee)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    Ok(outputs.into())
}

pub async fn post_compose_reveal_v2(
    State(env): State<Env>,
    Json(mut reveal): Json<Reveal>,
) -> Result<RevealOutputs> {
    if reveal.sat_per_vbyte.is_none() {
        let default_fee = default_sat_per_vbyte(&env).await?;
        reveal.sat_per_vbyte = Some(default_fee);
    }
    let outputs = compose_reveal_v2(reveal).map_err(|e| HttpError::BadRequest(e.to_string()))?;
    Ok(outputs.into())
}
