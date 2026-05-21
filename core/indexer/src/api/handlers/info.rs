use std::time::Duration;

use axum::extract::{Query, State};
use indexer_types::Info;
use serde::Deserialize;
use tokio::time::timeout;

use crate::api::{Env, result::Result};
use crate::built_info;

/// Upper bound on a long-poll `?wait=` so a client cannot pin a
/// connection open indefinitely. Clients are expected to poll at ~30s.
const MAX_WAIT_MS: u64 = 60_000;

/// Query params for the long-poll form of `GET /api/`. Both must be
/// present to engage long-polling; otherwise `Info` is returned at once.
#[derive(Deserialize)]
pub struct InfoQuery {
    /// Max milliseconds to block, capped at `MAX_WAIT_MS`.
    wait: Option<u64>,
    /// The `Info::signature` the caller last saw. The request blocks
    /// while the live signature still equals this.
    since: Option<String>,
}

/// Build the full `Info` from the reactor-published `InfoCore` snapshot,
/// overlaying the static fields and the `available` readiness flag. No
/// database access — the snapshot is maintained by the reactor.
async fn current_info(env: &Env) -> Info {
    let core = env.info_rx.borrow().clone();
    Info {
        version: built_info::PKG_VERSION.to_string(),
        target: built_info::TARGET.to_string(),
        network: env.config.network.to_string(),
        available: *env.available.read().await,
        consensus_mode: env.config.consensus_mode,
        height: core.height,
        checkpoint: core.checkpoint,
        consensus_height: core.consensus_height,
        last_result_id: core.last_result_id,
        recent_blocks: core.recent_blocks,
        signature: core.signature,
    }
}

/// `GET /api/` — current indexer `Info`.
///
/// Long-poll form: `?wait=<ms>&since=<sig>` blocks until `Info::signature`
/// differs from `since`, or `wait` ms elapse (capped at `MAX_WAIT_MS`).
/// Both params must be present to engage long-polling; a plain `GET /api/`
/// returns immediately.
pub async fn get_index(Query(query): Query<InfoQuery>, State(env): State<Env>) -> Result<Info> {
    if let (Some(wait_ms), Some(since)) = (query.wait, query.since) {
        let wait_ms = wait_ms.min(MAX_WAIT_MS);
        let mut rx = env.info_rx.clone();
        // `borrow_and_update` marks the current snapshot version as seen,
        // so the subsequent `changed()` resolves only on a *later* publish
        // — no missed wake, no permit/enable dance.
        let already_moved = rx.borrow_and_update().signature != since;
        if !already_moved {
            let _ = timeout(Duration::from_millis(wait_ms), rx.changed()).await;
        }
        return Ok(current_info(&env).await.into());
    }
    Ok(current_info(&env).await.into())
}

pub async fn stop(State(env): State<Env>) -> Result<Info> {
    env.cancel_token.cancel();
    Ok(current_info(&env).await.into())
}
