use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use indexer_types::{ConsensusMode, Info};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

use crate::api::{API_REQUEST_TIMEOUT_MS, Env, result::Result};
use crate::built_info;

/// Upper bound on a long-poll `?wait=`, derived from the router's
/// request-timeout budget. A request held past `API_REQUEST_TIMEOUT_MS`
/// is killed by the `TimeoutLayer` middleware (non-JSON 408), so the cap
/// sits 5s below it — headroom to build and write the response. The
/// subtraction is const-evaluated, so too small a timeout fails to
/// compile rather than silently breaking long-polls.
const MAX_WAIT_MS: u64 = API_REQUEST_TIMEOUT_MS - 5_000;

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
/// overlaying the static fields. The `require_available` middleware
/// ensures `InfoCore.height` is `Some` before any request reaches this
/// handler, so `.expect` here is unreachable in normal operation. No
/// database access — the snapshot is maintained by the info publisher.
fn current_info(env: &Env) -> Info {
    let core = env.info_rx.borrow().clone();
    let height = core
        .height
        .expect("require_available middleware ensures InfoCore.height is Some");
    Info {
        version: built_info::PKG_VERSION.to_string(),
        target: built_info::TARGET.to_string(),
        network: env.config.network.to_string(),
        consensus_mode: env.config.consensus_mode,
        height,
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
    }
    Ok(current_info(&env).into())
}

/// Node status available *before* the node is "available" — static identity
/// plus the pre-consensus signals (`reactor_ready`, the resolved consensus
/// listen address). Deliberately served outside the `require_available` gate:
/// a cluster bootstrapping from a seed must read the seed's listen address
/// before quorum (and thus availability) exists.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub version: String,
    pub target: String,
    pub network: String,
    pub consensus_mode: ConsensusMode,
    pub reactor_ready: bool,
    /// Resolved consensus listen multiaddr, or `null` until bound / for
    /// non-consensus nodes.
    pub consensus_listen_addr: Option<String>,
}

/// `GET /api/status` — ungated node status (see [`NodeStatus`]).
pub async fn get_status(State(env): State<Env>) -> Json<NodeStatus> {
    Json(NodeStatus {
        version: built_info::PKG_VERSION.to_string(),
        target: built_info::TARGET.to_string(),
        network: env.config.network.to_string(),
        consensus_mode: env.config.consensus_mode,
        reactor_ready: env.reactor_ready.load(Ordering::Relaxed),
        consensus_listen_addr: env.consensus_listen_addr.borrow().clone(),
    })
}
