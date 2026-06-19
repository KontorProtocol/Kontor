//! Node-local operational state in the `node_meta` key/value table — values that
//! are per-node and NOT part of consensus (so they live outside the checkpoint
//! chain and never roll back on a reorg). See [`super::contract_state`] for the
//! first tenant, the prune watermark.

use libsql::{Connection, params};

use super::Error;

/// `node_meta` key for the prune watermark `W_prev` — the highest height up to
/// which `contract_state` is already collapsed to one row per path (see
/// `project_state_pruning`). Persisted so a restart resumes incremental pruning
/// instead of re-scanning all finalized history.
pub const PRUNE_WATERMARK_KEY: &str = "prune_watermark";

/// Read a `u64` node-meta value, or `default` if the key is unset.
pub async fn get_meta_u64(conn: &Connection, key: &str, default: u64) -> Result<u64, Error> {
    let mut rows = conn
        .query("SELECT value FROM node_meta WHERE key = ?1", params![key])
        .await?;
    Ok(match rows.next().await? {
        Some(row) => row.get::<i64>(0)? as u64,
        None => default,
    })
}
