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

/// `node_meta` key marking that the `depositor_footprint` cache has been built from
/// live state. Set once after the first reconstruct; since block writes and reorgs
/// both maintain the cache atomically, a clean restart can then skip the rebuild.
pub const FOOTPRINT_BUILT_KEY: &str = "footprint_cache_built";

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

/// Upsert a `u64` node-meta value.
pub async fn set_meta_u64(conn: &Connection, key: &str, value: u64) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO node_meta(key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value as i64],
    )
    .await?;
    Ok(())
}
