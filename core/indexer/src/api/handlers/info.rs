use axum::extract::State;
use bitcoin::hashes::{Hash, sha256};
use indexer_types::{Info, RecentBlock};

use crate::api::{Env, result::Result};
use crate::built_info;
use crate::database::queries::{
    get_checkpoint_latest, select_latest_consensus_height, select_latest_result_id,
    select_recent_blocks,
};

/// Number of recent blocks surfaced in `Info::recent_blocks` — the SDK's
/// fast-path reorg-detection window.
const RECENT_BLOCKS_WINDOW: i64 = 10;

/// Opaque token over the long-poll-relevant state (`last_result_id` +
/// `recent_blocks`). The SDK passes the previous value back as `?since=`;
/// the long-poll endpoint blocks until it changes. Deliberately excludes
/// fields like `available` / `consensus_height` that don't trigger a
/// reactor `notify_waiters()`.
fn info_signature(last_result_id: i64, recent_blocks: &[RecentBlock]) -> String {
    let mut buf = format!("r{last_result_id}");
    for b in recent_blocks {
        buf.push_str(&format!(";{}:{}", b.height, b.hash));
    }
    sha256::Hash::hash(buf.as_bytes()).to_string()
}

async fn get_info(env: &Env) -> anyhow::Result<Info> {
    let conn = env.reader.connection().await?;
    let checkpoint = get_checkpoint_latest(&conn).await?.map(|c| c.hash);
    let consensus_height = select_latest_consensus_height(&conn).await?;
    let recent_blocks: Vec<RecentBlock> = select_recent_blocks(&conn, RECENT_BLOCKS_WINDOW)
        .await?
        .into_iter()
        .map(|b| RecentBlock {
            height: b.height,
            hash: b.hash,
        })
        .collect();
    // `recent_blocks` is height-descending, so its head is the tip.
    let height = recent_blocks
        .first()
        .map(|b| b.height)
        .unwrap_or((env.config.starting_block_height - 1) as i64);
    let last_result_id = select_latest_result_id(&conn).await?.unwrap_or(0);
    let signature = info_signature(last_result_id, &recent_blocks);
    Ok(Info {
        version: built_info::PKG_VERSION.to_string(),
        target: built_info::TARGET.to_string(),
        network: env.config.network.to_string(),
        available: *env.available.read().await,
        consensus_mode: env.config.consensus_mode,
        height,
        checkpoint,
        consensus_height,
        last_result_id,
        recent_blocks,
        signature,
    })
}

pub async fn get_index(State(env): State<Env>) -> Result<Info> {
    Ok(get_info(&env).await?.into())
}

pub async fn stop(State(env): State<Env>) -> Result<Info> {
    env.cancel_token.cancel();
    Ok(get_info(&env).await?.into())
}
