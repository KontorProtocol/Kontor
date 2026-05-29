//! `InfoCore` — the chain/result portion of the `GET /api/` response —
//! and the background task that keeps it fresh.
//!
//! The reactor already emits `Event` on every block / batch / rollback.
//! [`run_info_publisher`] subscribes to that broadcast, recomputes
//! `InfoCore` once per change, and publishes it on a `watch` channel
//! ([`Env::info_rx`]). The `GET /api/` handler reads the cached value and
//! overlays the static fields (`version` / `target` / `network`) and the
//! `available` flag to form the full `Info` response — so a long-poll
//! wake costs no DB queries, the compute happens once (not once per
//! blocked request), and it stays off the reactor's consensus hot path.

use anyhow::Result;
use bitcoin::hashes::{Hash, sha256};
use indexer_types::{Event, RecentBlock};
use libsql::Connection;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::database;
use crate::database::queries::{
    get_checkpoint_latest, select_latest_consensus_height, select_latest_result_id,
    select_recent_blocks,
};

/// Recent-block window surfaced in `Info::recent_blocks` — the SDK's
/// fast-path reorg-detection window.
pub const RECENT_BLOCKS_WINDOW: i64 = 10;

/// Everything in `Info` that changes as the indexer advances. Published
/// by [`run_info_publisher`], read by the `GET /api/` handler.
#[derive(Debug, Clone, Default)]
pub struct InfoCore {
    pub height: u64,
    pub checkpoint: Option<String>,
    pub consensus_height: Option<u64>,
    pub last_result_id: u64,
    pub recent_blocks: Vec<RecentBlock>,
    /// Hash of `last_result_id` + `recent_blocks` — the long-poll
    /// `?since=` token. Changes exactly when a new snapshot is published.
    pub signature: String,
}

/// Recompute `InfoCore` from the database. `fallback_height` is used as
/// `height` only when no blocks are indexed yet (startup seed).
pub async fn compute_info_core(conn: &Connection, fallback_height: u64) -> Result<InfoCore> {
    let checkpoint = get_checkpoint_latest(conn).await?.map(|c| c.hash);
    let consensus_height = select_latest_consensus_height(conn).await?;
    let recent_blocks: Vec<RecentBlock> = select_recent_blocks(conn, RECENT_BLOCKS_WINDOW)
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
        .unwrap_or(fallback_height);
    let last_result_id = select_latest_result_id(conn).await?.unwrap_or(0);
    let signature = info_signature(last_result_id, &recent_blocks);
    Ok(InfoCore {
        height,
        checkpoint,
        consensus_height,
        last_result_id,
        recent_blocks,
        signature,
    })
}

/// Opaque token over the long-poll-relevant state. Deliberately excludes
/// fields (`available` / `consensus_mode` / statics) that don't move with
/// the chain.
fn info_signature(last_result_id: u64, recent_blocks: &[RecentBlock]) -> String {
    let mut buf = format!("r{last_result_id}");
    for b in recent_blocks {
        buf.push_str(&format!(";{}:{}", b.height, b.hash));
    }
    sha256::Hash::hash(buf.as_bytes()).to_string()
}

/// Background task: recompute and publish `InfoCore` whenever the reactor
/// reports the chain moved. Subscribes to the `EventSubscriber` broadcast
/// — the reactor already emits `Event` on block/batch/rollback, so this
/// needs no reactor changes. Bursts are coalesced into a single recompute,
/// done on the pooled reader (off the consensus hot path).
pub fn run_info_publisher(
    cancel: CancellationToken,
    mut events: broadcast::Receiver<Event>,
    reader: database::Reader,
    starting_block_height: u64,
    info_tx: watch::Sender<InfoCore>,
) -> JoinHandle<()> {
    let fallback_height = starting_block_height.saturating_sub(1);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                recv = events.recv() => match recv {
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Coalesce any further buffered events — `InfoCore`
                        // is a snapshot, so one recompute reflects them all.
                        while events.try_recv().is_ok() {}
                        match reader.connection().await {
                            Ok(conn) => match compute_info_core(&conn, fallback_height).await {
                                Ok(core) => {
                                    let _ = info_tx.send(core);
                                }
                                Err(e) => warn!("info-publisher: compute failed: {e}"),
                            },
                            Err(e) => warn!("info-publisher: db connection failed: {e}"),
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = cancel.cancelled() => break,
            }
        }
    })
}
