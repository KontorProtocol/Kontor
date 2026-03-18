pub mod types;

use std::collections::HashSet;

use anyhow::anyhow;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use malachitebft_app_channel::Channels;

use indexer::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use indexer::consensus::Ctx;
use indexer::reactor::bitcoin_state::BitcoinState;
use indexer::reactor::consensus::{ConsensusState, handle_consensus_msg};
use indexer::reactor::executor::Executor;

pub use types::{FinalityEvent, StateEvent};

/// Default: how long to wait for a batch to be decided before executing a buffered block.
pub const DEFAULT_PENDING_BLOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// Run the reactor loop, handling both consensus messages and bitcoin events.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    consensus_state: &mut ConsensusState,
    executor: &mut impl Executor,
    bitcoin_state: &mut BitcoinState,
    node_index: usize,
    channels: &mut Channels<Ctx>,
    block_rx: &mut mpsc::Receiver<BlockEvent>,
    mempool_rx: &mut mpsc::Receiver<MempoolEvent>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    run_with_timeout(
        consensus_state,
        executor,
        bitcoin_state,
        node_index,
        channels,
        block_rx,
        mempool_rx,
        cancel,
        DEFAULT_PENDING_BLOCK_TIMEOUT,
    )
    .await
}

/// Run the reactor loop with a custom pending block timeout.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_timeout(
    consensus_state: &mut ConsensusState,
    executor: &mut impl Executor,
    bitcoin_state: &mut BitcoinState,
    node_index: usize,
    channels: &mut Channels<Ctx>,
    block_rx: &mut mpsc::Receiver<BlockEvent>,
    mempool_rx: &mut mpsc::Receiver<MempoolEvent>,
    cancel: CancellationToken,
    pending_block_timeout: Duration,
) -> anyhow::Result<()> {
    let mut pending_deadline: Option<Instant> = None;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Reactor cancelled");
                return Ok(());
            }
            Some(event) = block_rx.recv() => {
                match event {
                    BlockEvent::BlockInsert { block, .. } => {
                        let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid).collect();
                        bitcoin_state.track_block(block.height, block.hash, &txids);

                        info!(
                            height = block.height,
                            txs = block.transactions.len(),
                            mempool = bitcoin_state.mempool.len(),
                            "Block received"
                        );

                        bitcoin_state.pending_blocks.push_back(block);

                        // Process replay queue batches whose anchor has been reached
                        if !consensus_state.replay_queue.is_empty() {
                            while consensus_state
                                .replay_queue
                                .front()
                                .is_some_and(|(_, v)| v.anchor_height <= bitcoin_state.chain_tip)
                            {
                                let (height, value) =
                                    consensus_state.next_replay_batch().unwrap();

                                // Skip batches with stale anchor_hash (reorg replaced the block)
                                if bitcoin_state
                                    .block_hashes
                                    .get(&value.anchor_height)
                                    .is_some_and(|&local_hash| local_hash != value.anchor_hash)
                                {
                                    warn!(
                                        anchor = value.anchor_height,
                                        consensus_height = %height,
                                        "Skipping replay batch with stale anchor_hash"
                                    );
                                    continue;
                                }

                                // Replay path: resolve txids to full txs via mempool/executor
                                let mut resolved_txs = Vec::with_capacity(value.txids.len());
                                for txid in &value.txids {
                                    if let Some(tx) = bitcoin_state.mempool.get(txid) {
                                        resolved_txs.push(tx.clone());
                                    } else if let Some(tx) = executor.resolve_transaction(txid).await {
                                        resolved_txs.push(tx);
                                    } else {
                                        warn!(%txid, "Could not resolve txid during replay — skipping");
                                    }
                                }

                                consensus_state.record_decided_batch(height, &value);
                                consensus_state
                                    .process_decided_batch(
                                        executor,
                                        bitcoin_state,
                                        value.anchor_height,
                                        height,
                                        &resolved_txs,
                                    )
                                    .await;
                            }
                        } else if consensus_state
                            .pending_batches
                            .iter()
                            .any(|b| b.deadline <= bitcoin_state.chain_tip)
                        {
                            // Drain pending blocks so executor has seen them before finality checks
                            while let Some(pending) = bitcoin_state.pending_blocks.pop_front() {
                                executor.execute_block(&pending).await;
                            }
                            pending_deadline = None;
                            consensus_state.run_finality_checks(executor, bitcoin_state).await;
                        } else if pending_deadline.is_none() {
                            pending_deadline = Some(Instant::now() + pending_block_timeout);
                        }
                    }
                    BlockEvent::Rollback { to_height } => {
                        info!(to_height, "Bitcoin rollback — initiating replay");
                        consensus_state
                            .initiate_rollback(executor, bitcoin_state, to_height, HashSet::new())
                            .await;
                        pending_deadline = None;
                    }
                }
            }
            Some(event) = mempool_rx.recv() => {
                match event {
                    MempoolEvent::Insert(tx) => {
                        let txid = tx.compute_txid();
                        bitcoin_state.track_mempool_insert(tx).await;
                        debug!(%txid, mempool = bitcoin_state.mempool.len(), "Mempool insert");
                    }
                    MempoolEvent::Remove(txid) => {
                        bitcoin_state.track_mempool_remove(&txid).await;
                        debug!(%txid, mempool = bitcoin_state.mempool.len(), "Mempool remove");
                    }
                    MempoolEvent::Sync(txs) => {
                        bitcoin_state.track_mempool_sync(txs.into_iter()).await;
                        info!(mempool = bitcoin_state.mempool.len(), "Mempool sync");
                    }
                }
            }
            Some(msg) = channels.consensus.recv() => {
                handle_consensus_msg(consensus_state, executor, bitcoin_state, channels, msg, node_index).await?;
                if bitcoin_state.pending_blocks.is_empty() {
                    pending_deadline = None;
                }
            }
            _ = tokio::time::sleep_until(pending_deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(86400))), if pending_deadline.is_some() => {
                let count = bitcoin_state.pending_blocks.len();
                while let Some(block) = bitcoin_state.pending_blocks.pop_front() {
                    warn!(height = block.height, "Pending block timeout — executing without waiting for batch");
                    executor.execute_block(&block).await;
                }
                if count > 0 {
                    info!(count, "Drained pending blocks on timeout");
                }
                pending_deadline = None;
            }
            else => break,
        }
    }

    Err(anyhow!("All channels closed"))
}
