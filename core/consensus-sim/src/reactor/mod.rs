pub mod types;

use anyhow::anyhow;
use bitcoin::hashes::Hash;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use malachitebft_app_channel::Channels;

use indexer::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use indexer::consensus::{Ctx, Value};
use indexer::reactor::bitcoin_state::BitcoinState;
use indexer::reactor::consensus::{ConsensusState, handle_consensus_msg};
use indexer::reactor::executor::Executor;

pub use types::{FinalityEvent, StateEvent};

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
    let mut last_height: u64 = 0;
    let mut last_hash = bitcoin::BlockHash::all_zeros();
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
                        bitcoin_state.remove_confirmed_txids(&txids);

                        info!(
                            height = block.height,
                            txs = block.transactions.len(),
                            mempool = bitcoin_state.mempool.len(),
                            "Block received"
                        );

                        // Store block for execution when consensus decides it
                        consensus_state.block_cache.insert(block.height, block.clone());
                        consensus_state.pending_blocks.push_back((block.height, block.hash));

                        // Process replay queue entries whose anchor has been reached
                        while consensus_state
                            .replay_queue
                            .front()
                            .is_some_and(|(_, v)| v.block_height() <= last_height)
                        {
                            let (height, value) =
                                consensus_state.next_replay_batch().unwrap();

                            match &value {
                                Value::Batch { anchor_height, anchor_hash, txids, .. } => {
                                    let mut resolved_txs = Vec::with_capacity(txids.len());
                                    for txid in txids {
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
                                            *anchor_height,
                                            *anchor_hash,
                                            height,
                                            &[],
                                            &resolved_txs,
                                        )
                                        .await;
                                }
                                Value::Block { height: bh, .. } => {
                                    if let Some(block) = consensus_state.block_cache.remove(bh) {
                                        executor.execute_block(&block).await;
                                    }
                                }
                            }
                        }
                    }
                    BlockEvent::Rollback { to_height } => {
                        info!(to_height, "Bitcoin rollback — truncating state");
                        let removed = executor.rollback_state(to_height).await;
                        consensus_state.emit_state_event(
                            indexer::consensus::finality_types::StateEvent::RollbackExecuted {
                                to_anchor: to_height,
                                entries_removed: removed,
                                checkpoint: executor.checkpoint().await,
                            },
                        );
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
                let decided_block = handle_consensus_msg(consensus_state, executor, bitcoin_state, channels, msg, node_index, last_height, last_hash).await?;
                if let Some(block) = decided_block {
                    last_height = block.height;
                    last_hash = block.hash;
                    executor.execute_block(&block).await;
                    if consensus_state
                        .pending_batches
                        .iter()
                        .any(|b| b.deadline <= last_height)
                    {
                        if let Some(rollback_anchor) = consensus_state.run_finality_checks(executor, last_height).await {
                            last_height = rollback_anchor;
                        }
                    }
                }
            }
            else => break,
        }
    }

    Err(anyhow!("All channels closed"))
}
