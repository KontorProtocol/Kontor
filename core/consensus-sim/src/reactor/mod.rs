pub mod types;

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

/// How long to wait for a batch to be decided before executing a buffered block.
const PENDING_BLOCK_TIMEOUT: Duration = Duration::from_secs(30);

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
                        bitcoin_state.track_block(block.height, &txids);

                        info!(
                            height = block.height,
                            txs = block.transactions.len(),
                            mempool = bitcoin_state.mempool.len(),
                            "Block received"
                        );

                        bitcoin_state.pending_blocks.push_back(block);
                        if pending_deadline.is_none() {
                            pending_deadline = Some(Instant::now() + PENDING_BLOCK_TIMEOUT);
                        }

                        if consensus_state
                            .pending_batches
                            .iter()
                            .any(|b| b.deadline <= bitcoin_state.chain_tip)
                        {
                            consensus_state.run_finality_checks(executor, bitcoin_state).await;
                        }
                    }
                    BlockEvent::Rollback { to_height } => {
                        info!(to_height, "Bitcoin rollback");
                    }
                }
            }
            Some(event) = mempool_rx.recv() => {
                match event {
                    MempoolEvent::Insert(tx) => {
                        let txid = tx.compute_txid();
                        bitcoin_state.track_mempool_insert(tx);
                        debug!(%txid, mempool = bitcoin_state.mempool.len(), "Mempool insert");
                    }
                    MempoolEvent::Remove(txid) => {
                        bitcoin_state.track_mempool_remove(&txid);
                        debug!(%txid, mempool = bitcoin_state.mempool.len(), "Mempool remove");
                    }
                    MempoolEvent::Sync(txs) => {
                        bitcoin_state.track_mempool_sync(txs.into_iter());
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
