pub mod types;

use anyhow::anyhow;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use malachitebft_app_channel::Channels;

use indexer::bitcoin_follower::event::BitcoinEvent;
use indexer::consensus::Ctx;
use indexer::reactor::bitcoin_state::BitcoinState;
use indexer::reactor::consensus::{ConsensusState, handle_consensus_msg};
use indexer::reactor::executor::Executor;

pub use types::{FinalityEvent, StateEvent};

/// Run the reactor loop, handling both consensus messages and bitcoin events.
pub async fn run(
    consensus_state: &mut ConsensusState,
    executor: &mut impl Executor,
    bitcoin_state: &mut BitcoinState,
    node_index: usize,
    channels: &mut Channels<Ctx>,
    bitcoin_rx: &mut mpsc::Receiver<BitcoinEvent>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Reactor cancelled");
                return Ok(());
            }
            Some(event) = bitcoin_rx.recv() => {
                match event {
                    BitcoinEvent::BlockInsert { block, .. } => {
                        let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid).collect();
                        bitcoin_state.track_block(block.height, &txids);

                        info!(
                            height = block.height,
                            txs = block.transactions.len(),
                            mempool = bitcoin_state.mempool.len(),
                            "Block queued"
                        );

                        if consensus_state
                            .pending_batches
                            .iter()
                            .any(|b| b.deadline <= bitcoin_state.chain_tip)
                        {
                            let replay_up_to = consensus_state.last_processed_anchor.saturating_add(1);
                            consensus_state.run_finality_checks(executor, bitcoin_state, replay_up_to);
                        }
                    }
                    BitcoinEvent::MempoolInsert(tx) => {
                        let txid = tx.txid;
                        bitcoin_state.track_mempool_insert(txid);
                        debug!(%txid, mempool = bitcoin_state.mempool.len(), "Mempool insert");
                    }
                    BitcoinEvent::MempoolRemove(txid) => {
                        bitcoin_state.track_mempool_remove(&txid);
                        debug!(%txid, mempool = bitcoin_state.mempool.len(), "Mempool remove");
                    }
                    BitcoinEvent::MempoolSync(txs) => {
                        bitcoin_state.track_mempool_sync(txs.iter().map(|tx| tx.txid));
                        info!(mempool = bitcoin_state.mempool.len(), "Mempool sync");
                    }
                    BitcoinEvent::Rollback { to_height } => {
                        info!(to_height, "Bitcoin rollback");
                    }
                }
            }
            Some(msg) = channels.consensus.recv() => {
                handle_consensus_msg(consensus_state, executor, bitcoin_state, channels, msg, node_index).await?;
            }
            else => break,
        }
    }

    Err(anyhow!("All channels closed"))
}
