use tracing::{debug, info};

use indexer::bitcoin_follower::event::BitcoinEvent;

use super::State;
use super::types::FINALITY_WINDOW;

pub fn handle_bitcoin_event(state: &mut State, event: BitcoinEvent) {
    match event {
        BitcoinEvent::BlockInsert { block, .. } => {
            state.chain_tip = block.height;
            let confirmed_txids: Vec<_> = block
                .transactions
                .iter()
                .map(|tx| tx.txid)
                .collect();
            for txid in &confirmed_txids {
                state.mempool.remove(txid);
            }

            // Store block history for replay and queue for processing
            state
                .block_history
                .insert(block.height, confirmed_txids.clone());
            state.pending_blocks.push_back(block.height);

            // Prune old block history
            let prune_below = block.height.saturating_sub(FINALITY_WINDOW + 6);
            state.block_history.retain(|h, _| *h >= prune_below);

            info!(
                height = block.height,
                txs = block.transactions.len(),
                mempool = state.mempool.len(),
                "Block queued"
            );

            // Record confirmed txids for finality tracking
            state.record_confirmed_block(block.height, &confirmed_txids);

            // Finality deadlines are reached by block arrivals, not consensus decisions.
            // Check immediately so rollback/finalization isn't delayed until the next batch.
            if state
                .pending_batches
                .iter()
                .any(|b| b.deadline <= state.chain_tip)
            {
                let replay_up_to = state.last_processed_anchor.saturating_add(1);
                state.run_finality_checks(replay_up_to);
            }
        }
        BitcoinEvent::MempoolInsert(tx) => {
            state.mempool.insert(tx.txid);
            debug!(txid = %tx.txid, mempool = state.mempool.len(), "Mempool insert");
        }
        BitcoinEvent::MempoolRemove(txid) => {
            state.mempool.remove(&txid);
            debug!(%txid, mempool = state.mempool.len(), "Mempool remove");
        }
        BitcoinEvent::MempoolSync(txs) => {
            state.mempool.clear();
            for tx in txs {
                state.mempool.insert(tx.txid);
            }
            info!(mempool = state.mempool.len(), "Mempool sync");
        }
        BitcoinEvent::Rollback { to_height } => {
            info!(to_height, "Bitcoin rollback");
        }
    }
}
