use tracing::{debug, info};

use indexer::bitcoin_follower::event::BitcoinEvent;

use super::State;

pub fn handle_bitcoin_event(state: &mut State, event: BitcoinEvent) {
    match event {
        BitcoinEvent::BlockInsert { block, .. } => {
            let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid).collect();
            state.bitcoin_state.track_block(block.height, &txids);

            info!(
                height = block.height,
                txs = block.transactions.len(),
                mempool = state.bitcoin_state.mempool.len(),
                "Block queued"
            );

            // Finality deadlines are reached by block arrivals, not consensus decisions.
            // Check immediately so rollback/finalization isn't delayed until the next batch.
            if state
                .pending_batches
                .iter()
                .any(|b| b.deadline <= state.bitcoin_state.chain_tip)
            {
                let replay_up_to = state.last_processed_anchor.saturating_add(1);
                state.run_finality_checks(replay_up_to);
            }
        }
        BitcoinEvent::MempoolInsert(tx) => {
            let txid = tx.txid;
            state.bitcoin_state.track_mempool_insert(txid);
            debug!(%txid, mempool = state.bitcoin_state.mempool.len(), "Mempool insert");
        }
        BitcoinEvent::MempoolRemove(txid) => {
            state.bitcoin_state.track_mempool_remove(&txid);
            debug!(%txid, mempool = state.bitcoin_state.mempool.len(), "Mempool remove");
        }
        BitcoinEvent::MempoolSync(txs) => {
            state
                .bitcoin_state
                .track_mempool_sync(txs.iter().map(|tx| tx.txid));
            info!(mempool = state.bitcoin_state.mempool.len(), "Mempool sync");
        }
        BitcoinEvent::Rollback { to_height } => {
            info!(to_height, "Bitcoin rollback");
        }
    }
}
