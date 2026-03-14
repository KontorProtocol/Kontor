use std::collections::{HashMap, VecDeque};

use bitcoin::Txid;

pub struct BitcoinState {
    pub mempool: HashMap<Txid, bitcoin::Transaction>,
    pub chain_tip: u64,
    pub pending_blocks: VecDeque<indexer_types::Block>,
}

impl BitcoinState {
    pub fn new() -> Self {
        Self {
            mempool: HashMap::new(),
            chain_tip: 0,
            pending_blocks: VecDeque::new(),
        }
    }

    /// Track a new block: update chain tip and remove txids from mempool.
    pub fn track_block(&mut self, height: u64, txids: &[Txid]) {
        self.chain_tip = height;
        for txid in txids {
            self.mempool.remove(txid);
        }
    }

    /// Reset block-derived state after a rollback. Mempool is maintained
    /// by the event stream and doesn't need resetting.
    pub fn reset(&mut self) {
        self.chain_tip = 0;
        self.pending_blocks.clear();
    }

    pub fn track_mempool_insert(&mut self, tx: bitcoin::Transaction) {
        let txid = tx.compute_txid();
        self.mempool.insert(txid, tx);
    }

    pub fn track_mempool_remove(&mut self, txid: &Txid) {
        self.mempool.remove(txid);
    }

    pub fn track_mempool_sync(&mut self, txs: impl Iterator<Item = bitcoin::Transaction>) {
        self.mempool.clear();
        for tx in txs {
            let txid = tx.compute_txid();
            self.mempool.insert(txid, tx);
        }
    }
}
