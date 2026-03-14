use std::collections::HashMap;

use bitcoin::Txid;

pub struct BitcoinState {
    pub mempool: HashMap<Txid, bitcoin::Transaction>,
    pub chain_tip: u64,
    pub pending_block: Option<indexer_types::Block>,
    pub confirmed_txids: HashMap<Txid, u64>,
    confirmed_txids_window: u64,
}

impl BitcoinState {
    pub fn new(confirmed_txids_window: u64) -> Self {
        Self {
            mempool: HashMap::new(),
            chain_tip: 0,
            pending_block: None,
            confirmed_txids: HashMap::new(),
            confirmed_txids_window,
        }
    }

    /// Track a new block: update chain tip, remove txids from mempool,
    /// and record confirmations.
    pub fn track_block(&mut self, height: u64, txids: &[Txid]) {
        self.chain_tip = height;
        for txid in txids {
            self.mempool.remove(txid);
            self.confirmed_txids.entry(*txid).or_insert(height);
        }

        let prune_below = height.saturating_sub(self.confirmed_txids_window);
        self.confirmed_txids.retain(|_, h| *h >= prune_below);
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
