use std::collections::{BTreeMap, HashMap, VecDeque};

use bitcoin::Txid;

pub struct BitcoinState {
    pub mempool: HashMap<Txid, bitcoin::Transaction>,
    pub chain_tip: u64,
    pub block_history: BTreeMap<u64, Vec<Txid>>,
    pub pending_blocks: VecDeque<u64>,
    pub confirmed_txids: HashMap<Txid, u64>,
    history_window: u64,
}

impl BitcoinState {
    pub fn new(history_window: u64) -> Self {
        Self {
            mempool: HashMap::new(),
            chain_tip: 0,
            block_history: BTreeMap::new(),
            pending_blocks: VecDeque::new(),
            confirmed_txids: HashMap::new(),
            history_window,
        }
    }

    /// Track a new block: update chain tip, remove txids from mempool,
    /// record in block history and pending queue, record confirmations,
    /// and prune old history.
    pub fn track_block(&mut self, height: u64, txids: &[Txid]) {
        self.chain_tip = height;
        for txid in txids {
            self.mempool.remove(txid);
            self.confirmed_txids.entry(*txid).or_insert(height);
        }
        self.block_history.insert(height, txids.to_vec());
        self.pending_blocks.push_back(height);

        let prune_below = height.saturating_sub(self.history_window);
        self.block_history.retain(|h, _| *h >= prune_below);
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
