use std::collections::{HashMap, VecDeque};

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};

pub struct BitcoinState {
    pub mempool: HashMap<Txid, bitcoin::Transaction>,
    pub chain_tip: u64,
    pub chain_tip_hash: BlockHash,
    /// Block hash by height — populated as blocks arrive.
    pub block_hashes: HashMap<u64, BlockHash>,
    pub pending_blocks: VecDeque<indexer_types::Block>,
}

impl BitcoinState {
    pub fn new() -> Self {
        Self {
            mempool: HashMap::new(),
            chain_tip: 0,
            chain_tip_hash: BlockHash::all_zeros(),
            block_hashes: HashMap::new(),
            pending_blocks: VecDeque::new(),
        }
    }

    /// Track a new block: update chain tip/hash and remove txids from mempool.
    pub fn track_block(&mut self, height: u64, hash: BlockHash, txids: &[Txid]) {
        self.chain_tip = height;
        self.chain_tip_hash = hash;
        self.block_hashes.insert(height, hash);
        for txid in txids {
            self.mempool.remove(txid);
        }
    }

    /// Reset block-derived state after a rollback. Mempool is maintained
    /// by the event stream and doesn't need resetting.
    pub fn reset(&mut self) {
        self.chain_tip = 0;
        self.chain_tip_hash = BlockHash::all_zeros();
        self.block_hashes.clear();
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
