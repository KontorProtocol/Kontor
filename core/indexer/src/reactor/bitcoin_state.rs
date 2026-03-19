use std::collections::HashMap;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};

use crate::bitcoin_client::TxCache;

pub struct BitcoinState {
    pub mempool: HashMap<Txid, bitcoin::Transaction>,
    pub chain_tip: u64,
    pub chain_tip_hash: BlockHash,
    /// Block hash by height — populated as blocks arrive.
    pub block_hashes: HashMap<u64, BlockHash>,
    /// Shared tx cache (clone of the one held by BitcoinClient).
    /// Populated from mempool events and block transactions.
    pub tx_cache: Option<TxCache>,
}

impl BitcoinState {
    pub fn new() -> Self {
        Self {
            mempool: HashMap::new(),
            chain_tip: 0,
            chain_tip_hash: BlockHash::all_zeros(),
            block_hashes: HashMap::new(),
            tx_cache: None,
        }
    }

    pub fn with_tx_cache(mut self, cache: TxCache) -> Self {
        self.tx_cache = Some(cache);
        self
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
    }

    pub async fn track_mempool_insert(&mut self, tx: bitcoin::Transaction) {
        let txid = tx.compute_txid();
        if let Some(cache) = &self.tx_cache {
            cache.insert(txid, tx.clone()).await;
        }
        self.mempool.insert(txid, tx);
    }

    pub async fn track_mempool_remove(&mut self, txid: &Txid) {
        if let Some(cache) = &self.tx_cache {
            cache.invalidate(txid).await;
        }
        self.mempool.remove(txid);
    }

    pub async fn track_mempool_sync(&mut self, txs: impl Iterator<Item = bitcoin::Transaction>) {
        self.mempool.clear();
        for tx in txs {
            let txid = tx.compute_txid();
            if let Some(cache) = &self.tx_cache {
                cache.insert(txid, tx.clone()).await;
            }
            self.mempool.insert(txid, tx);
        }
    }
}
