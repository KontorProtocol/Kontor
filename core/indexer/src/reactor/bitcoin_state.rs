use std::collections::HashMap;

use bitcoin::Txid;

use crate::bitcoin_client::TxCache;

pub struct BitcoinState {
    pub mempool: HashMap<Txid, bitcoin::Transaction>,
    /// Shared tx cache (clone of the one held by BitcoinClient).
    /// Populated from mempool events and block transactions.
    pub tx_cache: Option<TxCache>,
}

impl BitcoinState {
    pub fn new() -> Self {
        Self {
            mempool: HashMap::new(),
            tx_cache: None,
        }
    }

    pub fn with_tx_cache(mut self, cache: TxCache) -> Self {
        self.tx_cache = Some(cache);
        self
    }

    /// Remove confirmed txids from the mempool when a block arrives.
    pub fn remove_confirmed_txids(&mut self, txids: &[Txid]) {
        for txid in txids {
            self.mempool.remove(txid);
        }
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
