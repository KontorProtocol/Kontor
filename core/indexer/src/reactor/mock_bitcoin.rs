use std::collections::HashMap;

use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{BlockHash, Txid};

use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use crate::test_utils::new_mock_block_hash;
use indexer_types::Block;

/// Create a minimal bitcoin::Transaction with a unique txid derived from the nonce.
pub fn make_tx(nonce: u32) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: Version::ONE,
        lock_time: LockTime::from_consensus(nonce),
        input: vec![],
        output: vec![],
    }
}

fn to_indexer_tx(index: usize, tx: &bitcoin::Transaction) -> indexer_types::Transaction {
    indexer_types::Transaction {
        txid: tx.compute_txid(),
        index: index as i64,
        ops: vec![],
        op_return_data: Default::default(),
    }
}

pub struct MockBitcoin {
    tip_height: u64,
    prev_hash: BlockHash,
    mempool: Vec<bitcoin::Transaction>,
    tx_counter: u32,
    /// Txs confirmed in mined blocks, keyed by txid. Used as RPC stand-in.
    mined_txs: HashMap<Txid, bitcoin::Transaction>,
    /// Track which txids were mined at which height, for rollback cleanup.
    block_txids: HashMap<u64, Vec<Txid>>,
    /// History of mined blocks for late joiners.
    mined_blocks: Vec<BlockEvent>,
}

impl MockBitcoin {
    pub fn new(start_height: u64) -> Self {
        Self {
            tip_height: start_height,
            prev_hash: new_mock_block_hash(start_height as u32),
            mempool: Vec::new(),
            tx_counter: 0,
            mined_txs: HashMap::new(),
            block_txids: HashMap::new(),
            mined_blocks: Vec::new(),
        }
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    pub fn mempool(&self) -> &[bitcoin::Transaction] {
        &self.mempool
    }

    pub fn mempool_txids(&self) -> Vec<Txid> {
        self.mempool.iter().map(|tx| tx.compute_txid()).collect()
    }

    pub fn generate_mempool_txs(&mut self, count: usize) -> Vec<MempoolEvent> {
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            self.tx_counter += 1;
            let tx = make_tx(self.tx_counter);
            events.push(MempoolEvent::Insert(tx.clone()));
            self.mempool.push(tx);
        }
        events
    }

    pub fn mine_block(&mut self, txids: &[Txid]) -> (Vec<BlockEvent>, Vec<MempoolEvent>) {
        self.tip_height += 1;
        let height = self.tip_height;

        let hash = new_mock_block_hash(height as u32);
        let prev_hash = self.prev_hash;
        self.prev_hash = hash;

        let mut confirmed_raw = Vec::new();
        let mut remove_events = Vec::new();

        for txid in txids {
            if let Some(pos) = self
                .mempool
                .iter()
                .position(|tx| tx.compute_txid() == *txid)
            {
                let tx = self.mempool.remove(pos);
                remove_events.push(MempoolEvent::Remove(tx.compute_txid()));
                confirmed_raw.push(tx);
            }
        }

        // Store confirmed txs for RPC-like resolution
        let mut height_txids = Vec::new();
        for tx in &confirmed_raw {
            let txid = tx.compute_txid();
            height_txids.push(txid);
            self.mined_txs.insert(txid, tx.clone());
        }
        self.block_txids.insert(height, height_txids);

        let block = Block {
            height,
            hash,
            prev_hash,
            transactions: confirmed_raw
                .iter()
                .enumerate()
                .map(|(i, tx)| to_indexer_tx(i, tx))
                .collect(),
        };

        let block_event = BlockEvent::BlockInsert {
            target_height: height,
            block,
        };
        self.mined_blocks.push(block_event.clone());

        (vec![block_event], remove_events)
    }

    pub fn mine_block_all(&mut self) -> (Vec<BlockEvent>, Vec<MempoolEvent>) {
        let txids = self.mempool_txids();
        self.mine_block(&txids)
    }

    pub fn mine_empty_block(&mut self) -> (Vec<BlockEvent>, Vec<MempoolEvent>) {
        self.mine_block(&[])
    }

    pub fn reset_to(&mut self, height: u64) {
        // Remove txs from blocks above the reset height
        let heights_to_remove: Vec<u64> = self
            .block_txids
            .keys()
            .filter(|&&h| h > height)
            .copied()
            .collect();
        for h in heights_to_remove {
            if let Some(txids) = self.block_txids.remove(&h) {
                for txid in txids {
                    self.mined_txs.remove(&txid);
                }
            }
        }
        self.tip_height = height;
        self.prev_hash = new_mock_block_hash(height as u32 + 1000);
        self.mined_blocks.retain(|e| match e {
            BlockEvent::BlockInsert { target_height, .. } => *target_height <= height,
            _ => true,
        });
    }

    /// Get all block events for late joiners that missed earlier blocks.
    pub fn get_all_block_events(&self) -> Vec<BlockEvent> {
        self.mined_blocks.clone()
    }

    /// Look up a raw transaction from mined blocks (RPC stand-in for tests).
    pub fn get_raw_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        self.mined_txs.get(txid).cloned()
    }

    pub fn drop_txid(&mut self, txid: &Txid) -> Option<MempoolEvent> {
        if let Some(pos) = self
            .mempool
            .iter()
            .position(|tx| tx.compute_txid() == *txid)
        {
            self.mempool.remove(pos);
            Some(MempoolEvent::Remove(*txid))
        } else {
            None
        }
    }
}
