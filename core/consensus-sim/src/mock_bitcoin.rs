use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{BlockHash, Txid};
use indexer::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use indexer::test_utils::new_mock_block_hash;
use indexer_types::Block;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Create a minimal bitcoin::Transaction with a unique txid derived from the nonce.
pub fn make_tx(nonce: u32) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: Version::ONE,
        lock_time: LockTime::from_consensus(nonce),
        input: vec![],
        output: vec![],
    }
}

/// Convert a bitcoin::Transaction to an indexer_types::Transaction (for BlockInsert events).
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
}

impl MockBitcoin {
    pub fn new(start_height: u64) -> Self {
        Self {
            tip_height: start_height,
            prev_hash: new_mock_block_hash(start_height as u32),
            mempool: Vec::new(),
            tx_counter: 0,
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

    /// Generate new transactions and return MempoolEvent::Insert events for each.
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

    /// Mine a block containing the specified txids, removing them from the mempool.
    /// Returns (block_events, mempool_events) for the separate channels.
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

        let block_events = vec![BlockEvent::BlockInsert {
            target_height: height,
            block,
        }];

        (block_events, remove_events)
    }

    /// Mine a block confirming all mempool transactions.
    pub fn mine_block_all(&mut self) -> (Vec<BlockEvent>, Vec<MempoolEvent>) {
        let txids = self.mempool_txids();
        self.mine_block(&txids)
    }

    /// Mine an empty block (no transactions confirmed).
    pub fn mine_empty_block(&mut self) -> (Vec<BlockEvent>, Vec<MempoolEvent>) {
        self.mine_block(&[])
    }

    /// Remove a txid from the mempool without confirming it.
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

/// Run the mock bitcoin source, periodically mining blocks and generating mempool txs.
pub async fn run(
    block_tx: mpsc::Sender<BlockEvent>,
    mempool_tx: mpsc::Sender<MempoolEvent>,
    cancel_token: CancellationToken,
    block_interval: Duration,
    txs_per_interval: usize,
) {
    let mut mock = MockBitcoin::new(0);
    let mut ticker = interval(block_interval);

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("MockBitcoin: cancelled");
                break;
            }
            _ = ticker.tick() => {
                let tx_events = mock.generate_mempool_txs(txs_per_interval);
                for event in tx_events {
                    if mempool_tx.send(event).await.is_err() {
                        return;
                    }
                }

                let (blk_events, mem_events) = mock.mine_block_all();
                for event in mem_events {
                    if mempool_tx.send(event).await.is_err() {
                        return;
                    }
                }
                for event in blk_events {
                    if block_tx.send(event).await.is_err() {
                        return;
                    }
                }

                info!(
                    height = mock.tip_height(),
                    mempool = mock.mempool().len(),
                    "MockBitcoin: mined block"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mine_block_advances_tip() {
        let mut mock = MockBitcoin::new(100);
        assert_eq!(mock.tip_height(), 100);
        mock.mine_empty_block();
        assert_eq!(mock.tip_height(), 101);
        mock.mine_empty_block();
        assert_eq!(mock.tip_height(), 102);
    }

    #[test]
    fn generate_mempool_txs_unique() {
        let mut mock = MockBitcoin::new(0);
        mock.generate_mempool_txs(10);
        let txids = mock.mempool_txids();
        let unique: std::collections::HashSet<_> = txids.iter().collect();
        assert_eq!(txids.len(), unique.len());
    }

    #[test]
    fn mine_block_confirms_specified() {
        let mut mock = MockBitcoin::new(0);
        mock.generate_mempool_txs(5);
        let target_txid = mock.mempool()[2].compute_txid();

        let (blk_events, _mem_events) = mock.mine_block(&[target_txid]);

        match &blk_events[0] {
            BlockEvent::BlockInsert { block, .. } => {
                assert_eq!(block.transactions.len(), 1);
                assert_eq!(block.transactions[0].txid, target_txid);
            }
            _ => panic!("Expected BlockInsert"),
        }

        assert_eq!(mock.mempool().len(), 4);
    }

    #[test]
    fn mine_block_removes_from_mempool() {
        let mut mock = MockBitcoin::new(0);
        mock.generate_mempool_txs(3);
        let txids = mock.mempool_txids();

        mock.mine_block(&txids[..2]);
        assert_eq!(mock.mempool().len(), 1);
        assert_eq!(mock.mempool()[0].compute_txid(), txids[2]);
    }

    #[test]
    fn mine_block_all_empties_mempool() {
        let mut mock = MockBitcoin::new(0);
        mock.generate_mempool_txs(5);
        assert_eq!(mock.mempool().len(), 5);

        mock.mine_block_all();
        assert_eq!(mock.mempool().len(), 0);
    }

    #[test]
    fn drop_txid_removes() {
        let mut mock = MockBitcoin::new(0);
        mock.generate_mempool_txs(3);
        let txid = mock.mempool()[1].compute_txid();

        let event = mock.drop_txid(&txid);
        assert!(event.is_some());
        assert_eq!(mock.mempool().len(), 2);
        assert!(mock.mempool().iter().all(|tx| tx.compute_txid() != txid));
    }

    #[test]
    fn prev_hash_chain_valid() {
        let mut mock = MockBitcoin::new(0);
        let mut prev_hashes = vec![mock.prev_hash];

        for _ in 0..5 {
            let (blk_events, _) = mock.mine_empty_block();
            match &blk_events[0] {
                BlockEvent::BlockInsert { block, .. } => {
                    assert_eq!(block.prev_hash, *prev_hashes.last().unwrap());
                    prev_hashes.push(block.hash);
                }
                _ => panic!("Expected BlockInsert"),
            }
        }
    }

    #[test]
    fn events_are_correct_types() {
        let mut mock = MockBitcoin::new(0);

        let tx_events = mock.generate_mempool_txs(2);
        assert_eq!(tx_events.len(), 2);
        for event in &tx_events {
            assert!(matches!(event, MempoolEvent::Insert(_)));
        }

        let (blk_events, mem_events) = mock.mine_block_all();
        assert!(matches!(&blk_events[0], BlockEvent::BlockInsert { .. }));
        for event in &mem_events {
            assert!(matches!(event, MempoolEvent::Remove(_)));
        }
    }
}
