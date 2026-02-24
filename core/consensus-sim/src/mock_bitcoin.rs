use bitcoin::BlockHash;
use bitcoin::Txid;
use indexer::bitcoin_follower::event::BitcoinEvent;
use indexer::test_utils::{new_mock_block_hash, new_mock_transaction};
use indexer_types::{Block, Transaction};
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tokio_util::sync::CancellationToken;
use tracing::info;

pub struct MockBitcoin {
    tip_height: u64,
    prev_hash: BlockHash,
    mempool: Vec<Transaction>,
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

    pub fn mempool(&self) -> &[Transaction] {
        &self.mempool
    }

    /// Generate new transactions and return MempoolInsert events for each.
    pub fn generate_mempool_txs(&mut self, count: usize) -> Vec<BitcoinEvent> {
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            self.tx_counter += 1;
            let tx = new_mock_transaction(self.tx_counter);
            events.push(BitcoinEvent::MempoolInsert(tx.clone()));
            self.mempool.push(tx);
        }
        events
    }

    /// Mine a block containing the specified txids, removing them from the mempool.
    pub fn mine_block(&mut self, txids: &[Txid]) -> Vec<BitcoinEvent> {
        self.tip_height += 1;
        let height = self.tip_height;

        let hash = new_mock_block_hash(height as u32);
        let prev_hash = self.prev_hash;
        self.prev_hash = hash;

        let mut confirmed = Vec::new();
        let mut remove_events = Vec::new();

        for txid in txids {
            if let Some(pos) = self.mempool.iter().position(|tx| tx.txid == *txid) {
                let tx = self.mempool.remove(pos);
                remove_events.push(BitcoinEvent::MempoolRemove(tx.txid));
                confirmed.push(tx);
            }
        }

        let block = Block {
            height,
            hash,
            prev_hash,
            transactions: confirmed,
        };

        let mut events = vec![BitcoinEvent::BlockInsert {
            target_height: height,
            block,
        }];
        events.extend(remove_events);
        events
    }

    /// Mine a block confirming all mempool transactions.
    pub fn mine_block_all(&mut self) -> Vec<BitcoinEvent> {
        let txids: Vec<Txid> = self.mempool.iter().map(|tx| tx.txid).collect();
        self.mine_block(&txids)
    }

    /// Mine an empty block (no transactions confirmed).
    pub fn mine_empty_block(&mut self) -> Vec<BitcoinEvent> {
        self.mine_block(&[])
    }

    /// Remove a txid from the mempool without confirming it.
    pub fn drop_txid(&mut self, txid: &Txid) -> Option<BitcoinEvent> {
        if let Some(pos) = self.mempool.iter().position(|tx| tx.txid == *txid) {
            self.mempool.remove(pos);
            Some(BitcoinEvent::MempoolRemove(*txid))
        } else {
            None
        }
    }
}

/// Run the mock bitcoin source, periodically mining blocks and generating mempool txs.
pub async fn run(
    event_tx: mpsc::Sender<BitcoinEvent>,
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
                    if event_tx.send(event).await.is_err() {
                        return;
                    }
                }

                let block_events = mock.mine_block_all();
                for event in block_events {
                    if event_tx.send(event).await.is_err() {
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
        let txids: Vec<Txid> = mock.mempool().iter().map(|tx| tx.txid).collect();
        let unique: std::collections::HashSet<_> = txids.iter().collect();
        assert_eq!(txids.len(), unique.len());
    }

    #[test]
    fn mine_block_confirms_specified() {
        let mut mock = MockBitcoin::new(0);
        mock.generate_mempool_txs(5);
        let target_txid = mock.mempool()[2].txid;

        let events = mock.mine_block(&[target_txid]);

        // BlockInsert should contain the confirmed tx
        let block_event = &events[0];
        match block_event {
            BitcoinEvent::BlockInsert { block, .. } => {
                assert_eq!(block.transactions.len(), 1);
                assert_eq!(block.transactions[0].txid, target_txid);
            }
            _ => panic!("Expected BlockInsert"),
        }

        // Should still have 4 txs in mempool
        assert_eq!(mock.mempool().len(), 4);
    }

    #[test]
    fn mine_block_removes_from_mempool() {
        let mut mock = MockBitcoin::new(0);
        mock.generate_mempool_txs(3);
        let txids: Vec<Txid> = mock.mempool().iter().map(|tx| tx.txid).collect();

        mock.mine_block(&txids[..2]);
        assert_eq!(mock.mempool().len(), 1);
        assert_eq!(mock.mempool()[0].txid, txids[2]);
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
        let txid = mock.mempool()[1].txid;

        let event = mock.drop_txid(&txid);
        assert!(event.is_some());
        assert_eq!(mock.mempool().len(), 2);
        assert!(mock.mempool().iter().all(|tx| tx.txid != txid));
    }

    #[test]
    fn prev_hash_chain_valid() {
        let mut mock = MockBitcoin::new(0);
        let mut prev_hashes = vec![mock.prev_hash];

        for _ in 0..5 {
            let events = mock.mine_empty_block();
            match &events[0] {
                BitcoinEvent::BlockInsert { block, .. } => {
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

        // Generate mempool txs → MempoolInsert events
        let tx_events = mock.generate_mempool_txs(2);
        assert_eq!(tx_events.len(), 2);
        for event in &tx_events {
            assert!(matches!(event, BitcoinEvent::MempoolInsert(_)));
        }

        // Mine block → BlockInsert + MempoolRemove events
        let block_events = mock.mine_block_all();
        assert!(matches!(&block_events[0], BitcoinEvent::BlockInsert { .. }));
        for event in &block_events[1..] {
            assert!(matches!(event, BitcoinEvent::MempoolRemove(_)));
        }
    }
}
