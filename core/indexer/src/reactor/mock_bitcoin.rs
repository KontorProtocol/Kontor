use std::collections::HashMap;
#[cfg(test)]
use std::sync::Arc;

use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, TxIn, TxOut, Txid};

use super::certified_fixture;
use crate::bitcoin_client::types::{MempoolEntry, MempoolEntryFees};
use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use crate::bitcoin_helpers::new_mock_block_hash;
#[cfg(test)]
use crate::runtime::ownership::AsyncGate;

/// Create a minimal bitcoin::Transaction with a unique txid derived from the nonce.
pub fn make_tx(nonce: u32) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: Version::ONE,
        lock_time: LockTime::from_consensus(nonce),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: nonce,
            },
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use bitcoin::{BlockHash, Witness, hashes::Hash};

    use super::MockBitcoin;
    use crate::bitcoin_follower::block::BlockInput;
    use crate::bitcoin_follower::event::BlockEvent;
    use crate::consensus::test_fixtures::context;

    fn inserted(events: &[BlockEvent]) -> &BlockInput {
        let BlockEvent::BlockInsert { block, .. } = &events[0] else {
            panic!("expected mined block");
        };
        block
    }

    #[test]
    fn mined_blocks_retain_exact_witnesses_and_checked_commitments() -> Result<()> {
        let mut bitcoin = MockBitcoin::new(0);
        bitcoin.generate_mempool_txs(2);
        bitcoin.mempool[0].input[0].witness = Witness::from_slice(&[b"retained witness"]);
        let transaction = bitcoin.mempool[0].clone();
        let txid = transaction.compute_txid();
        let (events, removed) = bitcoin.mine_block(&[txid]);
        assert_eq!(removed.len(), 1);
        assert_eq!(bitcoin.mempool.len(), 1);
        let block = inserted(&events);
        let input = block.exact_input(context())?;
        let transactions = input.transactions()?;
        assert_eq!(transactions.len(), 2);
        assert!(transactions[0].is_coinbase());
        assert_eq!(transactions[1], transaction);
        assert_eq!(bitcoin.get_raw_transaction(&txid), Some(transaction));
        assert_eq!(BlockInput::from_exact(&input)?, *block);
        assert_eq!(
            inserted(&bitcoin.get_all_block_events()).exact_input(context())?,
            input
        );
        let mut wrong_hash = block.clone();
        wrong_hash.hash = BlockHash::all_zeros();
        assert!(wrong_hash.exact_input(context()).is_err());
        Ok(())
    }

    #[test]
    fn reorg_preserves_surviving_header_and_replaces_removed_bodies() -> Result<()> {
        let mut bitcoin = MockBitcoin::new(17);
        let (events, _) = bitcoin.mine_empty_block();
        let first = inserted(&events).clone();
        bitcoin.generate_mempool_txs(1);
        let removed_txid = bitcoin.mempool_txids()[0];
        let (events, _) = bitcoin.mine_block_all();
        let removed = inserted(&events).clone();
        assert_eq!(removed.prev_hash, first.hash);
        bitcoin.reset_to(18);
        assert_eq!(bitcoin.get_all_block_events().len(), 1);
        assert_eq!(inserted(&bitcoin.get_all_block_events()), &first);
        assert!(bitcoin.get_raw_transaction(&removed_txid).is_none());
        let (events, _) = bitcoin.mine_empty_block();
        let replacement = inserted(&events);
        assert_eq!(replacement.height, removed.height);
        assert_eq!(replacement.prev_hash, first.hash);
        assert_ne!(replacement.hash, removed.hash);
        replacement.exact_input(context())?;
        first.exact_input(context())?;
        bitcoin.reset_to(17);
        let (events, _) = bitcoin.mine_empty_block();
        let new_first = inserted(&events);
        assert_eq!(new_first.prev_hash, first.prev_hash);
        assert_ne!(new_first.hash, first.hash);
        new_first.exact_input(context())?;
        Ok(())
    }
}

pub struct MockBitcoin {
    base_height: u64,
    base_hash: BlockHash,
    tip_height: u64,
    prev_hash: BlockHash,
    mempool: Vec<bitcoin::Transaction>,
    tx_counter: u32,
    transaction_factory: fn(u32) -> bitcoin::Transaction,
    first_block_transaction: Option<bitcoin::Transaction>,
    /// Txs confirmed in mined blocks, keyed by txid. Used as RPC stand-in.
    mined_txs: HashMap<Txid, bitcoin::Transaction>,
    /// Track which txids were mined at which height, for rollback cleanup.
    block_txids: HashMap<u64, Vec<Txid>>,
    /// History of mined blocks for late joiners.
    mined_blocks: Vec<BlockEvent>,
    /// Bumped by every `reset_to`, and mixed into new block hashes, so a block
    /// mined after a reorg differs from the one it replaces — as on the real
    /// chain. Without this, a re-mined block at the same height is bit-identical
    /// and no test can produce the stale-decision paths a real reorg produces.
    fork: u32,
    #[cfg(test)]
    pub(crate) replay_gate: Option<Arc<AsyncGate>>,
}

impl MockBitcoin {
    pub fn new(start_height: u64) -> Self {
        let base_hash = new_mock_block_hash(start_height as u32);
        Self {
            base_height: start_height,
            base_hash,
            tip_height: start_height,
            prev_hash: base_hash,
            mempool: Vec::new(),
            tx_counter: 0,
            transaction_factory: make_tx,
            first_block_transaction: None,
            mined_txs: HashMap::new(),
            block_txids: HashMap::new(),
            mined_blocks: Vec::new(),
            fork: 0,
            #[cfg(test)]
            replay_gate: None,
        }
    }

    pub fn with_transactions(
        mut self,
        first_block: bitcoin::Transaction,
        factory: fn(u32) -> bitcoin::Transaction,
    ) -> Self {
        self.first_block_transaction = Some(first_block);
        self.transaction_factory = factory;
        self
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
            let tx = (self.transaction_factory)(self.tx_counter);
            let txid = tx.compute_txid();
            let fee = MempoolEntry {
                vsize: 1,
                ancestorsize: 1,
                fees: MempoolEntryFees {
                    base: bitcoin::Amount::from_sat(1),
                    ancestor: bitcoin::Amount::from_sat(1),
                },
                depends: vec![],
            };
            events.push(MempoolEvent::TransactionAdded {
                txid,
                tx: tx.clone(),
                fee,
            });
            self.mempool.push(tx);
        }
        events
    }

    pub fn mine_block(&mut self, txids: &[Txid]) -> (Vec<BlockEvent>, Vec<MempoolEvent>) {
        self.tip_height += 1;
        let height = self.tip_height;

        let mut confirmed_raw = Vec::new();
        // Replacing the first block must replay setup, not inherit its old state.
        if height == self.base_height + 1
            && let Some(tx) = &self.first_block_transaction
        {
            confirmed_raw.push(tx.clone());
        }
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

        // Complete headers and commitments are required by the production
        // certified-input codec. This fixture still does not model PoW or UTXOs.
        let block = certified_fixture::block(height, self.prev_hash, self.fork, confirmed_raw);
        self.prev_hash = block.hash;

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
        assert!((self.base_height..=self.tip_height).contains(&height));
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
        self.mined_blocks.retain(|e| match e {
            BlockEvent::BlockInsert { target_height, .. } => *target_height <= height,
            _ => true,
        });
        // The next block builds on the SURVIVING block at the fork height, which
        // may itself have been mined under an earlier fork value — take its real
        // hash rather than recomputing one.
        self.prev_hash = self
            .mined_blocks
            .iter()
            .find_map(|e| match e {
                BlockEvent::BlockInsert { block, .. } if block.height == height => Some(block.hash),
                _ => None,
            })
            .unwrap_or_else(|| {
                assert_eq!(height, self.base_height, "missing surviving mock block");
                self.base_hash
            });
        self.fork = self
            .fork
            .checked_add(1)
            .expect("mock fork counter exhausted");
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
