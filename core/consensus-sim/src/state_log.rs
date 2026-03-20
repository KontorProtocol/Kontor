use std::collections::{BTreeMap, HashMap, HashSet};

use bitcoin::Txid;
use bitcoin::hashes::Hash;
use sha3::{Digest, Keccak256};

use prost::Message;

use indexer::consensus::codec::decode_commit_certificate;
use indexer::consensus::{CommitCertificate, Ctx, Height, Value};
use indexer::reactor::executor::Executor;
use indexer_types::Transaction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStatus {
    Batched,
    Confirmed,
}

fn tx_status_as_byte(status: &TxStatus) -> u8 {
    match status {
        TxStatus::Batched => 0,
        TxStatus::Confirmed => 1,
    }
}

#[derive(Debug, Clone)]
pub struct StateEntry {
    pub anchor_height: u64,
    pub batch_height: Option<Height>,
    pub txid: Txid,
    pub status: TxStatus,
}

/// Maps consensus height → anchor height for rollback recovery.
#[derive(Debug, Clone)]
struct BatchHeightEntry {
    consensus_height: Height,
    anchor_height: u64,
}

pub struct StateLog {
    entries: Vec<StateEntry>,
    checkpoint: [u8; 32],
    batch_heights: Vec<BatchHeightEntry>,
    /// Txids seen in confirmed Bitcoin blocks (for finality checks).
    /// Includes batched txids that were skipped for execution.
    block_confirmed: HashSet<Txid>,
    /// Decided values + certificates, keyed by consensus height.
    /// Used by Malachite sync protocol to serve historical decided values.
    decided: BTreeMap<Height, (Value, CommitCertificate<Ctx>)>,
    /// Known transactions — populated from mempool inserts and block confirmations.
    /// Used to resolve txids back to full transactions for batch execution.
    known_txs: HashMap<Txid, bitcoin::Transaction>,
    /// Records `replay_blocks_from` calls for test assertions.
    pub replay_requests: Vec<u64>,
}

impl Default for StateLog {
    fn default() -> Self {
        Self::new()
    }
}

impl StateLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            checkpoint: [0u8; 32],
            batch_heights: Vec::new(),
            block_confirmed: HashSet::new(),
            decided: BTreeMap::new(),
            known_txs: HashMap::new(),
            replay_requests: Vec::new(),
        }
    }

    /// Register a transaction so it can be resolved by txid later.
    pub fn track_transaction(&mut self, tx: bitcoin::Transaction) {
        let txid = tx.compute_txid();
        self.known_txs.insert(txid, tx);
    }

    pub fn checkpoint(&self) -> [u8; 32] {
        self.checkpoint
    }

    pub fn entries(&self) -> &[StateEntry] {
        &self.entries
    }

    pub fn status_of(&self, txid: &Txid) -> Option<&TxStatus> {
        self.entries
            .iter()
            .rev()
            .find(|e| &e.txid == txid)
            .map(|e| &e.status)
    }

    pub fn batched_txids(&self) -> HashSet<Txid> {
        self.entries
            .iter()
            .filter(|e| e.status == TxStatus::Batched)
            .map(|e| e.txid)
            .collect()
    }

    pub fn entries_at_anchor(&self, height: u64) -> Vec<&StateEntry> {
        self.entries
            .iter()
            .filter(|e| e.anchor_height == height)
            .collect()
    }

    /// Low-level append: add a single entry and update checkpoint.
    pub fn append_entry(&mut self, anchor_height: u64, txid: Txid, status: TxStatus) {
        let entry = StateEntry {
            anchor_height,
            batch_height: None,
            txid,
            status,
        };
        self.update_checkpoint(&entry);
        self.entries.push(entry);
    }

    /// Append entries for a decided batch. All txids get `Batched` status.
    pub fn apply_batch(&mut self, anchor_height: u64, consensus_height: Height, txids: &[Txid]) {
        self.batch_heights.push(BatchHeightEntry {
            consensus_height,
            anchor_height,
        });
        for txid in txids {
            let entry = StateEntry {
                anchor_height,
                batch_height: Some(consensus_height),
                txid: *txid,
                status: TxStatus::Batched,
            };
            self.update_checkpoint(&entry);
            self.entries.push(entry);
        }
    }

    /// Return the highest consensus height whose anchor_height < `anchor`.
    pub fn last_consensus_height_before(&self, anchor: u64) -> Option<Height> {
        self.batch_heights
            .iter()
            .filter(|e| e.anchor_height < anchor)
            .max_by_key(|e| e.consensus_height)
            .map(|e| e.consensus_height)
    }

    /// Append entries for a bitcoin block's transactions. Skips txids already in `Batched` status
    /// (deduplication — batched txs take priority).
    pub fn apply_block(&mut self, height: u64, txids: &[Txid]) {
        // Record all txids as block-confirmed (for finality checks),
        // even batched ones that we skip for execution.
        self.block_confirmed.extend(txids);

        let batched = self.batched_txids();
        for txid in txids {
            if batched.contains(txid) {
                continue;
            }
            let entry = StateEntry {
                anchor_height: height,
                batch_height: None,
                txid: *txid,
                status: TxStatus::Confirmed,
            };
            self.update_checkpoint(&entry);
            self.entries.push(entry);
        }
    }

    /// Remove all entries at or above `anchor_height` and recompute checkpoint.
    pub fn rollback_to(&mut self, anchor_height: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.anchor_height < anchor_height);
        self.batch_heights
            .retain(|e| e.anchor_height < anchor_height);
        // Rebuild block_confirmed from surviving entries
        self.block_confirmed.clear();
        let removed = before - self.entries.len();
        self.recompute_checkpoint();
        removed
    }

    fn update_checkpoint(&mut self, entry: &StateEntry) {
        let mut hasher = Keccak256::new();
        hasher.update(self.checkpoint);
        hasher.update(entry.txid.to_byte_array());
        hasher.update([tx_status_as_byte(&entry.status)]);
        self.checkpoint = hasher.finalize().into();
    }

    fn recompute_checkpoint(&mut self) {
        self.checkpoint = [0u8; 32];
        for i in 0..self.entries.len() {
            let txid_bytes = self.entries[i].txid.to_byte_array();
            let status_byte = tx_status_as_byte(&self.entries[i].status);
            let mut hasher = Keccak256::new();
            hasher.update(self.checkpoint);
            hasher.update(txid_bytes);
            hasher.update([status_byte]);
            self.checkpoint = hasher.finalize().into();
        }
    }
}

/// Executor implementation backed by StateLog — used by consensus-sim for testing.
impl Executor for StateLog {
    async fn validate_transaction(&self, tx: &bitcoin::Transaction) -> Option<Transaction> {
        // Sim doesn't parse real Kontor ops — return a dummy transaction
        Some(Transaction {
            txid: tx.compute_txid(),
            index: 0,
            ops: Vec::new(),
            op_return_data: Default::default(),
        })
    }

    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        self.known_txs.get(txid).cloned()
    }

    async fn filter_unbatched_txids(&self, txids: &[Txid]) -> Vec<Txid> {
        let known: HashSet<&Txid> = self.entries.iter().map(|e| &e.txid).collect();
        txids.iter().filter(|t| !known.contains(t)).copied().collect()
    }

    async fn execute_batch(
        &mut self,
        anchor_height: u64,
        anchor_hash: bitcoin::BlockHash,
        consensus_height: Height,
        certificate: &[u8],
        txs: &[indexer_types::Transaction],
    ) {
        let txids: Vec<Txid> = txs.iter().map(|tx| tx.txid).collect();
        self.apply_batch(anchor_height, consensus_height, &txids);

        // Store decided value if certificate is present (not a replay)
        if !certificate.is_empty()
            && let Ok(proto) = indexer::consensus::proto::CommitCertificate::decode(certificate)
            && let Ok(cert) = decode_commit_certificate(proto)
        {
            let value = Value::new_batch(anchor_height, anchor_hash, txids);
            self.decided.insert(consensus_height, (value, cert));
        }
    }

    async fn execute_block(&mut self, block: &indexer_types::Block) {
        let txids: Vec<Txid> = block.transactions.iter().map(|tx| tx.txid).collect();
        self.apply_block(block.height, &txids);
    }

    async fn rollback_state(&mut self, to_anchor: u64) -> usize {
        self.rollback_to(to_anchor)
    }

    async fn checkpoint(&self) -> Option<[u8; 32]> {
        Some(self.checkpoint)
    }

    async fn last_batch_consensus_height_before(&self, anchor: u64) -> Option<Height> {
        self.last_consensus_height_before(anchor)
    }

    async fn is_confirmed_on_chain(&self, txid: &bitcoin::Txid) -> bool {
        self.block_confirmed.contains(txid)
    }

    async fn last_executed_block_height(&self) -> Option<u64> {
        self.entries
            .iter()
            .filter(|e| e.status == TxStatus::Confirmed)
            .map(|e| e.anchor_height)
            .max()
    }

    async fn get_decided(&self, height: Height) -> Option<(Value, CommitCertificate<Ctx>)> {
        self.decided.get(&height).cloned()
    }

    async fn min_decided_height(&self) -> Option<Height> {
        self.decided.keys().next().copied()
    }

    async fn get_decided_from_anchor(&self, from_anchor: u64) -> Vec<(Height, Value)> {
        self.decided
            .iter()
            .filter(|(_, (value, _))| value.block_height() >= from_anchor)
            .map(|(h, (v, _))| (*h, v.clone()))
            .collect()
    }

    async fn replay_blocks_from(&mut self, height: u64) {
        self.replay_requests.push(height);
    }

    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        let txid = tx.compute_txid();
        Some(indexer_types::Transaction {
            txid,
            index: 0,
            ops: vec![],
            op_return_data: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_txid(n: u8) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Txid::from_byte_array(bytes)
    }

    #[test]
    fn apply_batch_appends_entries() {
        let mut log = StateLog::new();
        let txids = vec![make_txid(1), make_txid(2)];
        log.apply_batch(100, Height::new(1), &txids);

        assert_eq!(log.entries().len(), 2);
        assert_eq!(log.status_of(&make_txid(1)), Some(&TxStatus::Batched));
        assert_eq!(log.status_of(&make_txid(2)), Some(&TxStatus::Batched));
        assert_eq!(log.entries()[0].anchor_height, 100);
        assert_eq!(log.entries()[0].batch_height, Some(Height::new(1)));
    }

    #[test]
    fn apply_block_appends_confirmed_entries() {
        let mut log = StateLog::new();
        let txids = vec![make_txid(1), make_txid(2)];
        log.apply_block(100, &txids);

        assert_eq!(log.entries().len(), 2);
        assert_eq!(log.status_of(&make_txid(1)), Some(&TxStatus::Confirmed));
        assert_eq!(log.entries()[0].batch_height, None);
    }

    #[test]
    fn apply_block_skips_batched_duplicates() {
        let mut log = StateLog::new();
        let tx1 = make_txid(1);
        let tx2 = make_txid(2);
        let tx3 = make_txid(3);

        log.apply_batch(100, Height::new(1), &[tx1, tx2]);
        log.apply_block(100, &[tx1, tx2, tx3]);

        assert_eq!(log.entries().len(), 3);
        assert_eq!(log.status_of(&tx1), Some(&TxStatus::Batched));
        assert_eq!(log.status_of(&tx2), Some(&TxStatus::Batched));
        assert_eq!(log.status_of(&tx3), Some(&TxStatus::Confirmed));
    }

    #[test]
    fn rollback_truncates_at_anchor() {
        let mut log = StateLog::new();
        log.apply_batch(100, Height::new(1), &[make_txid(1)]);
        log.apply_batch(101, Height::new(2), &[make_txid(2)]);
        log.apply_batch(102, Height::new(3), &[make_txid(3)]);

        let removed = log.rollback_to(101);
        assert_eq!(removed, 2);
        assert_eq!(log.entries().len(), 1);
        assert_eq!(log.status_of(&make_txid(1)), Some(&TxStatus::Batched));
        assert_eq!(log.status_of(&make_txid(2)), None);
        assert_eq!(log.status_of(&make_txid(3)), None);
    }

    #[test]
    fn checkpoint_changes_on_append() {
        let mut log = StateLog::new();
        let initial = StateLog::checkpoint(&log);
        assert_eq!(initial, [0u8; 32]);

        log.apply_batch(100, Height::new(1), &[make_txid(1)]);
        let after_one = StateLog::checkpoint(&log);
        assert_ne!(after_one, initial);

        log.apply_batch(100, Height::new(1), &[make_txid(2)]);
        let after_two = StateLog::checkpoint(&log);
        assert_ne!(after_two, after_one);
    }

    #[test]
    fn checkpoint_restored_after_rollback() {
        let mut log = StateLog::new();
        log.apply_batch(100, Height::new(1), &[make_txid(1)]);
        let checkpoint_at_100 = StateLog::checkpoint(&log);

        log.apply_batch(101, Height::new(2), &[make_txid(2)]);
        assert_ne!(StateLog::checkpoint(&log), checkpoint_at_100);

        log.rollback_to(101);
        assert_eq!(StateLog::checkpoint(&log), checkpoint_at_100);
    }

    #[test]
    fn same_operations_produce_same_checkpoint() {
        let mut log_a = StateLog::new();
        let mut log_b = StateLog::new();

        let txids = vec![make_txid(1), make_txid(2)];
        log_a.apply_batch(100, Height::new(1), &txids);
        log_b.apply_batch(100, Height::new(1), &txids);

        assert_eq!(StateLog::checkpoint(&log_a), StateLog::checkpoint(&log_b));

        log_a.apply_block(100, &[make_txid(3)]);
        log_b.apply_block(100, &[make_txid(3)]);

        assert_eq!(StateLog::checkpoint(&log_a), StateLog::checkpoint(&log_b));
    }

    #[test]
    fn batched_txids_returns_all_batched() {
        let mut log = StateLog::new();
        log.apply_batch(100, Height::new(1), &[make_txid(1), make_txid(2)]);
        log.apply_block(100, &[make_txid(3)]);

        let batched = log.batched_txids();
        assert_eq!(batched.len(), 2);
        assert!(batched.contains(&make_txid(1)));
        assert!(batched.contains(&make_txid(2)));
        assert!(!batched.contains(&make_txid(3)));
    }

    #[test]
    fn entries_at_anchor_filters_correctly() {
        let mut log = StateLog::new();
        log.apply_batch(100, Height::new(1), &[make_txid(1)]);
        log.apply_batch(101, Height::new(2), &[make_txid(2)]);
        log.apply_block(100, &[make_txid(3)]);

        let at_100 = log.entries_at_anchor(100);
        assert_eq!(at_100.len(), 2);

        let at_101 = log.entries_at_anchor(101);
        assert_eq!(at_101.len(), 1);
    }
}
