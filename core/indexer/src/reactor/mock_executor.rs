use std::collections::{BTreeMap, HashMap, HashSet};

use bitcoin::Txid;
use bitcoin::hashes::Hash;
use sha3::{Digest, Keccak256};

use prost::Message;

use crate::consensus::codec::decode_commit_certificate;
use crate::consensus::{CommitCertificate, Ctx, Height, Value};
use crate::reactor::executor::Executor;
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

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BatchHeightEntry {
    consensus_height: Height,
    anchor_height: u64,
}

pub struct MockExecutor {
    entries: Vec<StateEntry>,
    checkpoint: [u8; 32],
    batch_heights: Vec<BatchHeightEntry>,
    block_confirmed: HashSet<Txid>,
    block_hashes: HashMap<u64, bitcoin::BlockHash>,
    decided: BTreeMap<Height, (Value, CommitCertificate<Ctx>)>,
    known_txs: HashMap<Txid, bitcoin::Transaction>,
    pub replay_requests: Vec<u64>,
}

impl Default for MockExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl MockExecutor {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            checkpoint: [0u8; 32],
            batch_heights: Vec::new(),
            block_confirmed: HashSet::new(),
            block_hashes: HashMap::new(),
            decided: BTreeMap::new(),
            known_txs: HashMap::new(),
            replay_requests: Vec::new(),
        }
    }

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

    pub fn apply_block(&mut self, height: u64, txids: &[Txid]) {
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

    pub fn rollback_to(&mut self, anchor_height: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.anchor_height < anchor_height);
        self.batch_heights
            .retain(|e| e.anchor_height < anchor_height);
        self.block_confirmed.clear();
        self.block_hashes.retain(|&h, _| h < anchor_height);
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

impl Executor for MockExecutor {
    async fn validate_transaction(&self, tx: &bitcoin::Transaction) -> Option<Transaction> {
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
        txids
            .iter()
            .filter(|t| !known.contains(t))
            .copied()
            .collect()
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

        if !certificate.is_empty()
            && let Ok(proto) = crate::consensus::proto::CommitCertificate::decode(certificate)
            && let Ok(cert) = decode_commit_certificate(proto)
        {
            let value = Value::new_batch(anchor_height, anchor_hash, txids);
            self.decided.insert(consensus_height, (value, cert));
        }
    }

    async fn execute_block(&mut self, block: &indexer_types::Block) {
        self.block_hashes.insert(block.height, block.hash);
        let txids: Vec<Txid> = block.transactions.iter().map(|tx| tx.txid).collect();
        self.apply_block(block.height, &txids);
    }

    async fn rollback_state(&mut self, to_anchor: u64) -> usize {
        self.rollback_to(to_anchor)
    }

    async fn checkpoint(&self) -> Option<[u8; 32]> {
        Some(self.checkpoint)
    }

    async fn is_confirmed_on_chain(&self, txid: &bitcoin::Txid) -> bool {
        self.block_confirmed.contains(txid)
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

    async fn block_hash_at_height(&self, height: u64) -> Option<bitcoin::BlockHash> {
        self.block_hashes.get(&height).copied()
    }
}
