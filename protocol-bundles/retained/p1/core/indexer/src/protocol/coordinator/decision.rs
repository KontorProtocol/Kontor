use bitcoin::{Transaction, Txid};

use crate::consensus::{Height, Value};

#[derive(Clone)]
pub struct DeferredDecision {
    pub consensus_height: Height,
    pub value: Value,
    pub certificate: Vec<u8>,
    /// Replay exclusions change execution only. The certified value and its
    /// witness-inclusive identity remain immutable through every rollback.
    pub execution_txs: Option<Vec<Transaction>>,
}

impl DeferredDecision {
    pub fn execution_txs(&self) -> Vec<Transaction> {
        self.execution_txs
            .clone()
            .unwrap_or_else(|| self.value.batch_raw_txs())
    }

    pub fn decided_txs(&self) -> Vec<Transaction> {
        self.value.batch_raw_txs()
    }
    pub fn decided_txids(&self) -> Vec<Txid> {
        self.value.batch_txids()
    }
}
