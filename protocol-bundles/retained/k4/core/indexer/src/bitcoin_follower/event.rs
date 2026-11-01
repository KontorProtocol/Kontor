use std::collections::HashMap;

use super::block::BlockInput;
use bitcoin::Txid;

use crate::bitcoin_client::types::MempoolEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum BlockEvent {
    BlockInsert {
        target_height: u64,
        block: BlockInput,
    },
    Rollback {
        to_height: u64,
    },
}

#[derive(Debug, Clone)]
pub enum MempoolEvent {
    /// A reconnect snapshot replaces raw inputs and fees atomically. Recognition
    /// belongs to the coordinator's selected executor, not the Bitcoin listener.
    Sync {
        transactions: Vec<bitcoin::Transaction>,
        fees: HashMap<Txid, MempoolEntry>,
        mempool_min_fee_sat_per_vb: u64,
    },
    TransactionAdded {
        txid: Txid,
        tx: bitcoin::Transaction,
        fee: MempoolEntry,
    },
    /// Raw fetch can race eviction. Preserve the fee sample without treating
    /// missing bytes as a negative protocol-recognition result.
    MempoolFeeSample {
        txid: Txid,
        fee: MempoolEntry,
    },
    Remove(Txid),
}
