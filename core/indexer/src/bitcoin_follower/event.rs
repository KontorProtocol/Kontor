use std::collections::HashMap;

use bitcoin::Txid;
use indexer_types::Block;

use crate::bitcoin_client::types::MempoolEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum BlockEvent {
    BlockInsert { target_height: u64, block: Block },
    Rollback { to_height: u64 },
}

/// Kontor-relevant transaction: the raw Bitcoin tx plus the parsed Kontor
/// instructions. Non-Kontor mempool txs are tracked only for fee-index
/// purposes and don't carry this payload.
#[derive(Debug, Clone)]
pub struct KontorTx {
    pub raw: bitcoin::Transaction,
    pub parsed: indexer_types::Transaction,
}

#[derive(Debug, Clone)]
pub enum MempoolEvent {
    /// Full snapshot, emitted on startup and on ZMQ reconnect. Replaces the
    /// entire pending-tx pool and fee index atomically. `fees` contains
    /// every tx in the mempool (not just Kontor ones); `kontor_txs` is
    /// the filtered subset.
    Sync {
        kontor_txs: Vec<(Txid, KontorTx)>,
        fees: HashMap<Txid, MempoolEntry>,
        mempool_min_fee_sat_per_vb: u64,
    },
    /// A Kontor-relevant tx was added to the mempool. Updates both the
    /// pending-tx pool and the fee index; triggers proposal debounce.
    KontorTxAdded {
        txid: Txid,
        tx: KontorTx,
        fee: MempoolEntry,
    },
    /// A non-Kontor mempool tx was observed. Updates the fee index only;
    /// does NOT trigger proposal debounce. Fires at much higher rate than
    /// `KontorTxAdded` during mainnet activity — keeping it as a separate
    /// variant makes the debounce distinction structurally explicit.
    MempoolFeeSample { txid: Txid, fee: MempoolEntry },
    /// A tx was removed from the mempool (confirmed, replaced, or evicted).
    /// May or may not have been Kontor-relevant.
    Remove(Txid),
}
