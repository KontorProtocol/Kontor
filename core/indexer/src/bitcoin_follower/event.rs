use bitcoin::Txid;
use indexer_types::{Block, Transaction};

#[derive(Debug, Clone, PartialEq)]
pub enum BitcoinEvent {
    BlockInsert { target_height: u64, block: Block },
    Rollback { to_height: u64 },
    MempoolSync(Vec<Transaction>),
    MempoolInsert(Transaction),
    MempoolRemove(Txid),
}
