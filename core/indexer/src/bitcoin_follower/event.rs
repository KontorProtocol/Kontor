use bitcoin::Txid;
use indexer_types::Block;

#[derive(Debug, Clone, PartialEq)]
pub enum BlockEvent {
    BlockInsert { target_height: u64, block: Block },
    Rollback { to_height: u64 },
}

#[derive(Debug, Clone, PartialEq)]
pub enum MempoolEvent {
    Sync(Vec<bitcoin::Transaction>),
    Insert(bitcoin::Transaction),
    Remove(Txid),
}
