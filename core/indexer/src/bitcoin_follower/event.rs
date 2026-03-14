use bitcoin::Txid;
use indexer_types::Block;

#[derive(Debug, Clone, PartialEq)]
pub enum BitcoinEvent {
    BlockInsert { target_height: u64, block: Block },
    Rollback { to_height: u64 },
    MempoolSync(Vec<bitcoin::Transaction>),
    MempoolInsert(bitcoin::Transaction),
    MempoolRemove(Txid),
}
