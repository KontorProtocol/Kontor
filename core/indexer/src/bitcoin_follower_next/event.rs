use indexer_types::Block;

#[derive(Debug, PartialEq)]
pub enum BitcoinEvent {
    BlockInsert { target_height: u64, block: Block },
    Rollback { to_height: u64 },
}
