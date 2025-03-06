use bitcoin::BlockHash;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct BlockRow {
    pub height: u64,
    pub hash: BlockHash,
}
