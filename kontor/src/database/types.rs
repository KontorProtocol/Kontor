use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockRow {
    pub height: u64,
    pub hash: BlockHash,
}
