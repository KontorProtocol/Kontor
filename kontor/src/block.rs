use bitcoin::{BlockHash, Transaction, Txid};

pub trait HasTxid {
    fn txid(&self) -> Txid;
}

impl HasTxid for Transaction {
    fn txid(&self) -> Txid {
        self.compute_txid()
    }
}

pub trait Tx: Clone + HasTxid + Send + Sync {}
impl<T> Tx for T where T: Clone + HasTxid + Send + Sync {}

#[derive(Clone, Debug, PartialEq)]
pub struct Block<T: Tx> {
    pub height: u64,
    pub hash: BlockHash,
    pub prev_hash: BlockHash,
    pub transactions: Vec<T>,
}
