use bitcoin::{BlockHash, Transaction, Txid};

pub trait HasTxid {
    fn txid(&self) -> Txid;
}

impl HasTxid for Transaction {
    fn txid(&self) -> Txid {
        self.compute_txid()
    }
}

pub trait Tx: Clone + HasTxid + Send {}
impl<T> Tx for T where T: Clone + HasTxid + Send {}

#[derive(Clone, Debug)]
pub struct Block<T: Tx> {
    pub height: u64,
    pub hash: BlockHash,
    pub prev_hash: BlockHash,
    pub transactions: Vec<T>,
}
