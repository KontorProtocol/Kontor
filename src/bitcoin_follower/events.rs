use bitcoin::{BlockHash, Txid};

use crate::block::{Block, Tx};

#[derive(Debug)]
pub enum ZmqEvent<T: Tx> {
    Connected,
    Disconnected(anyhow::Error),
    MempoolTransactions(Vec<T>),
    MempoolTransactionAdded(T),
    MempoolTransactionRemoved(Txid),
    BlockConnected(Block<T>),
    BlockDisconnected(BlockHash),
}

#[derive(Debug, PartialEq)]
pub enum Event<T: Tx> {
    MempoolUpdate { removed: Vec<Txid>, added: Vec<T> },
    MempoolSet(Vec<T>),
    Block(Block<T>),
    Rollback(u64),
}
