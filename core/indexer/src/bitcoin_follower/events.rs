use bitcoin::{BlockHash, Txid};

use crate::block::{Block, Tx};

#[derive(Debug)]
pub enum ZmqEvent<T: Tx> {
    Connected,
    Disconnected(anyhow::Error),
    MempoolTransactionAdded(T),
    MempoolTransactionRemoved(Txid),
    BlockConnected(Block<T>),
    BlockDisconnected(BlockHash),
}

#[derive(Debug, PartialEq)]
pub enum BlockId {
    Height(u64),
    Hash(BlockHash),
}

#[derive(Debug, PartialEq)]
pub enum Event<T: Tx> {
    MempoolSet(Vec<T>),
    MempoolInsert(Vec<T>),
    MempoolRemove(Vec<Txid>),
    BlockInsert((u64, Block<T>)),
    BlockRemove(BlockId),
}
