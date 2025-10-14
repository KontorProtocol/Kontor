use bitcoin::{BlockHash, Txid};

use crate::block::{Block, Transaction};

#[derive(Debug)]
pub enum ZmqEvent {
    Connected,
    Disconnected(anyhow::Error),
    MempoolTransactionAdded(Transaction),
    MempoolTransactionRemoved(Txid),
    BlockConnected(Block),
    BlockDisconnected(BlockHash),
}

#[derive(Debug, PartialEq)]
pub enum BlockId {
    Height(u64),
    Hash(BlockHash),
}

#[derive(Debug, PartialEq)]
pub enum Event {
    MempoolSet(Vec<Transaction>),
    MempoolInsert(Vec<Transaction>),
    MempoolRemove(Vec<Txid>),
    BlockInsert((u64, Block)),
    BlockRemove(BlockId),
}
