use std::fmt;

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

impl<T: Tx> fmt::Display for ZmqEvent<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZmqEvent::Connected => write!(f, "ZMQ connected"),
            ZmqEvent::Disconnected(e) => write!(f, "ZMQ disconnected with error: {}", e),
            ZmqEvent::MempoolTransactions(txs) => {
                write!(f, "ZMQ mempool transactions: {}", txs.len())
            }
            ZmqEvent::MempoolTransactionAdded(tx) => {
                write!(f, "ZMQ mempool transaction added: {}", tx.txid())
            }
            ZmqEvent::MempoolTransactionRemoved(txid) => {
                write!(f, "ZMQ mempool transaction removed: {}", txid)
            }
            ZmqEvent::BlockConnected(block) => {
                write!(f, "ZMQ block connected: {}", block.hash)
            }
            ZmqEvent::BlockDisconnected(block_hash) => {
                write!(f, "ZMQ block disconnected: {}", block_hash)
            }
        }
    }
}

#[derive(Debug)]
pub enum Event<T: Tx> {
    MempoolUpdates { added: Vec<T>, removed: Vec<Txid> },
    Block(Block<T>),
    Rollback(u64),
}

impl<T: Tx> fmt::Display for Event<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::MempoolUpdates { added, removed } => write!(
                f,
                "Mempool updates: added {} removed {}",
                added.len(),
                removed.len()
            ),
            Event::Rollback(block_hash) => {
                write!(f, "Rollback: {}", block_hash)
            }
            Event::Block(block) => {
                write!(f, "Block: {}", block.hash)
            }
        }
    }
}
