use anyhow::Result;
use bitcoin::{BlockHash, Transaction as BitcoinTransaction, Txid};
#[cfg(test)]
use indexer_types::{Block, Transaction};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::protocol::coordinator::linked::{PreparedBlock, PreparedTransaction};

#[derive(Clone, Debug, PartialEq)]
pub struct BlockInput {
    pub height: u64,
    pub hash: BlockHash,
    pub prev_hash: BlockHash,
    transactions: Transactions,
}

#[derive(Clone, Debug, PartialEq)]
enum Transactions {
    Raw(Vec<BitcoinTransaction>),
    #[cfg(test)]
    Recognized(Vec<Transaction>),
}

impl BlockInput {
    pub fn new(
        height: u64,
        hash: BlockHash,
        prev_hash: BlockHash,
        transactions: Vec<BitcoinTransaction>,
    ) -> Self {
        Self {
            height,
            hash,
            prev_hash,
            transactions: Transactions::Raw(transactions),
        }
    }

    pub fn txids(&self) -> Vec<Txid> {
        match &self.transactions {
            Transactions::Raw(transactions) => transactions
                .iter()
                .map(BitcoinTransaction::compute_txid)
                .collect(),
            #[cfg(test)]
            Transactions::Recognized(transactions) => {
                transactions.iter().map(|tx| tx.txid).collect()
            }
        }
    }

    pub(crate) fn prepare(
        self,
        recognize: impl Fn(&BitcoinTransaction) -> Result<Option<PreparedTransaction>> + Sync + Send,
    ) -> Result<PreparedBlock> {
        let transactions = match self.transactions {
            Transactions::Raw(transactions) => transactions
                .par_iter()
                .enumerate()
                .map(|(index, raw)| {
                    Ok(recognize(raw)?.map(|mut transaction| {
                        transaction.index = index as u32;
                        transaction
                    }))
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect(),
            #[cfg(test)]
            Transactions::Recognized(transactions) => transactions
                .into_iter()
                .map(PreparedTransaction::fixture)
                .collect(),
        };
        Ok(PreparedBlock {
            height: self.height,
            hash: self.hash,
            prev_hash: self.prev_hash,
            transactions,
        })
    }
}

// Synthetic state-machine fixtures have no Bitcoin witness bytes. Production
// ingress cannot use this conversion to bypass recognition at execution time.
#[cfg(test)]
impl From<Block> for BlockInput {
    fn from(block: Block) -> Self {
        Self {
            height: block.height,
            hash: block.hash,
            prev_hash: block.prev_hash,
            transactions: Transactions::Recognized(block.transactions),
        }
    }
}
