use bitcoin::{BlockHash, Transaction as BitcoinTransaction, Txid};
use indexer_types::{Block, Transaction};

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

    pub(crate) fn recognize(
        self,
        mut recognize: impl FnMut(&BitcoinTransaction) -> Option<Transaction>,
    ) -> Block {
        let transactions = match self.transactions {
            Transactions::Raw(transactions) => transactions
                .iter()
                .enumerate()
                .filter_map(|(index, raw)| {
                    recognize(raw).map(|mut transaction| {
                        transaction.index = index as u32;
                        transaction
                    })
                })
                .collect(),
            #[cfg(test)]
            Transactions::Recognized(transactions) => transactions,
        };
        Block {
            height: self.height,
            hash: self.hash,
            prev_hash: self.prev_hash,
            transactions,
        }
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
