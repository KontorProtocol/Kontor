use anyhow::Result;
#[cfg(test)]
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Transaction as BitcoinTransaction, Txid};
#[cfg(test)]
use indexer_types::{Block, Transaction};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::protocol::canonical_input::CanonicalInput;
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
        let input = match &self.transactions {
            Transactions::Raw(transactions) => CanonicalInput::bitcoin(transactions)?,
            #[cfg(test)]
            Transactions::Recognized(transactions) => CanonicalInput::synthetic(
                &transactions
                    .iter()
                    .map(|tx| tx.txid.to_byte_array())
                    .collect::<Vec<_>>(),
            )?,
        };
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
            input: Some(input),
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

#[cfg(test)]
mod tests {
    use std::slice::from_ref;

    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{BlockHash, Transaction, TxIn, Witness};

    use super::BlockInput;
    use crate::protocol::canonical_input::CanonicalInput;

    #[test]
    fn preparation_commits_unrecognized_transactions_before_filtering() {
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        };
        let prepare = |transactions| {
            BlockInput::new(
                1,
                BlockHash::all_zeros(),
                BlockHash::all_zeros(),
                transactions,
            )
            .prepare(|_| Ok(None))
            .unwrap()
        };
        let block = prepare(vec![transaction.clone()]);
        assert!(block.transactions.is_empty());
        assert_eq!(
            block.input,
            Some(CanonicalInput::bitcoin(from_ref(&transaction)).unwrap())
        );
        assert_ne!(block.input, prepare(vec![]).input);
        let mut changed = transaction;
        changed.input[0].witness = Witness::from_slice(&[b"different witness"]);
        assert_ne!(block.input, prepare(vec![changed]).input);
    }
}
