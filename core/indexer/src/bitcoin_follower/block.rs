use anyhow::{Result, bail, ensure};
use bitcoin::consensus::{deserialize, serialize};
#[cfg(test)]
use bitcoin::hashes::Hash;
use bitcoin::{Block as BitcoinBlock, BlockHash, Transaction as BitcoinTransaction, Txid};
#[cfg(test)]
use indexer_types::{Block, Transaction};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::protocol::canonical_input::CanonicalInput;
use crate::protocol::coordinator::certified_input::{
    Command, EraContext, ExactInput, MAX_BITCOIN_BYTES,
};
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
    Block(BitcoinBlock),
    #[cfg(test)]
    Raw(Vec<BitcoinTransaction>),
    #[cfg(test)]
    Recognized(Vec<Transaction>),
}

impl BlockInput {
    pub fn from_bitcoin(height: u64, expected_hash: BlockHash, block: BitcoinBlock) -> Self {
        Self {
            height,
            hash: expected_hash,
            prev_hash: block.header.prev_blockhash,
            transactions: Transactions::Block(block),
        }
    }

    pub(crate) fn exact_input(&self, context: EraContext) -> Result<ExactInput> {
        let block = match &self.transactions {
            Transactions::Block(block) => block,
            #[cfg(test)]
            _ => bail!("synthetic block has no certified Bitcoin body"),
        };
        ensure!(
            block.block_hash() == self.hash,
            "Bitcoin block hash differs from requested hash"
        );
        ensure!(
            block.header.prev_blockhash == self.prev_hash,
            "Bitcoin block parent differs from retained header"
        );
        ensure!(
            block.total_size() <= MAX_BITCOIN_BYTES,
            "Bitcoin block exceeds certified input limit"
        );
        Ok(ExactInput::block(context, self.height, serialize(block))?)
    }

    pub(crate) fn from_exact(input: &ExactInput) -> Result<Self> {
        let Command::Block { height, hash, .. } = input.descriptor().command else {
            bail!("batch input cannot be replayed as a Bitcoin block");
        };
        Ok(Self::from_bitcoin(height, hash, deserialize(input.body())?))
    }

    #[cfg(test)]
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
            Transactions::Block(block) => block
                .txdata
                .iter()
                .map(BitcoinTransaction::compute_txid)
                .collect(),
            #[cfg(test)]
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
        let raw = match self.transactions {
            Transactions::Block(block) => block.txdata,
            #[cfg(test)]
            Transactions::Raw(transactions) => transactions,
            #[cfg(test)]
            Transactions::Recognized(transactions) => {
                let input = CanonicalInput::synthetic(
                    &transactions
                        .iter()
                        .map(|tx| tx.txid.to_byte_array())
                        .collect::<Vec<_>>(),
                )?;
                return Ok(PreparedBlock {
                    height: self.height,
                    hash: self.hash,
                    prev_hash: self.prev_hash,
                    input: Some(input),
                    transactions: transactions
                        .into_iter()
                        .map(PreparedTransaction::fixture)
                        .collect(),
                });
            }
        };
        let input = CanonicalInput::bitcoin(&raw)?;
        let transactions = raw
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
            .collect();
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
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, Block as BitcoinBlock, BlockHash, Network, ScriptBuf, Transaction, TxIn, TxOut,
        Witness,
    };

    use super::BlockInput;
    use crate::protocol::canonical_input::CanonicalInput;
    use crate::protocol::coordinator::certified_input::{EraContext, ExactInput};
    use crate::protocol::identity::{ChainId, ProtocolId};

    fn context() -> EraContext {
        EraContext {
            chain: ChainId([1; 32]),
            era: [2; 32],
            protocol: ProtocolId([3; 32]),
            codec: 1,
        }
    }

    #[test]
    fn retained_block_replays_exact_header_and_witnesses_before_recognition() {
        let mut raw = genesis_block(Network::Regtest);
        raw.txdata[0].input[0].witness.push([0; 32]);
        let commitment =
            BitcoinBlock::compute_witness_commitment(&raw.witness_root().unwrap(), &[0; 32]);
        let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        script.extend_from_slice(commitment.as_byte_array());
        raw.txdata[0].output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(script),
        });
        raw.header.merkle_root = raw.compute_merkle_root().unwrap();
        let input = BlockInput::from_bitcoin(7, raw.block_hash(), raw.clone());
        let exact = input.exact_input(context()).unwrap();
        assert_eq!(exact.body(), serialize(&raw));
        let replay = BlockInput::from_exact(&exact).unwrap();
        assert_eq!(replay, input);
        let prepared = replay.prepare(|_| Ok(None)).unwrap();
        assert!(prepared.transactions.is_empty());
        assert_eq!(
            prepared.input,
            Some(CanonicalInput::bitcoin(&raw.txdata).unwrap())
        );

        let mut stripped = raw.clone();
        stripped.txdata[0].input[0].witness.clear();
        assert_eq!(stripped.block_hash(), raw.block_hash());
        assert!(
            BlockInput::from_bitcoin(7, raw.block_hash(), stripped)
                .exact_input(context())
                .is_err()
        );
        let wrong_hash = BlockInput::from_bitcoin(7, BlockHash::all_zeros(), raw);
        assert!(wrong_hash.exact_input(context()).is_err());
        let mut wrong_parent = input;
        wrong_parent.prev_hash = BlockHash::from_byte_array([9; 32]);
        assert!(wrong_parent.exact_input(context()).is_err());
        let batch = ExactInput::batch(context(), 7, wrong_parent.hash, &[]).unwrap();
        assert!(BlockInput::from_exact(&batch).is_err());
        assert!(
            BlockInput::new(7, wrong_parent.hash, wrong_parent.prev_hash, vec![])
                .exact_input(context())
                .is_err()
        );
    }

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
