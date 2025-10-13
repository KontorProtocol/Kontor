use bitcoin::{
    BlockHash, Txid, XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_IF},
    script::Instruction,
};

use crate::{
    reactor::types::{Inst, Op, OpMetadata, Transaction},
    runtime::{deserialize_cbor, wit::Signer},
};

pub trait HasTxid {
    fn txid(&self) -> Txid;
}

impl HasTxid for bitcoin::Transaction {
    fn txid(&self) -> Txid {
        self.compute_txid()
    }
}

impl HasTxid for Transaction {
    fn txid(&self) -> Txid {
        self.txid
    }
}

pub trait Tx: std::fmt::Debug + Clone + HasTxid + Send + Sync {}
impl<T> Tx for T where T: std::fmt::Debug + Clone + HasTxid + Send + Sync {}

#[derive(Clone, Debug, PartialEq)]
pub struct Block<T: Tx> {
    pub height: u64,
    pub hash: BlockHash,
    pub prev_hash: BlockHash,
    pub transactions: Vec<T>,
}

pub fn filter_map((tx_index, tx): (usize, bitcoin::Transaction)) -> Option<Transaction> {
    let ops = tx
        .input
        .iter()
        .enumerate()
        .filter_map(|(input_index, input)| {
            input.witness.taproot_leaf_script().and_then(|leaf| {
                let mut insts = leaf.script.instructions();
                if let Some(Ok(Instruction::PushBytes(key))) = insts.next()
                    && let Some(Ok(Instruction::Op(OP_CHECKSIG))) = insts.next()
                    // OP_FALSE
                    && let Some(Ok(Instruction::PushBytes(nullish))) = insts.next()
                    && nullish.is_empty()
                    && insts.next() == Some(Ok(Instruction::Op(OP_IF)))
                    && let Some(Ok(Instruction::PushBytes(kon))) = insts.next()
                    && kon.as_bytes() == b"kon"
                    // OP_0
                    && let Some(Ok(Instruction::PushBytes(nullish))) = insts.next()
                    && nullish.is_empty()
                    && let Ok(signer) = XOnlyPublicKey::from_slice(key.as_bytes())
                {
                    let mut data = Vec::new();
                    while let Some(Ok(Instruction::PushBytes(bs))) = insts.next() {
                        data.extend_from_slice(bs.as_bytes());
                    }

                    if let Ok(inst) = deserialize_cbor::<Inst>(&data) {
                        let metadata = OpMetadata {
                            input_index: input_index as i64,
                            signer: Signer::XOnlyPubKey(signer.to_string()),
                        };
                        return Some(match inst {
                            Inst::Publish { name, bytes } => Op::Publish {
                                metadata,
                                name,
                                bytes,
                            },
                            Inst::Call { contract, expr } => Op::Call {
                                metadata,
                                contract,
                                expr,
                            },
                        });
                    }
                }
                None
            })
        })
        .collect::<Vec<_>>();

    if ops.is_empty() {
        return None;
    }

    Some(Transaction {
        txid: tx.compute_txid(),
        tx_index: tx_index as i64,
        ops,
    })
}
