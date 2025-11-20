use bitcoin::{
    BlockHash, Txid, XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
    script::Instruction,
};

use crate::{
    reactor::types::{Inst, Op, OpMetadata},
    runtime::{deserialize, wit::Signer},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub txid: Txid,
    pub index: i64,
    pub ops: Vec<Op>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub height: u64,
    pub hash: BlockHash,
    pub prev_hash: BlockHash,
    pub transactions: Vec<Transaction>,
}

pub type TransactionFilterMap = fn((usize, bitcoin::Transaction)) -> Option<Transaction>;

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
                    let mut inst = insts.next();
                    while let Some(Ok(Instruction::PushBytes(bs))) = inst {
                        data.extend_from_slice(bs.as_bytes());
                        inst = insts.next();
                    }

                    if inst == Some(Ok(Instruction::Op(OP_ENDIF)))
                        && insts.next().is_none()
                        && let Ok(inst) = deserialize::<Inst>(&data)
                    {
                        let metadata = OpMetadata {
                            input_index: input_index as i64,
                            signer: Signer::XOnlyPubKey(signer.to_string()),
                        };
                        return Some(match inst {
                            Inst::Publish {
                                gas_limit,
                                name,
                                bytes,
                            } => Op::Publish {
                                metadata,
                                gas_limit,
                                name,
                                bytes,
                            },
                            Inst::Call {
                                gas_limit,
                                contract,
                                expr,
                            } => Op::Call {
                                metadata,
                                gas_limit,
                                contract,
                                expr,
                            },
                            Inst::Issuance => Op::Issuance { metadata },
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
        index: tx_index as i64,
        ops,
    })
}
