use bitcoin::{
    XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_RETURN},
    script::Instruction,
};
use indexer_types::{Inst, Op, OpMetadata, OpWithResult, Transaction, deserialize};
use indexmap::IndexMap;
use libsql::Connection;

use crate::{
    batch,
    database::{queries::get_op_result, types::OpResultId},
    runtime::wit::Signer,
};

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

                    if inst == Some(Ok(Instruction::Op(OP_ENDIF))) && insts.next().is_none() {
                        let metadata = OpMetadata {
                            previous_output: input.previous_output,
                            input_index: input_index as i64,
                            signer: Signer::XOnlyPubKey(signer.to_string()),
                        };

                        if batch::is_kbl1_payload(&data) {
                            return Some(Op::Batch {
                                metadata,
                                payload: data,
                            });
                        }

                        if let Ok(inst) = deserialize::<Inst>(&data) {
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
                }
                None
            })
        })
        .collect::<Vec<_>>();

    if ops.is_empty() {
        return None;
    }

    let op_return = tx.output.iter().find(|o| o.script_pubkey.is_op_return());
    let mut op_return_data = IndexMap::new();

    if let Some(op_return) = op_return {
        let mut op_return_instructions = op_return.script_pubkey.instructions();
        if let Some(Ok(Instruction::Op(OP_RETURN))) = op_return_instructions.next()
            && let Some(Ok(Instruction::PushBytes(data))) = op_return_instructions.next()
            && let Ok(entries) =
                deserialize::<Vec<(u64, indexer_types::OpReturnData)>>(data.as_bytes())
        {
            op_return_data = IndexMap::from_iter(entries);
        }
    }

    Some(Transaction {
        txid: tx.compute_txid(),
        index: tx_index as i64,
        ops,
        op_return_data,
    })
}

pub async fn inspect(
    conn: &Connection,
    btx: bitcoin::Transaction,
) -> anyhow::Result<Vec<OpWithResult>> {
    let mut ops = Vec::new();
    if let Some(tx) = filter_map((0, btx)) {
        for op in tx.ops {
            match &op {
                Op::Batch { metadata, payload } => {
                    if let Ok(decoded) = batch::decode_kbl1_batch(payload) {
                        let mut op_index = 0i64;
                        for (batch_op, range) in decoded.ops.iter().zip(decoded.op_ranges.iter()) {
                            if let batch::BatchOpV1::Op { signer, inst, .. } = batch_op {
                                let id = OpResultId::builder()
                                    .txid(tx.txid.to_string())
                                    .input_index(metadata.input_index)
                                    .op_index(op_index)
                                    .build();
                                let result = get_op_result(conn, &id).await?.map(Into::into);

                                // Best-effort signer resolution for display.
                                let signer = match signer {
                                    batch::SignerRefV1::Id(id) => {
                                        crate::database::queries::select_signer_registry_by_id(
                                            conn, *id,
                                        )
                                        .await?
                                        .and_then(|row| row.xonly_pubkey.as_slice().try_into().ok())
                                        .and_then(|xonly: [u8; 32]| {
                                            bitcoin::XOnlyPublicKey::from_slice(&xonly).ok()
                                        })
                                        .map(|x| Signer::XOnlyPubKey(x.to_string()))
                                        .unwrap_or_else(|| Signer::Nobody)
                                    }
                                    batch::SignerRefV1::XOnly(xonly) => {
                                        bitcoin::XOnlyPublicKey::from_slice(xonly)
                                            .map(|x| Signer::XOnlyPubKey(x.to_string()))
                                            .unwrap_or(Signer::Nobody)
                                    }
                                };

                                let metadata = OpMetadata {
                                    previous_output: metadata.previous_output,
                                    input_index: metadata.input_index,
                                    signer,
                                };
                                let op = match inst.clone() {
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
                                };
                                ops.push(OpWithResult { op, result });
                                op_index += 1;

                                let _ = range; // keep range available for future display/debug
                            }
                        }
                    } else {
                        let id = OpResultId::builder()
                            .txid(tx.txid.to_string())
                            .input_index(op.metadata().input_index)
                            .op_index(0)
                            .build();
                        let result = get_op_result(conn, &id).await?.map(Into::into);
                        ops.push(OpWithResult { op, result });
                    }
                }
                _ => {
                    let id = OpResultId::builder()
                        .txid(tx.txid.to_string())
                        .input_index(op.metadata().input_index)
                        .op_index(0)
                        .build();
                    let result = get_op_result(conn, &id).await?.map(Into::into);
                    ops.push(OpWithResult { op, result });
                }
            }
        }
    }
    Ok(ops)
}
