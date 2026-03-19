use bitcoin::{
    XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_RETURN},
    script::Instruction,
};
use indexer_types::{
    BlsBulkOp, Inst, Op, OpMetadata, OpWithResult, ParsedInput, Signer, Transaction, deserialize,
};
use indexmap::IndexMap;

use crate::{
    database::{queries::get_op_result, types::OpResultId},
    runtime::{Runtime, registry},
};

pub type TransactionFilterMap = fn((usize, bitcoin::Transaction)) -> Option<Transaction>;

pub fn filter_map((tx_index, tx): (usize, bitcoin::Transaction)) -> Option<Transaction> {
    let instructions = tx
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
                        return Some(ParsedInput {
                            previous_output: input.previous_output,
                            input_index: input_index as i64,
                            x_only_pubkey: signer.to_string(),
                            inst,
                        });
                    }
                }
                None
            })
        })
        .collect::<Vec<_>>();

    if instructions.is_empty() {
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
        instructions,
        op_return_data,
    })
}

async fn resolve_signer(runtime: &mut Runtime, x_only_pubkey: &str) -> Signer {
    match registry::api::get_entry(runtime, x_only_pubkey).await {
        Ok(Some(entry)) => Signer::SignerId {
            id: entry.signer_id,
            id_str: format!("__sid__{}", entry.signer_id),
        },
        _ => Signer::Nobody,
    }
}

async fn inst_to_ops(
    runtime: &mut Runtime,
    inst: &Inst,
    previous_output: bitcoin::OutPoint,
    input_index: i64,
    x_only_pubkey: &str,
) -> Vec<Op> {
    let metadata = OpMetadata {
        previous_output,
        input_index,
        signer: resolve_signer(runtime, x_only_pubkey).await,
    };

    match inst {
        Inst::Publish {
            gas_limit,
            name,
            bytes,
        } => vec![Op::Publish {
            metadata,
            gas_limit: *gas_limit,
            name: name.clone(),
            bytes: bytes.clone(),
        }],
        Inst::Call {
            gas_limit,
            contract,
            expr,
        } => vec![Op::Call {
            metadata,
            gas_limit: *gas_limit,
            contract: contract.clone(),
            expr: expr.clone(),
        }],
        Inst::Issuance => vec![Op::Issuance { metadata }],
        Inst::RegisterBlsKey {
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        } => vec![Op::RegisterBlsKey {
            metadata,
            bls_pubkey: bls_pubkey.clone(),
            schnorr_sig: schnorr_sig.clone(),
            bls_sig: bls_sig.clone(),
        }],
        Inst::BlsBulk { ops, .. } => {
            let mut resolved = Vec::with_capacity(ops.len());
            for bulk_op in ops {
                let inner_signer = match bulk_op {
                    BlsBulkOp::Call { signer_id, .. } => Signer::SignerId {
                        id: *signer_id,
                        id_str: format!("__sid__{}", signer_id),
                    },
                    BlsBulkOp::RegisterBlsKey { x_only_pubkey, .. } => {
                        resolve_signer(runtime, x_only_pubkey).await
                    }
                };
                let inner_meta = OpMetadata {
                    previous_output: metadata.previous_output,
                    input_index: metadata.input_index,
                    signer: inner_signer,
                };
                match bulk_op {
                    BlsBulkOp::Call {
                        gas_limit,
                        contract,
                        expr,
                        ..
                    } => Op::Call {
                        metadata: inner_meta,
                        gas_limit: *gas_limit,
                        contract: contract.clone(),
                        expr: expr.clone(),
                    },
                    BlsBulkOp::RegisterBlsKey {
                        bls_pubkey,
                        schnorr_sig,
                        bls_sig,
                        ..
                    } => Op::RegisterBlsKey {
                        metadata: inner_meta,
                        bls_pubkey: bls_pubkey.clone(),
                        schnorr_sig: schnorr_sig.clone(),
                        bls_sig: bls_sig.clone(),
                    },
                };
                resolved.push(op);
            }
            resolved
        }
    }
}

pub async fn inspect(runtime: &mut Runtime, btx: bitcoin::Transaction) -> anyhow::Result<Vec<OpWithResult>> {
    let mut results = Vec::new();
    if let Some(tx) = filter_map((0, btx)) {
        for input in &tx.instructions {
            let ops = inst_to_ops(
                runtime,
                &input.inst,
                input.previous_output,
                input.input_index,
                &input.x_only_pubkey,
            )
            .await;
            for (op_index, op) in ops.into_iter().enumerate() {
                let id = OpResultId::builder()
                    .txid(tx.txid.to_string())
                    .input_index(input.input_index)
                    .op_index(op_index as i64)
                    .build();
                let result = get_op_result(&runtime.storage.conn, &id).await?.map(Into::into);
                results.push(OpWithResult { op, result });
            }
        }
    }
    Ok(results)
}
