use anyhow::{Result, anyhow};
use bitcoin::{
    XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_RETURN},
    script::Instruction,
};
use indexer_types::{
    Inst, Insts, Op, OpMetadata, OpWithResult, Signer, Transaction, TransactionInput, deserialize,
};
use indexmap::IndexMap;
use libsql::Connection;

use crate::database::{queries::get_op_result, types::OpResultId};
pub type TransactionFilterMap = fn((usize, bitcoin::Transaction)) -> Option<Transaction>;

async fn inspect_input_ops(
    conn: &Connection,
    txid: &str,
    input: &indexer_types::TransactionInput,
) -> Result<Vec<OpWithResult>> {
    let signer_ids = input
        .insts
        .aggregate
        .as_ref()
        .map(|agg| agg.signer_ids.as_slice());

    if let Some(signer_ids) = signer_ids
        && signer_ids.len() != input.insts.ops.len()
    {
        return Err(anyhow!(
            "aggregate signer_ids length ({}) != ops length ({})",
            signer_ids.len(),
            input.insts.ops.len()
        ));
    }

    let mut ops = Vec::with_capacity(input.insts.ops.len());
    for (op_index, inst) in input.insts.ops.iter().enumerate() {
        let signer = match signer_ids {
            Some(signer_ids) => Signer::new_signer_id(signer_ids[op_index]),
            None => input.witness_signer.clone(),
        };
        let op = op_from_inst(
            inst.clone(),
            OpMetadata {
                previous_output: input.previous_output,
                input_index: input.input_index,
                signer,
            },
        );
        let id = OpResultId::builder()
            .txid(txid.to_string())
            .input_index(input.input_index)
            .op_index(op_index as i64)
            .build();
        let result = get_op_result(conn, &id).await?.map(Into::into);
        ops.push(OpWithResult { op, result });
    }

    Ok(ops)
}

pub fn op_from_inst(inst: Inst, metadata: OpMetadata) -> Op {
    match inst {
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
            nonce,
            expr,
        } => Op::Call {
            metadata,
            gas_limit,
            contract,
            nonce,
            expr,
        },
        Inst::RegisterBlsKey {
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        } => Op::RegisterBlsKey {
            metadata,
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        },
        Inst::Issuance => Op::Issuance { metadata },
    }
}

pub fn filter_map((tx_index, tx): (usize, bitcoin::Transaction)) -> Option<Transaction> {
    let inputs = tx
        .input
        .iter()
        .enumerate()
        .filter_map(|(input_index, input)| {
            input.witness.taproot_leaf_script().and_then(|leaf| {
                let mut script_insts = leaf.script.instructions();
                if let Some(Ok(Instruction::PushBytes(key))) = script_insts.next()
                    && let Some(Ok(Instruction::Op(OP_CHECKSIG))) = script_insts.next()
                    // OP_FALSE
                    && let Some(Ok(Instruction::PushBytes(nullish))) = script_insts.next()
                    && nullish.is_empty()
                    && script_insts.next() == Some(Ok(Instruction::Op(OP_IF)))
                    && let Some(Ok(Instruction::PushBytes(kon))) = script_insts.next()
                    && kon.as_bytes() == b"kon"
                    // OP_0
                    && let Some(Ok(Instruction::PushBytes(nullish))) = script_insts.next()
                    && nullish.is_empty()
                    && let Ok(signer) = XOnlyPublicKey::from_slice(key.as_bytes())
                {
                    let mut data = Vec::new();
                    let mut inst = script_insts.next();
                    while let Some(Ok(Instruction::PushBytes(bs))) = inst {
                        data.extend_from_slice(bs.as_bytes());
                        inst = script_insts.next();
                    }

                    if inst == Some(Ok(Instruction::Op(OP_ENDIF)))
                        && script_insts.next().is_none()
                        && let Ok(insts) = deserialize::<Insts>(&data)
                    {
                        return Some(TransactionInput {
                            previous_output: input.previous_output,
                            input_index: input_index as i64,
                            witness_signer: Signer::XOnlyPubKey(signer.to_string()),
                            insts,
                        });
                    }
                }
                None
            })
        })
        .collect::<Vec<_>>();

    if inputs.is_empty() {
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
        inputs,
        op_return_data,
    })
}

pub async fn inspect(conn: &Connection, btx: bitcoin::Transaction) -> Result<Vec<OpWithResult>> {
    let mut ops = Vec::new();
    if let Some(tx) = filter_map((0, btx)) {
        for input in &tx.inputs {
            ops.extend(inspect_input_ops(conn, &tx.txid.to_string(), input).await?);
        }
    }
    Ok(ops)
}
