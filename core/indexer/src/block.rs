use bitcoin::{
    XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_RETURN},
    script::Instruction,
};
use indexer_types::{
    Input, Inst, Insts, Op, OpMetadata, OpWithResult, Transaction, deserialize,
};
use indexmap::IndexMap;
use libsql::Connection;

use crate::database::{queries::get_op_result, types::OpResultId};

pub type TransactionFilterMap = fn((usize, bitcoin::Transaction)) -> Option<Transaction>;

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
                        return Some(Input {
                            previous_output: input.previous_output,
                            input_index: input_index as i64,
                            x_only_pubkey: signer,
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

pub async fn inspect(
    conn: &Connection,
    tx: &indexer_types::Transaction,
) -> anyhow::Result<Vec<OpWithResult>> {
    let mut ops = Vec::new();
    for input in &tx.inputs {
        if !input.insts.is_aggregate() {
            let identity = crate::database::queries::get_or_create_identity(
                conn,
                &input.x_only_pubkey.to_string(),
                0,
            )
            .await?;
            let metadata = OpMetadata {
                previous_output: input.previous_output,
                input_index: input.input_index,
                signer_id: identity.signer_id() as u64,
            };
            for (op_index, inst) in input.insts.ops.iter().enumerate() {
                let op = op_from_inst(inst.clone(), metadata.clone());
                let id = OpResultId::builder()
                    .txid(tx.txid.to_string())
                    .input_index(input.input_index)
                    .op_index(op_index as i64)
                    .build();
                let result = get_op_result(conn, &id).await?.map(Into::into);
                ops.push(OpWithResult { op, result });
            }
        }
    }
    Ok(ops)
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::key::{Keypair, Secp256k1, rand};
    use bitcoin::opcodes::all::{OP_ADD, OP_CHECKSIG, OP_ENDIF, OP_IF};
    use bitcoin::opcodes::{OP_0, OP_FALSE};
    use bitcoin::script::{Builder, PushBytesBuf};
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use indexer_types::{AggregateInfo, ContractAddress, Inst, Insts, serialize};

    use super::filter_map;
    use crate::test_utils::{PublicKey as TestPublicKey, build_inscription};

    fn tx_with_taproot_script_witness(
        tap_script: ScriptBuf,
        internal_key: bitcoin::XOnlyPublicKey,
    ) -> Transaction {
        let secp = Secp256k1::new();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, tap_script.clone())
            .expect("add_leaf")
            .finalize(&secp, internal_key)
            .expect("finalize");
        let control_block = spend_info
            .control_block(&(tap_script.clone(), LeafVersion::TapScript))
            .expect("control_block");
        let mut witness = Witness::new();
        witness.push(vec![0u8; 64]);
        witness.push(tap_script.as_bytes());
        witness.push(control_block.serialize());
        Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn random_xonly() -> bitcoin::XOnlyPublicKey {
        let secp = Secp256k1::new();
        Keypair::new(&secp, &mut rand::thread_rng())
            .x_only_public_key()
            .0
    }

    #[test]
    fn filter_map_parses_valid_aggregate_envelope() {
        let xonly = random_xonly();
        let contract = ContractAddress {
            name: "c".to_string(),
            height: 1,
            tx_index: 2,
        };
        let op = Inst::Call {
            gas_limit: 123,
            contract,
            nonce: Some(0),
            expr: "noop()".to_string(),
        };
        let insts = Insts {
            ops: vec![op.clone()],
            aggregate: Some(AggregateInfo {
                signer_ids: vec![7],
                signature: vec![9u8; 48],
            }),
        };
        let payload = serialize(&insts).expect("serialize Insts");
        let tap_script =
            build_inscription(payload, TestPublicKey::Taproot(&xonly)).expect("build tap script");
        let tx = tx_with_taproot_script_witness(tap_script, xonly);
        let parsed = filter_map((0, tx)).expect("expected tx to be recognized as Kontor tx");
        assert_eq!(parsed.inputs.len(), 1);
        let input = &parsed.inputs[0];
        assert_eq!(input.x_only_pubkey, xonly);
        assert_eq!(input.insts, insts);
    }

    #[test]
    fn filter_map_rejects_wrong_marker() {
        let xonly = random_xonly();
        let payload = serialize(&Insts::single(Inst::Issuance)).expect("serialize");
        let tap_script = Builder::new()
            .push_slice(xonly.serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(b"kor")
            .push_opcode(OP_0)
            .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
            .push_opcode(OP_ENDIF)
            .into_script();
        let tx = tx_with_taproot_script_witness(tap_script, xonly);
        assert!(filter_map((0, tx)).is_none());
    }

    #[test]
    fn filter_map_rejects_trailing_instructions_after_endif() {
        let xonly = random_xonly();
        let payload = serialize(&Insts::single(Inst::Issuance)).expect("serialize");
        let tap_script = Builder::new()
            .push_slice(xonly.serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(b"kon")
            .push_opcode(OP_0)
            .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_0)
            .into_script();
        let tx = tx_with_taproot_script_witness(tap_script, xonly);
        assert!(filter_map((0, tx)).is_none());
    }

    #[test]
    fn filter_map_concatenates_multi_push_payload() {
        let xonly = random_xonly();
        let inst = Inst::Call {
            gas_limit: 7,
            contract: ContractAddress {
                name: "arith".to_string(),
                height: 1,
                tx_index: 0,
            },
            nonce: None,
            expr: "eval(10, id)".to_string(),
        };
        let payload = serialize(&Insts::single(inst)).expect("serialize");
        let mid = payload.len() / 2;
        let (p0, p1) = payload.split_at(mid);
        let tap_script = Builder::new()
            .push_slice(xonly.serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(b"kon")
            .push_opcode(OP_0)
            .push_slice(PushBytesBuf::try_from(p0.to_vec()).expect("pushbytes"))
            .push_slice(PushBytesBuf::try_from(p1.to_vec()).expect("pushbytes"))
            .push_opcode(OP_ENDIF)
            .into_script();
        let tx = tx_with_taproot_script_witness(tap_script, xonly);
        let parsed = filter_map((0, tx)).expect("expected tx to be recognized");
        assert_eq!(parsed.inputs.len(), 1);
        let input = &parsed.inputs[0];
        assert_eq!(input.x_only_pubkey, xonly);
        assert_eq!(input.insts.ops.len(), 1);
        match &input.insts.ops[0] {
            Inst::Call {
                gas_limit,
                contract,
                nonce,
                expr,
            } => {
                assert_eq!(*gas_limit, 7);
                assert_eq!(contract.name, "arith");
                assert_eq!(*nonce, None);
                assert_eq!(expr, "eval(10, id)");
            }
            other => panic!("expected Inst::Call, got {other:?}"),
        }
    }

    #[test]
    fn filter_map_rejects_non_pushbytes_inside_envelope() {
        let xonly = random_xonly();
        let payload = serialize(&Insts::single(Inst::Issuance)).expect("serialize");
        let tap_script = Builder::new()
            .push_slice(xonly.serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(b"kon")
            .push_opcode(OP_0)
            .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
            .push_opcode(OP_ADD)
            .push_opcode(OP_ENDIF)
            .into_script();
        let tx = tx_with_taproot_script_witness(tap_script, xonly);
        assert!(filter_map((0, tx)).is_none());
    }

    #[test]
    fn filter_map_rejects_invalid_xonly_pubkey_bytes() {
        let internal_key = random_xonly();
        let payload = serialize(&Insts::single(Inst::Issuance)).expect("serialize");
        let tap_script = Builder::new()
            .push_slice([0u8; 32])
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(b"kon")
            .push_opcode(OP_0)
            .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
            .push_opcode(OP_ENDIF)
            .into_script();
        let tx = tx_with_taproot_script_witness(tap_script, internal_key);
        assert!(filter_map((0, tx)).is_none());
    }
}
