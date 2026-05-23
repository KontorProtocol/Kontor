use bitcoin::{
    XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_RETURN},
    script::Instruction,
};
use indexer_types::{
    Input, Inst, InstKind, Insts, Op, OpKind, OpMetadata, OpWithResult, Payment, PaymentIntent,
    Transaction, deserialize,
};
use libsql::Connection;

use crate::database::{
    queries::get_op_result,
    types::{CORE_SIGNER_ID, OpResultId},
};

pub type TransactionFilterMap = fn((usize, bitcoin::Transaction)) -> Option<Transaction>;

/// Publisher's resolved offer for a BLS aggregate bulk. Built once per bulk
/// in `process_aggregate_input` by combining `AggregateInfo.publisher_sponsorship`
/// (the publisher's signed commitment) with the publisher's resolved signer_id
/// (the Bitcoin x_only_pubkey, ensured into the signers table).
#[derive(Debug, Clone, Copy)]
pub struct PublisherOffer {
    pub signer_id: u64,
    pub gas_limit_per_op: u64,
}

/// Build an `Op` from a direct (non-aggregate) `Inst`. `PaymentIntent::Sponsored`
/// is rejected here: direct inputs have no publisher to fall back to.
pub fn op_from_direct_inst(inst: Inst, metadata_base: OpMetadataBase) -> Result<Op, anyhow::Error> {
    materialize_op(inst, metadata_base, None)
}

/// Build an `Op` from an aggregate `Inst` applying the sponsorship resolution
/// table:
///   SelfPay  | any        → user pays at their signed limit
///   Sponsored| Some(offer)→ publisher pays at offer.gas_limit_per_op
///   Sponsored| None       → rejected (orphan op, co-signer accepted sponsorship
///                          but no publisher offered)
pub fn op_from_aggregate_inst(
    inst: Inst,
    metadata_base: OpMetadataBase,
    publisher: Option<PublisherOffer>,
) -> Result<Op, anyhow::Error> {
    materialize_op(inst, metadata_base, publisher)
}

/// Origin-only OpMetadata fields supplied by the reactor. The `payment` part of
/// `OpMetadata` is resolved inside `materialize_op` from the `Inst.payment`
/// intent and any publisher offer.
#[derive(Debug, Clone, Copy)]
pub struct OpMetadataBase {
    pub previous_output: bitcoin::OutPoint,
    pub input_index: i64,
    pub op_index: i64,
    pub signer_id: u64,
}

fn materialize_op(
    inst: Inst,
    base: OpMetadataBase,
    publisher: Option<PublisherOffer>,
) -> Result<Op, anyhow::Error> {
    let Inst { payment, kind } = inst;
    let (payment, kind) = match kind {
        InstKind::Issuance => (core_payment(), OpKind::Issuance),
        // Sponsor is a payer-redirection directive — it does not become
        // an executable op. The reactor's batch-processing path consumes
        // it at materialization (see task #23: Sponsor one-step-lookahead
        // + Ctx.payer). Until that wiring lands, reject so a stray
        // Sponsor can't reach the runtime in an undefined state.
        InstKind::Sponsor { .. } => {
            return Err(anyhow::anyhow!(
                "Sponsor InstKind reached materialize_op — directive handling \
                 not yet implemented (task #23)"
            ));
        }
        other => {
            let resolved = resolve_payment(&payment, base.signer_id, publisher)?;
            let op_kind = match other {
                InstKind::Publish { name, bytes } => OpKind::Publish { name, bytes },
                InstKind::Call { contract, expr } => OpKind::Call { contract, expr },
                InstKind::RegisterBlsKey {
                    bls_pubkey,
                    schnorr_sig,
                    bls_sig,
                } => OpKind::RegisterBlsKey {
                    bls_pubkey,
                    schnorr_sig,
                    bls_sig,
                },
                InstKind::Issuance => unreachable!("Issuance handled above"),
                InstKind::Sponsor { .. } => unreachable!("Sponsor handled above"),
            };
            (resolved, op_kind)
        }
    };

    let metadata = OpMetadata {
        previous_output: base.previous_output,
        input_index: base.input_index,
        op_index: base.op_index,
        signer_id: base.signer_id,
        payment,
    };
    Ok(Op { metadata, kind })
}

/// Sentinel payment for system-paid ops (currently only `Issuance`).
/// The `is_core()` bypass in `prepare_call` ignores this field, so values
/// here exist for shape uniformity rather than runtime effect.
fn core_payment() -> Payment {
    Payment {
        signer_id: CORE_SIGNER_ID as u64,
        gas_limit: 0,
    }
}

fn resolve_payment(
    intent: &PaymentIntent,
    signer_id: u64,
    publisher: Option<PublisherOffer>,
) -> Result<Payment, anyhow::Error> {
    match (intent, publisher) {
        (PaymentIntent::SelfPay { limit }, _) => Ok(Payment {
            signer_id,
            gas_limit: *limit,
        }),
        (PaymentIntent::Sponsored, Some(offer)) => Ok(Payment {
            signer_id: offer.signer_id,
            gas_limit: offer.gas_limit_per_op,
        }),
        (PaymentIntent::Sponsored, None) => Err(anyhow::anyhow!(
            "PaymentIntent::Sponsored without a publisher offer"
        )),
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
                        && insts
                            .aggregate
                            .as_ref()
                            .is_none_or(|agg| agg.signers.len() == insts.ops.len())
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
    let mut op_return_data: Vec<indexer_types::OpReturnEntry> = Vec::new();

    if let Some(op_return) = op_return {
        let mut op_return_instructions = op_return.script_pubkey.instructions();
        if let Some(Ok(Instruction::Op(OP_RETURN))) = op_return_instructions.next()
            && let Some(Ok(Instruction::PushBytes(data))) = op_return_instructions.next()
            && let Ok(entries) =
                deserialize::<Vec<indexer_types::OpReturnEntry>>(data.as_bytes())
        {
            op_return_data = entries;
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
        // Per-op signer_ids: aggregates resolve each `SignerRef` (Id is
        // already-resolved; PubKey is looked up against the registry — by
        // the time inspect runs, any PubKey claim on a successfully
        // executed aggregate must have a corresponding signers row).
        // Direct inputs broadcast the witness signer to every op.
        let signer_ids: Vec<u64> = match &input.insts.aggregate {
            Some(agg) => {
                let mut ids = Vec::with_capacity(agg.signers.len());
                for s in &agg.signers {
                    let id = match &s.identity {
                        indexer_types::SignerRef::SignerId(id) => *id,
                        indexer_types::SignerRef::XOnlyPubkey(pk) => {
                            crate::database::queries::get_signer_entry_by_x_only_pubkey(
                                conn,
                                &pk.to_string(),
                            )
                            .await?
                            .map(|e| e.signer_id as u64)
                            .unwrap_or(0)
                        }
                    };
                    ids.push(id);
                }
                ids
            }
            None => {
                let id = crate::database::queries::get_signer_entry_by_x_only_pubkey(
                    conn,
                    &input.x_only_pubkey.to_string(),
                )
                .await?
                .map(|e| e.signer_id as u64)
                .unwrap_or(0);
                vec![id; input.insts.ops.len()]
            }
        };

        // For aggregate inputs with a sponsorship offer, resolve the publisher's
        // signer_id so sponsored ops materialize with the same Payment the
        // executor used. The `payer_signer_id` column on result rows is the
        // durable record of who paid (queryable in SQL / future readers); this
        // local resolution is what inspect needs to reconstruct `Op` for ops
        // that have no result row yet (e.g. `should_skip_result` cases).
        let publisher_offer: Option<PublisherOffer> = match &input.insts.aggregate {
            Some(agg) if agg.publisher_sponsorship.is_some() => {
                crate::database::queries::get_signer_entry_by_x_only_pubkey(
                    conn,
                    &input.x_only_pubkey.to_string(),
                )
                .await?
                .map(|e| PublisherOffer {
                    signer_id: e.signer_id as u64,
                    gas_limit_per_op: agg.publisher_sponsorship.unwrap(),
                })
            }
            _ => None,
        };

        for (op_index, inst) in input.insts.ops.iter().enumerate() {
            let base = OpMetadataBase {
                previous_output: input.previous_output,
                input_index: input.input_index,
                op_index: op_index as i64,
                signer_id: signer_ids.get(op_index).copied().unwrap_or(0),
            };
            // Dispatch on input shape so the entry point matches the
            // executor's (op_from_direct_inst for direct inputs,
            // op_from_aggregate_inst for aggregate inputs).
            let materialized = if input.insts.aggregate.is_some() {
                op_from_aggregate_inst(inst.clone(), base, publisher_offer)
            } else {
                op_from_direct_inst(inst.clone(), base)
            };
            let op = match materialized {
                Ok(op) => op,
                Err(e) => {
                    tracing::warn!("inspect: op {op_index} rejected at materialize: {e:#}");
                    ops.push(OpWithResult::Rejected {
                        input_index: input.input_index,
                        op_index: op_index as i64,
                        error_message: None,
                    });
                    continue;
                }
            };
            let id = OpResultId::builder()
                .txid(tx.txid.to_string())
                .input_index(input.input_index)
                .op_index(op_index as i64)
                .build();
            let result = get_op_result(conn, &id)
                .await?
                .map(indexer_types::ResultRow::from);
            // `result: None` is preserved (pre-refactor semantics) for ops the
            // executor skipped post-validation via `should_skip_result` or that
            // hit a non-deterministic failure — callers learn "this op was in
            // the tx but didn't produce a result row."
            //
            // `error_message: None` because inspect reads from chain state and
            // error strings aren't persisted. The simulate handler overwrites
            // this with live error detail captured during execution.
            ops.push(OpWithResult::Materialized {
                op,
                result,
                error_message: None,
            });
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
    use indexer_types::{
        AggregateInfo, AggregateSigner, ContractAddress, Inst, InstKind, Insts, PaymentIntent,
        SignerRef, serialize,
    };

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
        let op = Inst {
            payment: PaymentIntent::self_pay(123),
            kind: InstKind::Call {
                contract,
                expr: "noop()".to_string(),
            },
        };
        let insts = Insts {
            ops: vec![op.clone()],
            aggregate: Some(AggregateInfo {
                signers: vec![AggregateSigner {
                    identity: SignerRef::SignerId(7),
                    nonce: 0,
                }],
                signature: vec![9u8; 48],
                publisher_sponsorship: None,
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
        let payload = serialize(&Insts::single(Inst {
            payment: PaymentIntent::self_pay(10_000),
            kind: InstKind::Issuance,
        }))
        .expect("serialize");
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
        let payload = serialize(&Insts::single(Inst {
            payment: PaymentIntent::self_pay(10_000),
            kind: InstKind::Issuance,
        }))
        .expect("serialize");
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
        let inst = Inst {
            payment: PaymentIntent::self_pay(7),
            kind: InstKind::Call {
                contract: ContractAddress {
                    name: "arith".to_string(),
                    height: 1,
                    tx_index: 0,
                },
                expr: "eval(10, id)".to_string(),
            },
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
            Inst {
                payment,
                kind: InstKind::Call { contract, expr },
            } => {
                assert_eq!(*payment, PaymentIntent::self_pay(7));
                assert_eq!(contract.name, "arith");
                assert_eq!(expr, "eval(10, id)");
            }
            other => panic!("expected Inst::Call, got {other:?}"),
        }
    }

    #[test]
    fn filter_map_rejects_non_pushbytes_inside_envelope() {
        let xonly = random_xonly();
        let payload = serialize(&Insts::single(Inst {
            payment: PaymentIntent::self_pay(10_000),
            kind: InstKind::Issuance,
        }))
        .expect("serialize");
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
        let payload = serialize(&Insts::single(Inst {
            payment: PaymentIntent::self_pay(10_000),
            kind: InstKind::Issuance,
        }))
        .expect("serialize");
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

    // -----------------------------------------------------------------------
    // op_from_*_inst sponsorship resolution
    // -----------------------------------------------------------------------

    use super::{OpMetadataBase, PublisherOffer, op_from_aggregate_inst, op_from_direct_inst};
    use indexer_types::{OpKind, Payment};

    fn dummy_call_inst(payment: PaymentIntent) -> Inst {
        Inst {
            payment,
            kind: InstKind::Call {
                contract: ContractAddress {
                    name: "c".into(),
                    height: 1,
                    tx_index: 0,
                },
                expr: "noop()".into(),
            },
        }
    }

    fn dummy_base(signer_id: u64) -> OpMetadataBase {
        OpMetadataBase {
            previous_output: bitcoin::OutPoint::null(),
            input_index: 0,
            op_index: 0,
            signer_id,
        }
    }

    #[test]
    fn op_from_direct_inst_self_pay_uses_signer_id() {
        let inst = dummy_call_inst(PaymentIntent::self_pay(123));
        let op = op_from_direct_inst(inst, dummy_base(42)).unwrap();
        assert!(matches!(op.kind, OpKind::Call { .. }));
        assert_eq!(
            op.metadata.payment,
            Payment {
                signer_id: 42,
                gas_limit: 123,
            }
        );
    }

    #[test]
    fn op_from_direct_inst_rejects_sponsored() {
        let inst = dummy_call_inst(PaymentIntent::Sponsored);
        let err = op_from_direct_inst(inst, dummy_base(42))
            .expect_err("Sponsored in direct path must be rejected");
        assert!(err.to_string().contains("Sponsored"));
    }

    #[test]
    fn op_from_aggregate_inst_self_pay_ignores_offer() {
        // SelfPay always uses the co-signer's own commitment, even when a
        // publisher offer is present in the bulk.
        let inst = dummy_call_inst(PaymentIntent::self_pay(123));
        let offer = Some(PublisherOffer {
            signer_id: 99,
            gas_limit_per_op: 9999,
        });
        let op = op_from_aggregate_inst(inst, dummy_base(42), offer).unwrap();
        assert!(matches!(op.kind, OpKind::Call { .. }));
        assert_eq!(
            op.metadata.payment,
            Payment {
                signer_id: 42,
                gas_limit: 123,
            }
        );
    }

    #[test]
    fn op_from_aggregate_inst_sponsored_uses_publisher_offer() {
        let inst = dummy_call_inst(PaymentIntent::Sponsored);
        let offer = Some(PublisherOffer {
            signer_id: 99,
            gas_limit_per_op: 9999,
        });
        let op = op_from_aggregate_inst(inst, dummy_base(42), offer).unwrap();
        assert!(matches!(op.kind, OpKind::Call { .. }));
        assert_eq!(
            op.metadata.payment,
            Payment {
                signer_id: 99,
                gas_limit: 9999,
            }
        );
    }

    #[test]
    fn op_from_aggregate_inst_sponsored_without_offer_rejected() {
        let inst = dummy_call_inst(PaymentIntent::Sponsored);
        let err = op_from_aggregate_inst(inst, dummy_base(42), None)
            .expect_err("Sponsored without a publisher offer must be rejected");
        assert!(err.to_string().contains("Sponsored"));
    }
}
