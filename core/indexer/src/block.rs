use bitcoin::{
    XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_RETURN},
    script::Instruction,
};
use indexer_types::{
    Input, Inst, InstKind, Insts, Op, OpKind, OpMetadata, OpWithResult, Payment, Transaction,
    deserialize,
};
use libsql::Connection;

use crate::database::{
    queries::get_op_result,
    types::{CORE_SIGNER_ID, OpResultId},
};

pub type TransactionFilterMap = fn((usize, bitcoin::Transaction)) -> Option<Transaction>;

/// Origin-only OpMetadata fields supplied by the reactor. The `payment`
/// part of `OpMetadata` is filled in by `materialize_op` from
/// `Inst.gas_limit` and the optional payer override.
#[derive(Debug, Clone, Copy)]
pub struct OpMetadataBase {
    pub previous_output: bitcoin::OutPoint,
    pub input_index: i64,
    pub op_index: i64,
    pub signer_id: u64,
}

/// Build an `Op` from an `Inst`. Same entry point for direct and
/// aggregate inputs — the only thing that differs is `payment_override`,
/// which the caller (or `TxWalker::materialize`) computes:
///
/// - Direct, no Sponsor active → `None` (input signer pays at `inst.gas_limit`).
/// - Direct, cross-input Sponsor active → `Some(sponsor_payment)` (sponsor
///   pays at the sponsor's `gas_limit`, overriding `inst.gas_limit`).
/// - Aggregate, `AggregateSigner.sponsored = false` → `None` (co-signer pays).
/// - Aggregate, `AggregateSigner.sponsored = true` → `Some(Payment {
///   signer_id: publisher, gas_limit: inst.gas_limit })`.
/// - Aggregate with a cross-input Sponsor still active → sponsor wins.
///
/// The Sponsor Op itself is always materialized with `(base.signer_id,
/// inst.gas_limit)` (the sponsorship terms the reactor reads back to
/// drive subsequent inputs), regardless of any incoming override.
pub fn materialize_op(
    inst: Inst,
    base: OpMetadataBase,
    payment_override: Option<Payment>,
) -> Result<Op, anyhow::Error> {
    let Inst { gas_limit, kind } = inst;
    let (payment, kind) = match kind {
        InstKind::Issuance => (core_payment(), OpKind::Issuance),
        // Sponsor materializes as an Op so its sponsorship terms ride in
        // OpMetadata.payment for the reactor to read back. The Op itself
        // does *not* dispatch to a contract — `execute_op` short-circuits
        // OpKind::Sponsor — and the per-tx loop captures `payment` into
        // `pending_for_next` to drive the next input. The cross-input
        // `payment_override` (which would otherwise apply to this op) is
        // ignored here so the Sponsor's own commitment is preserved.
        InstKind::Sponsor => (
            Payment {
                signer_id: base.signer_id,
                gas_limit,
            },
            OpKind::Sponsor,
        ),
        other => {
            // Override replaces both payer and cap; otherwise default to
            // "input signer pays up to Inst.gas_limit." Override sources:
            // (a) cross-input Sponsor active from a previous input, or
            // (b) aggregate-sponsored (publisher pays at Inst.gas_limit).
            let payment = payment_override.unwrap_or(Payment {
                signer_id: base.signer_id,
                gas_limit,
            });
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
                InstKind::Sponsor => unreachable!("Sponsor handled above"),
            };
            (payment, op_kind)
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

/// Per-tx walker that owns the Sponsor state machine + payment-override
/// computation. Callers (block::inspect and the reactor's process_*_input)
/// do their own outer per-input loop — they differ on per-input work
/// (DB result lookup vs BLS verification + execution) — but the
/// active/pending_for_next dance, the override precedence rule, and the
/// per-input boundary reset are identical and dangerous to drift on.
///
/// Usage skeleton:
/// ```ignore
/// let mut walker = TxWalker::new();
/// for input in &tx.inputs {
///     let publisher = resolve_publisher_signer_id(input).await?;
///     for (op_index, inst) in input.insts.ops.iter().enumerate() {
///         let override_ = walker.payment_override(input, op_index, publisher, inst);
///         let op = op_from_*_inst(inst.clone(), base, override_)?;
///         walker.capture(&op);
///         // ...caller-specific per-op work (emit OpWithResult / execute_op)...
///     }
///     walker.next_input();
/// }
/// ```
#[derive(Debug, Default)]
pub struct TxWalker {
    /// Carried in from the previous input's `Sponsor` — overrides
    /// non-Sponsor non-Issuance ops in the current input.
    active: Option<Payment>,
    /// Captured during the current input from any `Sponsor` Op; promoted
    /// to `active` at the input boundary, then cleared. Sponsors sponsor
    /// only the input immediately following them.
    pending_for_next: Option<Payment>,
}

impl TxWalker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute the per-op `payment_override` for `op_index` in `input`:
    /// the active cross-input `Sponsor` payment wins over an aggregate's
    /// per-op publisher offer; otherwise `None` (the op self-pays from
    /// the input signer at its own `Inst.gas_limit`).
    pub fn payment_override(
        &self,
        input: &Input,
        op_index: usize,
        publisher_signer_id: Option<u64>,
        inst: &Inst,
    ) -> Option<Payment> {
        if let Some(active) = &self.active {
            return Some(active.clone());
        }
        let agg = input.insts.aggregate.as_ref()?;
        let sponsored = agg.signers.get(op_index).is_some_and(|s| s.sponsored);
        if !sponsored {
            return None;
        }
        publisher_signer_id.map(|signer_id| Payment {
            signer_id,
            gas_limit: inst.gas_limit,
        })
    }

    /// Call after materializing each op. If the op is a `Sponsor`, its
    /// `OpMetadata.payment` becomes the sponsorship payment for the NEXT
    /// input. (Multiple Sponsors in one input: last-wins.)
    pub fn capture(&mut self, op: &Op) {
        if matches!(op.kind, OpKind::Sponsor) {
            self.pending_for_next = Some(op.metadata.payment.clone());
        }
    }

    /// Call at the end of each input's op loop. Promotes the captured
    /// sponsor (if any) to `active` for the next input's ops, and clears
    /// `pending_for_next`. A Sponsor-less input clears any previously
    /// active sponsor, since Sponsor only sponsors the input immediately
    /// following it.
    pub fn next_input(&mut self) {
        self.active = self.pending_for_next.take();
    }

    /// One-stop per-op materialization: builds the `OpMetadataBase`,
    /// computes the payment override (cross-input Sponsor wins over the
    /// aggregate's per-op publisher offer), calls `materialize_op`, and
    /// captures any `Sponsor` Op's terms into `pending_for_next`.
    ///
    /// Callers (`block::inspect` and the reactor's `process_*_input`)
    /// supply the per-op `signer_id` (DB lookup / `get_or_create_identity`
    /// / BLS-resolved) and `publisher_signer_id` (only meaningful for
    /// aggregate inputs; `None` for direct).
    pub fn materialize(
        &mut self,
        input: &Input,
        op_index: usize,
        signer_id: u64,
        publisher_signer_id: Option<u64>,
        inst: &Inst,
    ) -> Result<Op, anyhow::Error> {
        let base = OpMetadataBase {
            previous_output: input.previous_output,
            input_index: input.input_index,
            op_index: op_index as i64,
            signer_id,
        };
        let payment_override = self.payment_override(input, op_index, publisher_signer_id, inst);
        let op = materialize_op(inst.clone(), base, payment_override)?;
        self.capture(&op);
        Ok(op)
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
            && let Ok(entries) = deserialize::<Vec<indexer_types::OpReturnEntry>>(data.as_bytes())
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
    let mut walker = TxWalker::new();
    for input in &tx.inputs {
        // Per-op signer_ids: aggregates resolve each `SignerRef` (Id is
        // already-resolved; PubKey is looked up against the registry — by
        // the time inspect runs, any PubKey claim on a successfully
        // executed aggregate must have a corresponding signers row).
        // Direct inputs broadcast the witness signer to every op.
        let signer_ids = resolve_input_signer_ids_via_db(conn, input).await?;
        // For aggregate inputs, the publisher's signer_id is the payer
        // for any op whose `AggregateSigner.sponsored = true`. `None` for
        // direct inputs.
        let publisher_signer_id = resolve_publisher_signer_id_via_db(conn, input).await?;

        for (op_index, inst) in input.insts.ops.iter().enumerate() {
            let signer_id = signer_ids.get(op_index).copied().unwrap_or(0);
            let op = match walker.materialize(input, op_index, signer_id, publisher_signer_id, inst)
            {
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
        walker.next_input();
    }
    Ok(ops)
}

/// DB-backed signer resolution for `block::inspect`. Aggregate inputs:
/// per-AggregateSigner; `SignerId(id)` is already resolved, `XOnlyPubkey`
/// is looked up. Direct inputs: the witness signer broadcast across every
/// op. Missing entries become `0` (preserves pre-refactor inspect
/// semantics — inspect is best-effort over historical state).
async fn resolve_input_signer_ids_via_db(
    conn: &Connection,
    input: &Input,
) -> anyhow::Result<Vec<u64>> {
    match &input.insts.aggregate {
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
            Ok(ids)
        }
        None => {
            let id = crate::database::queries::get_signer_entry_by_x_only_pubkey(
                conn,
                &input.x_only_pubkey.to_string(),
            )
            .await?
            .map(|e| e.signer_id as u64)
            .unwrap_or(0);
            Ok(vec![id; input.insts.ops.len()])
        }
    }
}

/// DB-backed publisher signer_id resolution for `block::inspect`. Returns
/// `Some` for aggregate inputs (the input's x_only_pubkey, looked up in
/// the signers table), `None` for direct inputs.
async fn resolve_publisher_signer_id_via_db(
    conn: &Connection,
    input: &Input,
) -> anyhow::Result<Option<u64>> {
    if input.insts.aggregate.is_none() {
        return Ok(None);
    }
    Ok(crate::database::queries::get_signer_entry_by_x_only_pubkey(
        conn,
        &input.x_only_pubkey.to_string(),
    )
    .await?
    .map(|e| e.signer_id as u64))
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
        AggregateInfo, AggregateSigner, ContractAddress, Inst, InstKind, Insts, SignerRef,
        serialize,
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
            gas_limit: 123,
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
                    sponsored: false,
                }],
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
        let payload = serialize(&Insts::single(Inst {
            gas_limit: 10_000,
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
            gas_limit: 10_000,
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
            gas_limit: 7,
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
                gas_limit,
                kind: InstKind::Call { contract, expr },
            } => {
                assert_eq!(*gas_limit, 7);
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
            gas_limit: 10_000,
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
            gas_limit: 10_000,
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
    // materialize_op — payer + gas_limit resolution
    // -----------------------------------------------------------------------

    use super::{OpMetadataBase, materialize_op};
    use indexer_types::{OpKind, Payment};

    fn dummy_call_inst(gas_limit: u64) -> Inst {
        Inst {
            gas_limit,
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
    fn materialize_uses_input_signer_and_inst_gas_limit_with_no_override() {
        let inst = dummy_call_inst(123);
        let op = materialize_op(inst, dummy_base(42), None).unwrap();
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
    fn materialize_override_replaces_both_signer_and_cap() {
        // Used for both the cross-input Sponsor case (override = sponsor's
        // payment) and the aggregate-sponsored case (override = publisher's
        // payment + inst.gas_limit). One mechanism.
        let inst = dummy_call_inst(123);
        let override_payment = Payment {
            signer_id: 99,
            gas_limit: 9_999,
        };
        let op = materialize_op(inst, dummy_base(42), Some(override_payment)).unwrap();
        assert_eq!(
            op.metadata.payment,
            Payment {
                signer_id: 99,
                gas_limit: 9_999,
            }
        );
        // The op's *signer* (the input's signer) is unchanged — override
        // only redirects the payer.
        assert_eq!(op.metadata.signer_id, 42);
    }

    #[test]
    fn materialize_sponsor_uses_its_own_payment_ignoring_override() {
        // Sponsor materializes as OpKind::Sponsor; metadata.payment
        // captures the sponsorship terms (input signer + inst.gas_limit).
        // An incoming override does NOT apply to Sponsor itself — its own
        // Payment is what the reactor reads back to drive the next input.
        let inst = Inst {
            gas_limit: 5_000,
            kind: InstKind::Sponsor,
        };
        let unrelated_override = Payment {
            signer_id: 99,
            gas_limit: 9_999,
        };
        let op = materialize_op(inst, dummy_base(42), Some(unrelated_override)).unwrap();
        assert!(matches!(op.kind, OpKind::Sponsor));
        assert_eq!(
            op.metadata.payment,
            Payment {
                signer_id: 42,
                gas_limit: 5_000,
            }
        );
    }

    // -----------------------------------------------------------------------
    // TxWalker: Sponsor state machine + payment-override precedence
    // -----------------------------------------------------------------------

    use super::TxWalker;
    use indexer_types::{Input, Op};

    fn direct_input(insts: Insts) -> Input {
        Input {
            previous_output: bitcoin::OutPoint::null(),
            input_index: 0,
            x_only_pubkey: random_xonly(),
            insts,
        }
    }

    fn aggregate_input(insts: Vec<Inst>, sponsored_flags: Vec<bool>) -> Input {
        let signers = sponsored_flags
            .into_iter()
            .map(|sponsored| AggregateSigner {
                identity: SignerRef::SignerId(0),
                nonce: 0,
                sponsored,
            })
            .collect();
        let bundle = Insts {
            ops: insts,
            aggregate: Some(AggregateInfo {
                signers,
                signature: vec![0u8; 48],
            }),
        };
        direct_input(bundle)
    }

    #[test]
    fn walker_payment_override_is_none_with_no_active_and_direct_input() {
        let walker = TxWalker::new();
        let input = direct_input(Insts::single(dummy_call_inst(123)));
        assert!(
            walker
                .payment_override(&input, 0, None, &input.insts.ops[0])
                .is_none()
        );
    }

    #[test]
    fn walker_payment_override_uses_publisher_for_aggregate_sponsored() {
        let walker = TxWalker::new();
        let input = aggregate_input(vec![dummy_call_inst(123)], vec![true]);
        let got = walker
            .payment_override(&input, 0, Some(7), &input.insts.ops[0])
            .expect("sponsored aggregate op → publisher override");
        assert_eq!(
            got,
            Payment {
                signer_id: 7,
                gas_limit: 123,
            }
        );
    }

    #[test]
    fn walker_payment_override_is_none_for_aggregate_non_sponsored() {
        let walker = TxWalker::new();
        let input = aggregate_input(vec![dummy_call_inst(123)], vec![false]);
        assert!(
            walker
                .payment_override(&input, 0, Some(7), &input.insts.ops[0])
                .is_none()
        );
    }

    #[test]
    fn walker_active_beats_publisher_offer() {
        let mut walker = TxWalker::new();
        let sponsor_op = Op {
            metadata: indexer_types::OpMetadata {
                previous_output: bitcoin::OutPoint::null(),
                input_index: 0,
                op_index: 0,
                signer_id: 0,
                payment: Payment {
                    signer_id: 42,
                    gas_limit: 5_000,
                },
            },
            kind: OpKind::Sponsor,
        };
        walker.capture(&sponsor_op);
        walker.next_input();
        // Even with publisher_signer_id provided, active (cross-input
        // Sponsor) wins.
        let input = aggregate_input(vec![dummy_call_inst(123)], vec![true]);
        let got = walker
            .payment_override(&input, 0, Some(7), &input.insts.ops[0])
            .expect("active sponsor present");
        assert_eq!(
            got,
            Payment {
                signer_id: 42,
                gas_limit: 5_000,
            }
        );
    }

    #[test]
    fn walker_capture_then_next_input_promotes_pending_to_active() {
        let mut walker = TxWalker::new();
        let sponsor_op = Op {
            metadata: indexer_types::OpMetadata {
                previous_output: bitcoin::OutPoint::null(),
                input_index: 0,
                op_index: 0,
                signer_id: 0,
                payment: Payment {
                    signer_id: 99,
                    gas_limit: 1_000,
                },
            },
            kind: OpKind::Sponsor,
        };
        walker.capture(&sponsor_op);
        // Before the input boundary, active is still None.
        let input = direct_input(Insts::single(dummy_call_inst(50)));
        assert!(
            walker
                .payment_override(&input, 0, None, &input.insts.ops[0])
                .is_none()
        );
        walker.next_input();
        // After the boundary, active reflects the captured Sponsor.
        let got = walker
            .payment_override(&input, 0, None, &input.insts.ops[0])
            .expect("active promoted from pending");
        assert_eq!(
            got,
            Payment {
                signer_id: 99,
                gas_limit: 1_000,
            }
        );
    }

    #[test]
    fn walker_capture_ignores_non_sponsor_ops() {
        let mut walker = TxWalker::new();
        let call_op = materialize_op(dummy_call_inst(123), dummy_base(42), None).unwrap();
        walker.capture(&call_op);
        walker.next_input();
        let input = direct_input(Insts::single(dummy_call_inst(50)));
        assert!(
            walker
                .payment_override(&input, 0, None, &input.insts.ops[0])
                .is_none()
        );
    }

    #[test]
    fn walker_next_input_clears_active_if_no_sponsor_this_round() {
        let mut walker = TxWalker::new();
        // First input: capture a Sponsor → active for input 2.
        walker.capture(&Op {
            metadata: indexer_types::OpMetadata {
                previous_output: bitcoin::OutPoint::null(),
                input_index: 0,
                op_index: 0,
                signer_id: 0,
                payment: Payment {
                    signer_id: 99,
                    gas_limit: 1_000,
                },
            },
            kind: OpKind::Sponsor,
        });
        walker.next_input();
        // Input 2: no new Sponsor captured.
        walker.next_input();
        // Input 3: active is gone — Sponsor only sponsors the immediately
        // following input.
        let input = direct_input(Insts::single(dummy_call_inst(50)));
        assert!(
            walker
                .payment_override(&input, 0, None, &input.insts.ops[0])
                .is_none()
        );
    }

    #[test]
    fn walker_capture_last_sponsor_wins_within_one_input() {
        let mut walker = TxWalker::new();
        for &signer_id in &[1u64, 2, 3] {
            walker.capture(&Op {
                metadata: indexer_types::OpMetadata {
                    previous_output: bitcoin::OutPoint::null(),
                    input_index: 0,
                    op_index: 0,
                    signer_id: 0,
                    payment: Payment {
                        signer_id,
                        gas_limit: 100 * signer_id,
                    },
                },
                kind: OpKind::Sponsor,
            });
        }
        walker.next_input();
        let input = direct_input(Insts::single(dummy_call_inst(50)));
        let got = walker
            .payment_override(&input, 0, None, &input.insts.ops[0])
            .expect("last Sponsor's payment is active");
        assert_eq!(
            got,
            Payment {
                signer_id: 3,
                gas_limit: 300,
            }
        );
    }
}
