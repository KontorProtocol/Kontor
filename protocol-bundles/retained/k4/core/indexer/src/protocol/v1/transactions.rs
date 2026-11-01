use bitcoin::consensus::encode::FromHexError;
use bitcoin::consensus::{Decodable, DecodeError};
use bitcoin::io::Cursor;
use bitcoin::{
    OutPoint, Transaction as BitcoinTransaction, XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
    script::Instruction,
};
use indexer_types::{
    Input, Inst, InstKind, Insts, Op, OpKind, OpMetadata, Payment, Transaction, deserialize,
};

use super::storage_identity::CORE_SIGNER_ID;

pub(crate) fn decode_simulation(raw: &[u8]) -> Result<BitcoinTransaction, String> {
    // Match deserialize_hex's consensus_decode entry and trailing-byte check;
    // deserialize_partial uses a different finite-reader entry point.
    let mut reader = Cursor::new(raw);
    let decoded = BitcoinTransaction::consensus_decode(&mut reader)
        .map_err(DecodeError::Consensus)
        .and_then(|transaction| {
            if reader.position() as usize == raw.len() {
                Ok(transaction)
            } else {
                Err(DecodeError::TooManyBytes)
            }
        });
    decoded.map_err(|error| FromHexError::Decode(error).to_string())
}

pub type TransactionFilterMap = fn((usize, BitcoinTransaction)) -> Option<Transaction>;

/// Origin-only OpMetadata fields supplied by the reactor. The `payment`
/// part of `OpMetadata` is filled in by `materialize_op` from
/// `Inst.gas_limit` and the optional payer override.
#[derive(Debug, Clone, Copy)]
pub struct OpMetadataBase {
    pub previous_output: OutPoint,
    pub input_index: u32,
    pub op_index: u32,
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
                InstKind::Publish {
                    name,
                    bytes,
                    provenance,
                } => OpKind::Publish {
                    name,
                    bytes,
                    provenance,
                },
                InstKind::Call { contract, expr } => OpKind::Call { contract, expr },
                InstKind::UpdateProvenance {
                    contract,
                    provenance,
                } => OpKind::UpdateProvenance {
                    contract,
                    provenance,
                },
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
        signer_id: CORE_SIGNER_ID,
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
    /// per-op publisher offer; otherwise `Ok(None)` (the op self-pays
    /// from the input signer at its own `Inst.gas_limit`).
    ///
    /// Returns `Err` when the op is aggregate-sponsored but no
    /// `publisher_signer_id` was supplied — falling through to `None`
    /// there would silently swap the payer to the co-signer, mis-
    /// attributing who paid gas. The executor always resolves the
    /// publisher via `get_or_create_identity` so it never hits this;
    /// `block::inspect`'s DB lookup can miss (no signers row) and is
    /// where the rejection surfaces, matching the old `PaymentIntent::
    /// Sponsored`-without-offer reject behavior.
    pub fn payment_override(
        &self,
        input: &Input,
        op_index: usize,
        publisher_signer_id: Option<u64>,
        inst: &Inst,
    ) -> Result<Option<Payment>, anyhow::Error> {
        if let Some(active) = &self.active {
            return Ok(Some(active.clone()));
        }
        let Some(agg) = input.insts.aggregate.as_ref() else {
            return Ok(None);
        };
        let sponsored = agg.signers.get(op_index).is_some_and(|s| s.sponsored);
        if !sponsored {
            return Ok(None);
        }
        let signer_id = publisher_signer_id.ok_or_else(|| {
            anyhow::anyhow!(
                "op {op_index} is aggregate-sponsored but the publisher has no resolved signer_id"
            )
        })?;
        Ok(Some(Payment {
            signer_id,
            gas_limit: inst.gas_limit,
        }))
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
            op_index: op_index as u32,
            signer_id,
        };
        let payment_override = self.payment_override(input, op_index, publisher_signer_id, inst)?;
        let op = materialize_op(inst.clone(), base, payment_override)?;
        self.capture(&op);
        Ok(op)
    }
}

pub fn filter_map((tx_index, tx): (usize, BitcoinTransaction)) -> Option<Transaction> {
    let inputs =
        tx.input
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
                        // Provenance is a pure function of the op (no chain
                        // state), so reject malformed provenance at decode time
                        // rather than letting it reach execution.
                        && insts.ops.iter().all(|inst| match &inst.kind {
                            InstKind::Publish { provenance, .. }
                            | InstKind::UpdateProvenance { provenance, .. } => {
                                provenance.validate().is_ok()
                            }
                            _ => true,
                        }) {
                            return Some(Input {
                                previous_output: input.previous_output,
                                input_index: input_index as u32,
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

    // The full payload after the single-byte OP_RETURN opcode, surfaced verbatim
    // to contracts; the host does not interpret it. An OP_RETURN script can carry
    // several pushes (e.g. a marker push then a payload push), so take everything
    // past the opcode rather than just the first push. `is_op_return` guarantees
    // the leading byte is the opcode, so `[1..]` is safe.
    let op_return_raw = tx
        .output
        .iter()
        .find(|o| o.script_pubkey.is_op_return())
        .map(|o| o.script_pubkey.as_bytes()[1..].to_vec());

    Some(Transaction {
        txid: tx.compute_txid(),
        index: tx_index as u32,
        inputs,
        op_return_raw,
    })
}

/// Check if a parsed transaction contains only batchable ops.
/// Publish must only execute via Value::Block decisions (contract address
/// depends on block height/tx_index). All other ops are batchable.
/// Aggregate inputs are always batchable.
pub fn is_batchable(inputs: &[Input]) -> bool {
    inputs.iter().all(|input| {
        if input.insts.is_aggregate() {
            return true;
        }
        !input
            .insts
            .ops
            .iter()
            .any(|inst| matches!(inst.kind, InstKind::Publish { .. }))
    })
}
