use anyhow::{Result, anyhow};
use bitcoin::{
    Address, AddressType, Amount, FeeRate, KnownHrp, OutPoint, Psbt, ScriptBuf, TxOut, Witness,
    absolute::LockTime,
    consensus::encode::serialize as serialize_tx,
    opcodes::{
        OP_0, OP_FALSE,
        all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_RETURN},
    },
    script::{Builder, PushBytesBuf},
    secp256k1::{Secp256k1, XOnlyPublicKey},
    taproot::{ControlBlock, LeafVersion, TaprootBuilder},
    transaction::{Transaction, TxIn, Version},
};

use bitcoin::Txid;
use bitcoin::key::constants::SCHNORR_SIGNATURE_SIZE;
use indexer_types::{
    CommitSource, Reveal, RevealOutput, RevealOutputInfo, RevealOutputs, RevealParticipant,
    TapLeafScript, serialize,
};
use std::{collections::HashSet, str::FromStr};

use crate::bitcoin_client::Client;

// Hardening limits
const MAX_PARTICIPANTS: usize = 1000;
const MAX_SCRIPT_BYTES: usize = 387 * 1024; // 387 KiB
const MAX_OP_RETURN_BYTES: usize = 80; // Standard policy
const MIN_ENVELOPE_SATS: u64 = 330; // P2TR dust floor
const MAX_UTXOS_PER_PARTICIPANT: usize = 64; // Hard cap per participant
const P2TR_OUTPUT_SIZE: usize = 34; // P2TR script pubkey size in bytes
const PROTOCOL_TAG: &[u8; 3] = b"kon"; // Protocol envelope marker

pub fn compose_reveal(reveal: Reveal) -> Result<RevealOutputs> {
    if reveal.participants.is_empty() && reveal.extra_inputs.is_empty() {
        return Err(anyhow!("Reveal must have at least one input"));
    }
    if reveal.participants.len() > MAX_PARTICIPANTS {
        return Err(anyhow!("Too many participants (max {})", MAX_PARTICIPANTS));
    }

    let sat_per_vbyte = reveal
        .sat_per_vbyte
        .ok_or_else(|| anyhow!("sat_per_vbyte required"))?;
    if sat_per_vbyte == 0 {
        return Err(anyhow!("Invalid fee rate"));
    }
    let fee_rate =
        FeeRate::from_sat_per_vb(sat_per_vbyte).ok_or_else(|| anyhow!("Invalid fee rate"))?;

    // Resolve each participant's per-input bits: leaf script, control
    // block, x-only key, outpoint, prevout. All participants must be
    // Existing here — Build is only valid in compose_commit / compose.
    // Validation lives in `participant_tap_data`.
    let mut resolved: Vec<ResolvedParticipant> = Vec::with_capacity(reveal.participants.len());
    for (i, p) in reveal.participants.iter().enumerate() {
        let (outpoint, prevout) = match &p.commit_source {
            CommitSource::Existing { outpoint, prevout } => (*outpoint, prevout.clone()),
            CommitSource::Build { .. } => {
                return Err(anyhow!(
                    "compose_reveal: participant {} has CommitSource::Build; use compose() or compose_commit() to build commits",
                    i
                ));
            }
        };
        let (x_only_public_key, script, control_block) =
            participant_tap_data(p).map_err(|e| anyhow!("participant {}: {}", i, e))?;
        resolved.push(ResolvedParticipant {
            x_only_public_key,
            outpoint,
            prevout,
            tap_leaf_script: TapLeafScript {
                leaf_version: LeafVersion::TapScript,
                script,
                control_block: ScriptBuf::from_bytes(control_block.serialize()),
            },
            output: p.output.clone(),
        });
    }

    // Compute the output layout. Shared with `estimate_reveal_vbytes` so
    // the commit's sizing matches the actual reveal exactly — if these
    // diverged the commit's tap output value would silently undercover
    // the reveal's real fee.
    let layout = compute_output_layout(&reveal)?;

    // At most one Change output (no well-defined way to split the
    // leftover across multiple).
    let change_count = layout
        .iter()
        .filter(|slot| {
            let output = match slot {
                LayoutSlot::FromParticipant(i) => resolved[*i].output.as_ref().unwrap(),
                LayoutSlot::FromExtra(j) => &reveal.extra_outputs[*j],
            };
            matches!(output, RevealOutput::Change { .. })
        })
        .count();
    if change_count > 1 {
        return Err(anyhow!(
            "at most one Change output allowed (got {})",
            change_count
        ));
    }

    // Resolve every output's script + value in layout order. Shared
    // with `estimate_reveal_vbytes` so the commit's sizing reflects the
    // same outputs the reveal will actually emit — script construction
    // lives in `plan_resolved_outputs` only, never duplicated.
    let resolved_outputs = plan_resolved_outputs(&reveal, &layout)?;

    // Total input value (used to resolve Change later)
    let total_input_value: u64 = resolved
        .iter()
        .map(|p| p.prevout.value.to_sat())
        .sum::<u64>()
        .saturating_add(
            reveal
                .extra_inputs
                .iter()
                .map(|e| e.prevout.value.to_sat())
                .sum::<u64>(),
        );

    // Sum of non-Change output values (Fixed + ChainedEnvelope + OpReturn[0]).
    let total_fixed_value = total_fixed_output_value(&reveal);

    // Build PSBT inputs (participants first, then extra_inputs)
    let mut psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    // Populate participant inputs with the standard taproot PSBT
    // fields: `tap_internal_key` identifies the signer, `tap_scripts`
    // (PSBT_IN_TAP_LEAF_SCRIPT, BIP 371) carries the leaf script the
    // SDK script-spends through. With both populated, wallets that
    // speak taproot PSBT can sign without any client-side fixup.
    for rp in &resolved {
        psbt.unsigned_tx.input.push(TxIn {
            previous_output: rp.outpoint,
            ..Default::default()
        });
        let control_block = ControlBlock::decode(rp.tap_leaf_script.control_block.as_bytes())
            .map_err(|e| anyhow!("invalid control block: {}", e))?;
        let mut tap_scripts = std::collections::BTreeMap::new();
        tap_scripts.insert(
            control_block,
            (
                rp.tap_leaf_script.script.clone(),
                rp.tap_leaf_script.leaf_version,
            ),
        );
        psbt.inputs.push(bitcoin::psbt::Input {
            witness_utxo: Some(rp.prevout.clone()),
            tap_internal_key: Some(rp.x_only_public_key),
            tap_scripts,
            ..Default::default()
        });
    }
    // Extra inputs are key-path P2TR spends. By convention they belong
    // to participant 0 (the call's primary actor) — `tap_internal_key`
    // gets that key so the wallet knows what to sign without the SDK
    // having to inject it client-side.
    let extra_internal_key = resolved.first().map(|rp| rp.x_only_public_key);
    for extra in &reveal.extra_inputs {
        psbt.unsigned_tx.input.push(TxIn {
            previous_output: extra.outpoint,
            ..Default::default()
        });
        psbt.inputs.push(bitcoin::psbt::Input {
            witness_utxo: Some(extra.prevout.clone()),
            tap_internal_key: extra_internal_key,
            ..Default::default()
        });
    }

    // Compute fee from a tx populated with all outputs + witness placeholders.
    // Outputs use real values for Fixed/ChainedEnvelope/OpReturn; Change is
    // placeholder for sizing only. Witnesses: participants are script-spend
    // (sig + script + control block); extras are key-path (sig only).
    let mut dummy_tx = psbt.unsigned_tx.clone();
    for (i, rp) in resolved.iter().enumerate() {
        dummy_tx.input[i].witness = placeholder_tap_script_witness(
            rp.tap_leaf_script.script.as_bytes(),
            rp.tap_leaf_script.control_block.as_bytes(),
        );
    }
    for i in 0..reveal.extra_inputs.len() {
        let idx = resolved.len() + i;
        dummy_tx.input[idx].witness = placeholder_key_spend_witness();
    }
    for output in &resolved_outputs {
        push_resolved_output_to_dummy(&mut dummy_tx, output);
    }
    let tx_vsize = dummy_tx.vsize() as u64;
    let fee = fee_rate
        .fee_vb(tx_vsize)
        .ok_or_else(|| anyhow!("fee calculation overflow"))?
        .to_sat();

    // Resolve Change values. At most one Change in the layout (validated above).
    let total_needed_no_change: u64 = total_fixed_value.saturating_add(fee);
    if total_input_value < total_needed_no_change {
        return Err(anyhow!(
            "insufficient input value: have {} sats, need {} (fixed outputs {} + fee {})",
            total_input_value,
            total_needed_no_change,
            total_fixed_value,
            fee
        ));
    }
    let change_value = total_input_value - total_needed_no_change;

    // Add outputs to the PSBT and build the parallel `output_info` Vec
    // describing each output's kind (Fixed/Change/ChainedEnvelope/OpReturn).
    //
    // Change handling — only silent-drop sub-dust if doing so can't
    // invalidate a participant's signature:
    //   - value >= dust: always materialize, regardless of position.
    //   - value < dust AND Change is the very last output AND either
    //     (a) there's exactly one participant — they sign after compose
    //         returns, so they bind to the post-drop layout, OR
    //     (b) Change sits past every participant index — no participant's
    //         input commits (under any sighash) to this position, so
    //         the drop is positionally invisible.
    //   - value < dust anywhere else: hard error. A drop in a multi-
    //     participant tx at or before the participant region risks
    //     invalidating a participant's pre-signed SACP witness (output
    //     at their index disappears or shifts).
    let n_participants = reveal.participants.len();
    let mut output_info: Vec<RevealOutputInfo> = Vec::with_capacity(resolved_outputs.len());
    let last_idx = resolved_outputs.len().saturating_sub(1);
    for (idx, ro) in resolved_outputs.into_iter().enumerate() {
        match ro {
            ResolvedOutputValue::Fixed { value, script } => {
                psbt.unsigned_tx.output.push(TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: script,
                });
                psbt.outputs.push(bitcoin::psbt::Output::default());
                output_info.push(RevealOutputInfo::Fixed { value });
            }
            ResolvedOutputValue::ChainedEnvelope {
                value,
                script,
                tap_leaf_script,
            } => {
                psbt.unsigned_tx.output.push(TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: script,
                });
                psbt.outputs.push(bitcoin::psbt::Output::default());
                output_info.push(RevealOutputInfo::ChainedEnvelope {
                    value,
                    tap_leaf_script,
                });
            }
            ResolvedOutputValue::Change { script } => {
                let is_last = idx == last_idx;
                let droppable = is_last && (n_participants <= 1 || idx >= n_participants);
                if change_value < MIN_ENVELOPE_SATS && !droppable {
                    return Err(anyhow!(
                        "Change at position {} would be sub-dust ({} sats < {} dust floor); silently dropping in a {}-participant tx could invalidate a participant's pre-signed witness — raise input value, place Change last past all participants, or use Fixed",
                        idx,
                        change_value,
                        MIN_ENVELOPE_SATS,
                        n_participants,
                    ));
                }
                if change_value >= MIN_ENVELOPE_SATS {
                    psbt.unsigned_tx.output.push(TxOut {
                        value: Amount::from_sat(change_value),
                        script_pubkey: script,
                    });
                    psbt.outputs.push(bitcoin::psbt::Output::default());
                    output_info.push(RevealOutputInfo::Change {
                        value: change_value,
                    });
                }
                // else: sub-dust Change at a position where dropping is
                // safe — silent drop to fee.
            }
            ResolvedOutputValue::OpReturn { script } => {
                psbt.unsigned_tx.output.push(TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: script,
                });
                psbt.outputs.push(bitcoin::psbt::Output::default());
                output_info.push(RevealOutputInfo::OpReturn);
            }
        }
    }

    // If there are no outputs (rare — e.g., all-None participants and
    // empty extras), Bitcoin would reject the tx. Emit a minimal empty
    // OP_RETURN so the tx is structurally valid. Push a matching
    // `output_info` entry so its invariant — same length as
    // `transaction.output` — is preserved.
    if psbt.unsigned_tx.output.is_empty() {
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: empty_op_return_script(),
        });
        psbt.outputs.push(bitcoin::psbt::Output::default());
        output_info.push(RevealOutputInfo::OpReturn);
    }

    let reveal_transaction = psbt.unsigned_tx.clone();
    let reveal_txid = reveal_transaction.compute_txid().to_string();
    let reveal_transaction_hex = hex::encode(serialize_tx(&reveal_transaction));
    let psbt_hex = psbt.serialize_hex();

    Ok(RevealOutputs::builder()
        .transaction(reveal_transaction)
        .transaction_hex(reveal_transaction_hex)
        .psbt_hex(psbt_hex)
        .txid(reveal_txid)
        .output_info(output_info)
        .build())
}

/// Parse a hex-encoded scriptPubKey into a `ScriptBuf`.
fn parse_hex_script(hex_str: &str) -> Result<ScriptBuf> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow!("invalid hex in script_pubkey: {}", e))?;
    Ok(ScriptBuf::from_bytes(bytes))
}

/// A `RevealParticipant` resolved to the data both `compose_reveal`
/// (real PSBT build) and the dummy-tx sizing path need: parsed key,
/// the outpoint/prevout pulled out of `CommitSource::Existing`, the
/// tap leaf script + control block, and the participant's paired
/// output (if any). All compose_reveal participants are Existing —
/// `participant_tap_data` does the parsing + size validation.
struct ResolvedParticipant {
    x_only_public_key: XOnlyPublicKey,
    outpoint: OutPoint,
    prevout: TxOut,
    tap_leaf_script: TapLeafScript,
    output: Option<RevealOutput>,
}

/// Parse + size-validate a participant's tap-leaf data. Returns the
/// parsed x-only key, the leaf script, and its control block — the
/// inputs both `compose_reveal` (for real PSBT inputs + witness
/// placeholders) and `estimate_reveal_vbytes` (for witness
/// placeholders only) need. Single source of truth, so adding a new
/// per-participant validation can't silently miss either path.
fn participant_tap_data(
    p: &RevealParticipant,
) -> Result<(XOnlyPublicKey, ScriptBuf, ControlBlock)> {
    let x_only_pk = XOnlyPublicKey::from_str(&p.x_only_public_key)
        .map_err(|e| anyhow!("invalid x_only_public_key: {}", e))?;
    let insts_bytes =
        serialize(&p.commit_insts).map_err(|e| anyhow!("failed to serialize insts: {}", e))?;
    if insts_bytes.is_empty() || insts_bytes.len() > MAX_SCRIPT_BYTES {
        return Err(anyhow!("leaf script data size invalid"));
    }
    let (script, _, control_block) = build_tap_script_and_script_address(x_only_pk, insts_bytes)?;
    Ok((x_only_pk, script, control_block))
}

/// Placeholder witness for a tap-leaf script-spend input — 64-byte
/// Schnorr signature + leaf script + control block. Used for vbyte
/// sizing only; the real witness is built at signing time.
fn placeholder_tap_script_witness(script_bytes: &[u8], control_block_bytes: &[u8]) -> Witness {
    let mut w = Witness::new();
    w.push(vec![0u8; SCHNORR_SIGNATURE_SIZE]);
    w.push(script_bytes);
    w.push(control_block_bytes);
    w
}

/// Placeholder witness for a key-path (BIP-86) spend — single 64-byte
/// Schnorr signature.
fn placeholder_key_spend_witness() -> Witness {
    let mut w = Witness::new();
    w.push(vec![0u8; SCHNORR_SIGNATURE_SIZE]);
    w
}

/// Sum of every non-Change, non-OpReturn output value in `reveal` —
/// the part of the tx's output sum that's caller-fixed (Fixed +
/// ChainedEnvelope). Change is computed by the indexer; OpReturn
/// carries 0 sats. Shared between `compose_reveal` (resolving the
/// `change_value = inputs − fixed − fee` equation) and
/// `compose_commit` (sizing the Build tap output that covers the
/// reveal's fixed outputs + fee).
fn total_fixed_output_value(reveal: &Reveal) -> u64 {
    let value_of = |o: &RevealOutput| -> u64 {
        match o {
            RevealOutput::Fixed { value, .. } => *value,
            RevealOutput::ChainedEnvelope { value, .. } => *value,
            RevealOutput::Change { .. } | RevealOutput::OpReturn { .. } => 0,
        }
    };
    reveal
        .participants
        .iter()
        .filter_map(|p| p.output.as_ref().map(value_of))
        .sum::<u64>()
        .saturating_add(reveal.extra_outputs.iter().map(value_of).sum::<u64>())
}

/// Where each tx output comes from — pinned to a participant's paired
/// `output` (placed at that participant's input index for SACP
/// alignment) or pulled from `extra_outputs` (filling a participant
/// slot with `None`, or appended after the participant region).
enum LayoutSlot {
    FromParticipant(usize),
    FromExtra(usize),
}

/// Compute the reveal's output layout — positions 0..N where
/// N = max participant index with a `Some` output. Each participant
/// with `Some` goes at its own input index; `None` slots are filled
/// by `extra_outputs` in order; any remaining extras append at the
/// end. Shared by `compose_reveal` (the real build) and
/// `estimate_reveal_vbytes` (the commit's fee-sizing dummy build) so
/// the two never diverge — divergence would silently underfund the
/// commit's tap output.
fn compute_output_layout(reveal: &Reveal) -> Result<Vec<LayoutSlot>> {
    let max_paired_idx = reveal
        .participants
        .iter()
        .enumerate()
        .rev()
        .find(|(_, p)| p.output.is_some())
        .map(|(i, _)| i);
    let mut layout: Vec<LayoutSlot> = Vec::new();
    let mut extras_cursor = 0usize;
    if let Some(max_idx) = max_paired_idx {
        for (i, p) in reveal.participants.iter().enumerate().take(max_idx + 1) {
            if p.output.is_some() {
                layout.push(LayoutSlot::FromParticipant(i));
            } else {
                if extras_cursor >= reveal.extra_outputs.len() {
                    return Err(anyhow!(
                        "participant {} has no paired output but no extra_output available to fill its slot",
                        i
                    ));
                }
                layout.push(LayoutSlot::FromExtra(extras_cursor));
                extras_cursor += 1;
            }
        }
    }
    while extras_cursor < reveal.extra_outputs.len() {
        layout.push(LayoutSlot::FromExtra(extras_cursor));
        extras_cursor += 1;
    }
    Ok(layout)
}

/// Each output slot resolved to its final script + value, with all
/// script construction (hex-parsing, tap-tree building, OP_RETURN
/// wrapping) and per-variant size validation done up front. `Change`
/// carries no value — that's resolved by the caller once the total
/// fee is known. Single source of truth shared by `compose_reveal`
/// (the real build) and `estimate_reveal_vbytes` (the commit's
/// sizing dummy) so adding a new `RevealOutput` variant or tweaking
/// script shape can't silently desync the two paths.
enum ResolvedOutputValue {
    Fixed {
        script: ScriptBuf,
        value: u64,
    },
    Change {
        script: ScriptBuf,
    },
    ChainedEnvelope {
        script: ScriptBuf,
        value: u64,
        tap_leaf_script: TapLeafScript,
    },
    OpReturn {
        script: ScriptBuf,
    },
}

/// Resolve every output in `reveal` into its final shape, in layout
/// order. Takes the precomputed `layout` (rather than computing it
/// internally) so callers that also need the raw layout for other
/// checks don't pay the cost twice. See `ResolvedOutputValue` for
/// why this lives in one place.
fn plan_resolved_outputs(
    reveal: &Reveal,
    layout: &[LayoutSlot],
) -> Result<Vec<ResolvedOutputValue>> {
    let mut resolved_outputs = Vec::with_capacity(layout.len());
    for slot in layout {
        let output = match slot {
            LayoutSlot::FromParticipant(i) => reveal.participants[*i]
                .output
                .as_ref()
                .expect("participant slot has Some output"),
            LayoutSlot::FromExtra(j) => &reveal.extra_outputs[*j],
        };
        let resolved = match output {
            RevealOutput::Fixed {
                script_pubkey,
                value,
            } => {
                let script = parse_hex_script(script_pubkey)?;
                ResolvedOutputValue::Fixed {
                    script,
                    value: *value,
                }
            }
            RevealOutput::Change { script_pubkey } => {
                let script = parse_hex_script(script_pubkey)?;
                ResolvedOutputValue::Change { script }
            }
            RevealOutput::ChainedEnvelope {
                insts,
                value,
                internal_key,
            } => {
                let internal_pk = XOnlyPublicKey::from_str(internal_key)?;
                let insts_bytes = serialize(insts)?;
                if insts_bytes.is_empty() || insts_bytes.len() > MAX_SCRIPT_BYTES {
                    return Err(anyhow!("ChainedEnvelope leaf data size invalid"));
                }
                let (script, addr, control_block) =
                    build_tap_script_and_script_address(internal_pk, insts_bytes)?;
                ResolvedOutputValue::ChainedEnvelope {
                    script: addr.script_pubkey(),
                    value: *value,
                    tap_leaf_script: TapLeafScript {
                        leaf_version: LeafVersion::TapScript,
                        script,
                        control_block: ScriptBuf::from_bytes(control_block.serialize()),
                    },
                }
            }
            RevealOutput::OpReturn { data } => {
                if data.len() > MAX_OP_RETURN_BYTES {
                    return Err(anyhow!(
                        "OP_RETURN data exceeds {} bytes",
                        MAX_OP_RETURN_BYTES
                    ));
                }
                let mut s = ScriptBuf::new();
                s.push_opcode(OP_RETURN);
                s.push_slice(PushBytesBuf::try_from(data.clone())?);
                ResolvedOutputValue::OpReturn { script: s }
            }
        };
        resolved_outputs.push(resolved);
    }
    Ok(resolved_outputs)
}

/// Push the dummy `TxOut` for a resolved output onto a vbytes-sizing
/// transaction. `Change` and `OpReturn` use 0 sats as the placeholder
/// value (vsize doesn't depend on it); `Fixed`/`ChainedEnvelope` use
/// their declared value (also irrelevant for vsize, but cheap to be
/// consistent).
fn push_resolved_output_to_dummy(dummy: &mut Transaction, output: &ResolvedOutputValue) {
    let (value, script) = match output {
        ResolvedOutputValue::Fixed { value, script } => (*value, script.clone()),
        ResolvedOutputValue::Change { script } => (0, script.clone()),
        ResolvedOutputValue::ChainedEnvelope { value, script, .. } => (*value, script.clone()),
        ResolvedOutputValue::OpReturn { script } => (0, script.clone()),
    };
    dummy.output.push(TxOut {
        value: Amount::from_sat(value),
        script_pubkey: script,
    });
}

/// Estimate the vbytes of the reveal tx built from `reveal`. Builds a
/// dummy tx with placeholder witnesses (Schnorr sig + script + control
/// block for tap-leaf participants; Schnorr sig for key-path extras).
/// Used by both `compose_commit` (to size Build tap outputs) and
/// `compose_reveal` (to compute the actual reveal fee).
fn estimate_reveal_vbytes(reveal: &Reveal) -> Result<u64> {
    let mut dummy = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Participants — tap-leaf script-spend inputs
    for p in &reveal.participants {
        let (_, script, control_block) = participant_tap_data(p)?;
        let txin = TxIn {
            witness: placeholder_tap_script_witness(script.as_bytes(), &control_block.serialize()),
            ..Default::default()
        };
        dummy.input.push(txin);
    }

    // Extra inputs — key-path spends
    for _ in &reveal.extra_inputs {
        let txin = TxIn {
            witness: placeholder_key_spend_witness(),
            ..Default::default()
        };
        dummy.input.push(txin);
    }

    // Outputs — defer to the shared resolver that compose_reveal also
    // uses, so per-variant script construction lives in one place and
    // sizing matches the reveal's actual output set.
    let layout = compute_output_layout(reveal)?;
    let plan = plan_resolved_outputs(reveal, &layout)?;
    for output in &plan {
        push_resolved_output_to_dummy(&mut dummy, output);
    }
    // Mirror compose_reveal's fallback: if the dummy ends up with zero
    // outputs (here only via an all-Nones/no-extras layout — estimate
    // doesn't drop sub-dust Change), add the same fallback OP_RETURN so
    // the commit's tap output is sized for a structurally valid reveal.
    // Uses `output.is_empty()` to match compose_reveal's wording exactly,
    // so a future change to either drop-logic stays in sync.
    if dummy.output.is_empty() {
        dummy.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: empty_op_return_script(),
        });
    }

    Ok(dummy.vsize() as u64)
}

/// `OP_RETURN <4 zero bytes>` — a minimal standard `nulldata` output
/// used as a structural-validity filler when a reveal would otherwise
/// have zero outputs (Bitcoin rejects 0-output txs). Carries no Kontor
/// semantics.
///
/// The 4-byte payload is sized to clear Bitcoin's
/// `MIN_STANDARD_TX_NONWITNESS_SIZE = 65` floor. A 1-input/1-output tx's
/// base (witness-stripped) size is `60 + scriptPubKey_len`; an empty
/// OP_RETURN script (`6a 00`) gives 62 bytes total and would be rejected
/// as `tx-size-small`. 4 bytes pushes the script to 6 bytes and the tx
/// to 66 bytes — one byte of margin past the floor.
fn empty_op_return_script() -> ScriptBuf {
    let mut s = ScriptBuf::new();
    s.push_opcode(OP_RETURN);
    s.push_slice(b"\0\0\0\0");
    s
}

/// Build commit transactions for each `CommitSource::Build` participant
/// in `reveal`. Each Build participant gets its own standalone commit
/// tx (separate funding, separate change). The Build's tap output value
/// is sized so the entire future reveal can be funded: each Build pays
/// an equal share of `(total_fixed_outputs + reveal_fee − existing_input_contributions)`.
///
/// Returns the built commit txs plus the input `Reveal` with each Build
/// participant converted to `Existing` (outpoint/prevout filled in).
/// Caller signs + broadcasts the commits, then later passes the returned
/// `reveal` to `compose_reveal` to build the reveal PSBT.
pub async fn compose_commit(
    reveal: Reveal,
    network: bitcoin::Network,
    bitcoin_client: &Client,
) -> Result<indexer_types::CommitOutputs> {
    if reveal.participants.is_empty() {
        return Err(anyhow!("Reveal must have at least one participant"));
    }
    if reveal.participants.len() > MAX_PARTICIPANTS {
        return Err(anyhow!("Too many participants (max {})", MAX_PARTICIPANTS));
    }

    let sat_per_vbyte = reveal
        .sat_per_vbyte
        .ok_or_else(|| anyhow!("sat_per_vbyte required"))?;
    if sat_per_vbyte == 0 {
        return Err(anyhow!("Invalid fee rate"));
    }
    let fee_rate =
        FeeRate::from_sat_per_vb(sat_per_vbyte).ok_or_else(|| anyhow!("Invalid fee rate"))?;

    // Find Build participants
    let build_indices: Vec<usize> = reveal
        .participants
        .iter()
        .enumerate()
        .filter_map(|(i, p)| matches!(p.commit_source, CommitSource::Build { .. }).then_some(i))
        .collect();
    if build_indices.is_empty() {
        return Err(anyhow!(
            "compose_commit requires at least one Build participant"
        ));
    }

    // Reject duplicate funding outpoints — within a single Build
    // participant's funding list, or across multiple Build participants.
    // Two inputs spending the same outpoint would make the commit tx
    // double-spend its own input.
    let mut global_funding: HashSet<&String> = HashSet::new();
    for &build_idx in &build_indices {
        if let CommitSource::Build {
            funding_utxo_ids, ..
        } = &reveal.participants[build_idx].commit_source
        {
            let mut local_funding: HashSet<&String> = HashSet::new();
            for op in funding_utxo_ids {
                if !local_funding.insert(op) {
                    return Err(anyhow!(
                        "duplicate funding outpoint provided for participant"
                    ));
                }
                if !global_funding.insert(op) {
                    return Err(anyhow!(
                        "duplicate funding outpoint provided across participants"
                    ));
                }
            }
        }
    }

    // Estimate future reveal fee
    let reveal_vbytes = estimate_reveal_vbytes(&reveal)?;
    let reveal_fee = fee_rate
        .fee_vb(reveal_vbytes)
        .ok_or_else(|| anyhow!("reveal fee overflow"))?
        .to_sat();

    // Sum non-Change output values from the future reveal.
    let total_fixed_outputs = total_fixed_output_value(&reveal);

    // Existing participants' prevouts + extra_inputs' prevouts contribute
    // value to the reveal already; Build participants must collectively
    // cover the remainder.
    let existing_contribution: u64 = reveal
        .participants
        .iter()
        .filter_map(|p| match &p.commit_source {
            CommitSource::Existing { prevout, .. } => Some(prevout.value.to_sat()),
            _ => None,
        })
        .sum::<u64>()
        .saturating_add(
            reveal
                .extra_inputs
                .iter()
                .map(|e| e.prevout.value.to_sat())
                .sum::<u64>(),
        );

    // If the future reveal has a Change output, leave a dust buffer so
    // the Change actually materializes as a non-dust output rather than
    // getting silently dropped to fee. Also enforce that each Build's
    // tap output value is itself ≥ dust threshold (a tap output below
    // dust would make the commit tx non-standard / non-relayable).
    let has_change = reveal
        .participants
        .iter()
        .any(|p| matches!(p.output, Some(RevealOutput::Change { .. })))
        || reveal
            .extra_outputs
            .iter()
            .any(|o| matches!(o, RevealOutput::Change { .. }));
    let change_buffer = if has_change { MIN_ENVELOPE_SATS } else { 0 };

    let n_builds = build_indices.len() as u64;
    let total_build_contribution = total_fixed_outputs
        .saturating_add(reveal_fee)
        .saturating_add(change_buffer)
        .saturating_sub(existing_contribution)
        .max(n_builds.saturating_mul(MIN_ENVELOPE_SATS));

    // Equal split across Build participants (deterministic remainder allocation)
    let base_share = total_build_contribution / n_builds;
    let remainder = total_build_contribution % n_builds;

    // Standalone commit tx per Build participant
    let mut commits: Vec<indexer_types::CommitTx> = Vec::with_capacity(build_indices.len());
    let mut updated_participants = reveal.participants.clone();

    for (build_order, &build_idx) in build_indices.iter().enumerate() {
        let participant = &reveal.participants[build_idx];
        let (build_addr_str, funding_utxo_ids) = match &participant.commit_source {
            CommitSource::Build {
                address,
                funding_utxo_ids,
            } => (address, funding_utxo_ids),
            _ => unreachable!(),
        };

        let tap_output_value = base_share
            + if (build_order as u64) < remainder {
                1
            } else {
                0
            };

        let build_address = Address::from_str(build_addr_str)?.require_network(network)?;
        match build_address.address_type() {
            Some(AddressType::P2tr) => {}
            _ => return Err(anyhow!("Build participant address must be P2TR")),
        }
        // Size + parse validation already happened in
        // `estimate_reveal_vbytes` above (via `participant_tap_data`),
        // so by here the leaf data is known-good.
        let x_only_pk = XOnlyPublicKey::from_str(&participant.x_only_public_key)?;
        let insts_bytes = serialize(&participant.commit_insts)?;
        let (_, tap_addr, _) = build_tap_script_and_script_address(x_only_pk, insts_bytes)?;

        // Bound the funding list before the RPC — a malformed request
        // with thousands of outpoints shouldn't trigger a bitcoind
        // round-trip to bounce.
        if funding_utxo_ids.len() > MAX_UTXOS_PER_PARTICIPANT {
            return Err(anyhow!(
                "too many utxos for Build participant (max {})",
                MAX_UTXOS_PER_PARTICIPANT
            ));
        }
        let funding_utxos = get_utxos(bitcoin_client, funding_utxo_ids.join(",")).await?;

        // Build an empty commit tx with just the tap output.
        // `Psbt::from_unsigned_tx` already initializes `psbt.outputs`
        // with one default entry per tx output, so the single tap
        // output's PSBT slot exists without an extra push (a stray push
        // here would desync psbt.outputs.len() from tx.output.len() and
        // produce a structurally invalid PSBT).
        let mut psbt = Psbt::from_unsigned_tx(Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(tap_output_value),
                script_pubkey: tap_addr.script_pubkey(),
            }],
        })?;

        // Select UTXOs covering tap output + commit fee. For standalone
        // commits, the full empty-tx header overhead is borne by this
        // single tx (no sharing), so pass the full header fee directly.
        let base_header_fee = empty_tx_header_fee(fee_rate)?;
        let (selected, commit_fee) = select_utxos_for_commit(
            &psbt.unsigned_tx,
            funding_utxos,
            tap_output_value,
            fee_rate,
            MIN_ENVELOPE_SATS,
            base_header_fee,
        )
        .map_err(|e| anyhow!("Build participant {}: {}", build_idx, e))?;

        let selected_sum: u64 = selected.iter().map(|(_, txo)| txo.value.to_sat()).sum();

        for (op, prev) in &selected {
            psbt.unsigned_tx.input.push(TxIn {
                previous_output: *op,
                ..Default::default()
            });
            psbt.inputs.push(bitcoin::psbt::Input {
                witness_utxo: Some(prev.clone()),
                tap_internal_key: Some(x_only_pk),
                ..Default::default()
            });
        }

        // Change to the Build participant's address. Track whether
        // it materialized — when below dust it's silently dropped to
        // fee — so the SDK can decide whether to chain the next
        // submit through this output without parsing the hex.
        let change = selected_sum.saturating_sub(tap_output_value + commit_fee);
        let change_value = if change >= MIN_ENVELOPE_SATS {
            psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: build_address.script_pubkey(),
            });
            psbt.outputs.push(bitcoin::psbt::Output::default());
            Some(change)
        } else {
            None
        };

        let commit_tx = psbt.unsigned_tx.clone();
        let commit_txid = commit_tx.compute_txid();
        let commit_tx_hex = hex::encode(serialize_tx(&commit_tx));
        let commit_psbt_hex = psbt.serialize_hex();

        commits.push(indexer_types::CommitTx {
            transaction: commit_tx,
            transaction_hex: commit_tx_hex,
            psbt_hex: commit_psbt_hex,
            txid: commit_txid.to_string(),
            change_value,
        });

        // Build → Existing transformation
        updated_participants[build_idx].commit_source = CommitSource::Existing {
            outpoint: OutPoint {
                txid: commit_txid,
                vout: 0,
            },
            prevout: TxOut {
                value: Amount::from_sat(tap_output_value),
                script_pubkey: tap_addr.script_pubkey(),
            },
        };
    }

    // Propagate the resolved fee rate (the original may have been
    // `None`, in which case we filled it from `default_sat_per_vbyte`)
    // — `compose_reveal` requires it to be `Some`.
    let updated_reveal = Reveal {
        sat_per_vbyte: Some(sat_per_vbyte),
        participants: updated_participants,
        extra_inputs: reveal.extra_inputs,
        extra_outputs: reveal.extra_outputs,
    };

    Ok(indexer_types::CommitOutputs {
        commits,
        reveal: updated_reveal,
    })
}

/// Combined compose: builds whatever needs building. If any Build
/// participants exist, builds those commits first (via `compose_commit`);
/// then builds the reveal PSBT (via `compose_reveal`) using the
/// resulting all-Existing Reveal.
pub async fn compose(
    reveal: Reveal,
    network: bitcoin::Network,
    bitcoin_client: &Client,
) -> Result<(Vec<indexer_types::CommitTx>, RevealOutputs)> {
    let has_build = reveal
        .participants
        .iter()
        .any(|p| matches!(p.commit_source, CommitSource::Build { .. }));

    let (commits, reveal_to_build) = if has_build {
        let commit_outputs = compose_commit(reveal, network, bitcoin_client).await?;
        (commit_outputs.commits, commit_outputs.reveal)
    } else {
        (Vec::new(), reveal)
    };

    let reveal_outputs = compose_reveal(reveal_to_build)?;
    Ok((commits, reveal_outputs))
}

// ============================================================================

pub fn build_tap_script_and_script_address(
    x_only_public_key: XOnlyPublicKey,
    data: Vec<u8>,
) -> Result<(ScriptBuf, Address, ControlBlock)> {
    let secp = Secp256k1::new();

    let mut builder = Builder::new()
        .push_slice(x_only_public_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(PROTOCOL_TAG)
        .push_opcode(OP_0);

    const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

    if data.is_empty() {
        return Err(anyhow!("script data cannot be empty"));
    }

    for chunk in data.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
        builder = builder.push_slice(PushBytesBuf::try_from(chunk.to_vec())?);
    }

    let tap_script = builder.push_opcode(OP_ENDIF).into_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, x_only_public_key)
        .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;

    let output_key = taproot_spend_info.output_key();
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    let control_block = taproot_spend_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .ok_or(anyhow!("failed to create control block"))?;

    Ok((tap_script, script_spendable_address, control_block))
}

// ============================================================================
// Fee Estimation
// ============================================================================

/// Fee for the empty-tx header overhead (version + tx-in/out counts +
/// locktime — about 11 vbytes). Per-participant delta-based fee
/// accounting (`estimate_participant_commit_fees`) only charges each
/// participant for the marginal vbytes they add, so the header is
/// never billed otherwise — this covers it.
pub fn empty_tx_header_fee(fee_rate: FeeRate) -> Result<u64> {
    let empty_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    fee_rate
        .fee_vb(empty_tx.vsize() as u64)
        .ok_or(anyhow!("fee calculation overflow"))
        .map(|a| a.to_sat())
}

/// Select UTXOs to fund a Build participant's commit tx. Picks UTXOs
/// greedily until they cover `script_spend_output_value + commit_fee +
/// envelope (dust buffer for change)`, where `commit_fee` is sized from
/// the actual vsize delta the selected inputs + change output would add
/// to `current_tx`. Returns `(selected_utxos, participant_fee)` or
/// errors with "Insufficient funds" if the pool can't cover it.
pub fn select_utxos_for_commit(
    current_tx: &Transaction,
    utxos: Vec<(OutPoint, TxOut)>,
    script_spend_output_value: u64,
    fee_rate: FeeRate,
    envelope: u64,
    base_header_fee_per_participant: u64,
) -> Result<(Vec<(OutPoint, TxOut)>, u64)> {
    if utxos.is_empty() {
        return Err(anyhow!("no UTXOs provided"));
    }

    let mut selected: Vec<(OutPoint, TxOut)> = Vec::new();
    let mut selected_sum: u64 = 0;
    let mut last_required: u64 = 0;

    for (outpoint, txout) in utxos {
        selected_sum += txout.value.to_sat();
        selected.push((outpoint, txout));

        // Estimate fees with and without change output, then add this
        // participant's share of the empty-tx header overhead.
        let (fee_with_change, fee_no_change) =
            estimate_participant_commit_fees(current_tx, &selected, fee_rate)?;
        let fee_with_change = fee_with_change + base_header_fee_per_participant;
        let fee_no_change = fee_no_change + base_header_fee_per_participant;

        // Check if we can afford script output + fee + dust-threshold change
        let required_with_change = script_spend_output_value
            .saturating_add(fee_with_change)
            .saturating_add(envelope);

        if selected_sum >= required_with_change {
            // Change will be >= envelope, so use fee that accounts for change output
            return Ok((selected, fee_with_change));
        }

        // Check if we can afford script output + fee (no change scenario)
        let required_no_change = script_spend_output_value.saturating_add(fee_no_change);

        if selected_sum >= required_no_change {
            // Calculate what change would actually be if we used fee_no_change
            let change = selected_sum - required_no_change;

            if change < envelope {
                // Change is sub-dust and won't be added - fee_no_change is correct
                return Ok((selected, fee_no_change));
            }
            // Edge case: change >= envelope but we can't afford fee_with_change.
            // Using fee_no_change would be wrong because a change output WILL be added.
            // Continue selecting more UTXOs until we can afford fee_with_change.
        }

        last_required = required_with_change;
    }

    Err(anyhow!(
        "Insufficient funds: have {} sats, need {} sats",
        selected_sum,
        last_required
    ))
}

/// Estimate commit fees for a participant with and without change output.
///
/// Builds temporary transactions to measure the exact vsize delta this
/// participant adds to the commit transaction.
///
/// Returns (fee_with_change, fee_without_change).
pub fn estimate_participant_commit_fees(
    base_tx: &Transaction,
    selected_utxos: &[(OutPoint, TxOut)],
    fee_rate: FeeRate,
) -> Result<(u64, u64)> {
    let base_vb = base_tx.vsize() as u64;

    // Build temp tx with this participant's inputs (with dummy witnesses) and outputs
    let mut temp_tx = base_tx.clone();

    for (outpoint, _) in selected_utxos.iter() {
        let mut txin = TxIn {
            previous_output: *outpoint,
            ..Default::default()
        };
        // Add dummy key-spend witness (64-byte Schnorr signature)
        let mut w = Witness::new();
        w.push(vec![0u8; SCHNORR_SIGNATURE_SIZE]);
        txin.witness = w;
        temp_tx.input.push(txin);
    }

    // Re-add a placeholder for the tap output that's already in
    // `base_tx`. This is NOT double-counting: the delta is
    // `temp_vb − base_vb`, which would otherwise subtract the tap
    // output's vbytes (they sit in base_vb), leaving the fee short
    // by ~34 vbytes per Build. The placeholder restores those bytes
    // in temp_vb so the subtraction nets out and the participant
    // pays for their own tap output. Empty `base_tx` callers (the
    // unit tests) end up counting an extra 34 vbytes, but they
    // assert the delta range, not exact values.
    temp_tx.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(vec![0u8; P2TR_OUTPUT_SIZE]),
    });

    // Add change output
    temp_tx.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(vec![0u8; P2TR_OUTPUT_SIZE]),
    });

    let vb_with_change = temp_tx.vsize() as u64;
    let delta_with_change = vb_with_change.saturating_sub(base_vb);
    let fee_with_change = fee_rate
        .fee_vb(delta_with_change)
        .ok_or(anyhow!("fee calculation overflow"))?
        .to_sat();

    // Remove change output and recalculate
    temp_tx.output.pop();
    let vb_no_change = temp_tx.vsize() as u64;
    let delta_no_change = vb_no_change.saturating_sub(base_vb);
    let fee_no_change = fee_rate
        .fee_vb(delta_no_change)
        .ok_or(anyhow!("fee calculation overflow"))?
        .to_sat();

    Ok((fee_with_change, fee_no_change))
}

async fn get_utxos(bitcoin_client: &Client, utxo_ids: String) -> Result<Vec<(OutPoint, TxOut)>> {
    let outpoints: Vec<OutPoint> = utxo_ids
        .split(',')
        .filter_map(|s| {
            let parts = s.split(':').collect::<Vec<&str>>();
            if parts.len() == 2 {
                let txid = Txid::from_str(parts[0]).ok()?;
                let vout = u32::from_str(parts[1]).ok()?;
                Some(OutPoint::new(txid, vout))
            } else {
                None
            }
        })
        .collect();

    let txids: Vec<Txid> = outpoints.iter().map(|op| op.txid).collect();
    let results = bitcoin_client
        .get_raw_transactions(txids.as_slice())
        .await
        .map_err(|e| anyhow!("Failed to fetch transactions: {}", e))?;
    if results.is_empty() {
        return Err(anyhow!("No funding transactions found"));
    }

    if results.len() != outpoints.len() {
        return Err(anyhow!(
            "RPC returned mismatched number of transactions (expected {}, got {})",
            outpoints.len(),
            results.len()
        ));
    }

    let mut funding_utxos: Vec<(OutPoint, TxOut)> = Vec::with_capacity(outpoints.len());
    for (outpoint, res) in outpoints.into_iter().zip(results) {
        let tx =
            res.map_err(|e| anyhow!("Failed to fetch transaction {}: {}", outpoint.txid, e))?;
        let maybe_prevout = tx.output.get(outpoint.vout as usize).cloned();
        match maybe_prevout {
            Some(prevout) => funding_utxos.push((outpoint, prevout)),
            None => {
                return Err(anyhow!(
                    "vout {} out of bounds for tx {}",
                    outpoint.vout,
                    outpoint.txid
                ));
            }
        }
    }

    Ok(funding_utxos)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use bitcoin::key::{Keypair, Secp256k1, XOnlyPublicKey, rand};
    use bitcoin::opcodes::all::OP_ENDIF;
    use bitcoin::script::Instruction;
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use tracing::info;

    use super::build_tap_script_and_script_address;

    fn generate_test_key() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());
        keypair.x_only_public_key().0
    }

    fn verify_control_block(
        key: XOnlyPublicKey,
        script: &bitcoin::ScriptBuf,
        control_block: &bitcoin::taproot::ControlBlock,
    ) {
        let secp = Secp256k1::new();
        let tap_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .expect("add leaf")
            .finalize(&secp, key)
            .expect("finalize taproot");
        let expected_cb = tap_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("derive control block");
        assert_eq!(
            control_block.serialize(),
            expected_cb.serialize(),
            "Control block should match independently derived one"
        );
        assert_eq!(control_block.leaf_version, LeafVersion::TapScript);
        let cb_bytes = control_block.serialize();
        assert!(cb_bytes.len() >= 33);
    }

    #[test]
    fn test_build_tap_script_and_script_address_empty() {
        let key = generate_test_key();
        let result = build_tap_script_and_script_address(key, vec![]);
        assert!(result.is_err(), "Data cannot be empty");
    }

    #[test]
    fn test_build_tap_script_and_script_address_519_bytes() -> Result<()> {
        let key = generate_test_key();
        let data = vec![0xFF; 519];
        let (script, _, control_block) = build_tap_script_and_script_address(key, data)?;
        verify_control_block(key, &script, &control_block);
        let instructions: Vec<_> = script.instructions().collect::<Result<Vec<_>, _>>()?;
        assert_eq!(instructions.len(), 8);
        let push_bytes: Vec<_> = instructions.into_iter().skip(6).collect();
        if let [Instruction::PushBytes(data), Instruction::Op(op)] = push_bytes.as_slice() {
            assert_eq!(data.len(), 519);
            assert_eq!(*op, OP_ENDIF);
        } else {
            panic!("Script structure doesn't match expected pattern");
        }
        Ok(())
    }

    #[test]
    fn test_build_tap_script_and_script_address_520_bytes() -> Result<()> {
        let key = generate_test_key();
        let data = vec![0xFF; 520];
        let (script, _, control_block) = build_tap_script_and_script_address(key, data)?;
        verify_control_block(key, &script, &control_block);
        let instructions: Vec<_> = script.instructions().collect::<Result<Vec<_>, _>>()?;
        assert_eq!(instructions.len(), 8);
        let push_bytes: Vec<_> = instructions.into_iter().skip(6).collect();
        if let [Instruction::PushBytes(data), Instruction::Op(op)] = push_bytes.as_slice() {
            assert_eq!(data.len(), 520);
            assert_eq!(*op, OP_ENDIF);
        } else {
            panic!("Script structure doesn't match expected pattern");
        }
        Ok(())
    }

    #[test]
    fn test_build_tap_script_and_script_address_521_bytes() -> Result<()> {
        let key = generate_test_key();
        let data = vec![0xFF; 521];
        let (script, _, control_block) = build_tap_script_and_script_address(key, data)?;
        verify_control_block(key, &script, &control_block);
        let instructions: Vec<_> = script.instructions().collect::<Result<Vec<_>, _>>()?;
        assert_eq!(instructions.len(), 9);
        let push_bytes: Vec<_> = instructions.into_iter().skip(6).collect();
        if let [
            Instruction::PushBytes(d1),
            Instruction::PushBytes(d2),
            Instruction::Op(op),
        ] = push_bytes.as_slice()
        {
            assert_eq!(d1.len(), 520);
            assert_eq!(d2.len(), 1);
            assert_eq!(*op, OP_ENDIF);
        } else {
            panic!("Script structure doesn't match expected pattern");
        }
        Ok(())
    }

    #[test]
    fn test_build_tap_script_and_script_address_small_chunking() -> Result<()> {
        let key = generate_test_key();
        let data = vec![0xFF; 1000];
        let (script, _, control_block) = build_tap_script_and_script_address(key, data)?;
        verify_control_block(key, &script, &control_block);
        let instructions: Vec<_> = script.instructions().collect::<Result<Vec<_>, _>>()?;
        assert_eq!(instructions.len(), 9);
        let push_bytes: Vec<_> = instructions.into_iter().skip(6).collect();
        if let [
            Instruction::PushBytes(d1),
            Instruction::PushBytes(d2),
            Instruction::Op(op),
        ] = push_bytes.as_slice()
        {
            assert_eq!(d1.len(), 520);
            assert_eq!(d2.len(), 480);
            assert_eq!(*op, OP_ENDIF);
        } else {
            panic!("Script structure doesn't match expected pattern");
        }
        Ok(())
    }

    #[test]
    fn test_build_tap_script_and_script_address_large_chunking() -> Result<()> {
        let key = generate_test_key();
        let data = vec![0xFF; 2700];
        let (script, _, control_block) = build_tap_script_and_script_address(key, data)?;
        verify_control_block(key, &script, &control_block);
        let instructions: Vec<_> = script.instructions().collect::<Result<Vec<_>, _>>()?;
        assert_eq!(instructions.len(), 13);
        let push_bytes: Vec<_> = instructions.into_iter().skip(6).collect();
        if let [
            Instruction::PushBytes(d1),
            Instruction::PushBytes(d2),
            Instruction::PushBytes(d3),
            Instruction::PushBytes(d4),
            Instruction::PushBytes(d5),
            Instruction::PushBytes(d6),
            _,
        ] = push_bytes.as_slice()
        {
            assert_eq!(d1.len(), 520);
            assert_eq!(d2.len(), 520);
            assert_eq!(d3.len(), 520);
            assert_eq!(d4.len(), 520);
            assert_eq!(d5.len(), 520);
            assert_eq!(d6.len(), 100);
        } else {
            panic!("Script structure doesn't match expected pattern");
        }
        Ok(())
    }

    #[test]
    fn test_build_tap_script_progressive_size_limit() -> Result<()> {
        let key = generate_test_key();
        crate::logging::setup();

        let mut current_size = 500_000;
        let increment = 100_000;
        let max_size = 5_500_000;

        while current_size <= max_size {
            let data = vec![0xFF; current_size];
            let (script, _, control_block) = build_tap_script_and_script_address(key, data)?;

            let cb_bytes = control_block.serialize();
            assert!(cb_bytes.len() >= 33);
            assert_eq!(control_block.leaf_version, LeafVersion::TapScript);

            let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;
            assert!(instructions.len() > 6);

            let expected_chunks = current_size.div_ceil(520);
            let actual_chunks = instructions.len() - 7;
            info!(
                "expected_chunks: {}, actual_chunks: {}",
                expected_chunks, actual_chunks
            );
            assert_eq!(actual_chunks, expected_chunks);
            assert!(script.len() > current_size);

            current_size += increment;
        }

        assert!(current_size > 5_000_000);
        Ok(())
    }
}
