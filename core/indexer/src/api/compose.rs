use anyhow::{Result, anyhow};
use bitcoin::{
    Address, AddressType, Amount, FeeRate, KnownHrp, OutPoint, Psbt, ScriptBuf, TxOut, Witness,
    absolute::LockTime,
    consensus::encode::{self, serialize as serialize_tx},
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
    CommitSource, Reveal, RevealOutput, RevealOutputInfo, RevealOutputs, TapLeafScript, serialize,
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

    let sat_per_vbyte = reveal
        .sat_per_vbyte
        .ok_or_else(|| anyhow!("sat_per_vbyte required"))?;
    if sat_per_vbyte == 0 {
        return Err(anyhow!("Invalid fee rate"));
    }
    let fee_rate =
        FeeRate::from_sat_per_vb(sat_per_vbyte).ok_or_else(|| anyhow!("Invalid fee rate"))?;

    // All participants must be Existing for compose_reveal — Build is only
    // valid in compose_commit / compose.
    for (i, p) in reveal.participants.iter().enumerate() {
        if !matches!(p.commit_source, CommitSource::Existing { .. }) {
            return Err(anyhow!(
                "compose_reveal: participant {} has CommitSource::Build; use compose() or compose_commit() to build commits",
                i
            ));
        }
    }

    // Resolve each participant's per-input bits: the leaf script, control
    // block, x-only key, outpoint, prevout. Validate the leaf-script data
    // (serialized Insts) is non-empty + within size limits.
    struct ResolvedParticipant {
        x_only_public_key: XOnlyPublicKey,
        outpoint: OutPoint,
        prevout: TxOut,
        tap_leaf_script: TapLeafScript,
        output: Option<RevealOutput>,
    }
    let mut resolved: Vec<ResolvedParticipant> = Vec::with_capacity(reveal.participants.len());
    for (i, p) in reveal.participants.iter().enumerate() {
        let (outpoint, prevout) = match &p.commit_source {
            CommitSource::Existing { outpoint, prevout } => (*outpoint, prevout.clone()),
            CommitSource::Build { .. } => unreachable!(),
        };
        let x_only_public_key = XOnlyPublicKey::from_str(&p.x_only_public_key)
            .map_err(|e| anyhow!("participant {}: invalid x_only_public_key: {}", i, e))?;
        let insts_bytes = serialize(&p.commit_insts)
            .map_err(|e| anyhow!("participant {}: failed to serialize insts: {}", i, e))?;
        if insts_bytes.is_empty() || insts_bytes.len() > MAX_SCRIPT_BYTES {
            return Err(anyhow!("participant {}: leaf script data size invalid", i));
        }
        let (script, _, control_block) =
            build_tap_script_and_script_address(x_only_public_key, insts_bytes)?;
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

    // Pre-compute output script + value (Change values are resolved last).
    // ChainedEnvelope also carries its tap leaf script (built from the
    // committed insts + internal key) — the SDK needs this to script-spend
    // the chained output in a follow-up tx, and we surface it via
    // `RevealOutputs.output_info`.
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
    let mut resolved_outputs: Vec<ResolvedOutputValue> = Vec::with_capacity(layout.len());
    for slot in &layout {
        let output = match slot {
            LayoutSlot::FromParticipant(i) => resolved[*i].output.as_ref().unwrap().clone(),
            LayoutSlot::FromExtra(j) => reveal.extra_outputs[*j].clone(),
        };
        let resolved = match output {
            RevealOutput::Fixed {
                script_pubkey,
                value,
            } => {
                let script = parse_hex_script(&script_pubkey)?;
                ResolvedOutputValue::Fixed { script, value }
            }
            RevealOutput::Change { script_pubkey } => {
                let script = parse_hex_script(&script_pubkey)?;
                ResolvedOutputValue::Change { script }
            }
            RevealOutput::ChainedEnvelope {
                insts,
                value,
                internal_key,
            } => {
                let internal_pk = XOnlyPublicKey::from_str(&internal_key)?;
                let insts_bytes = serialize(&insts)?;
                if insts_bytes.is_empty() || insts_bytes.len() > MAX_SCRIPT_BYTES {
                    return Err(anyhow!("ChainedEnvelope leaf data size invalid"));
                }
                let (script, addr, control_block) =
                    build_tap_script_and_script_address(internal_pk, insts_bytes)?;
                ResolvedOutputValue::ChainedEnvelope {
                    script: addr.script_pubkey(),
                    value,
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
                s.push_slice(PushBytesBuf::try_from(data)?);
                ResolvedOutputValue::OpReturn { script: s }
            }
        };
        resolved_outputs.push(resolved);
    }

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

    // Sum of non-Change output values (Fixed + ChainedEnvelope + OpReturn[0])
    let total_fixed_value: u64 = resolved_outputs
        .iter()
        .map(|o| match o {
            ResolvedOutputValue::Fixed { value, .. } => *value,
            ResolvedOutputValue::ChainedEnvelope { value, .. } => *value,
            ResolvedOutputValue::Change { .. } | ResolvedOutputValue::OpReturn { .. } => 0,
        })
        .sum();

    // Build PSBT inputs (participants first, then extra_inputs)
    let mut psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    for rp in &resolved {
        psbt.unsigned_tx.input.push(TxIn {
            previous_output: rp.outpoint,
            ..Default::default()
        });
        psbt.inputs.push(bitcoin::psbt::Input {
            witness_utxo: Some(rp.prevout.clone()),
            tap_internal_key: Some(rp.x_only_public_key),
            ..Default::default()
        });
    }
    for extra in &reveal.extra_inputs {
        psbt.unsigned_tx.input.push(TxIn {
            previous_output: extra.outpoint,
            ..Default::default()
        });
        psbt.inputs.push(bitcoin::psbt::Input {
            witness_utxo: Some(extra.prevout.clone()),
            ..Default::default()
        });
    }

    // Compute fee from a tx populated with all outputs + witness placeholders.
    // Outputs use real values for Fixed/ChainedEnvelope/OpReturn; Change is
    // placeholder for sizing only. Witnesses: participants are script-spend
    // (sig + script + control block); extras are key-path (sig only).
    let mut dummy_tx = psbt.unsigned_tx.clone();
    for (i, rp) in resolved.iter().enumerate() {
        let mut w = Witness::new();
        w.push(vec![0u8; SCHNORR_SIGNATURE_SIZE]);
        w.push(rp.tap_leaf_script.script.as_bytes());
        w.push(rp.tap_leaf_script.control_block.as_bytes());
        dummy_tx.input[i].witness = w;
    }
    for i in 0..reveal.extra_inputs.len() {
        let idx = resolved.len() + i;
        let mut w = Witness::new();
        w.push(vec![0u8; SCHNORR_SIGNATURE_SIZE]);
        dummy_tx.input[idx].witness = w;
    }
    for ro in &resolved_outputs {
        let (value, script) = match ro {
            ResolvedOutputValue::Fixed { value, script } => (*value, script.clone()),
            ResolvedOutputValue::ChainedEnvelope { value, script, .. } => (*value, script.clone()),
            ResolvedOutputValue::Change { script } => {
                // Placeholder value for sizing; resolved next.
                (0, script.clone())
            }
            ResolvedOutputValue::OpReturn { script } => (0, script.clone()),
        };
        dummy_tx.output.push(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script,
        });
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
                output_info.push(RevealOutputInfo::Fixed);
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
                output_info.push(RevealOutputInfo::ChainedEnvelope { tap_leaf_script });
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
                    output_info.push(RevealOutputInfo::Change);
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
    // empty extras), Bitcoin would reject the tx. Emit a minimal OP_RETURN
    // carrying the protocol tag so the tx is structurally valid.
    if psbt.unsigned_tx.output.is_empty() {
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: {
                let mut s = ScriptBuf::new();
                s.push_opcode(OP_RETURN);
                s.push_slice(PROTOCOL_TAG);
                s
            },
        });
        psbt.outputs.push(bitcoin::psbt::Output::default());
    }

    let commit_tap_leaf_scripts: Vec<TapLeafScript> = resolved
        .iter()
        .map(|rp| rp.tap_leaf_script.clone())
        .collect();

    let reveal_transaction = psbt.unsigned_tx.clone();
    let reveal_transaction_hex = hex::encode(serialize_tx(&reveal_transaction));
    let psbt_hex = psbt.serialize_hex();

    Ok(RevealOutputs::builder()
        .transaction(reveal_transaction)
        .transaction_hex(reveal_transaction_hex)
        .psbt_hex(psbt_hex)
        .commit_tap_leaf_scripts(commit_tap_leaf_scripts)
        .output_info(output_info)
        .build())
}

/// Parse a hex-encoded scriptPubKey into a `ScriptBuf`.
fn parse_hex_script(hex_str: &str) -> Result<ScriptBuf> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow!("invalid hex in script_pubkey: {}", e))?;
    Ok(ScriptBuf::from_bytes(bytes))
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

/// Append a `RevealOutput` to a dummy reveal tx for vbyte estimation.
/// Uses real values for Fixed/ChainedEnvelope and placeholder 0 for
/// Change/OpReturn (which still adds the correct vsize contribution).
fn add_output_to_dummy(dummy: &mut Transaction, output: &RevealOutput) -> Result<()> {
    match output {
        RevealOutput::Fixed {
            value,
            script_pubkey,
        } => {
            dummy.output.push(TxOut {
                value: Amount::from_sat(*value),
                script_pubkey: parse_hex_script(script_pubkey)?,
            });
        }
        RevealOutput::Change { script_pubkey } => {
            dummy.output.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: parse_hex_script(script_pubkey)?,
            });
        }
        RevealOutput::ChainedEnvelope {
            insts,
            value,
            internal_key,
        } => {
            let internal_pk = XOnlyPublicKey::from_str(internal_key)?;
            let insts_bytes = serialize(insts)?;
            let (_, addr, _) = build_tap_script_and_script_address(internal_pk, insts_bytes)?;
            dummy.output.push(TxOut {
                value: Amount::from_sat(*value),
                script_pubkey: addr.script_pubkey(),
            });
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
            dummy.output.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: s,
            });
        }
    }
    Ok(())
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
        let x_only_pk = XOnlyPublicKey::from_str(&p.x_only_public_key)?;
        let insts_bytes = serialize(&p.commit_insts)?;
        let (script, _, control_block) =
            build_tap_script_and_script_address(x_only_pk, insts_bytes)?;
        let mut txin = TxIn::default();
        let mut w = Witness::new();
        w.push(vec![0u8; SCHNORR_SIGNATURE_SIZE]);
        w.push(script.as_bytes());
        w.push(control_block.serialize());
        txin.witness = w;
        dummy.input.push(txin);
    }

    // Extra inputs — key-path spends
    for _ in &reveal.extra_inputs {
        let mut txin = TxIn::default();
        let mut w = Witness::new();
        w.push(vec![0u8; SCHNORR_SIGNATURE_SIZE]);
        txin.witness = w;
        dummy.input.push(txin);
    }

    // Outputs — defer to the shared layout helper that `compose_reveal`
    // also uses, so sizing here matches the actual reveal exactly.
    for slot in compute_output_layout(reveal)? {
        let out = match slot {
            LayoutSlot::FromParticipant(i) => reveal.participants[i]
                .output
                .as_ref()
                .expect("participant slot has Some output"),
            LayoutSlot::FromExtra(j) => &reveal.extra_outputs[j],
        };
        add_output_to_dummy(&mut dummy, out)?;
    }

    Ok(dummy.vsize() as u64)
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
    default_sat_per_vbyte: u64,
) -> Result<indexer_types::CommitOutputs> {
    if reveal.participants.is_empty() {
        return Err(anyhow!("Reveal must have at least one participant"));
    }
    if reveal.participants.len() > MAX_PARTICIPANTS {
        return Err(anyhow!("Too many participants (max {})", MAX_PARTICIPANTS));
    }

    let sat_per_vbyte = reveal.sat_per_vbyte.unwrap_or(default_sat_per_vbyte);
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

    // Sum non-Change output values from the future reveal
    let sum_output_values = |output: &RevealOutput| -> u64 {
        match output {
            RevealOutput::Fixed { value, .. } => *value,
            RevealOutput::ChainedEnvelope { value, .. } => *value,
            RevealOutput::Change { .. } | RevealOutput::OpReturn { .. } => 0,
        }
    };
    let total_fixed_outputs: u64 = reveal
        .participants
        .iter()
        .filter_map(|p| p.output.as_ref().map(sum_output_values))
        .sum::<u64>()
        .saturating_add(
            reveal
                .extra_outputs
                .iter()
                .map(sum_output_values)
                .sum::<u64>(),
        );

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
        let x_only_pk = XOnlyPublicKey::from_str(&participant.x_only_public_key)?;
        let insts_bytes = serialize(&participant.commit_insts)?;
        if insts_bytes.is_empty() || insts_bytes.len() > MAX_SCRIPT_BYTES {
            return Err(anyhow!("Build participant leaf data size invalid"));
        }
        let (_, tap_addr, _) = build_tap_script_and_script_address(x_only_pk, insts_bytes)?;

        let funding_utxos = get_utxos(bitcoin_client, funding_utxo_ids.join(",")).await?;
        if funding_utxos.len() > MAX_UTXOS_PER_PARTICIPANT {
            return Err(anyhow!(
                "too many utxos for Build participant (max {})",
                MAX_UTXOS_PER_PARTICIPANT
            ));
        }

        // Build an empty commit tx with just the tap output
        let mut psbt = Psbt::from_unsigned_tx(Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(tap_output_value),
                script_pubkey: tap_addr.script_pubkey(),
            }],
        })?;
        psbt.outputs.push(bitcoin::psbt::Output::default());

        // Select UTXOs covering tap output + commit fee. For standalone
        // commits, the full empty-tx header overhead is borne by this
        // single tx (no sharing), so pass the full header fee directly.
        let base_header_fee = calculate_base_header_fee_for_participant(0, 1, fee_rate)?;
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

        // Change to the Build participant's address
        let change = selected_sum.saturating_sub(tap_output_value + commit_fee);
        if change >= MIN_ENVELOPE_SATS {
            psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: build_address.script_pubkey(),
            });
            psbt.outputs.push(bitcoin::psbt::Output::default());
        }

        let commit_tx = psbt.unsigned_tx.clone();
        let commit_txid = commit_tx.compute_txid();
        let commit_tx_hex = hex::encode(serialize_tx(&commit_tx));
        let commit_psbt_hex = psbt.serialize_hex();

        commits.push(indexer_types::CommitTx {
            transaction: commit_tx,
            transaction_hex: commit_tx_hex,
            psbt_hex: commit_psbt_hex,
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

    let updated_reveal = Reveal {
        sat_per_vbyte: reveal.sat_per_vbyte,
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
    default_sat_per_vbyte: u64,
) -> Result<(Vec<indexer_types::CommitTx>, RevealOutputs)> {
    let has_build = reveal
        .participants
        .iter()
        .any(|p| matches!(p.commit_source, CommitSource::Build { .. }));

    let (commits, reveal_to_build) = if has_build {
        let commit_outputs =
            compose_commit(reveal, network, bitcoin_client, default_sat_per_vbyte).await?;
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

/// Distribute `total` evenly across `num_participants`, returning the
/// share for participant `participant_index`. The first `total % N`
/// participants pay `base + 1`; the rest pay `base`, where `base =
/// total / N`. Summing across all indices yields `total` exactly — no
/// over-collection (unlike a naive `div_ceil`).
fn distribute_fee(total: u64, participant_index: usize, num_participants: usize) -> u64 {
    if num_participants == 0 {
        return 0;
    }
    let n = num_participants as u64;
    let base = total / n;
    let remainder = total % n;
    base + if (participant_index as u64) < remainder {
        1
    } else {
        0
    }
}

/// Calculate this participant's share of the OP_RETURN output fee.
///
/// Returns 0 if no OP_RETURN data is present or no participants. The
/// total fee is derived from the actual serialized size of the
/// OP_RETURN output (not the policy maximum), so smaller payloads
/// pay proportionally less. Split using `distribute_fee` so the sum
/// across all participants exactly covers the output — no stray sats.
pub fn calculate_op_return_fee_for_participant(
    op_return_data: Option<&[u8]>,
    participant_index: usize,
    num_participants: usize,
    fee_rate: FeeRate,
) -> Result<u64> {
    let Some(data) = op_return_data else {
        return Ok(0);
    };
    if num_participants == 0 {
        return Ok(0);
    }
    let mut script = ScriptBuf::new();
    script.push_opcode(OP_RETURN);
    script.push_slice(PushBytesBuf::try_from(data.to_vec())?);
    let txout = TxOut {
        value: Amount::ZERO,
        script_pubkey: script,
    };
    // OP_RETURN is a non-witness output; its vsize contribution equals
    // its serialized length.
    let op_return_vsize = encode::serialize(&txout).len() as u64;
    let total_fee = fee_rate
        .fee_vb(op_return_vsize)
        .ok_or(anyhow!("fee calculation overflow"))?
        .to_sat();
    Ok(distribute_fee(
        total_fee,
        participant_index,
        num_participants,
    ))
}

/// Calculate this participant's share of the empty-tx header overhead.
///
/// Per-participant delta-based fee accounting (`calculate_reveal_fee_delta`,
/// `estimate_participant_commit_fees`) only charges each participant for
/// the marginal vbytes they add. The base tx header (version + counts +
/// locktime — about 11 vbytes) is never billed to anyone, so the signed
/// tx falls below the requested fee rate. Split that overhead using
/// `distribute_fee` so every participant pays the same effective rate
/// and the total exactly covers the header — no over-collection.
pub fn calculate_base_header_fee_for_participant(
    participant_index: usize,
    num_participants: usize,
    fee_rate: FeeRate,
) -> Result<u64> {
    if num_participants == 0 {
        return Ok(0);
    }
    let empty_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let header_vsize = empty_tx.vsize() as u64;
    let total_fee = fee_rate
        .fee_vb(header_vsize)
        .ok_or(anyhow!("fee calculation overflow"))?
        .to_sat();
    Ok(distribute_fee(
        total_fee,
        participant_index,
        num_participants,
    ))
}

/// Calculate reveal fee delta for a single participant.
///
/// Mutates the dummy transaction by adding the participant's input and outputs,
/// then returns the fee based on the vsize delta.
///
/// This is used in the single-pass commit/reveal building loops.
pub fn calculate_reveal_fee_delta(
    dummy_tx: &mut Transaction,
    tap_script: &ScriptBuf,
    control_block_bytes: &[u8],
    has_chained: bool,
    fee_rate: FeeRate,
    envelope: u64,
) -> Result<u64> {
    let vsize_before = dummy_tx.vsize() as u64;

    // Add input with script-spend witness
    let mut txin = TxIn::default();
    let mut w = Witness::new();
    w.push(vec![0u8; SCHNORR_SIGNATURE_SIZE]);
    w.push(tap_script.as_bytes());
    w.push(control_block_bytes);
    txin.witness = w;
    dummy_tx.input.push(txin);

    // Add chained output if present
    if has_chained {
        dummy_tx.output.push(TxOut {
            value: Amount::from_sat(envelope),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; P2TR_OUTPUT_SIZE]),
        });
    }

    // Add change output (assume it exists for fee calculation)
    dummy_tx.output.push(TxOut {
        value: Amount::from_sat(envelope),
        script_pubkey: ScriptBuf::from_bytes(vec![0u8; P2TR_OUTPUT_SIZE]),
    });

    let vsize_after = dummy_tx.vsize() as u64;
    let delta = vsize_after.saturating_sub(vsize_before);
    let fee = fee_rate
        .fee_vb(delta)
        .ok_or(anyhow!("fee calculation overflow"))?
        .to_sat();

    Ok(fee)
}

/// Estimate fee for a tx assuming key-spend inputs (64-byte signature witnesses).
pub fn estimate_key_spend_fee(tx: &Transaction, fee_rate: FeeRate) -> Option<u64> {
    let mut dummy = tx.clone();
    for inp in &mut dummy.input {
        let mut w = Witness::new();
        w.push(vec![0u8; SCHNORR_SIGNATURE_SIZE]);
        inp.witness = w;
    }
    fee_rate.fee_vb(dummy.vsize() as u64).map(|a| a.to_sat())
}

/// Select UTXOs for a commit participant using delta-based fee accounting.
///
/// This function accurately calculates fees by measuring the actual vsize delta
/// that this participant adds to the shared transaction, rather than assuming
/// a fixed transaction structure.
///
/// Returns (selected_utxos, participant_fee) or errors if insufficient funds.
/// // TODO: is this necessary???
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

    // Add script output (P2TR size = 34 bytes)
    temp_tx.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
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
