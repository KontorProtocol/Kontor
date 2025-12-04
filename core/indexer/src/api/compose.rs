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
use futures_util::future::try_join_all;

use bon::Builder;

use bitcoin::Txid;
use bitcoin::hashes::Hash;
use bitcoin::key::constants::SCHNORR_SIGNATURE_SIZE;
use indexer_types::{Inst, serialize};
use rand::{rng, seq::SliceRandom};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
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

#[derive(Serialize, Deserialize, Clone, Builder)]
pub struct InstructionQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub funding_utxo_ids: String,
    pub instruction: Inst,
    pub chained_instruction: Option<Inst>,
}

#[derive(Serialize, Deserialize, Builder)]
pub struct ComposeQuery {
    pub instructions: Vec<InstructionQuery>,
    pub sat_per_vbyte: u64,
    pub envelope: Option<u64>,
}

#[derive(Serialize, Builder, Clone)]
pub struct InstructionInputs {
    pub address: Address,
    pub x_only_public_key: XOnlyPublicKey,
    pub funding_utxos: Vec<(OutPoint, TxOut)>,
    pub instruction: Vec<u8>,
    pub chained_instruction: Option<Vec<u8>>,
}

#[derive(Serialize, Builder)]
pub struct ComposeInputs {
    pub instructions: Vec<InstructionInputs>,
    pub fee_rate: FeeRate,
    pub envelope: u64,
}

impl ComposeInputs {
    pub async fn from_query(
        query: ComposeQuery,
        network: bitcoin::Network,
        bitcoin_client: &Client,
    ) -> Result<Self> {
        if query.instructions.is_empty() {
            return Err(anyhow!("No instructions provided"));
        }
        if query.instructions.len() > MAX_PARTICIPANTS {
            return Err(anyhow!("Too many participants (max {})", MAX_PARTICIPANTS));
        }

        if query.sat_per_vbyte == 0 {
            return Err(anyhow!("Invalid fee rate"));
        }
        // Validate unique UTXOs within and across participants early
        let mut global_utxo_set: HashSet<String> = HashSet::new();
        for instruction_query in query.instructions.iter() {
            let utxo_ids: Vec<&str> = instruction_query.funding_utxo_ids.split(',').collect();
            let mut local_utxo_set: HashSet<&str> = HashSet::new();
            for utxo_id in utxo_ids.iter() {
                if !local_utxo_set.insert(utxo_id) {
                    return Err(anyhow!(
                        "duplicate funding outpoint provided for participant"
                    ));
                }
                if !global_utxo_set.insert(utxo_id.to_string()) {
                    return Err(anyhow!(
                        "duplicate funding outpoint provided across participants"
                    ));
                }
            }
        }

        let instructions: Vec<InstructionInputs> =
            try_join_all(query.instructions.iter().map(|instruction_query| async {
                let address: Address =
                    Address::from_str(&instruction_query.address)?.require_network(network)?;
                match address.address_type() {
                    Some(AddressType::P2tr) => {}
                    _ => return Err(anyhow!("Invalid address type")),
                }
                let x_only_public_key =
                    XOnlyPublicKey::from_str(&instruction_query.x_only_public_key)?;
                let funding_utxos =
                    get_utxos(bitcoin_client, instruction_query.funding_utxo_ids.clone()).await?;
                if funding_utxos.len() > MAX_UTXOS_PER_PARTICIPANT {
                    return Err(anyhow!(
                        "too many utxos for participant (max {})",
                        MAX_UTXOS_PER_PARTICIPANT
                    ));
                }
                let instruction = serialize(&instruction_query.instruction)?;
                if instruction.is_empty() || instruction.len() > MAX_SCRIPT_BYTES {
                    return Err(anyhow!("script data size invalid"));
                }

                let chained_script_data_bytes = match instruction_query.chained_instruction.as_ref()
                {
                    Some(inst) => {
                        let bytes = serialize(inst)?;
                        if bytes.is_empty() || bytes.len() > MAX_SCRIPT_BYTES {
                            return Err(anyhow!("chained script data size invalid"));
                        }
                        Some(bytes)
                    }
                    None => None,
                };
                Ok(InstructionInputs {
                    address,
                    x_only_public_key,
                    funding_utxos,
                    instruction,
                    chained_instruction: chained_script_data_bytes,
                })
            }))
            .await?;

        let fee_rate =
            FeeRate::from_sat_per_vb(query.sat_per_vbyte).ok_or(anyhow!("Invalid fee rate"))?;

        let envelope = query
            .envelope
            .unwrap_or(MIN_ENVELOPE_SATS)
            .max(MIN_ENVELOPE_SATS);

        Ok(Self {
            instructions,
            fee_rate,
            envelope,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct TapLeafScript {
    #[schemars(with = "u64")]
    #[serde(rename = "leafVersion")]
    pub leaf_version: LeafVersion,
    #[schemars(with = "String")]
    pub script: ScriptBuf,
    #[schemars(with = "String")]
    #[serde(rename = "controlBlock")]
    pub control_block: ScriptBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct ParticipantScripts {
    pub address: String,
    pub x_only_public_key: String,
    pub commit_tap_leaf_script: TapLeafScript,
    pub chained_tap_leaf_script: Option<TapLeafScript>,
}

#[derive(Debug, Serialize, Deserialize, Builder, JsonSchema)]
pub struct ComposeOutputs {
    #[schemars(with = "String")]
    pub commit_transaction: Transaction,
    pub commit_transaction_hex: String,
    pub commit_psbt_hex: String,
    #[schemars(with = "String")]
    pub reveal_transaction: Transaction,
    pub reveal_transaction_hex: String,
    pub reveal_psbt_hex: String,
    pub per_participant: Vec<ParticipantScripts>,
}

#[derive(Builder)]
pub struct CommitInputs {
    pub instructions: Vec<InstructionInputs>,
    pub fee_rate: FeeRate,
    pub envelope: u64,
}

impl From<ComposeInputs> for CommitInputs {
    fn from(value: ComposeInputs) -> Self {
        Self {
            instructions: value.instructions,
            fee_rate: value.fee_rate,
            envelope: value.envelope,
        }
    }
}

#[derive(Builder, Serialize, Clone, JsonSchema)]
pub struct CommitOutputs {
    #[schemars(with = "String")]
    pub commit_transaction: Transaction,
    pub commit_transaction_hex: String,
    pub commit_psbt_hex: String,
    pub reveal_inputs: RevealInputs,
}

#[derive(Serialize, Deserialize, Clone, Builder)]
pub struct RevealParticipantQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub commit_vout: u32,
    pub commit_script_data: Vec<u8>,
    pub chained_instruction: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub struct RevealQuery {
    pub commit_tx_hex: String,
    pub sat_per_vbyte: u64,
    pub participants: Vec<RevealParticipantQuery>,
    pub op_return_data: Option<Vec<u8>>,
    pub envelope: Option<u64>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct TxOutSchema {
    value: u64,
    script_pubkey: String,
}

#[derive(Clone, Serialize, Builder, JsonSchema)]
pub struct RevealParticipantInputs {
    #[schemars(with = "String")]
    pub address: Address,
    #[schemars(with = "String")]
    pub x_only_public_key: XOnlyPublicKey,
    #[schemars(with = "String")]
    pub commit_outpoint: OutPoint,
    #[schemars(with = "TxOutSchema")]
    pub commit_prevout: TxOut,
    pub commit_tap_leaf_script: TapLeafScript,
    pub chained_instruction: Option<Vec<u8>>,
}

#[derive(Builder, Serialize, Clone, JsonSchema)]
pub struct RevealInputs {
    #[schemars(with = "String")]
    pub commit_tx: Transaction,
    #[schemars(with = "u64")]
    pub fee_rate: FeeRate,
    pub participants: Vec<RevealParticipantInputs>,
    pub op_return_data: Option<Vec<u8>>,
    pub envelope: u64,
}

impl RevealInputs {
    pub async fn from_query(query: RevealQuery, network: bitcoin::Network) -> Result<Self> {
        if query.sat_per_vbyte == 0 {
            return Err(anyhow!("Invalid fee rate"));
        }
        let fee_rate =
            FeeRate::from_sat_per_vb(query.sat_per_vbyte).ok_or(anyhow!("Invalid fee rate"))?;

        let commit_tx = encode::deserialize_hex::<bitcoin::Transaction>(&query.commit_tx_hex)?;

        if query.participants.is_empty() {
            return Err(anyhow!("participants cannot be empty"));
        }

        let mut participants_inputs = Vec::with_capacity(query.participants.len());
        for p in query.participants.iter() {
            let address = Address::from_str(&p.address)?.require_network(network)?;
            match address.address_type() {
                Some(AddressType::P2tr) => {}
                _ => return Err(anyhow!("Invalid address type (must be P2TR)")),
            }
            let x_only_public_key = XOnlyPublicKey::from_str(&p.x_only_public_key)?;
            let commit_outpoint = OutPoint {
                txid: commit_tx.compute_txid(),
                vout: p.commit_vout,
            };

            let commit_prevout = commit_tx
                .output
                .get(commit_outpoint.vout as usize)
                .cloned()
                .ok_or_else(|| anyhow!("commit vout {} out of bounds", commit_outpoint.vout))?;

            // Build TapScriptPair from raw commit_script_data
            let (script, _, control_block) = build_tap_script_and_script_address(
                x_only_public_key,
                p.commit_script_data.clone(),
            )?;

            participants_inputs.push(RevealParticipantInputs {
                address,
                x_only_public_key,
                commit_outpoint,
                commit_prevout,
                commit_tap_leaf_script: TapLeafScript {
                    leaf_version: LeafVersion::TapScript,
                    script,
                    control_block: ScriptBuf::from_bytes(control_block.serialize()),
                },
                chained_instruction: p.chained_instruction.clone(),
            });
        }

        let envelope = query
            .envelope
            .unwrap_or(MIN_ENVELOPE_SATS)
            .max(MIN_ENVELOPE_SATS);

        Ok(Self {
            commit_tx,
            fee_rate,
            participants: participants_inputs,
            op_return_data: query.op_return_data,
            envelope,
        })
    }
}

#[derive(Builder, Serialize, Deserialize, JsonSchema)]
pub struct RevealOutputs {
    #[schemars(with = "String")]
    pub transaction: Transaction,
    pub transaction_hex: String,
    pub psbt_hex: String,
    pub participants: Vec<ParticipantScripts>,
}

pub fn compose(params: ComposeInputs) -> Result<ComposeOutputs> {
    // Build the commit tx
    let commit_outputs = compose_commit(CommitInputs {
        instructions: params.instructions,
        fee_rate: params.fee_rate,
        envelope: params.envelope,
    })?;

    // Build the reveal tx using reveal_inputs prepared during commit (inject chained data now)
    let reveal_inputs = commit_outputs.reveal_inputs.clone();
    let reveal_outputs = compose_reveal(reveal_inputs)?;

    // Build the final outputs
    let compose_outputs = ComposeOutputs::builder()
        .commit_transaction(commit_outputs.commit_transaction)
        .commit_transaction_hex(commit_outputs.commit_transaction_hex)
        .commit_psbt_hex(commit_outputs.commit_psbt_hex)
        .reveal_transaction(reveal_outputs.transaction.clone())
        .reveal_transaction_hex(reveal_outputs.transaction_hex)
        .reveal_psbt_hex(reveal_outputs.psbt_hex)
        .per_participant(reveal_outputs.participants)
        .build();

    Ok(compose_outputs)
}

pub fn compose_commit(params: CommitInputs) -> Result<CommitOutputs> {
    if params.instructions.is_empty() {
        return Err(anyhow!("No instructions provided"));
    }

    // Dummy tx for delta-based reveal fee calculation
    let mut dummy_reveal_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Commit PSBT we're building
    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    // Build RevealParticipantInputs in the loop with placeholder txid
    // We'll update the txid after the loop when the transaction is finalized
    let mut participants: Vec<RevealParticipantInputs> =
        Vec::with_capacity(params.instructions.len());

    // Single loop: build tap scripts, calculate reveal fees, build commit tx, build reveal participants
    for (i, instruction) in params.instructions.iter().enumerate() {
        // 1. Build tap script for this participant
        let (tap_script, script_spendable_address, control_block) =
            build_tap_script_and_script_address(
                instruction.x_only_public_key,
                instruction.instruction.clone(),
            )?;

        // 2. Calculate reveal fee delta using helper
        let has_chained = instruction.chained_instruction.is_some();
        let reveal_fee = calculate_reveal_fee_delta(
            &mut dummy_reveal_tx,
            &tap_script,
            &control_block.serialize(),
            has_chained,
            params.fee_rate,
            params.envelope,
        )?;

        // 3. Build commit transaction outputs for this participant

        // Script output value must cover:
        // 1. envelope: dust floor for change output in the reveal
        // 2. reveal_fee: miner fee for the reveal tx (delta-based)
        // 3. chained_envelope: if chained, the value locked in the chained output
        let chained_envelope = if has_chained { params.envelope } else { 0 };
        let script_spend_output_value = params
            .envelope
            .saturating_add(reveal_fee)
            .saturating_add(chained_envelope);

        // Shuffle UTXOs for privacy
        let mut utxos: Vec<(OutPoint, TxOut)> = instruction.funding_utxos.clone();
        utxos.shuffle(&mut rng());

        // Select UTXOs using delta-based fee accounting for commit
        let (selected, participant_commit_fee) = select_utxos_for_commit(
            &commit_psbt.unsigned_tx,
            utxos,
            script_spend_output_value,
            params.fee_rate,
            params.envelope,
        )
        .map_err(|e| anyhow!("participant {}: {}", i, e))?;

        let selected_sum: u64 = selected.iter().map(|(_, txo)| txo.value.to_sat()).sum();

        // Append selected inputs to the PSBT
        for (outpoint, prevout) in selected.iter() {
            commit_psbt.unsigned_tx.input.push(TxIn {
                previous_output: *outpoint,
                ..Default::default()
            });
            commit_psbt.inputs.push(bitcoin::psbt::Input {
                witness_utxo: Some(prevout.clone()),
                tap_internal_key: Some(instruction.x_only_public_key),
                ..Default::default()
            });
        }

        // Track vout before adding script output
        let vout = commit_psbt.unsigned_tx.output.len() as u32;

        // Build the script output (we need this for both the PSBT and RevealParticipantInputs)
        let script_output = TxOut {
            value: Amount::from_sat(script_spend_output_value),
            script_pubkey: script_spendable_address.script_pubkey(),
        };

        // Add script output to PSBT
        commit_psbt.unsigned_tx.output.push(script_output.clone());
        commit_psbt.outputs.push(bitcoin::psbt::Output::default());

        // Add change output if above dust threshold
        let change =
            selected_sum.saturating_sub(script_spend_output_value + participant_commit_fee);
        if change >= params.envelope {
            commit_psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: instruction.address.script_pubkey(),
            });
            commit_psbt.outputs.push(bitcoin::psbt::Output::default());
        }

        // 4. Build RevealParticipantInputs with placeholder txid (will be updated after loop)
        participants.push(RevealParticipantInputs {
            address: instruction.address.clone(),
            x_only_public_key: instruction.x_only_public_key,
            commit_outpoint: OutPoint {
                txid: Txid::all_zeros(), // Placeholder - updated after loop
                vout,
            },
            commit_prevout: script_output,
            commit_tap_leaf_script: TapLeafScript {
                leaf_version: LeafVersion::TapScript,
                script: tap_script,
                control_block: ScriptBuf::from_bytes(control_block.serialize()),
            },
            chained_instruction: instruction.chained_instruction.clone(),
        });
    }

    let commit_transaction = commit_psbt.unsigned_tx.clone();
    let commit_transaction_hex = hex::encode(serialize_tx(&commit_transaction));
    let commit_psbt_hex = commit_psbt.serialize_hex();
    let commit_txid = commit_transaction.compute_txid();

    // Update placeholder txid in all RevealParticipantInputs
    for participant in &mut participants {
        participant.commit_outpoint.txid = commit_txid;
    }

    let reveal_inputs = RevealInputs::builder()
        .commit_tx(commit_transaction.clone())
        .fee_rate(params.fee_rate)
        .participants(participants)
        .envelope(params.envelope)
        .build();

    Ok(CommitOutputs::builder()
        .commit_transaction(commit_transaction)
        .commit_transaction_hex(commit_transaction_hex)
        .commit_psbt_hex(commit_psbt_hex)
        .reveal_inputs(reveal_inputs)
        .build())
}

pub fn compose_reveal(params: RevealInputs) -> Result<RevealOutputs> {
    // Validate OP_RETURN size upfront
    if let Some(ref data) = params.op_return_data
        && data.len() > MAX_OP_RETURN_BYTES
    {
        return Err(anyhow!(
            "OP_RETURN data exceeds {} bytes",
            MAX_OP_RETURN_BYTES
        ));
    }

    // Calculate OP_RETURN fee to split evenly among participants
    let op_return_fee_per_participant = calculate_op_return_fee_per_participant(
        params.op_return_data.is_some(),
        params.participants.len(),
        params.fee_rate,
    )?;

    // Dummy tx for delta-based reveal fee calculation (OP_RETURN fee handled separately)
    let mut dummy_reveal_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Build the actual reveal transaction
    let mut psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    let mut participant_scripts: Vec<ParticipantScripts> =
        Vec::with_capacity(params.participants.len());
    let mut pending_change_outputs: Vec<TxOut> = Vec::with_capacity(params.participants.len());

    // Single loop: calculate fees, add inputs, add chained outputs, gather change
    for p in params.participants.iter() {
        // Calculate reveal fee delta using helper
        let has_chained = p.chained_instruction.is_some();
        let participant_delta_fee = calculate_reveal_fee_delta(
            &mut dummy_reveal_tx,
            &p.commit_tap_leaf_script.script,
            p.commit_tap_leaf_script.control_block.as_bytes(),
            has_chained,
            params.fee_rate,
            params.envelope,
        )?;

        // Total fee includes participant's share of OP_RETURN overhead
        let reveal_fee = participant_delta_fee + op_return_fee_per_participant;

        // Add input
        psbt.unsigned_tx.input.push(TxIn {
            previous_output: p.commit_outpoint,
            ..Default::default()
        });
        psbt.inputs.push(bitcoin::psbt::Input {
            witness_utxo: Some(p.commit_prevout.clone()),
            tap_internal_key: Some(p.x_only_public_key),
            ..Default::default()
        });

        // Build chained TapLeafScript and add chained output IMMEDIATELY (so they come first)
        let chained_tap_leaf_script = if let Some(ref chained) = p.chained_instruction {
            let (ch_tap, ch_addr, ch_control_block) =
                build_tap_script_and_script_address(p.x_only_public_key, chained.clone())?;
            // Add chained output at envelope value
            psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(params.envelope),
                script_pubkey: ch_addr.script_pubkey(),
            });
            psbt.outputs.push(bitcoin::psbt::Output::default());
            Some(TapLeafScript {
                leaf_version: LeafVersion::TapScript,
                script: ch_tap,
                control_block: ScriptBuf::from_bytes(ch_control_block.serialize()),
            })
        } else {
            None
        };

        // Calculate change and gather it (don't add to psbt yet)
        let chained_output_value = if has_chained { params.envelope } else { 0 };
        let change = p
            .commit_prevout
            .value
            .to_sat()
            .saturating_sub(chained_output_value + reveal_fee);

        if change >= params.envelope {
            pending_change_outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: p.address.script_pubkey(),
            });
        }

        participant_scripts.push(ParticipantScripts {
            address: p.address.to_string(),
            x_only_public_key: p.x_only_public_key.to_string(),
            commit_tap_leaf_script: p.commit_tap_leaf_script.clone(),
            chained_tap_leaf_script,
        });
    }

    // Add all change outputs after chained outputs
    for change_output in pending_change_outputs {
        psbt.unsigned_tx.output.push(change_output);
        psbt.outputs.push(bitcoin::psbt::Output::default());
    }

    // Add OP_RETURN at the very end (if present)
    if let Some(ref data) = params.op_return_data {
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: {
                let mut s = ScriptBuf::new();
                s.push_opcode(OP_RETURN);
                s.push_slice(PushBytesBuf::try_from(data.clone())?);
                s
            },
        });
        psbt.outputs.push(bitcoin::psbt::Output::default());
    }

    // If no outputs, add minimal OP_RETURN to avoid invalid tx
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

    let reveal_transaction = psbt.unsigned_tx.clone();
    let reveal_transaction_hex = hex::encode(serialize_tx(&reveal_transaction));
    let psbt_hex = psbt.serialize_hex();

    Ok(RevealOutputs::builder()
        .transaction(reveal_transaction)
        .transaction_hex(reveal_transaction_hex)
        .psbt_hex(psbt_hex)
        .participants(participant_scripts)
        .build())
}

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

/// Calculate the OP_RETURN fee to be split evenly among participants.
///
/// Returns the per-participant share of the OP_RETURN output fee (rounded up).
/// Returns 0 if no OP_RETURN data is present or no participants.
pub fn calculate_op_return_fee_per_participant(
    has_op_return: bool,
    num_participants: usize,
    fee_rate: FeeRate,
) -> Result<u64> {
    if !has_op_return || num_participants == 0 {
        return Ok(0);
    }

    // OP_RETURN output: 8 (value) + 1 (script len varint) + 1 (OP_RETURN) + 1 (push len) + up to 80 bytes
    // Max size with 80-byte payload = 91 bytes
    let op_return_vsize = 9 + MAX_OP_RETURN_BYTES as u64;
    let total_fee = fee_rate
        .fee_vb(op_return_vsize)
        .ok_or(anyhow!("fee calculation overflow"))?
        .to_sat();

    // Split evenly among participants (round up to ensure full coverage)
    Ok(total_fee.div_ceil(num_participants as u64))
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

        // Estimate fees with and without change output
        let (fee_with_change, fee_no_change) =
            estimate_participant_commit_fees(current_tx, &selected, fee_rate)?;

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
    for (outpoint, res) in outpoints.into_iter().zip(results.into_iter()) {
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
