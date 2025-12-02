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
    taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::{Transaction, TxIn, Version},
};
use futures_util::future::try_join_all;

use bon::Builder;

use bitcoin::Txid;
use bitcoin::key::constants::SCHNORR_SIGNATURE_SIZE;
use indexer_types::{Inst, serialize};
use rand::{rng, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, str::FromStr};

use crate::bitcoin_client::Client;

// Hardening limits
const MAX_PARTICIPANTS: usize = 1000;
const MAX_SCRIPT_BYTES: usize = 387 * 1024; // 387 KiB
const MAX_OP_RETURN_BYTES: usize = 80; // Standard policy
const MIN_ENVELOPE_SATS: u64 = 330; // P2TR dust floor
const MAX_UTXOS_PER_PARTICIPANT: usize = 64; // Hard cap per participant

#[derive(Serialize, Deserialize, Clone, Builder)]
pub struct InstructionQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub funding_utxo_ids: String,
    pub script_data: Inst,
    pub chained_script_data: Option<Inst>,
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
    pub script_data: Vec<u8>,
    pub chained_script_data: Option<Vec<u8>>,
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
                let script_data = serialize(&instruction_query.script_data)?;
                if script_data.is_empty() || script_data.len() > MAX_SCRIPT_BYTES {
                    return Err(anyhow!("script data size invalid"));
                }

                let chained_script_data_bytes = match instruction_query.chained_script_data.as_ref()
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
                    script_data,
                    chained_script_data: chained_script_data_bytes,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TapLeafScript {
    #[serde(rename = "leafVersion")]
    pub leaf_version: LeafVersion,
    pub script: ScriptBuf,
    #[serde(rename = "controlBlock")]
    pub control_block: ScriptBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TapScriptPair {
    pub tap_script: ScriptBuf,
    pub tap_leaf_script: TapLeafScript,
    pub script_data_chunk: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParticipantScripts {
    pub address: String,
    pub x_only_public_key: String,
    pub commit_tap_script_pair: TapScriptPair,
    pub chained_tap_script_pair: Option<TapScriptPair>,
}

#[derive(Debug, Serialize, Deserialize, Builder)]
pub struct ComposeOutputs {
    pub commit_transaction: Transaction,
    pub commit_transaction_hex: String,
    pub commit_psbt_hex: String,
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

#[derive(Builder, Serialize, Clone)]
pub struct CommitOutputs {
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
    pub commit_script_data: Vec<u8>, // do we want this to be the pair?
    pub envelope: Option<u64>,
    pub chained_script_data: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub struct RevealQuery {
    pub commit_tx_hex: String,
    pub sat_per_vbyte: u64,
    pub participants: Vec<RevealParticipantQuery>,
    pub op_return_data: Option<Vec<u8>>,
    pub envelope: Option<u64>,
}

#[derive(Clone, Serialize, Builder)]
pub struct RevealParticipantInputs {
    pub address: Address,
    pub x_only_public_key: XOnlyPublicKey,
    pub commit_outpoint: OutPoint,
    pub commit_prevout: TxOut,
    pub commit_tap_script_pair: TapScriptPair,
    pub chained_script_data: Option<Vec<u8>>,
}

/// Intermediate data collected during commit loop, before txid is known
struct PendingParticipant {
    address: Address,
    x_only_public_key: XOnlyPublicKey,
    vout: u32,
    tap_script_pair: TapScriptPair,
    chained_script_data: Option<Vec<u8>>,
}

#[derive(Builder, Serialize, Clone)]
pub struct RevealInputs {
    pub commit_tx: Transaction,
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

            // Build TapScriptPair from raw commit_script_data : TODO: should this be passed in or derived
            let (tap_script, _, _, control_block) = build_tap_script_and_script_address(
                x_only_public_key,
                p.commit_script_data.clone(),
            )?;
            let tap_leaf = TapLeafScript {
                leaf_version: LeafVersion::TapScript,
                script: tap_script.clone(),
                control_block: ScriptBuf::from_bytes(control_block.serialize()),
            };
            let commit_tap_script_pair = TapScriptPair {
                tap_script,
                tap_leaf_script: tap_leaf,
                script_data_chunk: p.commit_script_data.clone(),
            };

            participants_inputs.push(RevealParticipantInputs {
                address,
                x_only_public_key,
                commit_outpoint,
                commit_prevout,
                commit_tap_script_pair,
                chained_script_data: p.chained_script_data.clone(),
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

#[derive(Builder, Serialize, Deserialize)]
pub struct RevealOutputs {
    pub transaction: Transaction,
    pub transaction_hex: String,
    pub psbt: Psbt,
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
    // Start with an empty commit PSBT
    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    if params.instructions.is_empty() {
        return Err(anyhow!("No instructions provided"));
    }

    // Collect data needed to build RevealParticipantInputs after we have txid
    let mut participant_data: Vec<PendingParticipant> =
        Vec::with_capacity(params.instructions.len());

    // Steps for building the commit psbt:
    // TODO
    for instruction in params.instructions.iter() {
        let inst_script_data = instruction.script_data.clone();

        // Build tapscript for this address
        let (tap_script, _, script_spendable_address, control_block) =
            build_tap_script_and_script_address(
                instruction.x_only_public_key,
                inst_script_data.clone(),
            )?;

        // Estimate reveal fee
        let has_chained = instruction.chained_script_data.is_some();
        let reveal_fee = estimate_script_spend_fee(
            &tap_script,
            &control_block.serialize(),
            has_chained,
            params.fee_rate,
        )
        .ok_or(anyhow!("fee calculation overflow"))?;

        // Script output value must cover:
        // 1. envelope: dust floor for change output in the reveal
        // 2. reveal_fee: miner fee for the reveal tx
        // 3. chained_envelope: if chained, the value locked in the chained output (another envelope)
        let chained_envelope = if has_chained { params.envelope } else { 0 };
        let script_spend_output_value = params
            .envelope
            .saturating_add(reveal_fee)
            .saturating_add(chained_envelope);

        // Shuffle UTXOs
        let mut utxos: Vec<(OutPoint, TxOut)> = instruction.funding_utxos.clone();
        utxos.shuffle(&mut rng());

        // Select UTXOs and compute this participant's fee contribution
        let (selected, participant_fee) =
            select_utxos_for_commit(utxos, script_spend_output_value, params.fee_rate)?;
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

        // Add script output
        let script_vout = commit_psbt.unsigned_tx.output.len() as u32;
        commit_psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(script_spend_output_value),
            script_pubkey: script_spendable_address.script_pubkey(),
        });
        commit_psbt.outputs.push(bitcoin::psbt::Output::default());

        // Add change output if above dust
        let change = selected_sum.saturating_sub(script_spend_output_value + participant_fee);
        if change >= params.envelope {
            commit_psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: instruction.address.script_pubkey(),
            });
            commit_psbt.outputs.push(bitcoin::psbt::Output::default());
        }

        // Build TapScriptPair
        let tap_script_pair = TapScriptPair {
            tap_script: tap_script.clone(),
            tap_leaf_script: TapLeafScript {
                leaf_version: LeafVersion::TapScript,
                script: tap_script,
                control_block: ScriptBuf::from_bytes(control_block.serialize()),
            },
            script_data_chunk: inst_script_data,
        };

        participant_data.push(PendingParticipant {
            address: instruction.address.clone(),
            x_only_public_key: instruction.x_only_public_key,
            vout: script_vout,
            tap_script_pair,
            chained_script_data: instruction.chained_script_data.clone(),
        });
    }

    let commit_transaction = commit_psbt.unsigned_tx.clone();
    let commit_transaction_hex = hex::encode(serialize_tx(&commit_transaction));
    let commit_psbt_hex = commit_psbt.serialize_hex();
    let commit_txid = commit_transaction.compute_txid();

    // Build RevealParticipantInputs now that we have txid
    let participants: Vec<RevealParticipantInputs> = participant_data
        .into_iter()
        .map(|p| RevealParticipantInputs {
            address: p.address,
            x_only_public_key: p.x_only_public_key,
            commit_outpoint: OutPoint {
                txid: commit_txid,
                vout: p.vout,
            },
            commit_prevout: commit_transaction.output[p.vout as usize].clone(),
            commit_tap_script_pair: p.tap_script_pair,
            chained_script_data: p.chained_script_data,
        })
        .collect();

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
    // Start with empty PSBT (consistent with compose_commit)
    let mut psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    // Optional OP_RETURN first (keeps vsize expectations stable)
    if let Some(ref data) = params.op_return_data {
        if data.len() > MAX_OP_RETURN_BYTES {
            return Err(anyhow!(
                "OP_RETURN data exceeds {} bytes",
                MAX_OP_RETURN_BYTES
            ));
        }
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

    // Single loop: add inputs, outputs, and PSBT metadata for each participant
    let mut participant_scripts: Vec<ParticipantScripts> =
        Vec::with_capacity(params.participants.len());

    for p in params.participants.iter() {
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

        // Build chained TapScriptPair if chained_script_data is present
        let chained_tap_script_pair = if let Some(ref chained) = p.chained_script_data {
            let (ch_tap, _, ch_addr, ch_control_block) =
                build_tap_script_and_script_address(p.x_only_public_key, chained.clone())?;
            // Add chained output at envelope value
            psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(params.envelope),
                script_pubkey: ch_addr.script_pubkey(),
            });
            psbt.outputs.push(bitcoin::psbt::Output::default());
            Some(TapScriptPair {
                tap_script: ch_tap.clone(),
                tap_leaf_script: TapLeafScript {
                    leaf_version: LeafVersion::TapScript,
                    script: ch_tap,
                    control_block: ScriptBuf::from_bytes(ch_control_block.serialize()),
                },
                script_data_chunk: chained.clone(),
            })
        } else {
            None
        };

        // Compute and add change output
        let tap_script = &p.commit_tap_script_pair.tap_script;
        let control_block = &p.commit_tap_script_pair.tap_leaf_script.control_block;
        let has_chained = p.chained_script_data.is_some();
        let fixed_output_sum = if has_chained { params.envelope } else { 0 };

        let change = estimate_script_spend_fee(
            tap_script,
            control_block.as_bytes(),
            has_chained,
            params.fee_rate,
        )
        .and_then(|fee| {
            p.commit_prevout
                .value
                .to_sat()
                .checked_sub(fixed_output_sum + fee)
        });

        if let Some(v) = change
            && v >= params.envelope
        {
            psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(v),
                script_pubkey: p.address.script_pubkey(),
            });
            psbt.outputs.push(bitcoin::psbt::Output::default());
        }

        participant_scripts.push(ParticipantScripts {
            address: p.address.to_string(),
            x_only_public_key: p.x_only_public_key.to_string(),
            commit_tap_script_pair: p.commit_tap_script_pair.clone(),
            chained_tap_script_pair,
        });
    }

    // If no outputs, add minimal OP_RETURN to avoid invalid tx
    if psbt.unsigned_tx.output.is_empty() {
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: {
                let mut s = ScriptBuf::new();
                s.push_opcode(OP_RETURN);
                s.push_slice(b"kon");
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
        .psbt(psbt)
        .psbt_hex(psbt_hex)
        .participants(participant_scripts)
        .build())
}

pub fn build_tap_script_and_script_address(
    x_only_public_key: XOnlyPublicKey,
    data: Vec<u8>,
) -> Result<(ScriptBuf, TaprootSpendInfo, Address, ControlBlock)> {
    let secp = Secp256k1::new();

    let mut builder = Builder::new()
        .push_slice(x_only_public_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
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

    Ok((
        tap_script,
        taproot_spend_info,
        script_spendable_address,
        control_block,
    ))
}

// ============================================================================
// Fee Estimation
// ============================================================================

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

/// Estimate fee for a script-spend reveal tx.
/// All outputs are P2TR (34 bytes). has_chained adds a second output.
fn estimate_script_spend_fee(
    tap_script: &ScriptBuf,
    control_block_bytes: &[u8],
    has_chained: bool,
    fee_rate: FeeRate,
) -> Option<u64> {
    let num_outputs = if has_chained { 2 } else { 1 };
    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![{
            let mut txin = TxIn::default();
            let mut w = Witness::new();
            w.push(vec![0u8; SCHNORR_SIGNATURE_SIZE]);
            w.push(tap_script.as_bytes());
            w.push(control_block_bytes);
            txin.witness = w;
            txin
        }],
        output: (0..num_outputs)
            .map(|_| TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]), // P2TR
            })
            .collect(),
    };
    fee_rate.fee_vb(tx.vsize() as u64).map(|a| a.to_sat())
}

/// Select UTXOs for a commit participant.
/// Returns (selected_utxos, participant_fee) or errors if insufficient funds.
pub fn select_utxos_for_commit(
    utxos: Vec<(OutPoint, TxOut)>,
    script_output_value: u64,
    fee_rate: FeeRate,
) -> Result<(Vec<(OutPoint, TxOut)>, u64)> {
    let mut selected: Vec<(OutPoint, TxOut)> = Vec::new();
    let mut selected_sum: u64 = 0;

    for (outpoint, txout) in utxos {
        selected_sum += txout.value.to_sat();
        selected.push((outpoint, txout));

        // Fee for N key-spend inputs + 2 P2TR outputs
        let fee = estimate_commit_fee(selected.len(), fee_rate)
            .ok_or_else(|| anyhow!("fee calculation overflow"))?;
        let required = script_output_value + fee;

        if selected_sum >= required {
            return Ok((selected, fee));
        }
    }

    Err(anyhow!("Insufficient funds"))
}

/// Estimate commit fee for N inputs + 2 P2TR outputs (script + change)
fn estimate_commit_fee(num_inputs: usize, fee_rate: FeeRate) -> Option<u64> {
    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: (0..num_inputs).map(|_| TxIn::default()).collect(),
        output: vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
            },
        ],
    };
    estimate_key_spend_fee(&tx, fee_rate)
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
