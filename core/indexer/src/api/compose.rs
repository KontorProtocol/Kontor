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
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::{Transaction, TxIn, Version},
};

use bon::Builder;

use bitcoin::Txid;
use bitcoin::key::constants::SCHNORR_SIGNATURE_SIZE;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use std::{collections::HashSet, str::FromStr};

use crate::bitcoin_client::Client;

// Hardening limits
const MAX_PARTICIPANTS: usize = 1000;
const MAX_SCRIPT_BYTES: usize = 16 * 1024; // 16 KiB
const MAX_OP_RETURN_BYTES: usize = 80; // Standard policy
const MIN_ENVELOPE_SATS: u64 = 330; // P2TR dust floor
const MAX_UTXOS_PER_PARTICIPANT: usize = 64; // Hard cap per participant

#[derive(Serialize, Deserialize, Clone)]
pub struct ComposeAddressQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub funding_utxo_ids: String,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ComposeQuery {
    // base64-encoded JSON Vec<ComposeAddressQuery>
    #[serde(with = "addresses_b64_json")]
    pub addresses: Vec<ComposeAddressQuery>,
    // base64 string → Vec<u8>
    #[serde_as(as = "Base64")]
    pub script_data: Vec<u8>,
    pub sat_per_vbyte: u64,
    pub envelope: Option<u64>,
    // optional base64 string → Option<Vec<u8>>
    #[serde_as(as = "Option<Base64>")]
    pub chained_script_data: Option<Vec<u8>>,
}

mod addresses_b64_json {
    use super::*;
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(de: D) -> Result<Vec<ComposeAddressQuery>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(de)?;
        let bytes = BASE64_STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)?;
        serde_json::from_slice(&bytes).map_err(serde::de::Error::custom)
    }

    pub fn serialize<S>(value: &Vec<ComposeAddressQuery>, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = serde_json::to_vec(value).map_err(serde::ser::Error::custom)?;
        let s = BASE64_STANDARD.encode(bytes);
        ser.serialize_str(&s)
    }
}

#[derive(Serialize, Builder, Clone)]
pub struct ComposeAddressInputs {
    pub address: Address,
    pub x_only_public_key: XOnlyPublicKey,
    pub funding_utxos: Vec<(OutPoint, TxOut)>,
}

#[derive(Serialize, Builder)]
pub struct ComposeInputs {
    pub addresses: Vec<ComposeAddressInputs>,
    pub script_data: Vec<u8>,
    pub fee_rate: FeeRate,
    pub envelope: u64,
    pub chained_script_data: Option<Vec<u8>>,
}

impl ComposeInputs {
    pub async fn from_query(query: ComposeQuery, bitcoin_client: &Client) -> Result<Self> {
        use futures_util::future::try_join_all;

        if query.addresses.is_empty() {
            return Err(anyhow!("No addresses provided"));
        }
        if query.addresses.len() > MAX_PARTICIPANTS {
            return Err(anyhow!("Too many participants (max {})", MAX_PARTICIPANTS));
        }

        if query.sat_per_vbyte == 0 {
            return Err(anyhow!("Invalid fee rate"));
        }

        let addresses: Vec<ComposeAddressInputs> =
            try_join_all(query.addresses.iter().map(|address_query| async {
                let address: Address = Address::from_str(&address_query.address)?
                    .require_network(bitcoin::Network::Bitcoin)?;
                match address.address_type() {
                    Some(AddressType::P2tr) => {}
                    _ => return Err(anyhow!("Invalid address type")),
                }
                let x_only_public_key = XOnlyPublicKey::from_str(&address_query.x_only_public_key)?;
                let funding_utxos =
                    get_utxos(bitcoin_client, address_query.funding_utxo_ids.clone()).await?;
                if funding_utxos.len() > MAX_UTXOS_PER_PARTICIPANT {
                    return Err(anyhow!(
                        "too many utxos for participant (max {})",
                        MAX_UTXOS_PER_PARTICIPANT
                    ));
                }
                // Ensure no duplicate outpoints within a participant
                let mut local_set: HashSet<(Txid, u32)> = HashSet::new();
                for (op, _) in funding_utxos.iter() {
                    let key = (op.txid, op.vout);
                    if !local_set.insert(key) {
                        return Err(anyhow!(
                            "duplicate funding outpoint provided for participant"
                        ));
                    }
                }
                Ok(ComposeAddressInputs {
                    address,
                    x_only_public_key,
                    funding_utxos,
                })
            }))
            .await?;

        let fee_rate =
            FeeRate::from_sat_per_vb(query.sat_per_vbyte).ok_or(anyhow!("Invalid fee rate"))?;

        let script_data = query.script_data.clone();
        if script_data.is_empty() || script_data.len() > MAX_SCRIPT_BYTES {
            return Err(anyhow!("script data size invalid"));
        }

        let chained_script_data_bytes = query.chained_script_data.clone();
        if chained_script_data_bytes
            .as_ref()
            .is_some_and(|c| c.is_empty() || c.len() > MAX_SCRIPT_BYTES)
        {
            return Err(anyhow!("chained script data size invalid"));
        }
        let envelope = query
            .envelope
            .unwrap_or(MIN_ENVELOPE_SATS)
            .max(MIN_ENVELOPE_SATS);

        // Ensure unique addresses
        let mut addr_set: HashSet<String> = HashSet::with_capacity(addresses.len());
        for a in addresses.iter() {
            let key = a.address.to_string();
            if !addr_set.insert(key) {
                return Err(anyhow!("duplicate address provided"));
            }
        }

        // Ensure no duplicate outpoints across owners
        let mut outpoint_set: HashSet<(Txid, u32)> = HashSet::new();
        for a in addresses.iter() {
            for (op, _) in a.funding_utxos.iter() {
                let key = (op.txid, op.vout);
                if !outpoint_set.insert(key) {
                    return Err(anyhow!(
                        "duplicate funding outpoint provided across participants"
                    ));
                }
            }
        }

        Ok(Self {
            addresses,
            script_data,
            fee_rate,
            envelope,
            chained_script_data: chained_script_data_bytes,
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
    pub index: u32,
    pub address: String,
    pub x_only_public_key: String,
    pub commit: TapScriptPair,
    pub chained: Option<TapScriptPair>,
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
    pub addresses: Vec<ComposeAddressInputs>,
    pub script_data: Vec<u8>,
    pub fee_rate: FeeRate,
    pub envelope: u64,
}

impl From<ComposeInputs> for CommitInputs {
    fn from(value: ComposeInputs) -> Self {
        Self {
            addresses: value.addresses,
            script_data: value.script_data,
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
    pub per_participant_tap: Vec<TapScriptPair>,
    pub reveal_inputs: RevealInputs,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub struct RevealParticipantQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub commit_vout: u32,
    #[serde_as(as = "Base64")]
    pub commit_script_data: Vec<u8>,
    pub envelope: Option<u64>,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct RevealQuery {
    pub commit_txid: String,
    pub sat_per_vbyte: u64,
    pub participants: Vec<RevealParticipantQuery>,
    #[serde_as(as = "Option<Base64>")]
    pub op_return_data: Option<Vec<u8>>,
    pub envelope: Option<u64>,
    #[serde_as(as = "Option<Base64>")]
    pub chained_script_data: Option<Vec<u8>>,
}

#[derive(Clone, Serialize)]
pub struct RevealParticipantInputs {
    pub address: Address,
    pub x_only_public_key: XOnlyPublicKey,
    pub commit_outpoint: OutPoint,
    pub commit_prevout: TxOut,
    pub commit_script_data: Vec<u8>,
}

#[derive(Builder, Serialize, Clone)]
pub struct RevealInputs {
    pub commit_txid: bitcoin::Txid,
    pub fee_rate: FeeRate,
    pub participants: Vec<RevealParticipantInputs>,
    pub op_return_data: Option<Vec<u8>>,
    pub envelope: u64,
    pub chained_script_data: Option<Vec<u8>>,
}

impl RevealInputs {
    pub async fn from_query(query: RevealQuery, bitcoin_client: &Client) -> Result<Self> {
        if query.sat_per_vbyte == 0 {
            return Err(anyhow!("Invalid fee rate"));
        }
        let fee_rate =
            FeeRate::from_sat_per_vb(query.sat_per_vbyte).ok_or(anyhow!("Invalid fee rate"))?;
        let commit_txid = bitcoin::Txid::from_str(&query.commit_txid)?;

        if query.participants.is_empty() {
            return Err(anyhow!("participants cannot be empty"));
        }

        let mut participants_inputs = Vec::with_capacity(query.participants.len());
        for p in query.participants.iter() {
            let address =
                Address::from_str(&p.address)?.require_network(bitcoin::Network::Bitcoin)?;
            match address.address_type() {
                Some(AddressType::P2tr) => {}
                _ => return Err(anyhow!("Invalid address type (must be P2TR)")),
            }
            let x_only_public_key = XOnlyPublicKey::from_str(&p.x_only_public_key)?;
            let commit_outpoint = OutPoint {
                txid: commit_txid,
                vout: p.commit_vout,
            };
            let tx = bitcoin_client
                .get_raw_transaction(&commit_outpoint.txid)
                .await
                .map_err(|e| anyhow!("Failed to fetch transaction: {}", e))?;
            let commit_prevout = tx
                .output
                .get(commit_outpoint.vout as usize)
                .cloned()
                .ok_or_else(|| anyhow!("commit vout {} out of bounds", commit_outpoint.vout))?;
            let commit_script_data = p.commit_script_data.clone();

            participants_inputs.push(RevealParticipantInputs {
                address,
                x_only_public_key,
                commit_outpoint,
                commit_prevout,
                commit_script_data,
            });
        }

        let op_return_data = query.op_return_data.clone();

        let envelope = query
            .envelope
            .unwrap_or(MIN_ENVELOPE_SATS)
            .max(MIN_ENVELOPE_SATS);
        let chained_script_data = query.chained_script_data.clone();

        Ok(Self {
            commit_txid,
            fee_rate,
            participants: participants_inputs,
            op_return_data,
            envelope,
            chained_script_data,
        })
    }
}

#[derive(Builder, Serialize, Deserialize)]
pub struct RevealOutputs {
    pub transaction: Transaction,
    pub transaction_hex: String,
    pub psbt: Psbt,
    pub psbt_hex: String,
    // { "<address>": { tap_script, tap_leaf_script } }
    pub per_participant_chained_tap: Vec<TapScriptPair>,
}

pub fn compose(params: ComposeInputs) -> Result<ComposeOutputs> {
    // Clone addresses for response mapping prior to move
    let addresses_clone = params.addresses.clone();
    // Build the commit tx
    let commit_outputs = compose_commit(CommitInputs {
        addresses: params.addresses,
        script_data: params.script_data.clone(),
        fee_rate: params.fee_rate,
        envelope: params.envelope,
    })?;

    // Build the reveal tx using reveal_inputs prepared during commit (inject chained data now)
    let mut reveal_inputs = commit_outputs.reveal_inputs.clone();
    reveal_inputs.chained_script_data = params.chained_script_data.clone();
    let reveal_outputs = compose_reveal(reveal_inputs)?;

    // Build the final outputs
    let compose_outputs = ComposeOutputs::builder()
        .commit_transaction(commit_outputs.commit_transaction)
        .commit_transaction_hex(commit_outputs.commit_transaction_hex)
        .commit_psbt_hex(commit_outputs.commit_psbt_hex)
        .reveal_transaction(reveal_outputs.transaction.clone())
        .reveal_transaction_hex(reveal_outputs.transaction_hex)
        .reveal_psbt_hex(reveal_outputs.psbt_hex)
        .per_participant(
            commit_outputs
                .per_participant_tap
                .into_iter()
                .enumerate()
                .map(|(idx, commit_pair)| ParticipantScripts {
                    index: idx as u32,
                    address: addresses_clone[idx].address.to_string(),
                    x_only_public_key: addresses_clone[idx].x_only_public_key.to_string(),
                    commit: commit_pair,
                    chained: reveal_outputs.per_participant_chained_tap.get(idx).cloned(),
                })
                .collect(),
        )
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

    // Split script_data into N contiguous chunks
    let num_addrs = params.addresses.len();
    if num_addrs == 0 {
        return Err(anyhow!("No addresses provided"));
    }
    if params.script_data.is_empty() {
        return Err(anyhow!("script data cannot be empty"));
    }
    let chunks = split_even_chunks(&params.script_data, num_addrs)?;

    let mut per_participant_tap: Vec<TapScriptPair> = Vec::with_capacity(num_addrs);

    for (i, addr) in params.addresses.iter().enumerate() {
        let chunk = chunks[i].clone();

        // Build tapscript for this address
        let (tap_script, tap_info, script_spendable_address) =
            build_tap_script_and_script_address(addr.x_only_public_key, chunk.clone())?;

        // Estimate reveal fee using helper
        let reveal_fee = estimate_reveal_fee_for_address(
            &tap_script,
            &tap_info,
            addr.address.script_pubkey().len(),
            params.fee_rate,
        )?;

        // Script output must cover envelope + reveal fee
        let script_value = params.envelope.saturating_add(reveal_fee);

        // Select only necessary UTXOs for this address to cover script_value + commit delta fee
        let mut utxos = addr.funding_utxos.clone();
        // Sort ascending, then pop() to take largest-first deterministically
        utxos.sort_by_key(|(_, txout)| txout.value.to_sat());

        let mut selected: Vec<(OutPoint, TxOut)> = Vec::new();
        let mut selected_sum: u64 = 0;

        // Fee paid so far by previous participants (inputs - outputs) on the current tx
        let paid_so_far_inputs: u64 = commit_psbt
            .inputs
            .iter()
            .map(|inp| inp.witness_utxo.as_ref().map_or(0, |o| o.value.to_sat()))
            .sum::<u64>()
            .saturating_sub(
                commit_psbt
                    .unsigned_tx
                    .output
                    .iter()
                    .map(|o| o.value.to_sat())
                    .sum::<u64>(),
            );

        loop {
            // Waterfall-required total using dummy witnesses
            let mut base = commit_psbt.unsigned_tx.clone();
            for _ in 0..selected.len() {
                base.input.push(dummy_txin());
            }
            base.output.push(TxOut {
                value: Amount::from_sat(script_value),
                script_pubkey: script_spendable_address.script_pubkey(),
            });
            base.output.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: addr.address.script_pubkey(),
            });
            let total_fee_target = estimate_fee_with_dummy_key_witness(&base, params.fee_rate)
                .ok_or(anyhow!("fee calculation overflow"))?;
            let participant_fee_needed = total_fee_target.saturating_sub(paid_so_far_inputs);
            let required_total = script_value.saturating_add(participant_fee_needed);
            if selected_sum >= required_total {
                // We have enough; break selection loop
                break;
            }
            // Need another UTXO
            match utxos.pop() {
                Some((op, txo)) => {
                    selected_sum = selected_sum.saturating_add(txo.value.to_sat());
                    selected.push((op, txo));
                }
                None => {
                    return Err(anyhow!("Insufficient inputs for address {}", addr.address));
                }
            }
        }

        // Compute change for this address and append real outputs/inputs
        // Snapshot tx before adding this participant to compute total incremental fee correctly
        let tx_before_participant = commit_psbt.unsigned_tx.clone();
        // Append selected inputs to the real PSBT and set per-input metadata
        for (outpoint, prevout) in selected.iter() {
            commit_psbt.unsigned_tx.input.push(TxIn {
                previous_output: *outpoint,
                ..Default::default()
            });
            let inp: bitcoin::psbt::Input = bitcoin::psbt::Input {
                witness_utxo: Some(prevout.clone()),
                tap_internal_key: Some(addr.x_only_public_key),
                ..Default::default()
            };
            commit_psbt.inputs.push(inp);
        }
        // Add the script output
        commit_psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(script_value),
            script_pubkey: script_spendable_address.script_pubkey(),
        });
        // Maintain PSBT outputs array in sync with transaction outputs
        commit_psbt.outputs.push(bitcoin::psbt::Output::default());
        // Recompute fees precisely using total incremental delta relative to tx_before_participant
        let before_fee =
            estimate_fee_with_dummy_key_witness(&tx_before_participant, params.fee_rate)
                .ok_or(anyhow!("fee calculation overflow"))?;
        // Fee after adding a zero-valued change output for this participant:
        let mut with_change = commit_psbt.unsigned_tx.clone();
        with_change.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: addr.address.script_pubkey(),
        });
        let with_change_fee = estimate_fee_with_dummy_key_witness(&with_change, params.fee_rate)
            .ok_or(anyhow!("fee calculation overflow"))?;
        let total_incremental_fee = with_change_fee.saturating_sub(before_fee);

        // Change amount equals inputs selected minus (script_value + total incremental fee)
        let change_candidate =
            selected_sum.saturating_sub(script_value.saturating_add(total_incremental_fee));
        if change_candidate >= params.envelope {
            commit_psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(change_candidate),
                script_pubkey: addr.address.script_pubkey(),
            });
            commit_psbt.outputs.push(bitcoin::psbt::Output::default());
        }

        // Record mapping
        let tap_leaf = TapLeafScript {
            leaf_version: LeafVersion::TapScript,
            script: tap_script.clone(),
            control_block: ScriptBuf::from_bytes(
                tap_info
                    .control_block(&(tap_script.clone(), LeafVersion::TapScript))
                    .ok_or_else(|| anyhow!("Failed to create control block"))?
                    .serialize(),
            ),
        };
        per_participant_tap.push(TapScriptPair {
            tap_script: tap_script.clone(),
            tap_leaf_script: tap_leaf,
            script_data_chunk: chunk,
        });
    }

    let commit_transaction = commit_psbt.unsigned_tx.clone();
    let commit_transaction_hex = hex::encode(serialize_tx(&commit_transaction));
    let commit_psbt_hex = commit_psbt.serialize_hex();

    // Build reveal inputs here for convenience
    use std::collections::HashMap;
    let commit_txid = commit_transaction.compute_txid();
    let mut participants: Vec<RevealParticipantInputs> = Vec::with_capacity(params.addresses.len());
    // Track how many times we've assigned a given script_pubkey to ensure unique vout selection
    let mut spk_usage_counts: HashMap<ScriptBuf, u32> = HashMap::new();
    for (idx, a) in params.addresses.iter().enumerate() {
        let pair = &per_participant_tap[idx];
        let (_tap, _info, script_addr) = build_tap_script_and_script_address(
            a.x_only_public_key,
            pair.script_data_chunk.clone(),
        )?;
        let spk = script_addr.script_pubkey();
        let desired_occurrence = *spk_usage_counts.get(&spk).unwrap_or(&0);
        let mut seen = 0u32;
        let vout = commit_transaction
            .output
            .iter()
            .enumerate()
            .find_map(|(i, o)| {
                if o.script_pubkey == spk {
                    if seen == desired_occurrence {
                        Some(i as u32)
                    } else {
                        seen += 1;
                        None
                    }
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("failed to locate unique commit vout for {}", a.address))?;
        *spk_usage_counts.entry(spk.clone()).or_insert(0) += 1;
        let commit_outpoint = OutPoint {
            txid: commit_txid,
            vout,
        };
        let commit_prevout = commit_transaction.output[vout as usize].clone();
        participants.push(RevealParticipantInputs {
            address: a.address.clone(),
            x_only_public_key: a.x_only_public_key,
            commit_outpoint,
            commit_prevout,
            commit_script_data: pair.script_data_chunk.clone(),
        });
    }
    let reveal_inputs = RevealInputs::builder()
        .commit_txid(commit_txid)
        .fee_rate(params.fee_rate)
        .participants(participants)
        .envelope(params.envelope)
        .build();

    Ok(CommitOutputs::builder()
        .commit_transaction(commit_transaction)
        .commit_transaction_hex(commit_transaction_hex)
        .commit_psbt_hex(commit_psbt_hex)
        .per_participant_tap(per_participant_tap)
        .reveal_inputs(reveal_inputs)
        .build())
}

pub fn compose_reveal(params: RevealInputs) -> Result<RevealOutputs> {
    // Build a reveal tx that spends each participant's commit output
    let mut reveal_transaction = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: params
            .participants
            .iter()
            .map(|p| TxIn {
                previous_output: p.commit_outpoint,
                ..Default::default()
            })
            .collect(),
        output: vec![],
    };

    // Track whether we've already added an OP_RETURN; policy generally allows only one
    let mut op_return_added = false;
    // Optional OP_RETURN first (keeps vsize expectations stable)
    if let Some(data) = params.op_return_data.clone() {
        // Enforce total payload size including tag; policy considers total push size
        let mut payload = Vec::with_capacity(3 + data.len());
        payload.extend_from_slice(b"kon");
        payload.extend_from_slice(&data);
        if payload.len() > MAX_OP_RETURN_BYTES {
            return Err(anyhow!(
                "OP_RETURN data exceeds {} bytes",
                MAX_OP_RETURN_BYTES
            ));
        }
        reveal_transaction.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: {
                let mut s = ScriptBuf::new();
                s.push_opcode(OP_RETURN);
                s.push_slice(PushBytesBuf::try_from(payload)?);
                s
            },
        });
        op_return_added = true;
    }

    // Precompute commit tapscripts/control blocks per participant for sizing and PSBT
    let mut commit_scripts: Vec<(ScriptBuf, ScriptBuf)> =
        Vec::with_capacity(params.participants.len());
    for p in params.participants.iter() {
        let (tap_script, tap_info, _) =
            build_tap_script_and_script_address(p.x_only_public_key, p.commit_script_data.clone())?;
        let control_block = tap_info
            .control_block(&(tap_script.clone(), LeafVersion::TapScript))
            .ok_or(anyhow!("Failed to create control block"))?
            .serialize();
        commit_scripts.push((tap_script, ScriptBuf::from_bytes(control_block)));
    }

    // If chained_script_data is present, split it evenly across participants and add per-owner chained outputs
    let mut per_participant_chained_tap: Vec<TapScriptPair> =
        Vec::with_capacity(params.participants.len());
    if let Some(chained) = params.chained_script_data.clone() {
        let n = params.participants.len();
        let chunks = split_even_chunks(&chained, n)?;
        for (i, p) in params.participants.iter().enumerate() {
            let chunk = chunks[i].clone();

            let (ch_tap, ch_info, ch_addr) =
                build_tap_script_and_script_address(p.x_only_public_key, chunk.clone())?;
            // Per-owner chained output at envelope value
            reveal_transaction.output.push(TxOut {
                value: Amount::from_sat(params.envelope),
                script_pubkey: ch_addr.script_pubkey(),
            });
            // Record mapping for response
            let tap_leaf = TapLeafScript {
                leaf_version: LeafVersion::TapScript,
                script: ch_tap.clone(),
                control_block: ScriptBuf::from_bytes(
                    ch_info
                        .control_block(&(ch_tap.clone(), LeafVersion::TapScript))
                        .ok_or_else(|| anyhow!("Failed to create control block"))?
                        .serialize(),
                ),
            };
            per_participant_chained_tap.push(TapScriptPair {
                tap_script: ch_tap,
                tap_leaf_script: tap_leaf,
                script_data_chunk: chunk,
            });
        }
    }

    // For each owner, compute standalone change using single-input sizing with fixed witness shape
    for (i, p) in params.participants.iter().enumerate() {
        let mut owner_outputs: Vec<TxOut> = Vec::new();
        if params.chained_script_data.is_some() {
            // One P2TR chained output at envelope
            owner_outputs.push(TxOut {
                value: Amount::from_sat(params.envelope),
                script_pubkey: ScriptBuf::from_bytes(vec![0; 34]),
            });
        }
        let (ref tap_script, ref control_block) = commit_scripts[i];
        if let Some(v) = calculate_change_single(
            owner_outputs,
            (
                reveal_transaction.input[i].clone(),
                p.commit_prevout.clone(),
            ),
            tap_script,
            control_block,
            params.fee_rate,
        ) {
            if params.chained_script_data.is_some() {
                if v > params.envelope {
                    reveal_transaction.output.push(TxOut {
                        value: Amount::from_sat(v),
                        script_pubkey: p.address.script_pubkey(),
                    });
                }
            } else if v >= MIN_ENVELOPE_SATS {
                reveal_transaction.output.push(TxOut {
                    value: Amount::from_sat(v),
                    script_pubkey: p.address.script_pubkey(),
                });
            } else if !op_return_added {
                // Fallback: add a single OP_RETURN (at most one per tx) to avoid dust outputs
                reveal_transaction.output.push(TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: {
                        let mut s = ScriptBuf::new();
                        s.push_opcode(OP_RETURN);
                        s.push_slice(b"kon");
                        s
                    },
                });
                op_return_added = true;
            }
        }
    }

    // Now that reveal_transaction is finalized, build PSBT and set metadata
    let mut psbt = Psbt::from_unsigned_tx(reveal_transaction.clone())?;
    for (idx, p) in params.participants.iter().enumerate() {
        psbt.inputs[idx].witness_utxo = Some(p.commit_prevout.clone());
        psbt.inputs[idx].tap_internal_key = Some(p.x_only_public_key);
        // Use commit script merkle root
        let (tap_script, tap_info, _) =
            build_tap_script_and_script_address(p.x_only_public_key, p.commit_script_data.clone())?;
        let _ = tap_script; // not needed further here
        if let Some(root) = tap_info.merkle_root() {
            psbt.inputs[idx].tap_merkle_root = Some(root);
        } else {
            return Err(anyhow!("missing tap merkle root for provided script"));
        }
    }

    let reveal_transaction_hex = hex::encode(serialize_tx(&reveal_transaction));
    let psbt_hex = psbt.serialize_hex();
    let reveal_outputs = RevealOutputs::builder()
        .transaction(reveal_transaction)
        .transaction_hex(reveal_transaction_hex)
        .psbt(psbt)
        .psbt_hex(psbt_hex)
        .per_participant_chained_tap(per_participant_chained_tap)
        .build();

    Ok(reveal_outputs)
}

pub fn build_tap_script_and_script_address(
    x_only_public_key: XOnlyPublicKey,
    data: Vec<u8>,
) -> Result<(ScriptBuf, TaprootSpendInfo, Address)> {
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

    Ok((tap_script, taproot_spend_info, script_spendable_address))
}

pub fn calculate_change_single(
    outputs: Vec<TxOut>,
    input_tuple: (TxIn, TxOut),
    tap_script: &ScriptBuf,
    control_block: &ScriptBuf,
    fee_rate: FeeRate,
) -> Option<u64> {
    // Sum actual input value
    let (_txin, txout) = input_tuple;
    let input_sum = txout.value.to_sat();

    // Prepare output script lengths (existing owner outputs + dummy change spk len = 34)
    let mut spk_lens: Vec<usize> = outputs.iter().map(|o| o.script_pubkey.len()).collect();
    spk_lens.push(34);

    // Compute fee for single-input script spend with provided tapscript/control_block
    let vb = script_spend_vbytes(1, tap_script, control_block, &spk_lens);
    let fee = fee_rate.fee_vb(vb)?.to_sat();

    // Output sum excludes dummy change (value 0)
    let output_sum: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();

    input_sum.checked_sub(output_sum + fee)
}

// Fee estimation helpers for commit/reveal
pub fn tx_vbytes_est(tx: &Transaction) -> u64 {
    let mut no_wit = tx.clone();
    for inp in &mut no_wit.input {
        inp.witness = Witness::new();
    }
    let base_size = serialize_tx(&no_wit).len() as u64;
    let total_size = serialize_tx(tx).len() as u64;
    let witness_size = total_size.saturating_sub(base_size);
    let weight = base_size * 4 + witness_size;
    weight.div_ceil(4)
}

// Core low-level helper: return vbytes for a script-spend with the given tapscript/control_block,
// number of inputs, and output scriptPubKey lengths. Used by both fee estimation and change calc.
fn script_spend_vbytes(
    inputs_count: usize,
    tap_script: &ScriptBuf,
    control_block: &ScriptBuf,
    output_spk_lens: &[usize],
) -> u64 {
    let mut tx = build_dummy_tx(vec![], vec![]);
    for _ in 0..inputs_count {
        let mut txin = dummy_txin();
        let mut witness = Witness::new();
        witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
        witness.push(tap_script.clone());
        witness.push(control_block.clone());
        txin.witness = witness;
        tx.input.push(txin);
    }
    for &len in output_spk_lens.iter() {
        tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; len]),
        });
    }
    tx_vbytes_est(&tx)
}

pub fn estimate_reveal_fee_for_address(
    tap_script: &ScriptBuf,
    tap_info: &TaprootSpendInfo,
    recipient_spk_len: usize,
    fee_rate: FeeRate,
) -> Result<u64> {
    let cb = tap_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .ok_or(anyhow!("failed to create control block"))?;
    let vb = script_spend_vbytes(
        1,
        tap_script,
        &ScriptBuf::from_bytes(cb.serialize()),
        &[recipient_spk_len],
    );
    fee_rate
        .fee_vb(vb)
        .map_or(Err(anyhow!("fee calculation overflow")), |a| Ok(a.to_sat()))
}

pub fn build_dummy_tx(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

fn dummy_txin() -> TxIn {
    TxIn {
        ..Default::default()
    }
}

pub fn estimate_fee_with_dummy_key_witness(tx: &Transaction, fee_rate: FeeRate) -> Option<u64> {
    let mut t = tx.clone();
    for inp in &mut t.input {
        let mut w = Witness::new();
        w.push(vec![0u8; SCHNORR_SIGNATURE_SIZE]);
        inp.witness = w;
    }
    let vb = tx_vbytes_est(&t);
    fee_rate.fee_vb(vb).map(|a| a.to_sat())
}

pub fn split_even_chunks(data: &[u8], parts: usize) -> Result<Vec<Vec<u8>>> {
    if parts == 0 {
        return Err(anyhow!("parts must be > 0"));
    }
    let total = data.len();
    let base = total / parts;
    let rem = total % parts;
    let mut chunks = Vec::with_capacity(parts);
    let mut off = 0usize;
    for i in 0..parts {
        let take = base + if i < rem { 1 } else { 0 };
        chunks.push(data[off..off + take].to_vec());
        off += take;
    }
    Ok(chunks)
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
