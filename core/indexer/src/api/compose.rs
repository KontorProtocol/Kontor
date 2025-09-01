use anyhow::{Result, anyhow};
use base64::prelude::*;
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

use base64::engine::general_purpose::STANDARD as base64;
use bitcoin::Txid;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    str::FromStr,
};

use crate::bitcoin_client::Client;

// Hardening limits
const MAX_PARTICIPANTS: usize = 10;
const MAX_SCRIPT_BYTES: usize = 16 * 1024; // 16 KiB
const MAX_OP_RETURN_BYTES: usize = 80; // Standard policy
const MIN_ENVELOPE_SATS: u64 = 330; // P2TR dust floor

#[derive(Serialize, Deserialize)]
pub struct ComposeAddressQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub funding_utxo_ids: String,
}

#[derive(Serialize, Deserialize)]
pub struct ComposeQuery {
    pub addresses: Vec<ComposeAddressQuery>,
    pub script_data: String,
    pub sat_per_vbyte: u64,
    pub change_output: Option<bool>,
    pub envelope: Option<u64>,
    pub chained_script_data: Option<String>,
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
    pub change_output: Option<bool>,
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
                Ok(ComposeAddressInputs {
                    address,
                    x_only_public_key,
                    funding_utxos,
                })
            }))
            .await?;

        let fee_rate =
            FeeRate::from_sat_per_vb(query.sat_per_vbyte).ok_or(anyhow!("Invalid fee rate"))?;

        let script_data = base64.decode(&query.script_data)?;
        if script_data.is_empty() || script_data.len() > MAX_SCRIPT_BYTES {
            return Err(anyhow!("script data size invalid"));
        }

        let chained_script_data_bytes = query
            .chained_script_data
            .map(|chained_data| base64.decode(chained_data))
            .transpose()?;
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
            change_output: query.change_output,
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

#[derive(Debug, Serialize, Deserialize, Builder)]
pub struct ComposeAddressOutputs {
    // { "<address>": { tap_script: ..., tap_leaf_script: ... }, ... }
    pub address_tap_script: BTreeMap<String, TapScriptPair>,
}

#[derive(Debug, Serialize, Deserialize, Builder)]
pub struct ComposeAddressChainedOutputs {
    pub address_chained_tap_script: BTreeMap<String, TapScriptPair>,
}

#[derive(Debug, Serialize, Deserialize, Builder)]
pub struct ComposeOutputs {
    pub commit_transaction: Transaction,
    pub commit_transaction_hex: String,
    pub commit_psbt_hex: String,
    pub reveal_transaction: Transaction,
    pub reveal_transaction_hex: String,
    pub reveal_psbt_hex: String,
    pub address_tap_script: BTreeMap<String, TapScriptPair>,
    pub address_chained_tap_script: BTreeMap<String, TapScriptPair>,
}

#[derive(Builder)]
pub struct CommitInputs {
    pub addresses: Vec<ComposeAddressInputs>,
    pub script_data: Vec<u8>,
    pub fee_rate: FeeRate,
    pub envelope: u64,
    pub change_output: Option<bool>,
}

impl From<ComposeInputs> for CommitInputs {
    fn from(value: ComposeInputs) -> Self {
        Self {
            addresses: value.addresses,
            script_data: value.script_data,
            fee_rate: value.fee_rate,
            change_output: value.change_output,
            envelope: value.envelope,
        }
    }
}

#[derive(Builder, Serialize, Deserialize)]
pub struct CommitOutputs {
    pub commit_transaction: Transaction,
    pub commit_transaction_hex: String,
    pub commit_psbt_hex: String,
    pub address_tap_script: BTreeMap<String, TapScriptPair>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RevealParticipantQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub commit_vout: u32,
    pub commit_script_data: String,
    pub envelope: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct RevealQuery {
    pub commit_txid: String,
    pub sat_per_vbyte: u64,
    pub participants: Vec<RevealParticipantQuery>,
    pub op_return_data: Option<String>,
    pub envelope: Option<u64>,
    pub chained_script_data: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct RevealParticipantInputs {
    pub address: Address,
    pub x_only_public_key: XOnlyPublicKey,
    pub commit_outpoint: OutPoint,
    pub commit_prevout: TxOut,
    pub commit_script_data: Vec<u8>,
}

#[derive(Builder)]
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
            let commit_prevout = tx.output[commit_outpoint.vout as usize].clone();
            let commit_script_data = base64.decode(&p.commit_script_data)?;

            participants_inputs.push(RevealParticipantInputs {
                address,
                x_only_public_key,
                commit_outpoint,
                commit_prevout,
                commit_script_data,
            });
        }

        let op_return_data = query.op_return_data.map(|s| base64.decode(s)).transpose()?;

        let envelope = query.envelope.unwrap_or(330);
        let chained_script_data = query
            .chained_script_data
            .map(|s| base64.decode(s))
            .transpose()?;

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
    pub address_chained_tap_script: BTreeMap<String, TapScriptPair>,
}

pub fn compose(params: ComposeInputs) -> Result<ComposeOutputs> {
    // Clone addresses before moving into compose_commit
    let addresses_clone = params.addresses.clone();

    // Build the commit tx
    let commit_outputs = compose_commit(CommitInputs {
        addresses: params.addresses,
        script_data: params.script_data.clone(),
        fee_rate: params.fee_rate,
        change_output: params.change_output,
        envelope: params.envelope,
    })?;

    // Build the reveal tx inputs (multi-participant, using saved chunks)
    let reveal_inputs = {
        let commit_txid = commit_outputs.commit_transaction.compute_txid();
        let mut participants: Vec<RevealParticipantInputs> =
            Vec::with_capacity(addresses_clone.len());

        for a in addresses_clone.iter() {
            let key = a.address.to_string();
            let pair = commit_outputs
                .address_tap_script
                .get(&key)
                .ok_or_else(|| anyhow!("missing TapScriptPair for {}", key))?;

            // locate vout by rebuilding the script address from the exact chunk we embedded
            let (_tap, _info, script_addr) = build_tap_script_and_script_address(
                a.x_only_public_key,
                pair.script_data_chunk.clone(),
            )?;
            let spk = script_addr.script_pubkey();
            let vout = commit_outputs
                .commit_transaction
                .output
                .iter()
                .position(|o| o.script_pubkey == spk)
                .ok_or_else(|| anyhow!("failed to locate commit vout for {}", key))?
                as u32;

            let commit_outpoint = OutPoint {
                txid: commit_txid,
                vout,
            };
            let commit_prevout = commit_outputs.commit_transaction.output[vout as usize].clone();

            participants.push(RevealParticipantInputs {
                address: a.address.clone(),
                x_only_public_key: a.x_only_public_key,
                commit_outpoint,
                commit_prevout,
                commit_script_data: pair.script_data_chunk.clone(),
            });
        }

        RevealInputs {
            commit_txid,
            fee_rate: params.fee_rate,
            participants,
            op_return_data: None,
            envelope: params.envelope,
            chained_script_data: params.chained_script_data.clone(),
        }
    };

    // Build the reveal tx
    let reveal_outputs = compose_reveal(reveal_inputs)?; // work with psbt here

    // Build the final outputs
    let compose_outputs = ComposeOutputs::builder()
        .commit_transaction(commit_outputs.commit_transaction)
        .commit_transaction_hex(commit_outputs.commit_transaction_hex)
        .commit_psbt_hex(commit_outputs.commit_psbt_hex)
        .reveal_transaction(reveal_outputs.transaction.clone())
        .reveal_transaction_hex(reveal_outputs.transaction_hex)
        .reveal_psbt_hex(reveal_outputs.psbt_hex)
        .address_tap_script(commit_outputs.address_tap_script)
        .address_chained_tap_script(reveal_outputs.address_chained_tap_script)
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

    let mut address_tap_script: BTreeMap<String, TapScriptPair> = BTreeMap::new();

    // Split script_data into N contiguous chunks
    let num_addrs = params.addresses.len();
    if num_addrs == 0 {
        return Err(anyhow!("No addresses provided"));
    }
    if params.script_data.is_empty() {
        return Err(anyhow!("script data cannot be empty"));
    }
    let data_len = params.script_data.len();
    let base = data_len / num_addrs;
    let rem = data_len % num_addrs;
    let mut offset = 0;

    for (i, addr) in params.addresses.iter().enumerate() {
        // Determine chunk slice
        let take = base + if i < rem { 1 } else { 0 };
        let chunk = params.script_data[offset..offset + take].to_vec();
        offset += take;

        // Build tapscript for this address
        let (tap_script, tap_info, script_spendable_address) =
            build_tap_script_and_script_address(addr.x_only_public_key, chunk.clone())?;

        // Estimate reveal fee using helper
        let reveal_fee = estimate_reveal_fee_for_address(
            &tap_script,
            &tap_info,
            addr.address.script_pubkey().len(),
            params.envelope,
            params.fee_rate,
        );

        // Script output must cover envelope + reveal fee
        let script_value = params.envelope.saturating_add(reveal_fee);

        // Select only necessary UTXOs for this address to cover script_value + commit delta fee
        let mut utxos = addr.funding_utxos.clone();
        utxos.sort_by_key(|(_, txout)| std::cmp::Reverse(txout.value.to_sat()));

        let mut selected: Vec<(OutPoint, TxOut)> = Vec::new();
        let mut selected_sum: u64 = 0;

        loop {
            // Estimate commit delta fee for current tentative selection using helper
            let commit_delta_fee = estimate_commit_delta_fee(
                &commit_psbt.unsigned_tx,
                selected.len(),
                |_, w: &mut Witness| w.push(vec![0u8; 65]),
                script_spendable_address.script_pubkey().len(),
                addr.address.script_pubkey().len(),
                params.fee_rate,
            );

            let required_total = script_value.saturating_add(commit_delta_fee);
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
        // Recompute fee more precisely by sizing current tx and a tx with one extra change output,
        // then subtracting the base-sized fee to get exact delta for change.
        let base_vb = tx_vbytes_est(&commit_psbt.unsigned_tx);
        let base_fee = params.fee_rate.fee_vb(base_vb).expect("fee calc").to_sat();
        let mut with_change = commit_psbt.unsigned_tx.clone();
        with_change.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: addr.address.script_pubkey(),
        });
        let with_change_vb = tx_vbytes_est(&with_change);
        let with_change_fee = params
            .fee_rate
            .fee_vb(with_change_vb)
            .expect("fee calc")
            .to_sat();
        let change_fee_delta = with_change_fee.saturating_sub(base_fee);
        let required_total = script_value.saturating_add(change_fee_delta);
        let change_value = selected_sum.saturating_sub(required_total);
        if change_value > params.envelope {
            commit_psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(change_value),
                script_pubkey: addr.address.script_pubkey(),
            });
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
        address_tap_script.insert(
            addr.address.to_string(),
            TapScriptPair {
                tap_script: tap_script.clone(),
                tap_leaf_script: tap_leaf,
                script_data_chunk: chunk,
            },
        );
    }

    let commit_transaction = commit_psbt.unsigned_tx.clone();
    let commit_transaction_hex = hex::encode(serialize_tx(&commit_transaction));
    let commit_psbt_hex = commit_psbt.serialize_hex();

    Ok(CommitOutputs::builder()
        .commit_transaction(commit_transaction)
        .commit_transaction_hex(commit_transaction_hex)
        .commit_psbt_hex(commit_psbt_hex)
        .address_tap_script(address_tap_script)
        .build())
}

pub fn compose_reveal(params: RevealInputs) -> Result<RevealOutputs> {
    const SCHNORR_SIGNATURE_SIZE: usize = 65;

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

    // Optional OP_RETURN first (keeps vsize expectations stable)
    if let Some(data) = params.op_return_data.clone() {
        if data.len() > MAX_OP_RETURN_BYTES {
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
                s.push_slice(b"kon");
                s.push_slice(PushBytesBuf::try_from(data)?);
                s
            },
        });
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
    let mut address_chained_tap_script: BTreeMap<String, TapScriptPair> = BTreeMap::new();
    if let Some(chained) = params.chained_script_data.clone() {
        let n = params.participants.len();
        if n == 0 {
            return Err(anyhow!("participants cannot be empty"));
        }
        if params.envelope < MIN_ENVELOPE_SATS {
            return Err(anyhow!("envelope below dust"));
        }
        let total = chained.len();
        let base = total / n;
        let rem = total % n;
        let mut off = 0usize;
        for (i, p) in params.participants.iter().enumerate() {
            let take = base + if i < rem { 1 } else { 0 };
            let chunk = chained[off..off + take].to_vec();
            off += take;

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
            address_chained_tap_script.insert(
                p.address.to_string(),
                TapScriptPair {
                    tap_script: ch_tap,
                    tap_leaf_script: tap_leaf,
                    script_data_chunk: chunk,
                },
            );
        }
    }

    // Prepare PSBT and set per-input metadata
    let mut psbt = Psbt::from_unsigned_tx(reveal_transaction.clone())?;
    for (idx, p) in params.participants.iter().enumerate() {
        psbt.inputs[idx].witness_utxo = Some(p.commit_prevout.clone());
        psbt.inputs[idx].tap_internal_key = Some(p.x_only_public_key);
        // Use commit script merkle root
        let (tap_script, tap_info, _) =
            build_tap_script_and_script_address(p.x_only_public_key, p.commit_script_data.clone())?;
        let _ = tap_script; // not needed further here
        psbt.inputs[idx].tap_merkle_root = Some(
            tap_info
                .merkle_root()
                .expect("merkle root present for provided script"),
        );
    }

    // Fee sizing using calculate_change with exact witness shapes per input
    let f_for_index = |idx: usize| {
        let (ref tap_script, ref control_block) = commit_scripts[idx];
        move |_: usize, witness: &mut Witness| {
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
            witness.push(tap_script.clone());
            witness.push(control_block.clone());
        }
    };

    // For each owner, compute standalone change using single-input sizing
    for (i, p) in params.participants.iter().enumerate() {
        let single_input = vec![(
            reveal_transaction.input[i].clone(),
            p.commit_prevout.clone(),
        )];
        let mut owner_outputs: Vec<TxOut> = Vec::new();
        if params.chained_script_data.is_some() {
            // One P2TR chained output at envelope
            owner_outputs.push(TxOut {
                value: Amount::from_sat(params.envelope),
                script_pubkey: ScriptBuf::from_bytes(vec![0; 34]),
            });
        }
        if let Some(change_i) = calculate_change(
            f_for_index(i),
            single_input,
            owner_outputs,
            params.fee_rate,
            false,
        )
        .and_then(|v| (v > params.envelope).then_some(v))
        {
            reveal_transaction.output.push(TxOut {
                value: Amount::from_sat(change_i),
                script_pubkey: p.address.script_pubkey(),
            });
        }
    }

    let reveal_transaction_hex = hex::encode(serialize_tx(&reveal_transaction));
    let psbt_hex = psbt.serialize_hex();
    let reveal_outputs = RevealOutputs::builder()
        .transaction(reveal_transaction)
        .transaction_hex(reveal_transaction_hex)
        .psbt(psbt)
        .psbt_hex(psbt_hex)
        .address_chained_tap_script(address_chained_tap_script)
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

fn calculate_change<F>(
    f: F,
    input_tuples: Vec<(TxIn, TxOut)>,
    outputs: Vec<TxOut>,
    fee_rate: FeeRate,
    change_output: bool,
) -> Option<u64>
where
    F: Fn(usize, &mut Witness),
{
    let mut input_sum = 0;
    let mut inputs = Vec::new();
    input_tuples
        .into_iter()
        .enumerate()
        .for_each(|(i, (mut txin, txout))| {
            f(i, &mut txin.witness);
            inputs.push(txin);
            input_sum += txout.value.to_sat();
        });

    let mut dummy_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    if change_output {
        dummy_tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0; 34]),
        });
    }
    let output_sum: u64 = dummy_tx.output.iter().map(|o| o.value.to_sat()).sum();

    let vsize = dummy_tx.vsize() as u64;
    let fee = fee_rate
        .fee_vb(vsize)
        .expect("Fee calculation should not overflow")
        .to_sat();

    input_sum.checked_sub(output_sum + fee)
}

// Fee estimation helpers for commit/reveal
fn tx_vbytes_est(tx: &Transaction) -> u64 {
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

fn estimate_reveal_fee_for_address(
    tap_script: &ScriptBuf,
    tap_info: &TaprootSpendInfo,
    recipient_spk_len: usize,
    envelope: u64,
    fee_rate: FeeRate,
) -> u64 {
    let mut dummy = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                vout: 0,
            },
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(envelope),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; recipient_spk_len]),
        }],
    };
    let mut w = Witness::new();
    w.push(vec![0u8; 65]);
    w.push(tap_script.clone());
    w.push(
        tap_info
            .control_block(&(tap_script.clone(), LeafVersion::TapScript))
            .expect("cb")
            .serialize(),
    );
    dummy.input[0].witness = w;
    let vb = tx_vbytes_est(&dummy);
    fee_rate.fee_vb(vb).expect("fee calc").to_sat()
}

fn estimate_commit_delta_fee<F>(
    base_tx: &Transaction,
    new_inputs_count: usize,
    f: F,
    script_spk_len: usize,
    change_spk_len: usize,
    fee_rate: FeeRate,
) -> u64
where
    F: Fn(usize, &mut Witness),
{
    let before_vb = tx_vbytes_est(base_tx);
    let mut temp = base_tx.clone();
    for i in 0..new_inputs_count {
        temp.input.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                vout: 0,
            },
            ..Default::default()
        });
        let idx = temp.input.len() - 1;
        let mut w = Witness::new();
        f(i, &mut w);
        temp.input[idx].witness = w;
    }
    temp.output.push(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: ScriptBuf::from_bytes(vec![0u8; script_spk_len]),
    });
    temp.output.push(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: ScriptBuf::from_bytes(vec![0u8; change_spk_len]),
    });
    let after_vb = tx_vbytes_est(&temp);
    let delta_vb = after_vb.saturating_sub(before_vb);
    fee_rate.fee_vb(delta_vb).expect("fee calc").to_sat()
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

    let funding_txs: Vec<Transaction> = bitcoin_client
        .get_raw_transactions(
            outpoints
                .iter()
                .map(|outpoint| outpoint.txid)
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .await
        .map_err(|e| anyhow!("Failed to fetch transactions: {}", e))?
        .into_iter()
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    if funding_txs.is_empty() {
        return Err(anyhow!("No funding transactions found"));
    }

    let funding_utxos: Vec<(OutPoint, TxOut)> = outpoints
        .into_iter()
        .zip(funding_txs.into_iter())
        .map(|(outpoint, tx)| (outpoint, tx.output[outpoint.vout as usize].clone()))
        .collect();

    Ok(funding_utxos)
}
