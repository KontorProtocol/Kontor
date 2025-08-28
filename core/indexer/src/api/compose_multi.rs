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
use futures_util::future::OptionFuture;

use bon::Builder;

use base64::engine::general_purpose::STANDARD as base64;
use bitcoin::Txid;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::bitcoin_client::Client;

#[derive(Debug, Serialize, Deserialize)]
pub struct ParticipantMultiQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub funding_utxo_ids: String,
    pub script_data: String,
    pub change_output: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct ComposeMultiQuery {
    pub participants: Vec<ParticipantMultiQuery>,
    pub sat_per_vbyte: u64,
    pub envelope: Option<u64>,
    pub chained_script_data: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParticipantMultiInputs {
    pub address: Address,
    pub x_only_public_key: XOnlyPublicKey,
    pub funding_utxos: Vec<(OutPoint, TxOut)>,
    pub script_data: Vec<u8>,
    pub change_output: bool,
}

#[derive(Clone, Serialize, Builder)]
pub struct ComposeMultiInputs {
    pub participants: Vec<ParticipantMultiInputs>,
    pub fee_rate: FeeRate,
    pub envelope: u64,
    pub chained_script_data: Option<Vec<u8>>,
}

impl ComposeMultiInputs {
    pub async fn from_query(query: ComposeMultiQuery, bitcoin_client: &Client) -> Result<Self> {
        if query.participants.is_empty() {
            return Err(anyhow!("participants cannot be empty"));
        }
        if query.participants.len() > 16 {
            return Err(anyhow!("too many participants"));
        }

        let fee_rate =
            FeeRate::from_sat_per_vb(query.sat_per_vbyte).ok_or(anyhow!("Invalid fee rate"))?;
        let chained_script_data_bytes = query
            .chained_script_data
            .map(|chained_data| base64.decode(chained_data))
            .transpose()?;
        let envelope = query.envelope.unwrap_or(546);

        let mut participants: Vec<ParticipantMultiInputs> =
            Vec::with_capacity(query.participants.len());
        for qp in query.participants {
            let address =
                Address::from_str(&qp.address)?.require_network(bitcoin::Network::Bitcoin)?;
            if !matches!(address.address_type(), Some(AddressType::P2tr)) {
                return Err(anyhow!("Invalid address type"));
            }
            let x_only_public_key = XOnlyPublicKey::from_str(&qp.x_only_public_key)?;
            let funding_utxos = get_utxos(bitcoin_client, qp.funding_utxo_ids).await?;
            for (_, txo) in &funding_utxos {
                if txo.script_pubkey != address.script_pubkey() {
                    return Err(anyhow!("funding utxo does not match participant address"));
                }
            }
            let script_data = base64.decode(&qp.script_data)?;
            participants.push(ParticipantMultiInputs {
                address,
                x_only_public_key,
                funding_utxos,
                script_data,
                change_output: qp.change_output.unwrap_or(false),
            });
        }

        Ok(Self {
            participants,
            fee_rate,
            envelope,
            chained_script_data: chained_script_data_bytes,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TapLeafScriptMulti {
    #[serde(rename = "leafVersion")]
    pub leaf_version: LeafVersion,
    pub script: ScriptBuf,
    #[serde(rename = "controlBlock")]
    pub control_block: ScriptBuf,
}

#[derive(Debug, Serialize, Deserialize, Builder)]
pub struct ComposeMultiOutputs {
    pub commit_transaction: Transaction,
    pub commit_transaction_hex: String,
    pub commit_psbt_hex: String,
    pub reveal_transaction: Transaction,
    pub reveal_transaction_hex: String,
    pub reveal_psbt_hex: String,
    pub tap_leaf_scripts: Vec<TapLeafScriptMulti>,
    pub tap_scripts: Vec<ScriptBuf>,
}

#[derive(Builder)]
pub struct CommitMultiInputs {
    pub participants: Vec<ParticipantMultiInputs>,
    pub fee_rate: FeeRate,
    pub envelope: u64,
}

impl From<ComposeMultiInputs> for CommitMultiInputs {
    fn from(value: ComposeMultiInputs) -> Self {
        Self {
            participants: value.participants,
            fee_rate: value.fee_rate,
            envelope: value.envelope,
        }
    }
}

#[derive(Builder, Serialize, Deserialize)]
pub struct CommitMultiOutputs {
    pub commit_transaction: Transaction,
    pub commit_transaction_hex: String,
    pub commit_psbt_hex: String,
    pub tap_leaf_scripts: Vec<TapLeafScriptMulti>,
    pub tap_scripts: Vec<ScriptBuf>,
}

#[derive(Serialize, Deserialize)]
pub struct RevealMultiQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub commit_output: String,
    pub commit_script_data: String,
    pub sat_per_vbyte: u64,
    pub funding_utxo_ids: Option<String>,
    pub envelope: Option<u64>,
    pub reveal_output: Option<String>,
    pub chained_script_data: Option<String>,
    pub op_return_data: Option<String>,
}

#[derive(Builder)]
pub struct RevealMultiInputs {
    pub address: Address,
    pub x_only_public_key: XOnlyPublicKey,
    pub commit_script_data: Vec<u8>,
    pub commit_output: (OutPoint, TxOut),
    pub fee_rate: FeeRate,
    pub envelope: u64,
    pub funding_utxos: Option<Vec<(OutPoint, TxOut)>>,
    pub reveal_output: Option<TxOut>,
    pub chained_script_data: Option<Vec<u8>>,
    pub op_return_data: Option<Vec<u8>>,
}

impl RevealMultiInputs {
    pub async fn from_query(query: RevealMultiQuery, bitcoin_client: &Client) -> Result<Self> {
        let address =
            Address::from_str(&query.address)?.require_network(bitcoin::Network::Bitcoin)?;
        let x_only_public_key = XOnlyPublicKey::from_str(&query.x_only_public_key)?;

        let commit_script_data = base64.decode(&query.commit_script_data)?;

        let commit_outpoint = OutPoint::from_str(&query.commit_output)?;

        let commit_output = (
            commit_outpoint,
            bitcoin_client
                .get_raw_transaction(&commit_outpoint.txid)
                .await
                .map_err(|e| anyhow!("Failed to fetch transaction: {}", e))?
                .output[commit_outpoint.vout as usize]
                .clone(),
        );

        let fee_rate =
            FeeRate::from_sat_per_vb(query.sat_per_vbyte).ok_or(anyhow!("Invalid fee rate"))?;

        let funding_utxos = OptionFuture::from(
            query
                .funding_utxo_ids
                .map(|ids| get_utxos(bitcoin_client, ids)),
        )
        .await
        .transpose()?;

        let reveal_output = query
            .reveal_output
            .map(|output| -> Result<_> {
                let output_split = output.split(':').collect::<Vec<&str>>();
                let value = u64::from_str(output_split[0])?;
                let script_pubkey = ScriptBuf::from_hex(output_split[1])?;
                Ok(TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey,
                })
            })
            .transpose()?;

        let chained_script_data_bytes = query
            .chained_script_data
            .map(|chained_data| base64.decode(chained_data))
            .transpose()?;

        let op_return_data_bytes = query
            .op_return_data
            .map(|op_return_data| base64.decode(op_return_data))
            .transpose()?;

        let envelope = query.envelope.unwrap_or(546);

        Ok(Self {
            address,
            x_only_public_key,
            commit_script_data,
            commit_output,
            fee_rate,
            funding_utxos,
            envelope,
            reveal_output,
            chained_script_data: chained_script_data_bytes,
            op_return_data: op_return_data_bytes,
        })
    }
}

#[derive(Builder, Serialize, Deserialize)]
pub struct RevealMultiOutputs {
    pub transaction: Transaction,
    pub transaction_hex: String,
    pub psbt: Psbt,
    pub psbt_hex: String,
    pub chained_tap_script: Option<ScriptBuf>,
    pub chained_tap_leaf_script: Option<TapLeafScriptMulti>,
}

pub fn compose_multi(params: ComposeMultiInputs) -> Result<ComposeMultiOutputs> {
    // Commit for multiple participants
    let commit_outputs = compose_commit_multi(CommitMultiInputs::from(params.clone()))?;

    // Reveal inline
    let commit_tx = commit_outputs.commit_transaction.clone();
    let commit_txid = commit_tx.compute_txid();

    let mut reveal_inputs: Vec<TxIn> = Vec::new();
    let mut reveal_prevouts: Vec<TxOut> = Vec::new();
    for (i, o) in commit_tx.output.iter().enumerate() {
        reveal_inputs.push(TxIn {
            previous_output: OutPoint {
                txid: commit_txid,
                vout: i as u32,
            },
            ..Default::default()
        });
        reveal_prevouts.push(o.clone());
    }

    let mut reveal_outputs_vec: Vec<TxOut> = params
        .participants
        .iter()
        .map(|p| TxOut {
            value: Amount::from_sat(0),
            script_pubkey: p.address.script_pubkey(),
        })
        .collect();

    // Sizing using script-spend for each participant input
    const SCHNORR_SIGNATURE_SIZE: usize = 64;
    let input_tuples_reveal: Vec<(TxIn, TxOut)> = reveal_inputs
        .clone()
        .into_iter()
        .zip(reveal_prevouts.clone())
        .collect();

    let mut taps: Vec<(ScriptBuf, TaprootSpendInfo)> = Vec::new();
    for p in &params.participants {
        let (tap_script, tap_info, _) =
            build_tap_script_and_script_address_multi(p.x_only_public_key, p.script_data.clone())?;
        taps.push((tap_script, tap_info));
    }

    let change_reveal = calculate_change(
        |i, witness| {
            let (tap_script, tap_info) = &taps[i];
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
            witness.push(tap_script.clone());
            witness.push(
                tap_info
                    .control_block(&(tap_script.clone(), LeafVersion::TapScript))
                    .expect("cb")
                    .serialize(),
            );
        },
        input_tuples_reveal,
        reveal_outputs_vec.clone(),
        params.fee_rate,
        false,
    )
    .ok_or(anyhow!("Inputs are insufficient to cover the reveal"))?;

    let per_commit_vals: Vec<u64> = reveal_prevouts
        .iter()
        .take(params.participants.len())
        .map(|o| o.value.to_sat())
        .collect();
    let total_commit: u64 = per_commit_vals.iter().sum();
    let mut rem = change_reveal;
    for i in 0..params.participants.len() {
        let share = if i == params.participants.len() - 1 {
            rem
        } else {
            change_reveal.saturating_mul(per_commit_vals[i]) / total_commit
        };
        rem = rem.saturating_sub(share);
        reveal_outputs_vec[i].value = Amount::from_sat(share);
    }

    let reveal_transaction = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: reveal_inputs.clone(),
        output: reveal_outputs_vec.clone(),
    };
    let reveal_transaction_hex = hex::encode(serialize_tx(&reveal_transaction));

    let commit_psbt_hex = Psbt::from_unsigned_tx(commit_tx.clone())?.serialize_hex();
    let mut reveal_psbt = Psbt::from_unsigned_tx(reveal_transaction.clone())?;
    for (i, input) in reveal_psbt.inputs.iter_mut().enumerate() {
        input.witness_utxo = Some(reveal_prevouts[i].clone());
        input.tap_internal_key = Some(params.participants[i].x_only_public_key);
        input.tap_merkle_root = Some(taps[i].1.merkle_root().expect("merkle"));
    }
    let reveal_psbt_hex = reveal_psbt.serialize_hex();

    Ok(ComposeMultiOutputs::builder()
        .commit_transaction(commit_tx)
        .commit_transaction_hex(hex::encode(serialize_tx(
            &commit_outputs.commit_transaction,
        )))
        .commit_psbt_hex(commit_psbt_hex)
        .reveal_transaction(reveal_transaction)
        .reveal_transaction_hex(reveal_transaction_hex)
        .reveal_psbt_hex(reveal_psbt_hex)
        .tap_leaf_scripts(commit_outputs.tap_leaf_scripts)
        .tap_scripts(commit_outputs.tap_scripts)
        .build())
}

pub fn compose_commit_multi(params: CommitMultiInputs) -> Result<CommitMultiOutputs> {
    // Flatten inputs across all participants
    let mut inputs: Vec<TxIn> = Vec::new();
    let mut prevouts: Vec<TxOut> = Vec::new();
    for p in &params.participants {
        for (op, txo) in &p.funding_utxos {
            inputs.push(TxIn {
                previous_output: *op,
                ..Default::default()
            });
            prevouts.push(txo.clone());
        }
    }

    // One script output per participant, envelope value initially
    let mut outputs: Vec<TxOut> = Vec::new();
    let mut tap_scripts: Vec<ScriptBuf> = Vec::new();
    let mut tap_leafs: Vec<TapLeafScriptMulti> = Vec::new();
    for p in &params.participants {
        let (tap_script, taproot_spend_info, script_spendable_address) =
            build_tap_script_and_script_address_multi(p.x_only_public_key, p.script_data.clone())?;
        outputs.push(TxOut {
            value: Amount::from_sat(params.envelope),
            script_pubkey: script_spendable_address.script_pubkey(),
        });
        tap_leafs.push(TapLeafScriptMulti {
            leaf_version: LeafVersion::TapScript,
            script: tap_script.clone(),
            control_block: ScriptBuf::from_bytes(
                taproot_spend_info
                    .control_block(&(tap_script.clone(), LeafVersion::TapScript))
                    .expect("cb")
                    .serialize(),
            ),
        });
        tap_scripts.push(tap_script);
    }

    const SCHNORR_SIGNATURE_SIZE: usize = 64;
    let input_tuples: Vec<(TxIn, TxOut)> =
        inputs.clone().into_iter().zip(prevouts.clone()).collect();
    let change_amount = calculate_change(
        |_, witness| {
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
        },
        input_tuples,
        outputs.clone(),
        params.fee_rate,
        false,
    )
    .ok_or(anyhow!("Change amount is negative"))?;

    // Distribute change proportionally to participant input sum
    let per_participant_input_sum: Vec<u64> = params
        .participants
        .iter()
        .map(|p| p.funding_utxos.iter().map(|(_, t)| t.value.to_sat()).sum())
        .collect();
    let total_input_sum: u64 = per_participant_input_sum.iter().sum();
    let mut remaining = change_amount;
    let len = outputs.len();
    for i in 0..len {
        let share = if i == len - 1 {
            remaining
        } else {
            change_amount.saturating_mul(per_participant_input_sum[i]) / total_input_sum
        };
        remaining = remaining.saturating_sub(share);
        outputs[i].value += Amount::from_sat(share);
    }

    let commit_transaction = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };
    let commit_transaction_hex = hex::encode(serialize_tx(&commit_transaction));
    let commit_psbt_hex = Psbt::from_unsigned_tx(commit_transaction.clone())?.serialize_hex();

    Ok(CommitMultiOutputs::builder()
        .commit_transaction(commit_transaction)
        .commit_transaction_hex(commit_transaction_hex)
        .commit_psbt_hex(commit_psbt_hex)
        .tap_leaf_scripts(tap_leafs)
        .tap_scripts(tap_scripts)
        .build())
}

pub fn compose_reveal_multi(params: RevealMultiInputs) -> Result<RevealMultiOutputs> {
    const SCHNORR_SIGNATURE_SIZE: usize = 64;

    let mut reveal_transaction = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: params.commit_output.0,
            ..Default::default()
        }],
        output: vec![],
    };
    let commit_output = params.commit_output.clone();

    if let Some(reveal_output) = params.reveal_output {
        reveal_transaction.output.push(reveal_output);
    }

    let mut chained_tap_script_opt: Option<ScriptBuf> = None;

    if let Some(chained_script_data) = params.chained_script_data {
        // if chained_script_data is provided, script_spendable_address output for the new commit
        let (chained_tap_script_for_return, _, chained_script_spendable_address) =
            build_tap_script_and_script_address_multi(
                params.x_only_public_key,
                chained_script_data,
            )?;

        reveal_transaction.output.push(TxOut {
            value: Amount::from_sat(params.envelope),
            script_pubkey: chained_script_spendable_address.script_pubkey(),
        });
        chained_tap_script_opt = Some(chained_tap_script_for_return);
    }

    if let Some(op_return_data) = params.op_return_data {
        // if op_return data, add op_return output

        reveal_transaction.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: {
                let mut op_return_script = ScriptBuf::new();
                op_return_script.push_opcode(OP_RETURN);
                op_return_script.push_slice(b"kon");
                op_return_script.push_slice(PushBytesBuf::try_from(op_return_data.to_vec())?);

                op_return_script
            },
        });
    }
    let (tap_script, taproot_spend_info, _) = build_tap_script_and_script_address_multi(
        params.x_only_public_key,
        params.commit_script_data,
    )?;

    let control_block = taproot_spend_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .ok_or(anyhow!("Failed to create control block"))?;

    let f = |i: usize, witness: &mut Witness| {
        if i > 0 {
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
        } else {
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
            witness.push(tap_script.clone());
            witness.push(control_block.serialize());
        }
    };
    let mut input_tuples = vec![(
        reveal_transaction.input[0].clone(),
        params.commit_output.1.clone(),
    )];

    let mut change_amount = calculate_change(
        f,
        input_tuples.clone(),
        reveal_transaction.output.clone(),
        params.fee_rate,
        false,
    );

    if change_amount.is_none() {
        match params.funding_utxos.clone() {
            Some(funding_utxos) => {
                funding_utxos.iter().for_each(|(outpoint, _)| {
                    reveal_transaction.input.push(TxIn {
                        previous_output: *outpoint,
                        ..Default::default()
                    });
                });
                input_tuples = reveal_transaction
                    .input
                    .clone()
                    .into_iter()
                    .zip(
                        vec![params.commit_output]
                            .into_iter()
                            .chain(funding_utxos)
                            .map(|(_, txout)| txout),
                    )
                    .collect();

                change_amount = calculate_change(
                    f,
                    input_tuples.clone(),
                    reveal_transaction.output.clone(),
                    params.fee_rate,
                    false,
                );
            }
            None => {
                return Err(anyhow!("Inputs are insufficient to cover the reveal"));
            }
        }
    }

    let reveal_change: u64 = change_amount.ok_or(anyhow!("Reveal change amount is negative"))?;

    if reveal_transaction.output.is_empty() {
        let change_amount = calculate_change(
            f,
            input_tuples,
            reveal_transaction.output.clone(),
            params.fee_rate,
            true,
        );
        let reveal_change: u64 =
            change_amount.ok_or(anyhow!("Reveal change amount is negative"))?;
        if reveal_change > 546 {
            reveal_transaction.output.push(TxOut {
                value: Amount::from_sat(reveal_change),
                script_pubkey: params.address.script_pubkey(),
            });
        } else {
            reveal_transaction.output.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: {
                    let mut op_return_script = ScriptBuf::new();
                    op_return_script.push_opcode(OP_RETURN);
                    op_return_script.push_slice([0; 3]);

                    op_return_script
                },
            });
        }
    } else if reveal_change > 546 {
        // if change is above the dust limit, calculate the new fee with a change output, and check once more that there is enough change to cover the new tx size fee
        let change_amount = calculate_change(
            f,
            input_tuples,
            reveal_transaction.output.clone(),
            params.fee_rate,
            true,
        );

        if let Some(v) = change_amount
            && v > 546
        {
            reveal_transaction.output.push(TxOut {
                value: Amount::from_sat(v),
                script_pubkey: params.address.script_pubkey(),
            });
        };
    }
    let reveal_transaction_hex = hex::encode(serialize_tx(&reveal_transaction));
    let mut psbt = Psbt::from_unsigned_tx(reveal_transaction.clone())?;
    psbt.inputs[0].witness_utxo = Some(commit_output.1.clone());
    psbt.inputs[0].tap_internal_key = Some(params.x_only_public_key);
    psbt.inputs[0].tap_merkle_root = Some(
        taproot_spend_info
            .merkle_root()
            .expect("Should contain merkle root as script was provided above"),
    );

    if let Some(funding_utxos) = params.funding_utxos {
        psbt.inputs
            .iter_mut()
            .skip(1)
            .enumerate()
            .for_each(|(i, input)| {
                input.witness_utxo = Some(funding_utxos[i].1.clone());
                input.tap_internal_key = Some(params.x_only_public_key);
            });
    }
    let psbt_hex = psbt.serialize_hex();
    let base_builder = RevealMultiOutputs::builder()
        .transaction(reveal_transaction)
        .transaction_hex(reveal_transaction_hex)
        .psbt(psbt)
        .psbt_hex(psbt_hex);

    // if the reveal tx also contains a commit, append the chained commit data
    let reveal_outputs = match chained_tap_script_opt {
        Some(chained_tap_script) => base_builder
            .chained_tap_script(chained_tap_script.clone())
            .chained_tap_leaf_script(TapLeafScriptMulti {
                leaf_version: LeafVersion::TapScript,
                script: chained_tap_script,
                control_block: ScriptBuf::new(),
            })
            .build(),
        _ => base_builder.build(),
    };

    Ok(reveal_outputs)
}

pub fn build_tap_script_and_script_address_multi(
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
