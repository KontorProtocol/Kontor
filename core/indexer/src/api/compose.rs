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

#[derive(Serialize, Deserialize)]
pub struct ComposeQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub funding_utxo_ids: String,
    pub script_data: String,
    pub sat_per_vbyte: u64,
    pub change_output: Option<bool>,
    pub envelope: Option<u64>,
    pub chained_script_data: Option<String>,
}

#[derive(Serialize, Builder)]
pub struct ComposeInputs {
    pub address: Address,
    pub x_only_public_key: XOnlyPublicKey,
    pub funding_utxos: Vec<(OutPoint, TxOut)>,
    pub script_data: Vec<u8>,
    pub fee_rate: FeeRate,
    pub envelope: u64,
    pub change_output: Option<bool>,
    pub chained_script_data: Option<Vec<u8>>,
}

impl ComposeInputs {
    pub async fn from_query(query: ComposeQuery, bitcoin_client: &Client) -> Result<Self> {
        let address =
            Address::from_str(&query.address)?.require_network(bitcoin::Network::Bitcoin)?;
        let address_type = address.address_type();

        if let Some(address_type) = address_type {
            if address_type != AddressType::P2tr {
                return Err(anyhow!("Invalid address type"));
            }
        }
        let x_only_public_key = XOnlyPublicKey::from_str(&query.x_only_public_key)?;

        let fee_rate =
            FeeRate::from_sat_per_vb(query.sat_per_vbyte).ok_or(anyhow!("Invalid fee rate"))?;

        let funding_utxos = get_utxos(bitcoin_client, query.funding_utxo_ids).await?;

        let script_data = base64.decode(&query.script_data)?;

        let chained_script_data_bytes = query
            .chained_script_data
            .map(|chained_data| base64.decode(chained_data))
            .transpose()?;
        let envelope = query.envelope.unwrap_or(546);

        Ok(Self {
            address,
            x_only_public_key,
            funding_utxos,
            script_data,
            fee_rate,
            change_output: query.change_output,
            envelope,
            chained_script_data: chained_script_data_bytes,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TapLeafScript {
    #[serde(rename = "leafVersion")]
    pub leaf_version: LeafVersion,
    pub script: ScriptBuf,
    #[serde(rename = "controlBlock")]
    pub control_block: ScriptBuf,
}

#[derive(Debug, Serialize, Deserialize, Builder)]
pub struct ComposeOutputs {
    pub commit_transaction: Transaction,
    pub commit_transaction_hex: String,
    pub commit_psbt_hex: String,
    pub reveal_transaction: Transaction,
    pub reveal_transaction_hex: String,
    pub reveal_psbt_hex: String,
    pub tap_leaf_script: TapLeafScript,
    pub tap_script: ScriptBuf,
    pub chained_tap_script: Option<ScriptBuf>,
    pub chained_tap_leaf_script: Option<TapLeafScript>,
}

#[derive(Builder)]
pub struct CommitInputs {
    pub address: Address,
    pub x_only_public_key: XOnlyPublicKey,
    pub funding_utxos: Vec<(OutPoint, TxOut)>,
    pub script_data: Vec<u8>,
    pub fee_rate: FeeRate,
    pub envelope: u64,
    pub change_output: Option<bool>,
}

impl From<ComposeInputs> for CommitInputs {
    fn from(value: ComposeInputs) -> Self {
        Self {
            address: value.address.clone(),
            x_only_public_key: value.x_only_public_key,
            funding_utxos: value.funding_utxos,
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
    pub tap_leaf_script: TapLeafScript,
    pub tap_script: ScriptBuf,
}

#[derive(Serialize, Deserialize)]
pub struct RevealQuery {
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
pub struct RevealInputs {
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

impl RevealInputs {
    pub async fn from_query(query: RevealQuery, bitcoin_client: &Client) -> Result<Self> {
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
pub struct RevealOutputs {
    pub transaction: Transaction,
    pub transaction_hex: String,
    pub psbt: Psbt,
    pub psbt_hex: String,
    pub chained_tap_script: Option<ScriptBuf>,
    pub chained_tap_leaf_script: Option<TapLeafScript>,
}

pub fn compose(params: ComposeInputs) -> Result<ComposeOutputs> {
    // Build the commit tx
    let commit_outputs = compose_commit(CommitInputs {
        address: params.address.clone(),
        x_only_public_key: params.x_only_public_key,
        funding_utxos: params.funding_utxos.clone(),
        script_data: params.script_data.clone(),
        fee_rate: params.fee_rate,
        change_output: params.change_output,
        envelope: params.envelope,
    })?;

    // Build the reveal tx inputs
    let reveal_inputs = {
        let builder = RevealInputs::builder()
            .x_only_public_key(params.x_only_public_key)
            .address(params.address.clone())
            .envelope(params.envelope)
            .commit_output((
                OutPoint {
                    txid: commit_outputs.commit_transaction.compute_txid(),
                    vout: 0,
                },
                commit_outputs.commit_transaction.output[0].clone(),
            ))
            .commit_script_data(params.script_data.clone())
            .fee_rate(params.fee_rate);

        // apply chained data if provided
        match (params.chained_script_data, params.change_output) {
            (Some(chained_data), Some(true)) => builder
                .chained_script_data(chained_data)
                .funding_utxos(vec![(
                    OutPoint {
                        txid: commit_outputs.commit_transaction.compute_txid(),
                        vout: 1,
                    },
                    commit_outputs.commit_transaction.output[1].clone(),
                )])
                .build(),
            (Some(chained_data), None) => builder.chained_script_data(chained_data).build(),
            (None, Some(true)) => builder
                .funding_utxos(vec![(
                    OutPoint {
                        txid: commit_outputs.commit_transaction.compute_txid(),
                        vout: 1,
                    },
                    commit_outputs.commit_transaction.output[1].clone(),
                )])
                .build(),
            _ => builder.build(),
        }
    };

    // Build the reveal tx
    let reveal_outputs = compose_reveal(reveal_inputs)?; // work with psbt here

    // Build the final outputs
    let compose_outputs = {
        let base_builder = ComposeOutputs::builder()
            .commit_transaction(commit_outputs.commit_transaction)
            .commit_transaction_hex(commit_outputs.commit_transaction_hex)
            .commit_psbt_hex(commit_outputs.commit_psbt_hex)
            .reveal_transaction(reveal_outputs.transaction.clone())
            .reveal_transaction_hex(reveal_outputs.transaction_hex)
            .reveal_psbt_hex(reveal_outputs.psbt_hex)
            .tap_leaf_script(commit_outputs.tap_leaf_script)
            .tap_script(commit_outputs.tap_script);

        match (
            reveal_outputs.chained_tap_script,
            reveal_outputs.chained_tap_leaf_script,
        ) {
            (Some(chained_tap_script), Some(chained_tap_leaf_script)) => base_builder
                .chained_tap_script(chained_tap_script)
                .chained_tap_leaf_script(chained_tap_leaf_script)
                .build(),

            _ => base_builder.build(),
        }
    };

    Ok(compose_outputs)
}

pub fn compose_commit(params: CommitInputs) -> Result<CommitOutputs> {
    let inputs: Vec<TxIn> = params
        .funding_utxos
        .iter()
        .map(|(outpoint, _)| TxIn {
            previous_output: *outpoint,
            ..Default::default()
        })
        .collect();

    let input_tuples = inputs
        .clone()
        .into_iter()
        .zip(
            params
                .funding_utxos
                .clone()
                .into_iter()
                .map(|(_, txout)| txout),
        )
        .collect();

    let mut outputs = Vec::new();

    let (tap_script, taproot_spend_info, script_spendable_address) =
        build_tap_script_and_script_address(params.x_only_public_key, params.script_data)?;

    outputs.push(TxOut {
        value: Amount::from_sat(params.envelope),
        script_pubkey: script_spendable_address.script_pubkey(),
    });

    const SCHNORR_SIGNATURE_SIZE: usize = 64;

    let change_amount = calculate_change(
        |_, witness| {
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
        },
        input_tuples,
        outputs.clone(),
        params.fee_rate,
        params.change_output.unwrap_or(false),
    )
    .ok_or(anyhow!("Change amount is negative"))?;

    if let Some(change_output) = params.change_output {
        if change_output {
            outputs.push(TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: params.address.script_pubkey(),
            });
        }
    } else {
        outputs[0].value += Amount::from_sat(change_amount);
    }

    let commit_transaction = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    let commit_transaction_hex = hex::encode(serialize_tx(&commit_transaction));

    let mut commit_psbt = Psbt::from_unsigned_tx(commit_transaction.clone())?;
    commit_psbt
        .inputs
        .iter_mut()
        .enumerate()
        .for_each(|(i, input)| {
            input.witness_utxo = Some(params.funding_utxos[i].1.clone());
            input.tap_internal_key = Some(params.x_only_public_key);
        });
    let commit_psbt_hex = commit_psbt.serialize_hex();

    let commit_outputs = CommitOutputs::builder()
        .commit_transaction(commit_transaction)
        .tap_script(tap_script.clone())
        .tap_leaf_script(TapLeafScript {
            leaf_version: LeafVersion::TapScript,
            script: tap_script.clone(),
            control_block: ScriptBuf::from_bytes(
                taproot_spend_info
                    .control_block(&(tap_script, LeafVersion::TapScript))
                    .expect("Should not fail to generate control block because script is included")
                    .serialize(),
            ),
        })
        .commit_transaction_hex(commit_transaction_hex)
        .commit_psbt_hex(commit_psbt_hex)
        .build();
    Ok(commit_outputs)
}

pub fn compose_reveal(params: RevealInputs) -> Result<RevealOutputs> {
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
            build_tap_script_and_script_address(params.x_only_public_key, chained_script_data)?;

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
    let (tap_script, taproot_spend_info, _) =
        build_tap_script_and_script_address(params.x_only_public_key, params.commit_script_data)?;

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

        if let Some(v) = change_amount {
            if v > 546 {
                reveal_transaction.output.push(TxOut {
                    value: Amount::from_sat(v),
                    script_pubkey: params.address.script_pubkey(),
                });
            }
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
    let base_builder = RevealOutputs::builder()
        .transaction(reveal_transaction)
        .transaction_hex(reveal_transaction_hex)
        .psbt(psbt)
        .psbt_hex(psbt_hex);

    // if the reveal tx also contains a commit, append the chained commit data
    let reveal_outputs = match chained_tap_script_opt {
        Some(chained_tap_script) => base_builder
            .chained_tap_script(chained_tap_script.clone())
            .chained_tap_leaf_script(TapLeafScript {
                leaf_version: LeafVersion::TapScript,
                script: chained_tap_script,
                control_block: ScriptBuf::new(),
            })
            .build(),
        _ => base_builder.build(),
    };

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
