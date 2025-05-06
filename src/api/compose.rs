use anyhow::{Result, anyhow};
use bitcoin::{
    Address, Amount, FeeRate, KnownHrp, OutPoint, Psbt, ScriptBuf, TxOut, Witness,
    absolute::LockTime,
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

#[derive(Builder)]
pub struct ComposeInputs<'a> {
    pub sender_address: &'a Address,
    pub internal_key: &'a XOnlyPublicKey,
    pub sender_utxos: Vec<(OutPoint, TxOut)>,
    pub script_data: &'a [u8],
    pub fee_rate: FeeRate,
    pub change_output: Option<bool>,
    pub envelope: Option<u64>,
    pub chained_script_data: Option<&'a [u8]>,
}

#[derive(Builder)]
pub struct ComposeOutputs {
    pub commit_transaction: Transaction,
    pub reveal_transaction: Transaction,
    pub tap_script: ScriptBuf,
    pub chained_tap_script: Option<ScriptBuf>,
}

#[derive(Builder)]
pub struct CommitInputs<'a> {
    pub sender_address: &'a Address,
    pub internal_key: &'a XOnlyPublicKey,
    pub sender_utxos: Vec<(OutPoint, TxOut)>,
    pub script_data: &'a [u8],
    pub fee_rate: FeeRate,
    pub change_output: Option<bool>,
    pub envelope: Option<u64>,
}

impl<'a> From<ComposeInputs<'a>> for CommitInputs<'a> {
    fn from(value: ComposeInputs<'a>) -> Self {
        Self {
            sender_address: value.sender_address,
            internal_key: value.internal_key,
            sender_utxos: value.sender_utxos,
            script_data: value.script_data,
            fee_rate: value.fee_rate,
            change_output: value.change_output,
            envelope: value.envelope,
        }
    }
}

#[derive(Builder)]
pub struct CommitOutputs {
    pub commit_transaction: Transaction,
    pub tap_script: ScriptBuf,
    pub taproot_spend_info: TaprootSpendInfo,
}

#[derive(Builder)]
pub struct RevealInputs<'a> {
    pub internal_key: &'a XOnlyPublicKey,
    pub sender_address: &'a Address,
    pub commit_output: (OutPoint, TxOut),
    pub tap_script: &'a ScriptBuf,
    pub taproot_spend_info: &'a TaprootSpendInfo,
    pub fee_rate: FeeRate,
    pub funding_outputs: Option<Vec<(OutPoint, TxOut)>>,
    pub envelope: Option<u64>,

    pub reveal_output: Option<TxOut>,
    pub chained_script_data: Option<&'a [u8]>,
    pub op_return_data: Option<&'a Vec<u8>>,
}

#[derive(Builder)]
pub struct RevealOutputs {
    pub transaction: Transaction,
    pub psbt: Psbt,
    pub chained_tap_script: Option<ScriptBuf>,
}

pub fn compose(params: ComposeInputs) -> Result<ComposeOutputs> {
    // Build the commit tx
    let commit_outputs = compose_commit(CommitInputs {
        sender_address: params.sender_address,
        internal_key: params.internal_key,
        sender_utxos: params.sender_utxos.clone(),
        script_data: params.script_data,
        fee_rate: params.fee_rate,
        change_output: params.change_output,
        envelope: params.envelope,
    })?;

    // Build the reveal tx inputs
    let reveal_inputs = {
        let builder = RevealInputs::builder()
            .internal_key(params.internal_key)
            .sender_address(params.sender_address)
            .commit_output((
                OutPoint {
                    txid: commit_outputs.commit_transaction.compute_txid(),
                    vout: 0,
                },
                commit_outputs.commit_transaction.output[0].clone(),
            ))
            .tap_script(&commit_outputs.tap_script)
            .taproot_spend_info(&commit_outputs.taproot_spend_info)
            .fee_rate(params.fee_rate);

        // apply chained data if provided
        match params.chained_script_data {
            Some(chained_data) => builder.chained_script_data(chained_data).build(),
            None => builder.build(),
        }
    };

    // Build the reveal tx
    let reveal_outputs = compose_reveal(reveal_inputs)?; // work with psbt here

    // Build the final outputs
    let compose_outputs = {
        let base_builder = ComposeOutputs::builder()
            .commit_transaction(commit_outputs.commit_transaction)
            .reveal_transaction(reveal_outputs.transaction.clone())
            .tap_script(commit_outputs.tap_script);

        match reveal_outputs.chained_tap_script {
            Some(chained_tap_script) => base_builder.chained_tap_script(chained_tap_script).build(),
            None => base_builder.build(),
        }
    };

    Ok(compose_outputs)
}

pub fn compose_commit(params: CommitInputs) -> Result<CommitOutputs> {
    let sender_address = params.sender_address;
    let internal_key = params.internal_key;
    let sender_utxos = params.sender_utxos;
    let script_data = params.script_data;
    let fee_rate: FeeRate = params.fee_rate;
    let envelope = params.envelope.unwrap_or(546);
    let inputs: Vec<TxIn> = sender_utxos
        .iter()
        .map(|(outpoint, _)| TxIn {
            previous_output: *outpoint,
            ..Default::default()
        })
        .collect();

    let input_tuples = inputs
        .clone()
        .into_iter()
        .zip(sender_utxos.clone().into_iter().map(|(_, txout)| txout))
        .collect();

    let mut outputs = Vec::new();

    let (tap_script, taproot_spend_info, script_spendable_address) =
        build_tap_script_and_script_address(internal_key, script_data)?;

    outputs.push(TxOut {
        value: Amount::from_sat(envelope),
        script_pubkey: script_spendable_address.script_pubkey(),
    });

    const SCHNORR_SIGNATURE_SIZE: usize = 64;

    let change_amount = calculate_change(
        |_, witness| {
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
        },
        input_tuples,
        outputs.clone(),
        fee_rate,
        params.change_output.unwrap_or(false),
    )
    .ok_or(anyhow!("Change amount is negative"))?;

    if let Some(change_output) = params.change_output {
        if change_output {
            outputs.push(TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: sender_address.script_pubkey(),
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

    let commit_outputs = CommitOutputs::builder()
        .commit_transaction(commit_transaction)
        .tap_script(tap_script)
        .taproot_spend_info(taproot_spend_info)
        .build();
    Ok(commit_outputs)
}

pub fn compose_reveal(params: RevealInputs) -> Result<RevealOutputs> {
    let envelope = params.envelope.unwrap_or(546);
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
    if let Some(reveal_output) = params.reveal_output {
        reveal_transaction.output.push(reveal_output);
    }

    let mut chained_tap_script_opt: Option<ScriptBuf> = None;

    if let Some(chained_script_data) = params.chained_script_data {
        // if chained_script_data is provided, script_spendable_address output for the new commit
        let (chained_tap_script_for_return, _, chained_script_spendable_address) =
            build_tap_script_and_script_address(params.internal_key, chained_script_data)?;

        reveal_transaction.output.push(TxOut {
            value: Amount::from_sat(envelope),
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

    let control_block = params
        .taproot_spend_info
        .control_block(&(params.tap_script.clone(), LeafVersion::TapScript))
        .ok_or(anyhow!("Failed to create control block"))?;

    let f = |i: usize, witness: &mut Witness| {
        if i > 0 {
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
        } else {
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
            witness.push(params.tap_script.clone());
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
        match params.funding_outputs {
            Some(funding_outputs) => {
                funding_outputs.iter().for_each(|(outpoint, _)| {
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
                            .chain(funding_outputs)
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
                script_pubkey: params.sender_address.script_pubkey(),
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
                    script_pubkey: params.sender_address.script_pubkey(),
                });
            }
        };
    }
    let psbt = Psbt::from_unsigned_tx(reveal_transaction.clone()).unwrap();

    let base_builder = RevealOutputs::builder()
        .transaction(reveal_transaction)
        .psbt(psbt);

    // if the reveal tx also contains a commit, append the chained commit data
    let reveal_outputs = match chained_tap_script_opt {
        Some(chained_tap_script) => base_builder.chained_tap_script(chained_tap_script).build(),
        _ => base_builder.build(),
    };

    Ok(reveal_outputs)
}

fn build_tap_script_and_script_address(
    internal_key: &XOnlyPublicKey,
    data: &[u8],
) -> Result<(ScriptBuf, TaprootSpendInfo, Address)> {
    let secp = Secp256k1::new();
    let tap_script = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(data.to_vec())?)
        .push_opcode(OP_ENDIF)
        .into_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, *internal_key)
        .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;

    let output_key = taproot_spend_info.output_key();
    // Do we need random data somewhere in here? if provided the same internal key and data, it results in same script pub key, and sig becomes public on broadcast
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
    let fee = fee_rate.fee_vb(vsize).unwrap().to_sat();

    input_sum.checked_sub(output_sum + fee)
}
