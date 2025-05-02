use anyhow::{Result, anyhow};
use bitcoin::{
    Address, Amount, FeeRate, KnownHrp, OutPoint, ScriptBuf, TxOut, Witness,
    absolute::LockTime,
    opcodes::{
        OP_0, OP_FALSE,
        all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
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
    pub chained_script_data: Option<&'a [u8]>,
}

#[derive(Builder)]
pub struct ComposeOutputs {
    pub commit_transaction: Transaction,
    pub reveal_transaction: Transaction,
    pub tap_script: ScriptBuf,
    pub chained_tap_script: Option<ScriptBuf>,
    pub chained_reveal_transaction: Option<Transaction>,
}

#[derive(Builder)]
pub struct CommitInputs<'a> {
    pub sender_address: &'a Address,
    pub internal_key: &'a XOnlyPublicKey,
    pub sender_utxos: Vec<(OutPoint, TxOut)>,
    pub script_data: &'a [u8],
    pub fee_rate: FeeRate,
}

impl<'a> From<ComposeInputs<'a>> for CommitInputs<'a> {
    fn from(value: ComposeInputs<'a>) -> Self {
        Self {
            sender_address: value.sender_address,
            internal_key: value.internal_key,
            sender_utxos: value.sender_utxos,
            script_data: value.script_data,
            fee_rate: value.fee_rate,
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
    pub commit_transaction: &'a Transaction,
    pub tap_script: &'a ScriptBuf,
    pub taproot_spend_info: &'a TaprootSpendInfo,
    pub fee_rate: FeeRate,
    pub chained_script_data: Option<&'a [u8]>,
    // TODO add op_return data
}

#[derive(Builder)]
pub struct RevealOutputs {
    pub reveal_transaction: Transaction,
    pub chained_tap_script: Option<ScriptBuf>,
    pub chained_reveal_transaction: Option<Transaction>,
    pub chained_taproot_spend_info: Option<TaprootSpendInfo>,
}

pub fn compose(params: ComposeInputs) -> Result<ComposeOutputs> {
    // Build the commit tx
    let commit_outputs = compose_commit(CommitInputs {
        sender_address: params.sender_address,
        internal_key: params.internal_key,
        sender_utxos: params.sender_utxos.clone(),
        script_data: params.script_data,
        fee_rate: params.fee_rate,
    })?;

    // Build the reveal tx inputs
    let reveal_inputs = {
        let builder = RevealInputs::builder()
            .internal_key(params.internal_key)
            .sender_address(params.sender_address)
            .commit_transaction(&commit_outputs.commit_transaction)
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
    let reveal_outputs = compose_reveal(reveal_inputs)?;

    // Build the final outputs
    let compose_outputs = {
        let base_builder = ComposeOutputs::builder()
            .commit_transaction(commit_outputs.commit_transaction)
            .reveal_transaction(reveal_outputs.reveal_transaction.clone()) // Need to clone here
            .tap_script(commit_outputs.tap_script);

        match (
            reveal_outputs.chained_tap_script,
            reveal_outputs.chained_taproot_spend_info,
        ) {
            (Some(chained_tap_script), Some(chained_taproot_spend_info)) => {
                // Only if we have chained data, build the chained reveal
                let chained_reveal_inputs = RevealInputs::builder()
                    .internal_key(params.internal_key)
                    .sender_address(params.sender_address)
                    .commit_transaction(&reveal_outputs.reveal_transaction)
                    .tap_script(&chained_tap_script)
                    .taproot_spend_info(&chained_taproot_spend_info)
                    .fee_rate(params.fee_rate)
                    .build();

                let chained_reveal_outputs = compose_reveal(chained_reveal_inputs)?;

                base_builder
                    .chained_tap_script(chained_tap_script)
                    .chained_reveal_transaction(chained_reveal_outputs.reveal_transaction)
                    .build()
            }
            _ => base_builder.build(),
        }
    };

    Ok(compose_outputs)
}

pub fn compose_commit(params: CommitInputs) -> Result<CommitOutputs> {
    let sender_address = params.sender_address;
    let internal_key = params.internal_key;
    let sender_utxos = params.sender_utxos;
    let script_data = params.script_data;
    let fee_rate = params.fee_rate;

    let inputs: Vec<TxIn> = sender_utxos
        .iter()
        .map(|(outpoint, _)| TxIn {
            previous_output: *outpoint,
            ..Default::default()
        })
        .collect();

    let total_input_amount: u64 = sender_utxos
        .iter()
        .map(|(_, txout)| txout.value.to_sat())
        .sum();

    let mut outputs = Vec::new();

    let (tap_script, taproot_spend_info, script_spendable_address) =
        build_tap_script_and_script_address(internal_key, script_data)?;

    let dust = 546;

    outputs.push(TxOut {
        value: Amount::from_sat(dust),
        script_pubkey: script_spendable_address.script_pubkey(),
    });

    const SCHNORR_SIGNATURE_SIZE: usize = 64;
    let fee = calculate_fee(
        |_, witness| {
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
        },
        inputs.clone(),
        outputs.clone(),
        fee_rate,
        true,
    );

    let change_amount = total_input_amount
        .checked_sub(dust + fee)
        .ok_or(anyhow!("Change amount is negative"))?;

    // commit must have change to cover the reveal
    if change_amount < dust {
        return Err(anyhow!("Change amount is dust"));
    }

    outputs.push(TxOut {
        value: Amount::from_sat(change_amount),
        script_pubkey: sender_address.script_pubkey(),
    });

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
    let sender_address = params.sender_address;
    let internal_key = params.internal_key;
    let commit_transaction = params.commit_transaction;
    let tap_script = params.tap_script;
    let taproot_spend_info = params.taproot_spend_info;
    let fee_rate = params.fee_rate;
    let chained_script_data = params.chained_script_data;

    const SCHNORR_SIGNATURE_SIZE: usize = 64;
    let dust = 546;

    let mut reveal_transaction = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: commit_transaction.compute_txid(),
                    vout: 1,
                },
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint {
                    txid: commit_transaction.compute_txid(),
                    vout: 0,
                },
                ..Default::default()
            },
        ],
        output: vec![],
    };

    let mut chained_tap_script_opt: Option<ScriptBuf> = None;
    let mut chained_taproot_spend_info_opt: Option<TaprootSpendInfo> = None;

    if let Some(chained_script_data) = chained_script_data {
        // if chained_script_data is provided, script_spendable_address output for the new commit
        let (
            chained_tap_script_for_return,
            chained_taproot_spend_info_for_return,
            chained_script_spendable_address,
        ) = build_tap_script_and_script_address(internal_key, chained_script_data)?;

        reveal_transaction.output.push(TxOut {
            value: Amount::from_sat(dust),
            script_pubkey: chained_script_spendable_address.script_pubkey(),
        });
        chained_tap_script_opt = Some(chained_tap_script_for_return);
        chained_taproot_spend_info_opt = Some(chained_taproot_spend_info_for_return);
    }

    let control_block = taproot_spend_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .ok_or(anyhow!("Failed to create control block"))?;

    let f = |i: usize, witness: &mut Witness| {
        if i == 0 {
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
        } else {
            witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
            witness.push(tap_script.clone());
            witness.push(control_block.serialize());
        }
    };

    let fee = calculate_fee(
        f,
        reveal_transaction.input.clone(),
        reveal_transaction.output.clone(),
        fee_rate,
        false,
    );

    let commit_outputs_sum: u64 = commit_transaction
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();

    let mut change_deduction = fee;
    if chained_script_data.is_some() {
        change_deduction = fee + dust;
    }

    println!("commit_outputs_sum: {}", commit_outputs_sum);
    let reveal_change = commit_outputs_sum
        .checked_sub(change_deduction)
        .ok_or(anyhow!("Reveal change amount is negative"))?;

    if reveal_change > dust {
        // if change is above the dust limit, calculate the new fee with a change output, and check once more that there is enough change to cover the new tx size fee
        let fee = calculate_fee(
            f,
            reveal_transaction.input.clone(),
            reveal_transaction.output.clone(),
            fee_rate,
            true,
        );

        let mut change_deduction = fee;
        if chained_script_data.is_some() {
            change_deduction = fee + dust;
        }

        let reveal_change = commit_outputs_sum.checked_sub(change_deduction);

        if let Some(v) = reveal_change {
            if v > dust {
                reveal_transaction.output.push(TxOut {
                    value: Amount::from_sat(v),
                    script_pubkey: sender_address.script_pubkey(),
                });
            }
        };
    }

    let base_builder = RevealOutputs::builder().reveal_transaction(reveal_transaction);

    // if the reveal tx also contains a commit, append the chained commit data
    let reveal_outputs = match (chained_tap_script_opt, chained_taproot_spend_info_opt) {
        (Some(chained_tap_script), Some(chained_taproot_spend_info)) => base_builder
            .chained_tap_script(chained_tap_script)
            .chained_taproot_spend_info(chained_taproot_spend_info)
            .build(),
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
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    Ok((tap_script, taproot_spend_info, script_spendable_address))
}

fn calculate_fee<F>(
    f: F,
    mut inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    fee_rate: FeeRate,
    change_output: bool,
) -> u64
where
    F: Fn(usize, &mut Witness),
{
    inputs.iter_mut().enumerate().for_each(|(i, txin)| {
        f(i, &mut txin.witness);
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

    let vsize = dummy_tx.vsize() as u64;
    fee_rate.fee_vb(vsize).unwrap().to_sat()
}
