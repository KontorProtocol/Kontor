use anyhow::{Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::opcodes::OP_FALSE;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut,
    Witness,
};
use indexer_types::{Insts, serialize};

use crate::bitcoin_helpers::sign_script_spend_with_sighash;

pub fn launch_tap_script(
    public_key: XOnlyPublicKey,
    instructions: &Insts,
    amount: u64,
    network: Network,
) -> Result<ScriptBuf> {
    let mut leaf = Builder::new()
        .push_slice(public_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_slice(amount.to_be_bytes())
        .push_slice(network.magic().to_bytes());
    for chunk in serialize(instructions)?.chunks(520) {
        leaf = leaf.push_slice(PushBytesBuf::try_from(chunk.to_vec())?);
    }
    Ok(leaf.push_opcode(OP_ENDIF).into_script())
}

pub fn signed_launch_transaction(
    key: &Keypair,
    instructions: Insts,
    previous_output: OutPoint,
    output: TxOut,
) -> Result<Transaction> {
    let secp = Secp256k1::new();
    let public_key = key.x_only_public_key().0;
    let amount = 1_000_000u64;
    let leaf = launch_tap_script(public_key, &instructions, amount, Network::Regtest)?;
    let spend = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())?
        .finalize(&secp, public_key)
        .map_err(|_| anyhow!("fixture Taproot tree"))?;
    let prevout = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
    };
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(previous_output.vout),
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![output],
    };
    sign_script_spend_with_sighash(
        &secp,
        &spend,
        &leaf,
        &mut transaction,
        &[prevout],
        key,
        0,
        TapSighashType::AllPlusAnyoneCanPay,
    )?;
    Ok(transaction)
}
