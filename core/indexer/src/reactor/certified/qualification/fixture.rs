use anyhow::{Context, Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::opcodes::{
    OP_0, OP_FALSE,
    all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use indexer_types::{Inst, InstKind, Insts, serialize};

pub(super) fn issuance_transaction() -> Result<Transaction> {
    raw_transaction(Insts::direct(vec![Inst {
        gas_limit: 100_000,
        kind: InstKind::Issuance,
    }]))
}

fn raw_transaction(instructions: Insts) -> Result<Transaction> {
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[38; 32])?);
    let public = key.x_only_public_key().0;
    let mut script = Builder::new()
        .push_slice(public.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0);
    for chunk in serialize(&instructions)?.chunks(520) {
        script = script.push_slice(PushBytesBuf::try_from(chunk.to_vec())?);
    }
    let script = script.push_opcode(OP_ENDIF).into_script();
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())?
        .finalize(&secp, public)
        .map_err(|_| anyhow!("qualification taproot leaf failed to finalize"))?;
    let control = spend
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .context("missing fixture leaf")?;
    let mut witness = Witness::new();
    // Bitcoin signature acceptance belongs to ingestion, outside this execution check.
    witness.push([0u8; 64]);
    witness.push(script.as_bytes());
    witness.push(control.serialize());
    Ok(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    })
}
