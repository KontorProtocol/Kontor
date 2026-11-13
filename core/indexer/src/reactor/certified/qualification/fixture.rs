use anyhow::{Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::{
    OP_FALSE,
    all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use indexer_types::{Inst, InstKind, Insts, serialize};

use crate::bitcoin_helpers::sign_qualification_script_spend;

pub(crate) fn issuance_transaction() -> Result<Transaction> {
    issuance_transaction_at(OutPoint {
        txid: Txid::from_byte_array([91; 32]),
        vout: 0,
    })
}

pub(crate) fn issuance_transaction_at(previous_output: OutPoint) -> Result<Transaction> {
    raw_transaction_at(
        Insts::direct(vec![Inst {
            gas_limit: 100_000,
            kind: InstKind::Issuance,
        }]),
        previous_output,
    )
}

pub(crate) fn raw_transaction_at(
    instructions: Insts,
    previous_output: OutPoint,
) -> Result<Transaction> {
    raw_transaction_at_with_lock_time(instructions, previous_output, LockTime::ZERO)
}

pub(crate) fn raw_transaction_at_with_lock_time(
    instructions: Insts,
    previous_output: OutPoint,
    lock_time: LockTime,
) -> Result<Transaction> {
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[38; 32])?);
    let public = key.x_only_public_key().0;
    let amount = 1_000_000u64;
    let mut script = Builder::new()
        .push_slice(public.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon2")
        .push_slice(amount.to_be_bytes())
        .push_slice(Network::Regtest.magic().to_bytes());
    for chunk in serialize(&instructions)?.chunks(520) {
        script = script.push_slice(PushBytesBuf::try_from(chunk.to_vec())?);
    }
    let script = script.push_opcode(OP_ENDIF).into_script();
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())?
        .finalize(&secp, public)
        .map_err(|_| anyhow!("qualification taproot leaf failed to finalize"))?;
    let prevout = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
    };
    let mut transaction = Transaction {
        version: Version(2),
        lock_time,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    };
    sign_qualification_script_spend(
        &secp,
        &spend,
        &script,
        &mut transaction,
        &[prevout],
        &key,
        0,
        TapSighashType::AllPlusAnyoneCanPay,
    )?;
    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};
    use bitcoin::consensus::serialize as serialize_bitcoin;
    use bitcoin::{Network, OutPoint};

    use super::{issuance_transaction, issuance_transaction_at};
    use crate::protocol::v1::transactions::filter_map_for_network;

    #[test]
    fn certified_fixture_witness_is_stable_and_bound_to_outpoint() -> Result<()> {
        let parent = issuance_transaction()?;
        let repeated = issuance_transaction()?;
        assert_eq!(serialize_bitcoin(&parent), serialize_bitcoin(&repeated));
        assert_eq!(parent.compute_wtxid(), repeated.compute_wtxid());
        let child_outpoint = OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        };
        let child = issuance_transaction_at(child_outpoint)?;
        assert_ne!(child.compute_txid(), parent.compute_txid());
        for tx in [parent, child] {
            let recognized = filter_map_for_network((0, tx), Network::Regtest)
                .context("signed certified transaction was not recognized")?;
            assert_eq!(recognized.inputs.len(), 1);
            assert_eq!(recognized.inputs[0].insts.ops.len(), 1);
        }
        Ok(())
    }
}
