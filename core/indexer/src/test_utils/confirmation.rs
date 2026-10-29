use anyhow::{Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use indexer_types::{Inst, InstKind, Insts, serialize};

use super::{PublicKey, build_inscription, new_mock_transaction, sign_script_spend};
use crate::runtime::ContractAddress;

pub fn signed_confirmation_call(key: &Keypair, contract: ContractAddress) -> Result<Transaction> {
    let secp = Secp256k1::new();
    let public_key = key.x_only_public_key().0;
    let script = build_inscription(
        serialize(&Insts {
            ops: vec![Inst {
                gas_limit: 100_000,
                kind: InstKind::Call {
                    contract,
                    expr: "write-result-payload(1)".into(),
                },
            }],
            aggregate: None,
        })?,
        PublicKey::Taproot(&public_key),
    )?;
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())?
        .finalize(&secp, public_key)
        .map_err(|_| anyhow!("fixture taproot tree"))?;
    let prevout = TxOut {
        value: Amount::from_sat(1_000_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
    };
    let mut tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: new_mock_transaction(600).txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(900_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    sign_script_spend(&secp, &spend, &script, &mut tx, &[prevout], key, 0)?;
    Ok(tx)
}
