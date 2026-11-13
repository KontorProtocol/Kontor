use anyhow::Result;
use bitcoin::secp256k1::Keypair;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut};
use indexer_types::{Inst, InstKind, Insts};

use super::{new_mock_transaction, signed_launch_transaction};
use crate::runtime::ContractAddress;

pub fn signed_confirmation_call(key: &Keypair, contract: ContractAddress) -> Result<Transaction> {
    signed_launch_transaction(
        key,
        Insts {
            ops: vec![Inst {
                gas_limit: 100_000,
                kind: InstKind::Call {
                    contract,
                    expr: "write-result-payload(1)".into(),
                },
            }],
            aggregate: None,
        },
        OutPoint {
            txid: new_mock_transaction(600).txid,
            vout: 0,
        },
        TxOut {
            value: Amount::from_sat(900_000),
            script_pubkey: ScriptBuf::new(),
        },
    )
}
