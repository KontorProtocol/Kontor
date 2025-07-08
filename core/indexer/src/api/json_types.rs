use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid, Witness,
    absolute::LockTime,
    transaction::{Transaction, TxIn, Version},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct JsonTxOut {
    #[schema(value_type = u64)]
    pub value: Amount,
    #[schema(value_type = String)]
    pub script_pubkey: ScriptBuf,
}

impl From<&TxOut> for JsonTxOut {
    fn from(tx_out: &TxOut) -> Self {
        JsonTxOut {
            value: tx_out.value,
            script_pubkey: tx_out.script_pubkey.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct JsonOutPoint {
    #[schema(value_type = String)]
    pub txid: Txid,
    pub vout: u32,
}

impl From<&OutPoint> for JsonOutPoint {
    fn from(out_point: &OutPoint) -> Self {
        JsonOutPoint {
            txid: out_point.txid,
            vout: out_point.vout,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct JsonTxIn {
    pub previous_output: JsonOutPoint,
    #[schema(value_type = String)]
    pub script_sig: ScriptBuf,
    #[schema(value_type = u32)]
    pub sequence: Sequence,
    #[schema(value_type = Vec<String>)]
    pub witness: Witness,
}

impl From<&TxIn> for JsonTxIn {
    fn from(tx_in: &TxIn) -> Self {
        JsonTxIn {
            previous_output: JsonOutPoint::from(&tx_in.previous_output),
            script_sig: tx_in.script_sig.clone(),
            sequence: tx_in.sequence,
            witness: tx_in.witness.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct JsonTransaction {
    #[schema(value_type = i32)]
    pub version: Version,
    #[schema(value_type = u32)]
    pub lock_time: LockTime,
    pub input: Vec<JsonTxIn>,
    pub output: Vec<JsonTxOut>,
}

impl From<&Transaction> for JsonTransaction {
    fn from(tx: &Transaction) -> Self {
        JsonTransaction {
            version: tx.version,
            lock_time: tx.lock_time,
            input: tx.input.iter().map(JsonTxIn::from).collect(),
            output: tx.output.iter().map(JsonTxOut::from).collect(),
        }
    }
}
