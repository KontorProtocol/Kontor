use std::{collections::HashMap, sync::Mutex};

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, absolute::LockTime,
    transaction::Version,
};

use super::*;
use crate::bitcoin_client::types::SubmitPackageTxResult;

#[derive(Default)]
struct State {
    observed: HashMap<Txid, Transaction>,
    reject: Option<Txid>,
    sends: Vec<Txid>,
    packages: usize,
    lookups: usize,
}

#[derive(Default)]
struct Rpc(Mutex<State>);

impl RelayRpc for Rpc {
    async fn observe(&self, txid: &Txid) -> std::result::Result<Transaction, RpcError> {
        let mut state = self.0.lock().unwrap();
        state.lookups += 1;
        state
            .observed
            .get(txid)
            .cloned()
            .ok_or_else(|| RpcError::Unexpected("not found".into()))
    }
    async fn package(&self, raws: &[String]) -> std::result::Result<SubmitPackageResult, RpcError> {
        self.0.lock().unwrap().packages += 1;
        let mut result = SubmitPackageResult {
            package_msg: "success".into(),
            tx_results: HashMap::new(),
        };
        for raw in raws {
            let tx: Transaction = encode::deserialize_hex(raw).unwrap();
            let error = self.send(raw).await.err().map(|error| error.to_string());
            if error.is_some() {
                result.package_msg = "rejected".into();
            }
            result.tx_results.insert(
                tx.compute_wtxid().to_string(),
                SubmitPackageTxResult {
                    txid: tx.compute_txid(),
                    other_wtxid: None,
                    error,
                },
            );
        }
        Ok(result)
    }
    async fn send(&self, raw: &str) -> std::result::Result<String, RpcError> {
        let tx: Transaction = encode::deserialize_hex(raw).unwrap();
        let txid = tx.compute_txid();
        let mut state = self.0.lock().unwrap();
        state.sends.push(txid);
        if state.reject == Some(txid) {
            return Err(RpcError::Unexpected("policy rejection".into()));
        }
        state.observed.insert(txid, tx);
        Ok(txid.to_string())
    }
}

fn transaction(parent: Option<&Transaction>, amount: u64) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: parent
                .map(|tx| OutPoint::new(tx.compute_txid(), 0))
                .unwrap_or(OutPoint::null()),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[b"witness"]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn package() -> Vec<Transaction> {
    let parent = transaction(None, 1000);
    let child = transaction(Some(&parent), 500);
    vec![parent, child]
}

fn raw(transactions: &[Transaction]) -> Vec<String> {
    transactions.iter().map(encode::serialize_hex).collect()
}

#[tokio::test]
async fn partial_package_preserves_exact_observations_and_retry_skips_confirmed_parent() {
    let transactions = package();
    let rpc = Rpc::default();
    rpc.0.lock().unwrap().reject = Some(transactions[1].compute_txid());
    let partial = process(&rpc, &raw(&transactions), true).await.unwrap();
    assert_eq!(partial.outcome, BroadcastOutcome::Partial);
    assert_eq!(
        partial.transactions[0].status,
        TransactionObservation::Accepted
    );
    assert_eq!(
        partial.transactions[1].status,
        TransactionObservation::Unknown
    );
    assert!(
        partial.transactions[1]
            .reason
            .as_ref()
            .unwrap()
            .contains("policy rejection")
    );
    // Fresh observation also covers txindex's confirmed-parent response; no
    // mempool membership is required before sending the missing child alone.
    rpc.0.lock().unwrap().reject = None;
    let accepted = process(&rpc, &raw(&transactions), true).await.unwrap();
    assert_eq!(accepted.outcome, BroadcastOutcome::Accepted);
    let state = rpc.0.lock().unwrap();
    assert_eq!(state.packages, 1);
    assert_eq!(
        state.sends,
        vec![
            transactions[0].compute_txid(),
            transactions[1].compute_txid(),
            transactions[1].compute_txid()
        ]
    );
}

#[tokio::test]
async fn sequential_failure_stops_descendants_and_reconciliation_never_relays() {
    let mut transactions = package();
    transactions.push(transaction(transactions.last(), 200));
    let rpc = Rpc::default();
    rpc.0.lock().unwrap().reject = Some(transactions[1].compute_txid());
    assert_eq!(
        process(&rpc, &raw(&transactions), true)
            .await
            .unwrap()
            .outcome,
        BroadcastOutcome::Partial
    );
    assert_eq!(rpc.0.lock().unwrap().sends.len(), 2);
    assert_eq!(
        process(&rpc, &raw(&transactions), false)
            .await
            .unwrap()
            .outcome,
        BroadcastOutcome::Partial
    );
    assert_eq!(rpc.0.lock().unwrap().sends.len(), 2);
}

#[tokio::test]
async fn reconcile_accepts_exact_confirmed_bytes_but_not_a_different_witness() {
    let transactions = package();
    let rpc = Rpc::default();
    for tx in &transactions {
        rpc.0
            .lock()
            .unwrap()
            .observed
            .insert(tx.compute_txid(), tx.clone());
    }
    assert_eq!(
        process(&rpc, &raw(&transactions), false)
            .await
            .unwrap()
            .outcome,
        BroadcastOutcome::Accepted
    );
    let mut conflicting = transactions[1].clone();
    conflicting.input[0].witness = Witness::from_slice(&[b"another witness"]);
    assert_eq!(conflicting.compute_txid(), transactions[1].compute_txid());
    rpc.0
        .lock()
        .unwrap()
        .observed
        .insert(conflicting.compute_txid(), conflicting);
    let report = process(&rpc, &raw(&transactions), false).await.unwrap();
    assert_eq!(report.outcome, BroadcastOutcome::Partial);
    assert!(
        report.transactions[1]
            .reason
            .as_ref()
            .unwrap()
            .starts_with("conflicting_witness:")
    );
    assert_eq!(
        report.transactions[1].wtxid,
        transactions[1].compute_wtxid().to_string()
    );
    assert!(rpc.0.lock().unwrap().sends.is_empty());
}

#[tokio::test]
async fn cached_transaction_is_not_current_bitcoin_evidence() {
    let tx = transaction(None, 1000);
    let client = Client::new("http://127.0.0.1:1".into(), "".into(), "".into()).unwrap();
    client
        .tx_cache()
        .insert(tx.compute_txid(), tx.clone())
        .await;
    assert_eq!(
        observe(&client, &tx).await.status,
        TransactionObservation::Unknown
    );
}

#[tokio::test]
async fn malformed_later_transaction_is_rejected_before_any_rpc() {
    let rpc = Rpc::default();
    let mut raws = raw(&package());
    raws.push("bad hex".into());
    assert!(process(&rpc, &raws, true).await.is_err());
    assert_eq!(rpc.0.lock().unwrap().lookups, 0);
    assert!(rpc.0.lock().unwrap().sends.is_empty());
}

#[test]
fn package_reply_retains_conflicting_witness_evidence() {
    let mut tx = transaction(None, 1000);
    let other = tx.compute_wtxid();
    tx.input[0].witness = Witness::from_slice(&[b"different"]);
    let entry: SubmitPackageTxResult = serde_json::from_value(
        serde_json::json!({ "txid": tx.compute_txid(), "other-wtxid": other }),
    )
    .unwrap();
    assert_eq!(entry.other_wtxid, Some(other));
    assert_ne!(entry.other_wtxid, Some(tx.compute_wtxid()));
}
