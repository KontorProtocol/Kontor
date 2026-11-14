use std::future::Future;

use axum::{Json, extract::State};
use bitcoin::{Transaction, Txid, consensus::encode};
use indexer_types::BroadcastQuery;
use serde::Serialize;
use ts_rs::TS;

use crate::api::{Env, error::HttpError, result::Result};
use crate::bitcoin_client::{Client, error::Error as RpcError, types::SubmitPackageResult};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastOutcome {
    Accepted,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum TransactionObservation {
    Accepted,
    Unknown,
}

#[derive(Debug, Serialize, TS)]
pub struct BroadcastObservation {
    pub txid: String,
    pub wtxid: String,
    pub status: TransactionObservation,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, TS)]
pub struct BroadcastReport {
    pub outcome: BroadcastOutcome,
    pub transactions: Vec<BroadcastObservation>,
}

trait RelayRpc {
    fn observe(
        &self,
        txid: &Txid,
    ) -> impl Future<Output = std::result::Result<Transaction, RpcError>> + Send;
    fn package(
        &self,
        raw: &[String],
    ) -> impl Future<Output = std::result::Result<SubmitPackageResult, RpcError>> + Send;
    fn send(&self, raw: &str)
    -> impl Future<Output = std::result::Result<String, RpcError>> + Send;
}

impl RelayRpc for Client {
    async fn observe(&self, txid: &Txid) -> std::result::Result<Transaction, RpcError> {
        // The ordinary txid cache can outlive mempool eviction or a witness
        // replacement. Funding reconciliation needs a fresh Bitcoin observation.
        let raw: String = self
            .call(
                "getrawtransaction",
                vec![txid.to_string().into(), false.into()],
            )
            .await?;
        Ok(encode::deserialize_hex(&raw)?)
    }

    async fn package(&self, raw: &[String]) -> std::result::Result<SubmitPackageResult, RpcError> {
        self.submit_package(raw).await
    }

    async fn send(&self, raw: &str) -> std::result::Result<String, RpcError> {
        self.call("sendrawtransaction", vec![raw.into()]).await
    }
}

async fn observe(rpc: &impl RelayRpc, tx: &Transaction) -> BroadcastObservation {
    let txid = tx.compute_txid();
    let (status, reason) = match rpc.observe(&txid).await {
        Ok(observed) if observed == *tx => (TransactionObservation::Accepted, None),
        Ok(_) => (
            TransactionObservation::Unknown,
            Some("conflicting_witness: Bitcoin returned different transaction bytes".to_owned()),
        ),
        Err(error) => (
            TransactionObservation::Unknown,
            Some(format!("not_observed: {error}")),
        ),
    };
    BroadcastObservation {
        txid: txid.to_string(),
        wtxid: tx.compute_wtxid().to_string(),
        status,
        reason,
    }
}

async fn report(rpc: &impl RelayRpc, transactions: &[Transaction]) -> BroadcastReport {
    let mut observations = Vec::with_capacity(transactions.len());
    for tx in transactions {
        observations.push(observe(rpc, tx).await);
    }
    let accepted = observations
        .iter()
        .filter(|entry| entry.status == TransactionObservation::Accepted)
        .count();
    BroadcastReport {
        outcome: if accepted == transactions.len() {
            BroadcastOutcome::Accepted
        } else if accepted > 0 {
            BroadcastOutcome::Partial
        } else {
            BroadcastOutcome::Unknown
        },
        transactions: observations,
    }
}

async fn process(
    rpc: &impl RelayRpc,
    raw: &[String],
    publish: bool,
) -> std::result::Result<BroadcastReport, HttpError> {
    if raw.is_empty() {
        return Err(HttpError::BadRequest("no transactions provided".to_owned()));
    }
    let transactions = raw
        .iter()
        .map(|raw| {
            encode::deserialize_hex::<Transaction>(raw)
                .map_err(|error| HttpError::BadRequest(format!("invalid transaction hex: {error}")))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let initial = report(rpc, &transactions).await;
    if !publish || initial.outcome == BroadcastOutcome::Accepted {
        return Ok(initial);
    }
    let missing: Vec<_> = initial
        .transactions
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            (entry.status != TransactionObservation::Accepted).then_some(index)
        })
        .collect();
    let mut relay_errors = vec![None; transactions.len()];
    let parent_child = missing.len() == 2
        && transactions[missing[1]]
            .input
            .iter()
            .any(|input| input.previous_output.txid == transactions[missing[0]].compute_txid());
    if parent_child {
        let package: Vec<_> = missing.iter().map(|&index| raw[index].clone()).collect();
        match rpc.package(&package).await {
            Ok(result) => {
                for &index in &missing {
                    let tx = &transactions[index];
                    relay_errors[index] = match result
                        .tx_results
                        .get(&tx.compute_wtxid().to_string())
                    {
                        Some(entry)
                            if entry
                                .other_wtxid
                                .is_some_and(|other| other != tx.compute_wtxid()) =>
                        {
                            Some(
                                "conflicting_witness: another witness is in the Bitcoin mempool"
                                    .to_owned(),
                            )
                        }
                        Some(entry) if entry.txid == tx.compute_txid() => entry.error.clone(),
                        _ => Some(format!("unreported transaction: {}", result.package_msg)),
                    };
                }
            }
            Err(error) => {
                for &index in &missing {
                    relay_errors[index] = Some(error.to_string());
                }
            }
        }
    } else {
        for index in missing {
            if let Err(error) = rpc.send(&raw[index]).await {
                relay_errors[index] = Some(error.to_string());
                // An already-confirmed parent must not prevent its missing child
                // from being relayed. A txid-only "already known" error is not proof.
                if observe(rpc, &transactions[index]).await.status
                    != TransactionObservation::Accepted
                {
                    break;
                }
            }
        }
    }
    let mut final_report = report(rpc, &transactions).await;
    for (entry, error) in final_report.transactions.iter_mut().zip(relay_errors) {
        if entry.status == TransactionObservation::Unknown
            && let Some(error) = error
        {
            let observation = entry.reason.take().unwrap_or_default();
            entry.reason = Some(format!("{error}; {observation}"));
        }
    }
    Ok(final_report)
}

pub async fn post_transaction_broadcast(
    State(env): State<Env>,
    Json(query): Json<BroadcastQuery>,
) -> Result<BroadcastReport> {
    Ok(process(&env.bitcoin, &query.transactions, true)
        .await?
        .into())
}

pub async fn post_transaction_reconcile(
    State(env): State<Env>,
    Json(query): Json<BroadcastQuery>,
) -> Result<BroadcastReport> {
    Ok(process(&env.bitcoin, &query.transactions, false)
        .await?
        .into())
}

#[cfg(test)]
mod tests;
