use anyhow::Result;
use indexer_types::{ContractAddress, Input, OpWithResult, ResultRow, SignerRef, Transaction};

use super::storage_error::host_failure;
use super::transactions::TxWalker;
use crate::protocol::storage_inspection::{InspectionCallbacks, ResultRecord};

pub(crate) async fn inspect(
    callbacks: &InspectionCallbacks,
    tx: &Transaction,
) -> Result<Vec<OpWithResult>> {
    let mut ops = Vec::new();
    let mut walker = TxWalker::new();
    for input in &tx.inputs {
        // Per-op signer_ids: aggregates resolve each `SignerRef` (Id is
        // already-resolved; PubKey is looked up against the registry — by
        // the time inspect runs, any PubKey claim on a successfully
        // executed aggregate must have a corresponding signers row).
        // Direct inputs broadcast the witness signer to every op.
        let signer_ids = resolve_input_signer_ids(callbacks, input).await?;
        // For aggregate inputs, the publisher's signer_id is the payer
        // for any op whose `AggregateSigner.sponsored = true`. `None` for
        // direct inputs.
        let publisher_signer_id = resolve_publisher_signer_id(callbacks, input).await?;

        for (op_index, inst) in input.insts.ops.iter().enumerate() {
            let signer_id = signer_ids.get(op_index).copied().unwrap_or(0);
            let op = match walker.materialize(input, op_index, signer_id, publisher_signer_id, inst)
            {
                Ok(op) => op,
                Err(e) => {
                    tracing::warn!("inspect: op {op_index} rejected at materialize: {e:#}");
                    ops.push(OpWithResult::Rejected {
                        input_index: input.input_index,
                        op_index: op_index as u32,
                        error_message: None,
                    });
                    continue;
                }
            };
            let result = (callbacks.1)(tx.txid.to_string(), input.input_index, op_index as u32)
                .await
                .map_err(host_failure)?
                .map(materialize_result)
                .transpose()?;
            // `result: None` is preserved (pre-refactor semantics) for ops the
            // executor skipped post-validation via `should_skip_result` or that
            // hit a non-deterministic failure, callers learn "this op was in
            // the tx but didn't produce a result row."
            //
            // `error_message: None` because inspect reads from chain state and
            // error strings aren't persisted. The simulate handler overwrites
            // this with live error detail captured during execution.
            ops.push(OpWithResult::Materialized {
                op,
                result,
                error_message: None,
            });
        }
        walker.next_input();
    }
    Ok(ops)
}

/// DB-backed signer resolution for `block::inspect`. Aggregate inputs:
/// per-AggregateSigner; `SignerId(id)` is already resolved, `XOnlyPubkey`
/// is looked up. Direct inputs: the witness signer broadcast across every
/// op. Missing entries become `0` (preserves pre-refactor inspect
/// semantics, inspection is best-effort over historical state).
async fn resolve_input_signer_ids(
    callbacks: &InspectionCallbacks,
    input: &Input,
) -> Result<Vec<u64>> {
    match &input.insts.aggregate {
        Some(agg) => {
            let mut ids = Vec::with_capacity(agg.signers.len());
            for s in &agg.signers {
                let id = match &s.identity {
                    SignerRef::SignerId(id) => *id,
                    SignerRef::XOnlyPubkey(pk) => (callbacks.0)(pk.to_string())
                        .await
                        .map_err(host_failure)?
                        .unwrap_or(0),
                };
                ids.push(id);
            }
            Ok(ids)
        }
        None => {
            let id = (callbacks.0)(input.x_only_pubkey.to_string())
                .await
                .map_err(host_failure)?
                .unwrap_or(0);
            Ok(vec![id; input.insts.ops.len()])
        }
    }
}

/// DB-backed publisher signer_id resolution for `block::inspect`. Returns
/// `Some` for aggregate inputs (the input's x_only_pubkey, looked up in
/// the signers table), `None` for direct inputs.
async fn resolve_publisher_signer_id(
    callbacks: &InspectionCallbacks,
    input: &Input,
) -> Result<Option<u64>> {
    if input.insts.aggregate.is_none() {
        return Ok(None);
    }
    (callbacks.0)(input.x_only_pubkey.to_string())
        .await
        .map_err(host_failure)
}

fn materialize_result(row: ResultRecord) -> Result<ResultRow> {
    let (
        (id, height, tx_index, input_index, op_index, result_index),
        (func, gas, status, value),
        ((name, contract_height, contract_tx_index), txid, signer_id, payer_signer_id),
    ) = row;
    Ok(ResultRow {
        id,
        height,
        tx_index,
        input_index,
        op_index,
        result_index,
        func,
        gas,
        status: serde_json::from_value(status.into())?,
        value,
        contract: ContractAddress {
            name,
            height: contract_height,
            tx_index: contract_tx_index,
        }
        .to_string(),
        txid,
        signer_id,
        payer_signer_id,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use anyhow::Result;
    use bitcoin::{OutPoint, XOnlyPublicKey};
    use indexer_types::{Input, Inst, InstKind, Insts, OpStatus, OpWithResult};

    use super::inspect;
    use crate::protocol::storage_inspection::InspectionCallbacks;
    use crate::reg_tester::random_x_only_pubkey;
    use crate::test_utils::new_mock_transaction;

    #[tokio::test]
    async fn inspection_preserves_read_order_missing_rows_and_error_causes() -> Result<()> {
        let key: XOnlyPublicKey = random_x_only_pubkey().parse()?;
        let mut transaction = new_mock_transaction(17);
        transaction.inputs = [2, 5]
            .into_iter()
            .map(|input_index| Input {
                previous_output: OutPoint::null(),
                input_index,
                x_only_pubkey: key,
                insts: Insts::single(Inst {
                    gas_limit: 70,
                    kind: InstKind::Issuance,
                }),
            })
            .collect();
        for fail_result in [false, true] {
            let trace = Arc::new(Mutex::new(Vec::new()));
            let reads = trace.clone();
            let results = trace.clone();
            let callbacks: InspectionCallbacks = (
                Arc::new(move |pubkey| {
                    assert_eq!(pubkey, key.to_string());
                    reads.lock().unwrap().push("identity".to_owned());
                    Box::pin(async { Ok(None) })
                }),
                Arc::new(move |_, input, op| {
                    results.lock().unwrap().push(format!("result:{input}:{op}"));
                    Box::pin(async move {
                        if fail_result {
                            return Err(vec!["query failed".into(), "driver denied".into()]);
                        }
                        Ok((input == 2).then(|| {
                            (
                                (9, 11, Some(3), Some(2), Some(0), 4),
                                (
                                    "issuance".into(),
                                    23,
                                    "OutOfFuel".into(),
                                    Some("value".into()),
                                ),
                                (("token".into(), 0, 0), Some("tx".into()), 12, Some(13)),
                            )
                        }))
                    })
                }),
            );
            let result = inspect(&callbacks, &transaction).await;
            if fail_result {
                assert_eq!(
                    format!("{:#}", result.unwrap_err()),
                    "query failed: driver denied"
                );
                assert_eq!(*trace.lock().unwrap(), ["identity", "result:2:0"]);
            } else {
                assert_eq!(
                    *trace.lock().unwrap(),
                    ["identity", "result:2:0", "identity", "result:5:0"]
                );
                let result = result?;
                assert_eq!(result.len(), 2);
                let OpWithResult::Materialized {
                    op,
                    result: Some(row),
                    error_message,
                } = &result[0]
                else {
                    panic!("expected materialized first result");
                };
                assert_eq!(op.metadata.signer_id, 0);
                assert_eq!(row.id, 9);
                assert_eq!(row.tx_index, Some(3));
                assert_eq!(row.result_index, 4);
                assert_eq!(row.gas, 23);
                assert_eq!(row.status, OpStatus::OutOfFuel);
                assert_eq!(row.contract, "token_0_0");
                assert_eq!(row.payer_signer_id, Some(13));
                assert!(error_message.is_none());
                assert!(matches!(
                    &result[1],
                    OpWithResult::Materialized { result: None, .. }
                ));
            }
        }
        Ok(())
    }
}
