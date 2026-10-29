use std::collections::{BTreeSet, HashMap};

use indexer_types::{
    InspectedOp, OpWithResult, ResultInfo, ResultRow, TransactionInfo, TransactionRow,
};
use libsql::{Connection, Value};

use crate::database::queries::Error;

struct Confirmation {
    height: Option<u64>,
    bitcoin_tx_index: Option<u32>,
    batch_height: Option<u64>,
}

// Callers hold one read transaction across the legacy query and enrichment so a
// reorg cannot combine an old receipt with new confirmation coordinates.
async fn confirmations(
    conn: &Connection,
    txids: BTreeSet<&str>,
) -> Result<HashMap<String, Confirmation>, Error> {
    let txids: Vec<_> = txids.into_iter().collect();
    let mut confirmations = HashMap::new();
    for chunk in txids.chunks(900) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let mut rows = conn
            .query(
                &format!(
                    "SELECT txid, confirmed_height, confirmed_bitcoin_tx_index, batch_height
                     FROM transactions WHERE txid IN ({placeholders})"
                ),
                chunk
                    .iter()
                    .map(|txid| Value::from(*txid))
                    .collect::<Vec<_>>(),
            )
            .await?;
        while let Some(row) = rows.next().await? {
            let height = row.get::<Option<u64>>(1)?;
            confirmations.insert(
                row.get(0)?,
                Confirmation {
                    height,
                    bitcoin_tx_index: if height.is_some() { row.get(2)? } else { None },
                    batch_height: row.get(3)?,
                },
            );
        }
    }
    Ok(confirmations)
}

pub(super) async fn transactions(
    conn: &Connection,
    rows: Vec<TransactionRow>,
) -> Result<Vec<TransactionInfo>, Error> {
    let confirmations =
        confirmations(conn, rows.iter().map(|row| row.txid.as_str()).collect()).await?;
    rows.into_iter()
        .map(|row| {
            let confirmation = confirmations.get(&row.txid).ok_or_else(|| {
                Error::InvalidData(format!("missing transaction metadata: {}", row.txid))
            })?;
            Ok(TransactionInfo {
                execution_height: row.height,
                confirmed_bitcoin_tx_index: confirmation.bitcoin_tx_index,
                row,
            })
        })
        .collect()
}

pub(super) async fn results(
    conn: &Connection,
    rows: Vec<ResultRow>,
) -> Result<Vec<ResultInfo>, Error> {
    let confirmations = confirmations(
        conn,
        rows.iter().filter_map(|row| row.txid.as_deref()).collect(),
    )
    .await?;
    rows.into_iter()
        .map(|row| {
            let confirmation = row
                .txid
                .as_ref()
                .map(|txid| {
                    confirmations.get(txid).ok_or_else(|| {
                        Error::InvalidData(format!("missing receipt transaction metadata: {txid}"))
                    })
                })
                .transpose()?;
            Ok(ResultInfo {
                execution_height: row.height,
                confirmed_height: confirmation.and_then(|value| value.height),
                confirmed_bitcoin_tx_index: confirmation.and_then(|value| value.bitcoin_tx_index),
                batch_height: confirmation.and_then(|value| value.batch_height),
                row,
            })
        })
        .collect()
}

pub(super) async fn inspection(
    conn: &Connection,
    ops: Vec<OpWithResult>,
) -> Result<Vec<InspectedOp>, Error> {
    let rows = ops.iter().filter_map(|op| op.result().cloned()).collect();
    let enriched: HashMap<_, _> = results(conn, rows)
        .await?
        .into_iter()
        .map(|info| (info.row.id, info))
        .collect();
    ops.into_iter()
        .map(|op| match op {
            OpWithResult::Materialized {
                op,
                result,
                error_message,
            } => {
                let result = result
                    .map(|row| {
                        enriched.get(&row.id).cloned().ok_or_else(|| {
                            Error::InvalidData(format!(
                                "missing inspected receipt metadata: {}",
                                row.id
                            ))
                        })
                    })
                    .transpose()?;
                Ok(InspectedOp::Materialized {
                    op,
                    result,
                    error_message,
                })
            }
            OpWithResult::Rejected {
                input_index,
                op_index,
                error_message,
            } => Ok(InspectedOp::Rejected {
                input_index,
                op_index,
                error_message,
            }),
        })
        .collect()
}
