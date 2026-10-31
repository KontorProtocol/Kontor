use anyhow::{Result, ensure};
use indexer_types::TransactionRow;
use serde_json::json;

use super::{BatchProof, Confirmation, Pending, TransactionProof};
use crate::reactor::workload_tests::smoke::populated::checkpoint::Checkpoint;
use crate::runtime::fuel::ExecutionUsage;

fn batch(anchor: u64, txids: &[&str]) -> Result<BatchProof> {
    let directory = Checkpoint::directory()?;
    Ok(BatchProof {
        transactions: txids
            .iter()
            .enumerate()
            .map(|(index, txid)| TransactionProof {
                transaction: TransactionRow {
                    id: index as u64,
                    txid: (*txid).into(),
                    height: anchor,
                    confirmed_height: None,
                    tx_index: None,
                    batch_height: Some(1),
                },
                paid: Vec::new(),
                usage: ExecutionUsage::default(),
                confirmation_index: index as u32,
            })
            .collect(),
        anchor_height: anchor,
        checkpoint: Checkpoint::capture(directory.path(), &json!({}))?,
    })
}

fn plan(txid: &str, height: u64, filtered_index: u32, bitcoin_index: u32) -> Confirmation {
    Confirmation {
        txid: txid.into(),
        height,
        filtered_index,
        bitcoin_index,
    }
}

#[test]
fn workload_pending_plan_preserves_obligations_on_invalid_addition() -> Result<()> {
    let mut pending = Pending::new(101);
    pending.record(
        batch(101, &["a", "b"])?,
        vec![plan("a", 103, 0, 2), plan("b", 107, 0, 2)],
    )?;
    ensure!(pending.len() == 2);
    for (txids, plans) in [
        (
            vec!["c", "a"],
            vec![plan("c", 104, 0, 2), plan("a", 105, 0, 2)],
        ),
        (vec!["c"], vec![plan("c", 103, 0, 4)]),
        (vec!["c"], vec![plan("c", 103, 1, 2)]),
        (
            vec!["c", "c"],
            vec![plan("c", 104, 0, 2), plan("c", 104, 1, 4)],
        ),
    ] {
        ensure!(pending.record(batch(101, &txids)?, plans).is_err());
        ensure!(pending.len() == 2 && pending.seen.len() == 2 && !pending.seen.contains("c"));
    }
    pending.entries.remove("a");
    ensure!(
        pending
            .record(batch(101, &["a"])?, vec![plan("a", 104, 0, 2)])
            .is_err()
    );
    ensure!(pending.len() == 1 && pending.seen.len() == 2);
    Ok(())
}

#[test]
fn workload_pending_plan_enforces_heights_and_complete_positions() -> Result<()> {
    for confirmation in [
        plan("a", 101, 0, 2),
        plan("a", 108, 0, 2),
        plan("a", 102, 0, 0),
        plan("wrong", 102, 0, 2),
    ] {
        let mut pending = Pending::new(101);
        ensure!(
            pending
                .record(batch(101, &["a"])?, vec![confirmation])
                .is_err()
        );
        ensure!(pending.len() == 0 && pending.seen.is_empty());
    }
    let mut pending = Pending::new(101);
    ensure!(
        pending
            .record(batch(102, &["a"])?, vec![plan("a", 103, 0, 2)])
            .is_err()
    );
    ensure!(pending.record(batch(101, &["a"])?, vec![]).is_err());
    let mut overflow = Pending::new(u64::MAX);
    ensure!(
        overflow
            .record(batch(u64::MAX, &["a"])?, vec![plan("a", u64::MAX, 0, 2)])
            .is_err()
    );
    Ok(())
}
