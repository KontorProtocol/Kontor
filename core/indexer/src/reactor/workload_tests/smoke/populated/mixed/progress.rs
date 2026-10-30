use std::collections::BTreeSet;
use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use bitcoin::Transaction;
use indexer_types::ResultRow;

use super::super::super::{database_projection, receipts};
use super::super::batch::BatchProof;
use super::super::checkpoint::Checkpoint;
use super::super::oracle::{Before, root_receipts};
use super::{ExecutionSlice, MixedLayout, MixedWorkload};
use crate::block::filter_map;
use crate::reactor::Reactor;
use crate::reactor::executor::RuntimeExecutor;

#[derive(Clone)]
pub(in super::super) struct Progress<'a> {
    workload: &'a MixedWorkload,
    layout: MixedLayout,
    txids: &'a [String],
    next_operation: usize,
}

impl<'a> Progress<'a> {
    pub(in super::super) fn new(
        workload: &'a MixedWorkload,
        layout: MixedLayout,
        txids: &'a [String],
    ) -> Result<Self> {
        ensure!(matches!(
            layout,
            MixedLayout::Single {
                operations_per_transaction: 2,
                ..
            }
        ));
        ensure!(txids.len().checked_mul(2) == Some(workload.rounds * 20));
        ensure!(txids.iter().collect::<BTreeSet<_>>().len() == txids.len());
        Ok(Self {
            workload,
            layout,
            txids,
            next_operation: 0,
        })
    }

    fn validate_next(&self, operations: &Range<usize>) -> Result<()> {
        self.workload.validate_range(operations)?;
        ensure!(
            operations.start == self.next_operation,
            "mixed operation range is not next"
        );
        ensure!(
            operations.start.is_multiple_of(2) && operations.end.is_multiple_of(2),
            "mixed operation range splits a transaction"
        );
        Ok(())
    }

    async fn check(
        &mut self,
        trial: &mut Reactor<RuntimeExecutor>,
        model: &Before,
        rows: &[ResultRow],
        operations: Range<usize>,
    ) -> Result<Before> {
        self.validate_next(&operations)?;
        let txids = &self.txids[operations.start / 2..operations.end / 2];
        let selected: BTreeSet<_> = txids.iter().map(String::as_str).collect();
        let all: Vec<_> = rows
            .iter()
            .filter(|row| row.txid.as_deref().is_some_and(|id| selected.contains(id)))
            .collect();
        let mut roots = Vec::new();
        for txid in txids {
            let transaction = root_receipts(rows, txid)?;
            ensure!(
                transaction.len() == 2,
                "mixed transaction lost an operation"
            );
            roots.extend(transaction);
        }
        self.workload
            .check_slice(
                &mut trial.runtime,
                &all,
                &roots,
                &ExecutionSlice {
                    operations: operations.clone(),
                    layout: self.layout,
                    height: trial.last_height,
                    confirmed: false,
                },
            )
            .await?;
        if let Some(files) = &self.workload.files {
            let created = (0..operations.end)
                .filter(|index| self.workload.file_index(index / 20, index % 20).is_some())
                .count();
            files.check_pending(&mut trial.runtime, created).await?;
        }
        let effects = self
            .workload
            .effects_range(self.layout, operations.clone())?;
        let next = model.check_batch(trial, rows, txids, &effects).await?;
        let duplicate = next
            .check_batch(trial, rows, txids, &effects)
            .await
            .err()
            .context("mixed batch accounting accepted a duplicate charge")?;
        ensure!(duplicate.to_string() == "paid execution payer balance mismatch");
        self.next_operation = operations.end;
        Ok(next)
    }

    pub(in super::super) async fn execute_chunks(
        &mut self,
        trial: &mut Reactor<RuntimeExecutor>,
        reveals: &[Transaction],
        operations_per_batch: usize,
        checkpoint_directory: &Path,
        model: &mut Before,
    ) -> Result<Vec<BatchProof>> {
        ensure!(matches!(operations_per_batch, 20 | 40));
        let count = operations_per_batch / 2;
        ensure!(reveals.len() == self.txids.len() && reveals.len().is_multiple_of(count));
        // Freeze identity and transaction shape before any canonical execution.
        for (reveal, txid) in reveals.iter().zip(self.txids) {
            ensure!(reveal.compute_txid().to_string() == *txid);
            let decoded =
                filter_map((0, reveal.clone())).context("mixed batch input did not decode")?;
            ensure!(decoded.inputs.len() == 1 && decoded.inputs[0].insts.ops.len() == 2);
        }
        let mut proofs = Vec::new();
        for (index, chunk) in reveals.chunks_exact(count).enumerate() {
            let first = index * count;
            let operations = first * 2..(first + chunk.len()) * 2;
            self.validate_next(&operations)?;
            let proof = BatchProof::execute_many(trial, chunk, first, checkpoint_directory).await?;
            let rows = receipts(&trial.db_conn(), trial.last_height).await?;
            let mut wrong_rows = rows.clone();
            let wrong = wrong_rows
                .iter_mut()
                .find(|row| {
                    row.txid.as_ref() == Some(&self.txids[first]) && row.op_index == Some(0)
                })
                .context("missing mixed position control receipt")?;
            wrong.tx_index = Some(0);
            let mut wrong_progress = self.clone();
            let error = wrong_progress
                .check(trial, model, &wrong_rows, operations.clone())
                .await
                .err()
                .context("confirmed position accepted before confirmation")?;
            ensure!(error.to_string() == "mixed receipt execution position changed");
            ensure!(wrong_progress.next_operation == self.next_operation);
            let mut candidate = self.clone();
            let next = candidate
                .check(trial, model, &rows, operations.clone())
                .await?;
            let duplicate = candidate
                .validate_next(&operations)
                .err()
                .context("duplicate mixed range accepted")?;
            ensure!(duplicate.to_string() == "mixed operation range is not next");
            let skipped = self
                .validate_next(&(operations.start + 2..operations.end))
                .err()
                .context("skipped mixed range accepted")?;
            ensure!(skipped.to_string() == "mixed operation range is not next");
            Checkpoint::capture(
                checkpoint_directory,
                &database_projection(&trial.db_conn()).await?,
            )?
            .check(proof.checkpoint())?;
            *self = candidate;
            *model = next;
            eprintln!(
                "workload_mixed_batch_checked={}",
                serde_json::json!({
                    "height": trial.last_height, "operations_start": operations.start,
                    "operations_end": operations.end, "transactions": chunk.len(),
                })
            );
            proofs.push(proof);
        }
        ensure!(self.next_operation == self.workload.rounds * 20);
        Ok(proofs)
    }
}
