use std::path::Path;

use anyhow::{Context, Result, ensure};
use bitcoin::Transaction;
use indexer_types::{Block, ResultRow, TransactionRow};
use libsql::{Connection, params};

use super::super::{database_projection, receipts};
use super::checkpoint::Checkpoint;
use super::oracle::root_receipts;
use crate::block::filter_map;
use crate::consensus::Height;
use crate::database::confirmation::get_confirmation_position;
use crate::database::queries::{
    get_transaction_by_txid, get_transaction_execution_usage, select_latest_consensus_height,
};
use crate::reactor::Reactor;
use crate::reactor::batches::BatchOutcome;
use crate::reactor::executor::RuntimeExecutor;
use crate::runtime::fuel::ExecutionUsage;

pub(super) mod pending;

use pending::Confirmation;

#[derive(Clone)]
struct TransactionProof {
    transaction: TransactionRow,
    paid: Vec<ResultRow>,
    usage: ExecutionUsage,
    confirmation_index: u32,
}

pub(super) struct BatchProof {
    transactions: Vec<TransactionProof>,
    anchor_height: u64,
    checkpoint: Checkpoint,
}

impl BatchProof {
    pub(super) async fn execute(
        trial: &mut Reactor<RuntimeExecutor>,
        reveal: &Transaction,
        checkpoint_directory: &Path,
    ) -> Result<Self> {
        let proof =
            Self::execute_many(trial, std::slice::from_ref(reveal), 0, checkpoint_directory)
                .await?;
        ensure!(proof.transactions[0].paid.len() == 3);
        ensure!(proof.transactions[0].usage.deposit_fuel > 0);
        Ok(proof)
    }

    pub(super) async fn execute_chunks(
        trial: &mut Reactor<RuntimeExecutor>,
        reveals: &[Transaction],
        operations_per_batch: usize,
        checkpoint_directory: &Path,
    ) -> Result<Vec<Self>> {
        ensure!(matches!(operations_per_batch, 20 | 40));
        let transactions_per_batch = operations_per_batch / 2;
        ensure!(!reveals.is_empty() && reveals.len().is_multiple_of(transactions_per_batch));
        let mut proofs = Vec::new();
        for (index, chunk) in reveals.chunks_exact(transactions_per_batch).enumerate() {
            for reveal in chunk {
                let decoded =
                    filter_map((0, reveal.clone())).context("batch fixture did not decode")?;
                ensure!(decoded.inputs.len() == 1 && decoded.inputs[0].insts.ops.len() == 2);
            }
            proofs.push(
                Self::execute_many(
                    trial,
                    chunk,
                    index * transactions_per_batch,
                    checkpoint_directory,
                )
                .await?,
            );
        }
        Ok(proofs)
    }

    pub(super) async fn execute_many(
        trial: &mut Reactor<RuntimeExecutor>,
        reveals: &[Transaction],
        first_confirmation_index: usize,
        checkpoint_directory: &Path,
    ) -> Result<Self> {
        ensure!(!reveals.is_empty());
        let height = select_latest_consensus_height(&trial.db_conn())
            .await?
            .context("missing anchor decision")?
            .checked_add(1)
            .context("batch height overflow")?;
        let anchor = trial.last_hash.context("missing batch anchor")?;
        let anchor_height = trial.last_height;
        // Already-decided batches exercise execution and confirmation, not
        // consensus authorization. Keep the original transaction order intact.
        let outcome = trial
            .process_decided_batch(
                anchor_height,
                anchor,
                Height::new(height),
                &[],
                reveals,
                None,
            )
            .await?;
        ensure!(outcome == BatchOutcome::Executed, "batch was not executed");
        let conn = trial.db_conn();
        let all_paid = receipts(&conn, anchor_height).await?;
        let mut transactions = Vec::new();
        for (index, reveal) in reveals.iter().enumerate() {
            let txid = reveal.compute_txid().to_string();
            let decoded =
                filter_map((0, reveal.clone())).context("batch fixture did not decode")?;
            let expected_operations: usize = decoded
                .inputs
                .iter()
                .map(|input| input.insts.ops.len())
                .sum();
            let transaction = get_transaction_by_txid(&conn, &txid)
                .await?
                .context("batch did not persist its transaction")?;
            ensure!(
                transaction.height == anchor_height
                    && transaction.batch_height == Some(height)
                    && transaction.confirmed_height.is_none()
                    && transaction.tx_index.is_none()
                    && get_confirmation_position(&conn, &txid).await?.is_none(),
                "batch transaction unexpectedly confirmed or lost its execution identity"
            );
            let paid: Vec<_> = all_paid
                .iter()
                .filter(|row| row.txid.as_deref() == Some(&txid))
                .cloned()
                .collect();
            ensure!(root_receipts(&paid, &txid)?.len() == expected_operations);
            ensure!(paid.iter().all(|row| row.tx_index.is_none()));
            let usage = get_transaction_execution_usage(&conn, transaction.id)
                .await?
                .context("batch did not persist execution usage")?;
            ensure!(usage.user_fuel > 0);
            transactions.push(TransactionProof {
                transaction,
                paid,
                usage,
                confirmation_index: u32::try_from(
                    first_confirmation_index
                        .checked_add(index)
                        .context("confirmation index overflow")?,
                )?,
            });
        }
        Ok(Self {
            transactions,
            anchor_height,
            checkpoint: Checkpoint::capture(
                checkpoint_directory,
                &database_projection(&conn).await?,
            )?,
        })
    }

    pub(super) fn confirmation_plan(&self, block: &Block) -> Result<Vec<Confirmation>> {
        self.transactions
            .iter()
            .map(|proof| {
                let (index, transaction) = block
                    .transactions
                    .iter()
                    .enumerate()
                    .find(|(_, transaction)| transaction.txid.to_string() == proof.transaction.txid)
                    .context("batch transaction absent from frozen confirmation block")?;
                Ok(Confirmation {
                    txid: proof.transaction.txid.clone(),
                    height: block.height,
                    filtered_index: u32::try_from(index)?,
                    bitcoin_index: transaction.index,
                })
            })
            .collect()
    }

    pub(super) fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    pub(super) async fn check(self, trial: &Reactor<RuntimeExecutor>) -> Result<Vec<ResultRow>> {
        let conn = trial.db_conn();
        let anchor_height = self.anchor_height;
        let confirmed_height = anchor_height
            .checked_add(1)
            .context("confirmation height overflow")?;
        ensure!(trial.last_height == confirmed_height);
        let all_paid = receipts(&conn, anchor_height).await?;
        let mut checked = Vec::new();
        for proof in self.transactions {
            let raw_position = proof
                .confirmation_index
                .checked_mul(2)
                .and_then(|index| index.checked_add(2))
                .context("raw position overflow")?;
            checked.extend(
                proof
                    .check(
                        &conn,
                        &all_paid,
                        Some((confirmed_height, proof.confirmation_index, raw_position)),
                    )
                    .await?,
            );
        }
        Ok(checked)
    }
}

impl TransactionProof {
    async fn check(
        &self,
        conn: &Connection,
        all_paid: &[ResultRow],
        confirmation: Option<(u64, u32, u32)>,
    ) -> Result<Vec<ResultRow>> {
        let txid = &self.transaction.txid;
        let actual = get_transaction_by_txid(conn, txid)
            .await?
            .context("pending or confirmed batch transaction disappeared")?;
        ensure!(
            actual.id == self.transaction.id
                && actual.txid == *txid
                && actual.height == self.transaction.height
                && actual.batch_height == self.transaction.batch_height
                && actual.confirmed_height == confirmation.map(|position| position.0)
                && actual.tx_index == confirmation.map(|position| position.1)
                && get_confirmation_position(conn, txid).await?
                    == confirmation.map(|position| position.2),
            "confirmation changed execution identity or recorded the wrong Bitcoin position"
        );
        ensure!(
            get_transaction_execution_usage(conn, actual.id).await? == Some(self.usage),
            "confirmation changed transaction execution usage"
        );
        let paid: Vec<_> = all_paid
            .iter()
            .filter(|row| row.txid.as_deref() == Some(txid))
            .cloned()
            .collect();
        let mut expected = self.paid.clone();
        for row in &mut expected {
            // Receipt queries join confirmation ordinals; persisted execution fields stay fixed.
            row.tx_index = confirmation.map(|position| position.1);
        }
        ensure!(
            paid == expected,
            "confirmation changed paid execution receipts"
        );
        let mut counts = conn
            .query(
                "SELECT count(*) FROM contract_results WHERE tx_id = ?",
                params![actual.id],
            )
            .await?;
        let count: u64 = counts
            .next()
            .await?
            .context("missing receipt count")?
            .get(0)?;
        ensure!(
            count == u64::try_from(expected.len())?,
            "confirmation appended or hid paid receipts"
        );
        Ok(paid)
    }
}
