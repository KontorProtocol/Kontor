use anyhow::{Context, Result, ensure};
use bitcoin::Transaction;
use indexer_types::{ResultRow, TransactionRow};
use libsql::params;

use super::super::{ANCHOR_HEIGHT, SMOKE_HEIGHT, receipts};
use crate::consensus::Height;
use crate::database::confirmation::get_confirmation_position;
use crate::database::queries::{
    get_transaction_by_txid, get_transaction_execution_usage, select_latest_consensus_height,
};
use crate::reactor::Reactor;
use crate::reactor::batches::BatchOutcome;
use crate::reactor::executor::RuntimeExecutor;
use crate::runtime::fuel::ExecutionUsage;

pub(super) struct BatchProof {
    transaction: TransactionRow,
    paid: Vec<ResultRow>,
    usage: ExecutionUsage,
}

impl BatchProof {
    pub(super) async fn execute(
        trial: &mut Reactor<RuntimeExecutor>,
        reveal: &Transaction,
    ) -> Result<Self> {
        let height = select_latest_consensus_height(&trial.db_conn())
            .await?
            .context("missing anchor decision")?
            .checked_add(1)
            .context("batch height overflow")?;
        let anchor = trial.last_hash.context("missing batch anchor")?;
        ensure!(trial.last_height == ANCHOR_HEIGHT);
        // Supply an already-decided, unfiltered batch. The empty certificate
        // exercises execution only, not consensus authorization or validation.
        let outcome = trial
            .process_decided_batch(
                ANCHOR_HEIGHT,
                anchor,
                Height::new(height),
                &[],
                std::slice::from_ref(reveal),
                None,
            )
            .await?;
        ensure!(outcome == BatchOutcome::Executed, "batch was not executed");
        let conn = trial.db_conn();
        let txid = reveal.compute_txid().to_string();
        let transaction = get_transaction_by_txid(&conn, &txid)
            .await?
            .context("batch did not persist its transaction")?;
        ensure!(
            transaction.height == ANCHOR_HEIGHT
                && transaction.batch_height == Some(height)
                && transaction.confirmed_height.is_none()
                && transaction.tx_index.is_none()
                && get_confirmation_position(&conn, &txid).await?.is_none(),
            "batch transaction unexpectedly confirmed or lost its execution identity"
        );
        let paid: Vec<_> = receipts(&conn, ANCHOR_HEIGHT)
            .await?
            .into_iter()
            .filter(|row| row.txid.as_deref() == Some(&txid))
            .collect();
        ensure!(paid.len() == 3 && paid.iter().all(|row| row.tx_index.is_none()));
        let usage = get_transaction_execution_usage(&conn, transaction.id)
            .await?
            .context("batch did not persist execution usage")?;
        ensure!(usage.user_fuel > 0 && usage.deposit_fuel > 0);
        Ok(Self {
            transaction,
            paid,
            usage,
        })
    }

    pub(super) async fn check(self, trial: &Reactor<RuntimeExecutor>) -> Result<Vec<ResultRow>> {
        let conn = trial.db_conn();
        let txid = &self.transaction.txid;
        let confirmed = get_transaction_by_txid(&conn, txid)
            .await?
            .context("confirmation lost the batch transaction")?;
        ensure!(
            confirmed.id == self.transaction.id
                && confirmed.height == self.transaction.height
                && confirmed.batch_height == self.transaction.batch_height
                && confirmed.confirmed_height == Some(SMOKE_HEIGHT)
                && confirmed.tx_index == Some(0)
                && get_confirmation_position(&conn, txid).await? == Some(2),
            "confirmation changed execution identity or recorded the wrong Bitcoin position"
        );
        ensure!(
            get_transaction_execution_usage(&conn, confirmed.id).await? == Some(self.usage),
            "confirmation changed transaction execution usage"
        );
        let paid: Vec<_> = receipts(&conn, ANCHOR_HEIGHT)
            .await?
            .into_iter()
            .filter(|row| row.txid.as_deref() == Some(txid))
            .collect();
        let mut expected = self.paid;
        for row in &mut expected {
            // The public receipt query joins this legacy confirmation ordinal
            // from transactions. Every persisted execution field must survive.
            row.tx_index = Some(0);
        }
        ensure!(
            paid == expected,
            "confirmation changed paid execution receipts"
        );
        let mut counts = conn
            .query(
                "SELECT count(*) FROM contract_results WHERE tx_id = ?",
                params![confirmed.id],
            )
            .await?;
        let count: u64 = counts
            .next()
            .await?
            .context("missing receipt count")?
            .get(0)?;
        ensure!(count == 3, "confirmation appended or hid paid receipts");
        Ok(paid)
    }
}
