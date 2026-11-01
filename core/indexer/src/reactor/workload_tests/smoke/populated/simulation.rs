use anyhow::{Context, Result, ensure};
use bitcoin::Transaction;
use indexer_types::{OpStatus, ResultRow};

use super::super::{GAS_LIMIT, SMOKE_HEIGHT, database_projection};
use crate::block::filter_map;
use crate::reactor::Reactor;
use crate::reactor::executor::RuntimeExecutor;

pub(super) struct SimulationProof {
    paid: Vec<ResultRow>,
}

impl SimulationProof {
    pub(super) async fn execute(
        trial: &mut Reactor<RuntimeExecutor>,
        reveal: &Transaction,
    ) -> Result<Self> {
        let tx = filter_map((0, reveal.clone())).context("simulation input did not decode")?;
        let before = database_projection(&trial.db_conn()).await?;
        let storage_height = trial.test_runtime().await.storage.height;
        let tip = (trial.last_height, trial.last_hash);
        ensure!(!trial.test_runtime().await.simulating);
        let mut previous = None;
        let mut paid = Vec::new();
        for _ in 0..2 {
            let results = trial.simulate(tx.clone()).await?;
            ensure!(
                database_projection(&trial.db_conn()).await? == before,
                "simulation persisted fees, receipts, state or lifecycle work"
            );
            {
                let runtime = trial.test_runtime().await;
                ensure!(
                    !runtime.simulating
                        && runtime.storage.height == storage_height
                        && (trial.last_height, trial.last_hash) == tip,
                    "simulation left the reactor in a speculative context"
                );
            }
            ensure!(results.len() == 3);
            paid.clear();
            for (index, result) in results.iter().enumerate() {
                ensure!(
                    result.op().is_some(),
                    "simulation rejected a valid fixture op"
                );
                let row = result
                    .result()
                    .context("simulation omitted a paid receipt")?;
                ensure!(
                    row.height == SMOKE_HEIGHT
                        && row.input_index == Some(0)
                        && row.op_index == Some(index as u32)
                        && row.txid.as_deref() == Some(tx.txid.to_string().as_str())
                        && row.gas > 0
                        && row.gas <= GAS_LIMIT
                );
                if index == 1 {
                    ensure!(
                        row.status == OpStatus::Other
                            && result
                                .error_message()
                                .is_some_and(|message| !message.is_empty())
                    );
                } else {
                    ensure!(row.status == OpStatus::Ok && result.error_message().is_none());
                }
                paid.push(row.clone());
            }
            if let Some(previous) = &previous {
                ensure!(
                    &results == previous,
                    "repeated simulation changed its result"
                );
            }
            previous = Some(results);
        }
        Ok(Self { paid })
    }

    pub(super) fn check(self, canonical: &[&ResultRow]) -> Result<()> {
        ensure!(canonical.len() == self.paid.len());
        for (simulated, canonical) in self.paid.into_iter().zip(canonical) {
            // Simulation uses a discarded next-block context; the real batch
            // executes at its anchor. Compare outcomes, not ephemeral positions.
            // These calls do not read height, and both run before block maintenance.
            let mut expected = simulated;
            expected.id = canonical.id;
            expected.height = canonical.height;
            expected.tx_index = canonical.tx_index;
            ensure!(
                &expected == *canonical,
                "simulation and canonical execution differ"
            );
        }
        Ok(())
    }
}
