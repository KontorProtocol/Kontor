use std::future::Future;
use std::time::Instant;

use anyhow::Result;
use indexer_types::Event;
use tracing::warn;

use crate::consensus::finality_types::StateEvent;
use crate::reactor::Reactor;
use crate::reactor::execution::ExecutionStep;
use crate::reactor::executor::Executor;

impl<E: Executor> Reactor<E> {
    pub(crate) fn apply_certified_closure(
        &mut self,
        height: u64,
    ) -> impl Future<Output = Result<()>> + '_ {
        Box::pin(async move {
            loop {
                let started_at = Instant::now();
                match self.execution.step_certified_closure(height).await? {
                    ExecutionStep::Complete => return Ok(()),
                    ExecutionStep::Planning | ExecutionStep::Observed => {}
                    ExecutionStep::RolledBack(height) => {
                        self.observe_rollback(height).await;
                        let checkpoint = self.consensus.get_checkpoint(&self.db_conn()).await;
                        self.consensus
                            .emit_state_event(StateEvent::RollbackExecuted {
                                to_anchor: height + 1,
                                entries_removed: 0,
                                checkpoint,
                            });
                    }
                    ExecutionStep::Block(applied) => self.observe_block(applied, started_at).await,
                    ExecutionStep::Batch {
                        applied,
                        anchor_height,
                        anchor_hash,
                        consensus_height,
                        original,
                        selected,
                    } => {
                        let executed = selected.as_deref().unwrap_or(&original);
                        let outcome = self
                            .observe_batch(
                                applied,
                                anchor_height,
                                anchor_hash,
                                consensus_height,
                                executed,
                                started_at,
                            )
                            .await;
                        for transaction in &original {
                            self.consensus.mempool.suppress(&transaction.compute_txid());
                        }
                        if let Some(txids) = outcome.announced_txids(executed)
                            && let Some(tx) = &self.event_tx
                            && tx.send(Event::BatchProcessed { txids }).await.is_err()
                        {
                            warn!("Event receiver dropped, cannot send BatchProcessed event");
                        }
                    }
                    ExecutionStep::Finality if self.consensus.observation.is_some() => {
                        // Observation failure must not turn a committed stage into a retry.
                        match self
                            .consensus
                            .run_finality_checks(&self.db_conn(), self.execution.last_height)
                            .await
                        {
                            Ok((events, _)) => self.consensus.emit_finality_events(&events),
                            Err(error) => {
                                warn!(%error, "Cannot refresh optional finality observations")
                            }
                        }
                    }
                    ExecutionStep::Finality => {}
                }
                tokio::task::yield_now().await;
            }
        })
    }
}
