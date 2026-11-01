use std::future::Future;

use anyhow::{Context, Result, ensure};

use crate::bitcoin_follower::block::BlockInput;
use crate::consensus::{Height, Value};
use crate::database::certified_history::{self, closure, completion, finality, replay_input, work};
use crate::protocol::coordinator::application_closure::{StageOutcome, WorkItem};
use crate::protocol::coordinator::certified_input::Command;
use crate::protocol::coordinator::closure_execution::begin_stage;
use crate::protocol::coordinator::decision::DeferredDecision;
use crate::reactor::Reactor;
use crate::reactor::executor::Executor;

impl<E: Executor> Reactor<E> {
    pub(crate) fn apply_certified_closure(
        &mut self,
        height: u64,
    ) -> impl Future<Output = Result<()>> + '_ {
        // Keep the planner and executor state machines out of the caller's frame.
        Box::pin(async move {
            let conn = self.db_conn();
            closure::begin(&conn, height).await?;
            loop {
                let progress = closure::progress(&conn, height).await?;
                let Some((action, _)) = progress.next else {
                    completion::publish(&conn, height).await?;
                    return Ok(());
                };
                match action {
                    WorkItem::Rollback { height } => self.rollback(height).await?,
                    WorkItem::Execute { decision } | WorkItem::Replay { decision, .. } => {
                        let retained = certified_history::load(&conn, decision).await?;
                        let value = Value::from_input(retained.input().clone())?;
                        match *value.command() {
                            Command::Block { .. } => {
                                ensure!(
                                    matches!(action, WorkItem::Execute { .. }),
                                    "batch replay item names a block"
                                );
                                let block = BlockInput::from_exact(value.input())?;
                                let decision = DeferredDecision {
                                    consensus_height: Height::new(decision),
                                    value,
                                    certificate: retained.proof().to_vec(),
                                    execution_txs: None,
                                };
                                self.handle_block(block, &decision).await?;
                            }
                            Command::Batch {
                                anchor_height,
                                anchor_hash,
                            } => {
                                let original = value.batch_raw_txs();
                                let selected = if let WorkItem::Replay { input, .. } = action {
                                    let origin = work::published(&conn, progress.remaining.plan)
                                        .await?
                                        .origin;
                                    Some(
                                        replay_input::get(&conn, input, origin, decision)
                                            .await?
                                            .transactions(&original)?,
                                    )
                                } else {
                                    None
                                };
                                self.process_decided_batch(
                                    anchor_height,
                                    anchor_hash,
                                    Height::new(decision),
                                    retained.proof(),
                                    selected.as_deref().unwrap_or(&original),
                                    selected.as_ref().map(|_| original.as_slice()),
                                )
                                .await?;
                            }
                        }
                    }
                    WorkItem::Finality => {
                        while !finality::step(&conn, height).await? {
                            tokio::task::yield_now().await;
                        }
                        let draft = work::for_origin(&conn, progress.work_origin()?).await?;
                        let stage =
                            begin_stage(&self.owner_service, &self.session, self.network, height)
                                .await?
                                .context("finality stage disappeared")?;
                        let result = async {
                            let cursor = work::publish(&conn, draft).await?;
                            Ok(((), StageOutcome::FinalityEvaluated, cursor))
                        }
                        .await;
                        stage.finish(result).await?;
                    }
                    WorkItem::Observe => {
                        let stage =
                            begin_stage(&self.owner_service, &self.session, self.network, height)
                                .await?
                                .context("observation stage disappeared")?;
                        let remaining = stage.remaining_after();
                        stage
                            .finish(Ok(((), StageOutcome::Observed, remaining)))
                            .await?;
                    }
                }
            }
        })
    }
}
