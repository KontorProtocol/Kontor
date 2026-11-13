use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, ensure};
use bitcoin::{BlockHash, Network, Transaction};
use libsql::Connection;

use super::PruneConfig;
use super::batches::AppliedBatch;
use super::blocks::AppliedBlock;
use super::consensus_state::certified_startup;
use super::executor::Executor;
use crate::bitcoin_follower::block::BlockInput;
use crate::consensus::{Height, Value};
use crate::database::certified_history::{
    self, Status, branch, closure, completion, control, finality, reconcile, replay_input, work,
};
use crate::database::queries::{PRUNE_WATERMARK_KEY, get_meta_u64, select_block_latest};
use crate::protocol::coordinator::activation_execution;
use crate::protocol::coordinator::application_closure::{StageOutcome, WorkItem};
use crate::protocol::coordinator::certified_input::Command;
use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol::coordinator::closure_execution::{begin_stage, select_stage};
use crate::protocol::coordinator::decision::DeferredDecision;
use crate::protocol::coordinator::linked::{TransactionRecognizer, session_factory_for_definition};
use crate::protocol::coordinator::selection::{
    ApplicationPosition, ExecutionSelection, select_canonical, select_current,
};
use crate::protocol::identity::ExecutionDefinitionId;
use crate::runtime::ownership::OwnerService;
use crate::runtime::pool::LinkedSession;
use crate::stopper::ShutdownSignal;

// Startup hands this owner to the live reactor after recovery. No engine, RPC
// admission state, or notification channel is needed to apply certified work.
pub(super) struct ExecutionContext<E: Executor> {
    pub(super) executor: E,
    pub(super) recognizer: TransactionRecognizer,
    pub(super) session: LinkedSession,
    pub(super) sessions: BTreeMap<ExecutionDefinitionId, LinkedSession>,
    pub(super) network: Network,
    pub(super) protocol_context: EraContext,
    pub(super) owner_service: OwnerService,
    pub(super) prune: PruneConfig,
    pub(super) prune_watermark: u64,
    pub(super) last_height: u64,
    pub(super) last_hash: Option<BlockHash>,
}

impl<E: Executor> ExecutionContext<E> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        executor: E,
        session: LinkedSession,
        network: Network,
        owner_service: OwnerService,
        protocol_context: EraContext,
        prune: PruneConfig,
        last_height: u64,
        last_hash: Option<BlockHash>,
    ) -> Self {
        let recognizer = TransactionRecognizer::new(
            session.origin(),
            network,
            session.executor.operations.recognize.clone(),
        );
        Self {
            executor,
            recognizer,
            session,
            sessions: BTreeMap::new(),
            network,
            protocol_context,
            owner_service,
            prune,
            prune_watermark: 0,
            last_height,
            last_hash,
        }
    }

    pub(super) fn db_conn(&self) -> Connection {
        self.session.conn.clone()
    }

    pub(super) fn select_executor(
        &self,
        position: ApplicationPosition,
    ) -> impl Future<Output = Result<ExecutionSelection>> + Send + 'static {
        let conn = self.db_conn();
        let network = self.network;
        async move { select_current(&conn, network, position).await }
    }

    pub(super) async fn select_session(&mut self, selection: &ExecutionSelection) -> Result<()> {
        selection.ensure_live()?;
        ensure!(
            self.session.conn.is_autocommit()
                && !self.session.canonical_busy.load(Ordering::SeqCst),
            "executor session selection requires a settled root"
        );
        selection.verify_base(&self.session.conn).await?;
        let Some(definition) = selection.canonical_execution() else {
            selection.ensure_runtime(self.network, self.session.origin())?;
            return Ok(());
        };
        if self.session.executor.execution_definition? == definition {
            selection.ensure_runtime(self.network, self.session.origin())?;
            return Ok(());
        }
        let next = match self.sessions.get(&definition) {
            Some(session) => session.clone(),
            None => {
                let factory = session_factory_for_definition(self.network, definition, None)?;
                let executor = factory(self.db_conn().into()).await?;
                let mut session = LinkedSession::new(self.db_conn(), executor);
                // All cached executors use the same physical writer connection.
                // A different definition must not create another admission gate.
                session.canonical_busy = self.session.canonical_busy.clone();
                session
            }
        };
        selection.execution_identity(next.executor.execution_definition?)?;
        selection.ensure_runtime(self.network, next.origin())?;
        selection.verify_base(&self.session.conn).await?;
        self.sessions.insert(
            self.session.executor.execution_definition?,
            self.session.clone(),
        );
        self.sessions.insert(definition, next.clone());
        self.recognizer = TransactionRecognizer::new(
            next.origin(),
            self.network,
            next.executor.operations.recognize.clone(),
        );
        self.session = next;
        Ok(())
    }

    async fn restore_canonical_session(&mut self) -> Result<()> {
        let selection = select_canonical(
            &self.db_conn(),
            self.network,
            ApplicationPosition::Committee,
        )
        .await?;
        self.select_session(&selection).await
    }
}

pub(super) enum ExecutionStep {
    Planning,
    RolledBack(u64),
    Block(AppliedBlock),
    Batch {
        applied: AppliedBatch,
        anchor_height: u64,
        anchor_hash: BlockHash,
        consensus_height: Height,
        original: Vec<Transaction>,
        selected: Option<Vec<Transaction>>,
    },
    Finality,
    Control,
    Observed,
    Activation,
    Complete,
}

impl<E: Executor> ExecutionContext<E> {
    // Each return follows a settled transaction. The caller may yield or honor
    // shutdown here, including between pages of a large finality plan.
    pub(super) fn step_certified_closure(
        &mut self,
        height: u64,
    ) -> impl Future<Output = Result<ExecutionStep>> + '_ {
        Box::pin(async move {
            let conn = self.db_conn();
            if certified_history::frontier(&conn).await?.closed_height >= height {
                completion::completed(&conn, height).await?;
                self.restore_canonical_session().await?;
                return Ok(ExecutionStep::Complete);
            }
            let progress = closure::begin(&conn, height).await?;
            let Some((action, _)) = progress.next else {
                completion::publish(&conn, height).await?;
                self.restore_canonical_session().await?;
                return Ok(ExecutionStep::Complete);
            };
            let selection = select_stage(&conn, self.network, action).await?;
            self.select_session(&selection).await?;
            let outcome: Result<ExecutionStep> = match action {
                WorkItem::Reconcile => {
                    if !reconcile::step(&conn, height).await? {
                        return Ok(ExecutionStep::Planning);
                    }
                    let draft = work::for_origin(&conn, progress.work_origin()?).await?;
                    let stage =
                        begin_stage(&self.owner_service, &self.session, self.network, height)
                            .await?
                            .context("reconciliation stage disappeared")?;
                    let result = async {
                        let cursor = work::publish(&conn, draft).await?;
                        Ok(((), StageOutcome::Reconciled, cursor))
                    }
                    .await;
                    stage.finish(result).await?;
                    Ok(ExecutionStep::Planning)
                }
                WorkItem::Activate { .. } => {
                    activation_execution::step(
                        &self.owner_service,
                        &self.session,
                        self.network,
                        height,
                    )
                    .await?;
                    Ok(ExecutionStep::Activation)
                }
                WorkItem::Rollback { height } => {
                    self.rollback(height).await?;
                    Ok(ExecutionStep::RolledBack(height))
                }
                WorkItem::Execute { decision } | WorkItem::Replay { decision, .. } => {
                    let retained = certified_history::load(&conn, decision).await?;
                    let value = Value::from_input(retained.input().clone())?;
                    match *value.command() {
                        Command::Control { .. } => {
                            ensure!(
                                matches!(action, WorkItem::Execute { .. }),
                                "control has transaction replay work"
                            );
                            let stage = begin_stage(
                                &self.owner_service,
                                &self.session,
                                self.network,
                                height,
                            )
                            .await?
                            .context("control stage disappeared")?;
                            let remaining = stage.remaining_after();
                            let result = control::admission::apply(&conn, height, decision)
                                .await
                                .map(|outcome| ((), outcome, remaining));
                            stage.finish(result).await?;
                            Ok(ExecutionStep::Control)
                        }
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
                            Ok(ExecutionStep::Block(
                                self.handle_block(block, &decision).await?,
                            ))
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
                            let consensus_height = Height::new(decision);
                            let applied = self
                                .process_decided_batch(
                                    anchor_height,
                                    anchor_hash,
                                    consensus_height,
                                    retained.proof(),
                                    selected.as_deref().unwrap_or(&original),
                                    selected.as_ref().map(|_| original.as_slice()),
                                )
                                .await?;
                            Ok(ExecutionStep::Batch {
                                applied,
                                anchor_height,
                                anchor_hash,
                                consensus_height,
                                original,
                                selected,
                            })
                        }
                    }
                }
                WorkItem::Finality => {
                    if !finality::step(&conn, height).await? {
                        return Ok(ExecutionStep::Planning);
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
                    Ok(ExecutionStep::Finality)
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
                    Ok(ExecutionStep::Observed)
                }
            };
            let outcome = outcome?;
            self.restore_canonical_session().await?;
            Ok(outcome)
        })
    }

    async fn restore_applied_tip(&mut self) -> Result<()> {
        let conn = self.db_conn();
        let position = closure::canonical_position(&conn, self.protocol_context.chain).await?;
        let boundary = branch::boundary(&conn, self.protocol_context).await?;
        let block = select_block_latest(&conn)
            .await?
            .context("applied Bitcoin position missing")?;
        ensure!(
            block.height == position.storage_height,
            "applied block and canonical cursor differ"
        );
        if block.height == 0 {
            self.last_height = boundary.first_height - 1;
            self.last_hash = None;
        } else {
            ensure!(
                block.height >= boundary.first_height,
                "applied tip precedes Bitcoin baseline"
            );
            self.last_height = block.height;
            self.last_hash = Some(block.hash);
        }
        Ok(())
    }

    pub(super) async fn recover(&mut self, shutdown: &ShutdownSignal) -> Result<bool> {
        let conn = self.db_conn();
        self.prune_watermark = get_meta_u64(&conn, PRUNE_WATERMARK_KEY, 0)
            .await
            .context("loading prune watermark before recovery failed")?;
        let frontier = certified_history::frontier(&conn).await?;
        ensure!(
            frontier.status == Status::Ready && frontier.context == Some(self.protocol_context),
            "recovery lacks initialized certified history"
        );
        if frontier.authenticated_height > frontier.closed_height {
            let height = frontier.authenticated_height;
            closure::begin(&conn, height).await?;
            closure::recover(&conn, height).await?;
            self.restore_applied_tip().await?;
            loop {
                if shutdown.is_cancelled() {
                    return Ok(false);
                }
                if matches!(
                    self.step_certified_closure(height).await?,
                    ExecutionStep::Complete
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
        self.protocol_context = certified_startup(&conn).await?.0;
        self.restore_applied_tip().await?;
        self.restore_canonical_session().await?;
        ensure!(
            conn.is_autocommit(),
            "recovery retained a writer transaction"
        );
        Ok(!shutdown.is_cancelled())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::database::canonical_history;
    use crate::protocol::coordinator::activation_execution::tests::fixture;
    use crate::protocol::coordinator::linked::{begin_canonical_unit, finish_canonical_unit};
    use crate::reactor::executor::NoopExecutor;

    #[tokio::test]
    async fn session_selection_rejects_busy_stale_and_uninstalled_targets() -> Result<()> {
        let (_directory, session, service, _) = Box::pin(fixture()).await?;
        let conn = session.conn.clone();
        let context = certified_history::frontier(&conn).await?.context.unwrap();
        let owner = session.executor.owner.clone();
        let mut execution = ExecutionContext::new(
            NoopExecutor,
            session,
            Network::Regtest,
            service,
            context,
            PruneConfig {
                enabled: false,
                retain_blocks: 144,
            },
            1,
            None,
        );
        let selected = execution
            .select_executor(ApplicationPosition::Committee)
            .await?;
        assert!(selected.canonical_execution().is_some());
        execution.select_session(&selected).await?;
        assert!(Arc::ptr_eq(&owner, &execution.session.executor.owner));

        execution
            .session
            .canonical_busy
            .store(true, Ordering::SeqCst);
        assert!(execution.select_session(&selected).await.is_err());
        execution
            .session
            .canonical_busy
            .store(false, Ordering::SeqCst);
        let lease = begin_canonical_unit(
            &execution.owner_service,
            &execution.session,
            &selected,
            execution.network,
            false,
        )
        .await?;
        assert!(execution.select_session(&selected).await.is_err());
        finish_canonical_unit(lease, Ok(()), false).await?;

        // The fixture's scheduled successor deliberately has no installed mapping.
        // Routing must fail before opening a migration or advancing its stage.
        let before = canonical_history::state(&conn).await?;
        let progress = closure::progress(&conn, 1).await?;
        let error = execution.step_certified_closure(1).await.err().unwrap();
        assert!(format!("{error:#}").contains("protocol is not installed"));
        assert_eq!(canonical_history::state(&conn).await?, before);
        assert_eq!(closure::progress(&conn, 1).await?.stage, progress.stage);
        assert!(conn.is_autocommit());
        assert!(Arc::ptr_eq(&owner, &execution.session.executor.owner));

        conn.execute("BEGIN", ()).await?;
        canonical_history::rollback(&conn, 0).await?;
        conn.execute("COMMIT", ()).await?;
        assert!(execution.select_session(&selected).await.is_err());
        assert!(Arc::ptr_eq(&owner, &execution.session.executor.owner));
        Ok(())
    }
}
