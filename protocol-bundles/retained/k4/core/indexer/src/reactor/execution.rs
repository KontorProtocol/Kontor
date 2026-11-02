use std::future::Future;

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
    self, Status, branch, closure, completion, finality, replay_input, work,
};
use crate::database::queries::{PRUNE_WATERMARK_KEY, get_meta_u64, select_block_latest};
use crate::protocol::coordinator::application_closure::{StageOutcome, WorkItem};
use crate::protocol::coordinator::certified_input::Command;
use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol::coordinator::closure_execution::begin_stage;
use crate::protocol::coordinator::decision::DeferredDecision;
use crate::protocol::coordinator::linked::TransactionRecognizer;
use crate::protocol::coordinator::selection::{
    ApplicationPosition, ExecutionSelection, select_legacy_p1,
};
use crate::runtime::ownership::OwnerService;
use crate::runtime::pool::LinkedSession;
use crate::stopper::ShutdownSignal;

// Startup hands this owner to the live reactor after recovery. No engine, RPC
// admission state, or notification channel is needed to apply certified work.
pub(super) struct ExecutionContext<E: Executor> {
    pub(super) executor: E,
    pub(super) recognizer: TransactionRecognizer,
    pub(super) session: LinkedSession,
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
        async move { select_legacy_p1(&conn, network, position).await }
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
    Observed,
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
                return Ok(ExecutionStep::Complete);
            }
            let progress = closure::begin(&conn, height).await?;
            let Some((action, _)) = progress.next else {
                completion::publish(&conn, height).await?;
                return Ok(ExecutionStep::Complete);
            };
            match action {
                WorkItem::Rollback { height } => {
                    self.rollback(height).await?;
                    Ok(ExecutionStep::RolledBack(height))
                }
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
            }
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
        certified_startup(&conn).await?;
        self.restore_applied_tip().await?;
        ensure!(
            conn.is_autocommit(),
            "recovery retained a writer transaction"
        );
        Ok(!shutdown.is_cancelled())
    }
}
