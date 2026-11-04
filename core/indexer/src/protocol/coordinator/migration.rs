use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::{BlockHash, Network, hashes::Hash};
use thiserror::Error;

use super::linked::{abort_failed_begin, begin_unit, finish_canonical_unit};
use super::selection::ExecutionSelection;
use crate::database::canonical_history::{self, ApplicationCursor, HistoryState, MigrationReceipt};
use crate::database::migration_input::MigrationInput;
use crate::database::queries::{get_checkpoint_latest, max_block_height, select_block_at_height};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::identity::{ExecutionIdentity, MigrationDefinition, PlanId};
use crate::protocol::migration_work::{MigrationMeter, MigrationWork};
use crate::runtime::ownership::adapter::HostFailure;
use crate::runtime::ownership::{LinkedCanonicalRootLease, OwnerService};
use crate::runtime::pool::LinkedSession;

#[cfg(test)]
mod tests;

pub(crate) struct MigrationRequest {
    pub(crate) expected: ApplicationCursor,
    pub(crate) execution: ExecutionIdentity,
    pub(crate) plan: PlanId,
    pub(crate) anchor_height: u64,
    pub(crate) anchor_hash: BlockHash,
    pub(crate) checkpoint: Option<[u8; 32]>,
    pub(crate) definition: MigrationDefinition,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum MigrationRejected {
    #[error("migration definition is not registered by the selected executor")]
    UnknownDefinition,
    #[error("migration work budget exhausted")]
    Budget,
    #[error("migration routine violated its execution interface")]
    InvalidOperation,
    #[error("executor returned an unknown migration outcome {0}")]
    UnknownOutcome(u8),
}

#[derive(Debug, Error)]
#[error("migration work consumed: {0:?}")]
pub(crate) struct MigrationAttemptWork(pub(crate) Option<MigrationWork>);

impl MigrationRequest {
    fn application(&self) -> Result<CanonicalApplication> {
        ensure!(
            self.expected.authentic,
            "migration requires authentic input history"
        );
        ensure!(
            self.expected.storage_height == self.anchor_height,
            "migration must follow its anchor's execution"
        );
        let ordinal = self
            .expected
            .ordinal
            .checked_add(1)
            .context("application ordinal overflow")?;
        ensure!(
            ordinal <= i64::MAX as u64 && self.anchor_height <= i64::MAX as u64,
            "migration position exceeds database range"
        );
        Ok(CanonicalApplication {
            chain: self.expected.chain,
            ordinal,
            parent_lineage: self.expected.lineage,
            execution: self.execution,
            storage_height: self.anchor_height,
            source: ApplicationSource::Migration {
                anchor_height: self.anchor_height,
                anchor_hash: self.anchor_hash.to_byte_array(),
                plan: self.plan,
                definition: self.definition.id()?,
                checkpoint: self.checkpoint,
            },
            input: None,
        })
    }
}

// Authorization and after-H scheduling belong to the upgrade controller. This
// entry point owns the atomic state transition for its already selected request.
pub(crate) async fn apply(
    service: &OwnerService,
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
    request: &MigrationRequest,
) -> Result<MigrationReceipt> {
    let mut migration = begin(service, session, selection, network, request).await?;
    let result = migration.execute().await;
    migration.finish(result).await
}

// Activation prepares its closure ticket inside this unit, then writes its
// protocol/control records before finishing it. No second root or commit is needed.
pub(crate) struct OwnedMigration<'a> {
    lease: LinkedCanonicalRootLease,
    session: LinkedSession,
    selection: ExecutionSelection,
    request: &'a MigrationRequest,
    input: Arc<MigrationInput>,
    used: Option<MigrationWork>,
    phase: MigrationPhase,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MigrationPhase {
    Ready,
    Failed,
    Succeeded,
}

pub(crate) async fn begin<'a>(
    service: &OwnerService,
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
    request: &'a MigrationRequest,
) -> Result<OwnedMigration<'a>> {
    begin_inner(service, session, selection, network, request)
        .await
        .map_err(|error| error.context(MigrationAttemptWork(Some(MigrationWork::default()))))
}

async fn begin_inner<'a>(
    service: &OwnerService,
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
    request: &'a MigrationRequest,
) -> Result<OwnedMigration<'a>> {
    selection.ensure_runtime(network, session.origin())?;
    selection.ensure_migration_at(request.anchor_height, request.anchor_hash)?;
    let execution = session.executor.execution_definition?;
    let selected_identity = match request.execution {
        ExecutionIdentity::Baseline(execution) | ExecutionIdentity::Protocol { execution, .. } => {
            execution
        }
    };
    ensure!(
        execution == request.definition.execution && execution == selected_identity,
        "migration definition does not belong to the selected executor"
    );
    request.application()?;
    request.definition.encode()?;
    let input = MigrationInput::open(&session.conn).await?;
    let capacity = service.reserve_root_capacity().await?;
    let lease = service
        .begin_linked_migration_reserved(session, capacity, selection.clone(), input.clone())
        .await?;
    if let Err(error) = begin_unit(session, selection, network).await {
        abort_failed_begin(lease, session).await?;
        return Err(error);
    }
    Ok(OwnedMigration {
        lease,
        session: session.clone(),
        selection: selection.clone(),
        request,
        input,
        used: Some(MigrationWork::default()),
        phase: MigrationPhase::Ready,
    })
}

impl OwnedMigration<'_> {
    pub(crate) async fn execute(&mut self) -> Result<MigrationReceipt> {
        ensure!(
            self.phase == MigrationPhase::Ready,
            "migration unit was already executed"
        );
        // Cancellation or an error must not leave this unit eligible to commit.
        self.phase = MigrationPhase::Failed;
        let result = self.execute_inner().await;
        if result.is_ok() {
            self.phase = MigrationPhase::Succeeded;
        }
        result
    }

    async fn execute_inner(&mut self) -> Result<MigrationReceipt> {
        let session = &self.session;
        let selection = &self.selection;
        let request = self.request;
        let input = &self.input;
        let used = &mut self.used;
        let application = request.application()?;
        let key = application.migration_key()?;
        let encoded_definition = request.definition.encode()?;
        async {
            let anchor = select_block_at_height(&session.conn, request.anchor_height)
                .await?
                .context("migration anchor is absent")?;
            ensure!(
                anchor.hash == request.anchor_hash,
                "migration anchor changed"
            );
            // A successful retry can occur after later applications. Its original
            // prestate/checkpoint no longer describes the tip, so check the surviving
            // marker before comparing current state to the requested prestate.
            if let Some(receipt) =
                canonical_history::surviving_migration_result(&session.conn, key).await?
            {
                ensure!(
                    receipt.application == application,
                    "migration retry context changed"
                );
                MigrationMeter::new(request.definition.budget).charge(receipt.work)?;
                return Ok(receipt);
            }
            ensure!(
                canonical_history::state(&session.conn).await?
                    == HistoryState::Ready(request.expected),
                "migration canonical prestate changed"
            );
            ensure!(
                max_block_height(&session.conn).await? == Some(request.anchor_height),
                "new migration cannot write behind the canonical block tip"
            );
            let checkpoint = get_checkpoint_latest(&session.conn)
                .await?
                .map(|row| -> Result<[u8; 32]> {
                    hex::decode(row.hash)?
                        .try_into()
                        .map_err(|_| anyhow!("invalid legacy checkpoint digest"))
                })
                .transpose()?;
            ensure!(
                checkpoint == request.checkpoint,
                "migration checkpoint changed"
            );
            input
                .pin(request.expected, request.anchor_height, request.anchor_hash)
                .await?;
            *used = None;
            let outcome = (session.executor.operations.migration)(
                session.executor.owner.clone(),
                selection.envelope(),
                encoded_definition,
                input.callbacks(),
            )
            .await
            .map_err(|(tag, message, values)| {
                *used = values.map(MigrationWork::from_values);
                HostFailure::from((tag, message))
            })?;
            let values = outcome.map_err(|(tag, values)| {
                *used = values.map(MigrationWork::from_values);
                match tag {
                    0 => MigrationRejected::UnknownDefinition,
                    1 => MigrationRejected::Budget,
                    2 => MigrationRejected::InvalidOperation,
                    tag => MigrationRejected::UnknownOutcome(tag),
                }
            })?;
            let work = MigrationWork::from_values(values);
            *used = Some(work);
            MigrationMeter::new(request.definition.budget).charge(work)?;
            canonical_history::append_migration(&session.conn, &application, work).await?;
            Ok(MigrationReceipt { application, work })
        }
        .await
    }

    pub(crate) async fn finish<T>(self, result: Result<T>) -> Result<T> {
        let result = result.and_then(|value| {
            ensure!(
                self.phase == MigrationPhase::Succeeded,
                "cannot commit an unfinished or failed migration"
            );
            Ok(value)
        });
        finish_canonical_unit(self.lease, result, true)
            .await
            .map_err(|error| error.context(MigrationAttemptWork(self.used)))
    }
}
