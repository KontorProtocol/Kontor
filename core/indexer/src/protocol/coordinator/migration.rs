use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::{BlockHash, Network, hashes::Hash};
use thiserror::Error;

use super::linked::{begin_unit, finish_canonical_unit};
use super::selection::ExecutionSelection;
use crate::database::canonical_history::{self, ApplicationCursor, HistoryState, MigrationReceipt};
use crate::database::migration_input::MigrationInput;
use crate::database::queries::{get_checkpoint_latest, max_block_height, select_block_at_height};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::identity::{ExecutionIdentity, MigrationDefinition, PlanId};
use crate::protocol::migration_work::{MigrationMeter, MigrationWork};
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::HostFailure;
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
#[cfg_attr(
    not(any(test, feature = "protocol-qualification")),
    allow(dead_code, reason = "K3 substrate; live activation is wired in K7")
)]
pub(crate) async fn apply(
    service: &OwnerService,
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
    request: &MigrationRequest,
) -> Result<MigrationReceipt> {
    selection.ensure_runtime(network, session.origin())?;
    ensure!(
        selection.envelope().3
            == (
                8,
                request.anchor_height,
                Some(request.anchor_hash.to_byte_array()),
                0
            ),
        "migration request does not match its execution selection"
    );
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
    let application = request.application()?;
    let key = application.migration_key()?;
    let encoded_definition = request.definition.encode()?;
    let input = MigrationInput::open(&session.conn).await?;
    let capacity = service.reserve_root_capacity().await?;
    let mut lease = service
        .begin_linked_migration_reserved(session, capacity, selection.clone(), input.clone())
        .await?;
    if let Err(error) = begin_unit(session, selection, network).await {
        lease.drain().await?;
        if !session.conn.is_autocommit() {
            lease.settle(false).await?;
        }
        lease.complete().await?;
        return Err(error);
    }
    let result = async {
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
            canonical_history::state(&session.conn).await? == HistoryState::Ready(request.expected),
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
        let outcome = (session.executor.operations.migration)(
            session.executor.owner.clone(),
            selection.envelope(),
            encoded_definition,
            input.callbacks(),
        )
        .await
        .map_err(HostFailure::from)?;
        let values = outcome.map_err(|tag| match tag {
            0 => MigrationRejected::UnknownDefinition,
            1 => MigrationRejected::Budget,
            2 => MigrationRejected::InvalidOperation,
            tag => MigrationRejected::UnknownOutcome(tag),
        })?;
        let work = MigrationWork::from_values(values);
        MigrationMeter::new(request.definition.budget).charge(work)?;
        canonical_history::append_migration(&session.conn, &application, work).await?;
        Ok(MigrationReceipt { application, work })
    }
    .await;
    finish_canonical_unit(lease, result, true).await
}
