use anyhow::{Context, Result, ensure};
use bitcoin::{BlockHash, Network};

use super::application_closure::{StageOutcome, StageRecord, WorkItem};
use super::certified_input::Command;
use super::closure_execution::{begin_stage, record_stage};
use super::migration::{self, MigrationRequest};
use super::registry;
use super::selection::{ApplicationPosition, ExecutionSelection, select_canonical};
use crate::database::canonical_history::{self, HistoryState};
use crate::database::certified_history::{activation, closure, load_verified_input};
use crate::database::queries::get_checkpoint_latest;
use crate::protocol::identity::{ExecutionIdentity, MigrationDefinition};
use crate::runtime::ownership::OwnerService;
use crate::runtime::pool::LinkedSession;

async fn boundary(session: &LinkedSession, height: u64) -> Result<(u64, u64, BlockHash)> {
    let progress = closure::progress(&session.conn, height).await?;
    let Some((WorkItem::Activate { decision }, _)) = progress.next else {
        anyhow::bail!("closure has no activation work");
    };
    let certified = load_verified_input(&session.conn, decision).await?;
    let Command::Block { height, hash, .. } = certified.decision().descriptor.command else {
        anyhow::bail!("activation work does not name a block");
    };
    Ok((decision, height, hash))
}

pub(crate) async fn step(
    service: &OwnerService,
    session: &LinkedSession,
    network: Network,
    height: u64,
) -> Result<StageRecord> {
    let (_, anchor, hash) = boundary(session, height).await?;
    let pending = activation::pending(&session.conn, anchor, hash).await?;
    if let Some(state) = pending {
        let target = &state.plan.manifest;
        let installed = registry::resolve(target)?;
        ensure!(
            session.origin() == installed.executor,
            "activation requires the target executor session"
        );
        let selection = select_canonical(
            &session.conn,
            network,
            ApplicationPosition::Migration {
                anchor_height: anchor,
                anchor_hash: hash,
            },
        )
        .await?;
        return apply(
            service,
            session,
            &selection,
            network,
            height,
            installed.migration,
        )
        .await;
    }
    let stage = begin_stage(service, session, network, height)
        .await?
        .context("activation stage disappeared")?;
    let result = (|| {
        ensure!(
            matches!(stage.action(), WorkItem::Activate { .. }),
            "activation work changed"
        );
        Ok(((), StageOutcome::NoActivation, stage.remaining_after()))
    })();
    let (_, record) = stage.finish(result).await?;
    Ok(record)
}

pub(crate) async fn apply(
    service: &OwnerService,
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
    height: u64,
    definition: MigrationDefinition,
) -> Result<StageRecord> {
    let (decision, anchor_height, anchor_hash) = boundary(session, height).await?;
    let state = activation::pending(&session.conn, anchor_height, anchor_hash)
        .await?
        .context("activation no longer has a pending plan")?;
    let plan = &state.plan;
    ensure!(
        definition.id()? == plan.manifest.migration
            && definition.execution == plan.manifest.executor,
        "installed migration differs from pending target"
    );
    let HistoryState::Ready(expected) = canonical_history::state(&session.conn).await? else {
        anyhow::bail!("activation lacks canonical history");
    };
    let checkpoint = get_checkpoint_latest(&session.conn)
        .await?
        .map(|row| -> Result<[u8; 32]> {
            hex::decode(row.hash)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid migration checkpoint"))
        })
        .transpose()?;
    let request = MigrationRequest {
        expected,
        execution: ExecutionIdentity::Protocol {
            protocol: plan.manifest.id()?,
            execution: plan.manifest.executor,
        },
        plan: plan.id,
        anchor_height,
        anchor_hash,
        checkpoint,
        definition,
    };
    let mut owned = migration::begin(service, session, selection, network, &request).await?;
    let result = async {
        let ticket = closure::prepare(&session.conn, height)
            .await?
            .context("activation work disappeared during admission")?;
        ensure!(
            ticket.action() == WorkItem::Activate { decision },
            "activation work changed during admission"
        );
        ensure!(
            activation::pending(&session.conn, anchor_height, anchor_hash).await? == Some(state),
            "activation state changed during admission"
        );
        let remaining = ticket.remaining_after();
        let receipt = owned.execute().await?;
        activation::record(&session.conn, &receipt).await?;
        record_stage(
            session,
            selection,
            network,
            ticket,
            StageOutcome::Applied,
            remaining,
        )
        .await
    }
    .await;
    owned.finish(result).await
}

#[cfg(test)]
pub(crate) mod tests;
