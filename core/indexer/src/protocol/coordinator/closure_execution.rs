use anyhow::{Context, Result, ensure};
use bitcoin::Network;

use super::application_closure::{StageOutcome, StageRecord, WorkItem};
use super::certified_input::Command;
use super::linked::{begin_canonical_unit, finish_canonical_unit, observe_registrations};
use super::registration_history::RegistrationSnapshot;
use super::selection::{ApplicationPosition, ExecutionSelection, select_legacy_p1};
use crate::database::certified_history::{closure, load, registrations};
use crate::runtime::ownership::{LinkedCanonicalRootLease, OwnerService};
use crate::runtime::pool::LinkedSession;

pub(crate) struct OwnedClosureStage {
    lease: LinkedCanonicalRootLease,
    ticket: closure::StageTicket,
    session: LinkedSession,
    selection: ExecutionSelection,
    network: Network,
}

impl OwnedClosureStage {
    pub(crate) fn selection(&self) -> &ExecutionSelection {
        &self.selection
    }

    pub(crate) fn action(&self) -> WorkItem {
        self.ticket.action()
    }

    pub(crate) fn remaining_after(&self) -> Vec<WorkItem> {
        self.ticket.remaining_after()
    }

    pub(crate) async fn finish<T>(
        self,
        result: Result<(T, StageOutcome, Vec<WorkItem>)>,
    ) -> Result<(T, StageRecord)> {
        let Self {
            lease,
            ticket,
            session,
            selection,
            network,
        } = self;
        let result = async {
            let (value, outcome, remaining) = result?;
            let previous = registrations::latest(&session.conn)
                .await?
                .context("stage lacks prior registration observation")?;
            let watched = previous
                .entries
                .iter()
                .map(|entry| entry.holder.clone())
                .collect();
            let observation = observe_registrations(&session, &selection, network, watched).await?;
            let position =
                closure::canonical_position(&session.conn, previous.position.context.chain).await?;
            let snapshot = RegistrationSnapshot::observe(
                Some(&previous),
                ticket.observation_position(position.lineage)?,
                observation,
            )?;
            let record =
                closure::commit_stage(&session.conn, ticket, outcome, remaining, &snapshot).await?;
            Ok((value, record))
        }
        .await;
        finish_canonical_unit(lease, result, true).await
    }
}

pub(crate) async fn begin_stage(
    service: &OwnerService,
    session: &LinkedSession,
    network: Network,
    height: u64,
) -> Result<Option<OwnedClosureStage>> {
    let progress = closure::begin(&session.conn, height).await?;
    let Some(action) = progress.remaining.first().copied() else {
        return Ok(None);
    };
    let position = match action {
        WorkItem::Execute { decision } => {
            let input = load(&session.conn, decision).await?;
            match input.decision().descriptor.command {
                Command::Batch {
                    anchor_height,
                    anchor_hash,
                } => ApplicationPosition::Batch {
                    anchor_height,
                    anchor_hash,
                    consensus_height: decision,
                },
                Command::Block { height, hash, .. } => ApplicationPosition::Block {
                    height,
                    hash,
                    consensus_height: decision,
                },
            }
        }
        WorkItem::Rollback { height } => ApplicationPosition::Maintenance {
            rollback_height: Some(height),
        },
        WorkItem::Finality | WorkItem::Observe => ApplicationPosition::Committee,
    };
    let selection = select_legacy_p1(&session.conn, network, position).await?;
    let lease = begin_canonical_unit(service, session, &selection, network, false).await?;
    let admission = closure::prepare(&session.conn, height)
        .await
        .and_then(|ticket| {
            let ticket = ticket.context("closure work disappeared during admission")?;
            ensure!(
                ticket.action() == action,
                "closure work changed during admission"
            );
            Ok(ticket)
        });
    let ticket = match admission {
        Ok(ticket) => ticket,
        Err(error) => {
            return finish_canonical_unit::<Option<OwnedClosureStage>>(lease, Err(error), false)
                .await;
        }
    };
    Ok(Some(OwnedClosureStage {
        lease,
        ticket,
        session: session.clone(),
        selection,
        network,
    }))
}

#[cfg(test)]
mod tests;
