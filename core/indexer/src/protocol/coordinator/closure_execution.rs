use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use libsql::Connection;

use super::application_closure::{StageOutcome, StageRecord, WorkItem};
use super::certified_input::Command;
use super::closure_work::WorkCursor;
use super::linked::{begin_canonical_unit, finish_canonical_unit, observe_registrations};
use super::registration_history::RegistrationSnapshot;
use super::selection::{ApplicationPosition, ExecutionSelection, select_canonical};
use crate::database::certified_history::{
    activation, closure, load, load_verified_input, registrations,
};
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

    pub(crate) fn remaining_after(&self) -> WorkCursor {
        self.ticket.remaining_after()
    }

    pub(crate) async fn finish<T>(
        self,
        result: Result<(T, StageOutcome, WorkCursor)>,
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
            let record =
                record_stage(&session, &selection, network, ticket, outcome, remaining).await?;
            Ok((value, record))
        }
        .await;
        finish_canonical_unit(lease, result, true).await
    }
}

// Migration owns its transaction itself. Sharing this recording step lets it
// persist the same observation and stage proof without nesting canonical roots.
pub(crate) async fn record_stage(
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
    ticket: closure::StageTicket,
    outcome: StageOutcome,
    remaining: WorkCursor,
) -> Result<StageRecord> {
    let previous = registrations::latest(&session.conn)
        .await?
        .context("stage lacks prior registration observation")?;
    let watched = previous
        .entries
        .iter()
        .map(|entry| entry.holder.clone())
        .collect();
    let observation = observe_registrations(session, selection, network, watched).await?;
    let position =
        closure::canonical_position(&session.conn, previous.position.context.chain).await?;
    let snapshot = RegistrationSnapshot::observe(
        Some(&previous),
        ticket.observation_position(position.lineage)?,
        observation,
    )?;
    closure::commit_stage(&session.conn, ticket, outcome, remaining, &snapshot).await
}

pub(crate) async fn begin_stage(
    service: &OwnerService,
    session: &LinkedSession,
    network: Network,
    height: u64,
) -> Result<Option<OwnedClosureStage>> {
    let progress = closure::begin(&session.conn, height).await?;
    let Some((action, _)) = progress.next else {
        return Ok(None);
    };
    let selection = if matches!(action, WorkItem::Activate { .. }) {
        // Only the no-activation outcome uses this root. Actual migration owns
        // its transaction and stage record together in activation_execution.
        select_canonical(&session.conn, network, ApplicationPosition::Committee).await?
    } else {
        select_stage(&session.conn, network, action).await?
    };
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

pub(crate) async fn select_stage(
    conn: &Connection,
    network: Network,
    action: WorkItem,
) -> Result<ExecutionSelection> {
    let position = match action {
        WorkItem::Execute { decision } | WorkItem::Replay { decision, .. } => {
            let input = load(conn, decision).await?;
            match input.decision().descriptor.command {
                Command::Control { .. } => ApplicationPosition::Committee,
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
        WorkItem::Activate { decision } => {
            let input = load_verified_input(conn, decision).await?;
            let Command::Block { height, hash, .. } = input.decision().descriptor.command else {
                anyhow::bail!("activation work does not name a block");
            };
            if activation::pending(conn, height, hash).await?.is_some() {
                ApplicationPosition::Migration {
                    anchor_height: height,
                    anchor_hash: hash,
                }
            } else {
                ApplicationPosition::Committee
            }
        }
    };
    select_canonical(conn, network, position).await
}

#[cfg(test)]
mod tests;
