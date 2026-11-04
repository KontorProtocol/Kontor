use anyhow::{Context, Result, ensure};
use libsql::Connection;

use super::{Position, current, is_retracted, record, reference_floor};
use crate::database::canonical_history;
use crate::database::certified_history::{
    branch, closure, committee, completion, eras, frontier, genesis_predecessor,
    load_verified_input, protocol,
};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::coordinator::application_closure::{StageOutcome, WorkItem};
use crate::protocol::coordinator::certified_decision::CommitteeRecord;
use crate::protocol::coordinator::certified_input::{Command, EraContext, ExactInput};
use crate::protocol::coordinator::control::{
    AcceptedControl, AuthenticatedReference, ControlState, UpgradeControl,
};
use crate::protocol::identity::ExecutionIdentity;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct Rejected(&'static str);

pub(crate) async fn state(conn: &Connection, context: EraContext) -> Result<ControlState> {
    ensure!(
        frontier(conn).await?.context == Some(context)
            && eras::selected_protocol(conn).await? == context.protocol,
        "control admission awaits the canonical protocol's completed ordering era"
    );
    let manifest = protocol(conn, context.protocol).await?;
    let mut state = current(conn).await?.unwrap_or(ControlState {
        context,
        current_manifest: manifest.clone(),
        head: genesis_predecessor(eras::genesis(conn).await?)?,
        nonce: 0,
        pending: None,
    });
    ensure!(
        state.context.chain == context.chain && manifest.chain == context.chain,
        "canonical control chain differs"
    );
    // Only the view advances to the completed era. Historical approvals and
    // surviving head/nonce/plan remain exactly the originally recorded values.
    state.context = context;
    state.current_manifest = manifest;
    Ok(state)
}

struct Admission {
    state: ControlState,
    authority: CommitteeRecord,
    reference: AuthenticatedReference,
    bitcoin_height: u64,
    reference_floor: u64,
}

pub(crate) async fn validate_proposal(
    conn: &Connection,
    input: &ExactInput,
    inclusion: u64,
    at: Position,
) -> Result<()> {
    let (envelope, admission) = admission(conn, input, inclusion, at).await?;
    envelope.action.validate_proposal(
        &admission.state,
        &admission.authority,
        admission.reference,
        admission.bitcoin_height,
        admission.reference_floor,
    )?;
    Ok(())
}

pub(crate) async fn verify(
    conn: &Connection,
    input: &ExactInput,
    inclusion: u64,
    at: Position,
) -> Result<AcceptedControl> {
    let (envelope, admission) = admission(conn, input, inclusion, at).await?;
    Ok(envelope.verify(
        &admission.state,
        &admission.authority,
        admission.reference,
        admission.bitcoin_height,
        admission.reference_floor,
    )?)
}

// Preparation and signed admission both use authenticated positions. Neither
// a caller's local Bitcoin tip nor an envelope's anchor sets the clock.
async fn admission(
    conn: &Connection,
    input: &ExactInput,
    inclusion: u64,
    at: Position,
) -> Result<(UpgradeControl, Admission)> {
    let Command::Control {
        anchor_height,
        anchor_hash,
    } = input.descriptor().command
    else {
        anyhow::bail!("control admission received another command");
    };
    let envelope = input.upgrade_control()?;
    let frontier = frontier(conn).await?;
    ensure!(
        inclusion > 0
            && frontier.closed_height.checked_add(1) == Some(inclusion)
            && at.decision == inclusion,
        Rejected("control inclusion does not follow closed history")
    );
    let context = input.descriptor().context;
    ensure!(
        frontier.context == Some(context),
        Rejected("control era differs")
    );
    let reference = envelope.action.reference_height;
    ensure!(
        reference > 0 && reference < inclusion,
        Rejected("control reference is not closed")
    );
    let closed = completion::completed(conn, reference).await?;
    let tip = branch::tip_at(conn, inclusion - 1)
        .await?
        .context("control inclusion lacks a certified Bitcoin tip")?;
    ensure!(
        tip == (anchor_height, anchor_hash),
        Rejected("control position differs from certified tip")
    );
    let canonical = closure::canonical_position(conn, context.chain).await?;
    ensure!(
        canonical.storage_height == tip.0,
        "control admission precedes canonical closure"
    );
    ensure!(
        !is_retracted(conn, envelope.action.id()?, at).await?,
        Rejected("control action was retracted")
    );
    let state = state(conn, context).await?;
    let authority = committee(conn, inclusion).await?;
    Ok((
        envelope,
        Admission {
            state,
            authority,
            reference: AuthenticatedReference {
                height: reference,
                decision: closed.decision,
                bitcoin_height: closed.bitcoin_height,
            },
            bitcoin_height: tip.0,
            reference_floor: reference_floor(conn, at).await?,
        },
    ))
}

pub(crate) async fn apply(conn: &Connection, height: u64, decision: u64) -> Result<StageOutcome> {
    ensure!(
        !conn.is_autocommit(),
        "control application requires owned closure transaction"
    );
    let progress = closure::progress(conn, height).await?;
    ensure!(
        progress
            .next
            .is_some_and(|(action, _)| action == WorkItem::Execute { decision }),
        "control application differs from closure work"
    );
    let input = load_verified_input(conn, decision).await?;
    let envelope = input.input().upgrade_control()?;
    let at = Position {
        decision: height,
        stage: progress
            .stage
            .checked_add(1)
            .context("control stage exhausted")?,
    };
    if is_retracted(conn, envelope.action.id()?, at).await? {
        ensure!(
            decision < height,
            "new control submission was already retracted"
        );
        return Ok(StageOutcome::RetractedControl);
    }
    // Replayed controls must already have been invalidated by the owned undo.
    // Reauthorizing an old envelope against today's committee would resurrect it.
    ensure!(
        decision == height,
        "retained control lacks its rollback disposition"
    );
    let accepted = verify(conn, input.input(), decision, at).await?;
    let context = input.decision().descriptor.context;
    let position = closure::canonical_position(conn, context.chain).await?;
    let application = CanonicalApplication {
        chain: context.chain,
        ordinal: position
            .ordinal
            .checked_add(1)
            .context("canonical ordinal exhausted")?,
        parent_lineage: position.lineage,
        execution: ExecutionIdentity::Protocol {
            protocol: context.protocol,
            execution: accepted.next.current_manifest.executor,
        },
        storage_height: position.storage_height,
        source: ApplicationSource::UpgradeControl {
            decision,
            action: accepted.action,
            control: accepted.control,
        },
        input: None,
    };
    canonical_history::append(conn, &application).await?;
    record(conn, &application, &accepted.next, at).await?;
    Ok(StageOutcome::Applied)
}
