use anyhow::{Context, Result, ensure};
use libsql::{Connection, Row, params};

use super::{closure, fixed};
use crate::database::canonical_history::{self, HistoryState};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::coordinator::application_closure::WorkItem;
use crate::protocol::coordinator::closure_work::WorkOrigin;
use crate::protocol::coordinator::control::ControlState;

const PAGE: u64 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Position {
    pub(crate) decision: u64,
    pub(crate) stage: u64,
}

struct Effect {
    application: CanonicalApplication,
    action: [u8; 32],
    control: [u8; 32],
    decision: u64,
    state: ControlState,
}

fn effect(row: &Row) -> Result<Effect> {
    let application = CanonicalApplication::decode(&row.get::<Vec<u8>>(0)?)?;
    let ordinal = row.get::<u64>(1)?;
    let lineage = fixed::<32>(row.get(2)?)?;
    let decision = u64::from_be_bytes(fixed(row.get(3)?)?);
    let action = fixed::<32>(row.get(4)?)?;
    let control = fixed::<32>(row.get(5)?)?;
    let state = ControlState::decode(&row.get::<Vec<u8>>(6)?)?;
    ensure!(
        application.ordinal == ordinal
            && application.lineage()? == lineage
            && application.source
                == (ApplicationSource::UpgradeControl {
                    decision,
                    action,
                    control
                })
            && application.chain == state.context.chain
            && state.head == control,
        "canonical upgrade control binding differs"
    );
    Ok(Effect {
        application,
        action,
        control,
        decision,
        state,
    })
}

pub(crate) async fn current(conn: &Connection) -> Result<Option<ControlState>> {
    let row = conn
        .query(
            "SELECT a.record, c.ordinal, c.lineage, c.decision, c.action, c.control, c.state
         FROM canonical_upgrade_controls c JOIN canonical_applications a ON a.ordinal = c.ordinal
         ORDER BY c.ordinal DESC LIMIT 1",
            (),
        )
        .await?
        .next()
        .await?;
    row.map(|row| effect(&row).map(|value| value.state))
        .transpose()
}

pub(crate) async fn reference_floor(conn: &Connection, at: Position) -> Result<u64> {
    let row = conn
        .query(
            "SELECT rollback_decision FROM upgrade_control_retractions
         WHERE (rollback_decision, rollback_stage) <= (?1, ?2)
         ORDER BY rollback_decision DESC, rollback_stage DESC LIMIT 1",
            params![
                at.decision.to_be_bytes().to_vec(),
                at.stage.to_be_bytes().to_vec()
            ],
        )
        .await?
        .next()
        .await?;
    row.map(|row| fixed(row.get(0)?).map(u64::from_be_bytes))
        .transpose()
        .map(|v| v.unwrap_or(0))
}

pub(crate) async fn is_retracted(
    conn: &Connection,
    action: [u8; 32],
    at: Position,
) -> Result<bool> {
    Ok(conn
        .query(
            "SELECT 1 FROM upgrade_control_retractions WHERE action = ?1
         AND (rollback_decision, rollback_stage) <= (?2, ?3)",
            params![
                action.to_vec(),
                at.decision.to_be_bytes().to_vec(),
                at.stage.to_be_bytes().to_vec()
            ],
        )
        .await?
        .next()
        .await?
        .is_some())
}

// Called only after authorization and canonical lineage append, within that
// same owned unit. A snapshot's survival follows its application, not its certificate.
pub(crate) async fn record(
    conn: &Connection,
    application: &CanonicalApplication,
    state: &ControlState,
    at: Position,
) -> Result<()> {
    ensure!(
        !conn.is_autocommit(),
        "control record requires canonical transaction"
    );
    let ApplicationSource::UpgradeControl {
        decision,
        action,
        control,
    } = application.source
    else {
        anyhow::bail!("control snapshot has another application source");
    };
    let HistoryState::Ready(cursor) = canonical_history::state(conn).await? else {
        anyhow::bail!("control snapshot lacks canonical history");
    };
    ensure!(
        cursor.authentic
            && cursor.chain == application.chain
            && cursor.ordinal == application.ordinal
            && cursor.lineage == application.lineage()?
            && state.context.chain == application.chain
            && state.head == control
            && state.nonce > 0
            && decision == at.decision
            && at.stage > 0,
        "control snapshot is not the current authorized application"
    );
    ensure!(
        !is_retracted(conn, action, at).await?,
        "control action was retracted"
    );
    conn.execute(
        "INSERT INTO canonical_upgrade_controls (ordinal, lineage, decision, action, control, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![application.ordinal, cursor.lineage.to_vec(), decision.to_be_bytes().to_vec(),
            action.to_vec(), control.to_vec(), state.encode()?],
    ).await?;
    Ok(())
}

pub(crate) async fn retract(conn: &Connection, progress: &closure::Progress) -> Result<u64> {
    ensure!(
        !conn.is_autocommit(),
        "control retraction requires canonical transaction"
    );
    let Some((WorkItem::Rollback { height }, _)) = progress.next else {
        anyhow::bail!("control retraction requires rollback work");
    };
    ensure!(
        closure::progress(conn, progress.plan.height).await? == *progress
            && closure::canonical_position(conn, progress.plan.context.chain).await?
                == progress.position,
        "control retraction has stale rollback origin"
    );
    let at = Position {
        decision: progress.plan.height,
        stage: progress
            .stage
            .checked_add(1)
            .context("rollback stage overflow")?,
    };
    retract_at(conn, progress.work_origin()?, at, height).await
}

async fn retract_at(
    conn: &Connection,
    origin: WorkOrigin,
    at: Position,
    height: u64,
) -> Result<u64> {
    ensure!(
        !conn.is_autocommit(),
        "control retraction requires canonical transaction"
    );
    ensure!(
        at.decision == origin.height && at.stage > 0,
        "invalid control rollback position"
    );
    let mut count = 0u64;
    loop {
        let mut rows = conn
            .query(
                "SELECT a.record, c.ordinal, c.lineage, c.decision, c.action, c.control, c.state
             FROM canonical_applications a INDEXED BY idx_canonical_applications_height
             JOIN canonical_upgrade_controls c ON c.ordinal = a.ordinal
             WHERE a.storage_height > ?1 ORDER BY a.storage_height, a.ordinal LIMIT ?2",
                params![height, PAGE],
            )
            .await?;
        let mut removed = Vec::new();
        while let Some(row) = rows.next().await? {
            removed.push(effect(&row)?);
        }
        drop(rows);
        if removed.is_empty() {
            return Ok(count);
        }
        for value in removed {
            ensure!(
                value.decision <= at.decision,
                "rollback precedes control application"
            );
            conn.execute(
                "INSERT INTO upgrade_control_retractions
                 (action, original_ordinal, original_lineage, original_decision,
                  rollback_decision, rollback_stage, rollback_origin, rollback_height)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(action) DO NOTHING",
                params![
                    value.action.to_vec(),
                    value.application.ordinal,
                    value.application.lineage()?.to_vec(),
                    value.decision.to_be_bytes().to_vec(),
                    at.decision.to_be_bytes().to_vec(),
                    at.stage.to_be_bytes().to_vec(),
                    origin.encode()?,
                    height.to_be_bytes().to_vec()
                ],
            )
            .await?;
            let stored = conn.query(
                "SELECT original_ordinal, original_lineage, original_decision, rollback_decision,
                        rollback_stage, rollback_origin, rollback_height
                 FROM upgrade_control_retractions WHERE action = ?1", [value.action.to_vec()],
            ).await?.next().await?.context("control retraction disappeared")?;
            ensure!(
                stored.get::<u64>(0)? == value.application.ordinal
                    && fixed::<32>(stored.get(1)?)? == value.application.lineage()?
                    && u64::from_be_bytes(fixed(stored.get(2)?)?) == value.decision
                    && u64::from_be_bytes(fixed(stored.get(3)?)?) == at.decision
                    && u64::from_be_bytes(fixed(stored.get(4)?)?) == at.stage
                    && stored.get::<Vec<u8>>(5)? == origin.encode()?
                    && u64::from_be_bytes(fixed(stored.get(6)?)?) == height,
                "historical control retraction differs on reconstruction"
            );
            let changed = conn.execute(
                "DELETE FROM canonical_upgrade_controls WHERE ordinal = ?1 AND lineage = ?2 AND control = ?3",
                params![value.application.ordinal, value.application.lineage()?.to_vec(), value.control.to_vec()],
            ).await?;
            ensure!(changed == 1, "control changed during rollback");
            count = count
                .checked_add(1)
                .context("control retraction count overflow")?;
        }
    }
}

#[cfg(test)]
mod tests;
