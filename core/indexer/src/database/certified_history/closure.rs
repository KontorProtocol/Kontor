use anyhow::{Context, Result, ensure};
use bitcoin::hashes::Hash;
use libsql::{Connection, TransactionBehavior, params};

use super::{Status, durable_writer, fixed, frontier, load, registrations};
use crate::database::canonical_history::{self, HistoryState};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::canonical_input::CanonicalInput;
use crate::protocol::coordinator::application_closure::{
    CanonicalPosition, ClosurePlan, StageOutcome, StageRecord, WorkItem,
};
use crate::protocol::coordinator::certified_input::Command;
use crate::protocol::coordinator::registration_history::{
    ObservationPosition, RegistrationSnapshot,
};
use crate::protocol::identity::ChainId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Progress {
    pub(crate) plan: ClosurePlan,
    pub(crate) stage: u64,
    pub(crate) head: [u8; 32],
    pub(crate) position: CanonicalPosition,
    pub(crate) remaining: Vec<WorkItem>,
}

pub(crate) struct StageTicket(Progress);

impl StageTicket {
    pub(crate) fn action(&self) -> WorkItem {
        self.0.remaining[0]
    }

    pub(crate) fn observation_position(&self, lineage: [u8; 32]) -> Result<ObservationPosition> {
        Ok(ObservationPosition {
            context: self.0.plan.context,
            height: self.0.plan.height,
            decision: self.0.plan.decision,
            stage: self
                .0
                .stage
                .checked_add(1)
                .context("closure stage overflow")?,
            lineage,
        })
    }
}

pub(crate) async fn canonical_position(
    conn: &Connection,
    chain: ChainId,
) -> Result<CanonicalPosition> {
    let HistoryState::Ready(cursor) = canonical_history::state(conn).await? else {
        anyhow::bail!("closure lacks canonical history");
    };
    ensure!(
        cursor.authentic && cursor.chain == chain,
        "closure canonical identity differs"
    );
    Ok(CanonicalPosition {
        ordinal: cursor.ordinal,
        lineage: cursor.lineage,
        storage_height: cursor.storage_height,
    })
}

async fn plan(conn: &Connection, height: u64) -> Result<ClosurePlan> {
    let row = conn
        .query(
            "SELECT plan_id, record FROM closure_plans WHERE height = ?1",
            [height.to_be_bytes().to_vec()],
        )
        .await?
        .next()
        .await?
        .context("closure plan unavailable")?;
    let plan = ClosurePlan::decode(&row.get::<Vec<u8>>(1)?)?;
    ensure!(
        plan.height == height && plan.id()? == fixed::<32>(row.get(0)?)?,
        "closure plan binding differs"
    );
    Ok(plan)
}

pub(crate) async fn stage(conn: &Connection, height: u64, index: u64) -> Result<StageRecord> {
    let row = conn.query("SELECT stage_id, record, observation_id FROM closure_stages WHERE height = ?1 AND stage = ?2",
        params![height.to_be_bytes().to_vec(), index.to_be_bytes().to_vec()]).await?.next().await?
        .context("closure stage unavailable")?;
    let record = StageRecord::decode(&row.get::<Vec<u8>>(1)?)?;
    ensure!(
        record.height == height
            && record.stage == index
            && record.id()? == fixed::<32>(row.get(0)?)?
            && record.observation == fixed::<32>(row.get(2)?)?,
        "closure stage binding differs"
    );
    let observation = registrations::at(conn, height, index).await?;
    ensure!(
        observation.id()? == record.observation
            && observation.position.lineage == record.output.lineage,
        "closure stage observation differs"
    );
    Ok(record)
}

fn initial_progress(plan: ClosurePlan) -> Result<Progress> {
    Ok(Progress {
        stage: 0,
        head: plan.id()?,
        position: plan.input,
        remaining: plan.initial_work(),
        plan,
    })
}

fn advance(previous: &Progress, record: &StageRecord) -> Result<Progress> {
    ensure!(
        record.plan == previous.plan.id()?
            && record.height == previous.plan.height
            && previous.stage.checked_add(1) == Some(record.stage)
            && record.previous == previous.head
            && record.input == previous.position
            && previous.remaining.first() == Some(&record.action),
        "closure stage does not extend its worklist and lineage"
    );
    if record.action != WorkItem::Finality {
        ensure!(
            record.remaining == previous.remaining[1..],
            "ordinary closure stage changed the remaining worklist"
        );
    }
    ensure!(
        record
            .applications
            .iter()
            .all(|application| application.chain == previous.plan.context.chain),
        "closure stage application changed chain"
    );
    Ok(Progress {
        plan: previous.plan.clone(),
        stage: record.stage,
        head: record.id()?,
        position: record.output,
        remaining: record.remaining.clone(),
    })
}

pub(crate) async fn progress(conn: &Connection, height: u64) -> Result<Progress> {
    let initial = initial_progress(plan(conn, height).await?)?;
    let row = conn
        .query(
            "SELECT stage FROM closure_stages WHERE height = ?1 ORDER BY stage DESC LIMIT 1",
            [height.to_be_bytes().to_vec()],
        )
        .await?
        .next()
        .await?;
    let Some(row) = row else {
        return Ok(initial);
    };
    let index = u64::from_be_bytes(fixed(row.get(0)?)?);
    ensure!(index > 0, "zero closure stage");
    let latest = stage(conn, height, index).await?;
    let previous = if index == 1 {
        initial
    } else {
        let prior = stage(conn, height, index - 1).await?;
        ensure!(prior.plan == initial.head, "closure stage plan differs");
        Progress {
            plan: initial.plan,
            stage: prior.stage,
            head: prior.id()?,
            position: prior.output,
            remaining: prior.remaining,
        }
    };
    advance(&previous, &latest)
}

pub(crate) async fn begin(conn: &Connection, height: u64) -> Result<Progress> {
    durable_writer(conn).await?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let state = frontier(&tx).await?;
    ensure!(
        state.status == Status::Ready
            && state.authenticated_height == height
            && state.closed_height.checked_add(1) == Some(height),
        "decision is not awaiting closure"
    );
    let certified = load(&tx, height).await?;
    let context = state.context.context("missing closure context")?;
    let decision = certified.decision();
    ensure!(
        decision.id()?
            == state
                .authenticated_id
                .context("missing authenticated decision")?,
        "closure decision frontier differs"
    );
    let exists = tx
        .query(
            "SELECT 1 FROM closure_plans WHERE height = ?1",
            [height.to_be_bytes().to_vec()],
        )
        .await?
        .next()
        .await?
        .is_some();
    if !exists {
        let position = canonical_position(&tx, context.chain).await?;
        let previous = registrations::latest(&tx)
            .await?
            .context("closure lacks prior registration observation")?;
        ensure!(
            previous.position.height == state.closed_height
                && previous.position.lineage == position.lineage,
            "untracked canonical work preceded closure"
        );
        let plan = ClosurePlan {
            context,
            height,
            decision: decision.id()?,
            previous_closure: state.closure_id.context("missing preceding closure")?,
            input: position,
        };
        tx.execute(
            "INSERT INTO closure_plans (height, plan_id, record) VALUES (?1, ?2, ?3)",
            params![
                height.to_be_bytes().to_vec(),
                plan.id()?.to_vec(),
                plan.encode()?
            ],
        )
        .await?;
    }
    let result = progress(&tx, height).await?;
    ensure!(
        result.plan.context == context
            && result.plan.decision == decision.id()?
            && Some(result.plan.previous_closure) == state.closure_id,
        "closure plan context changed"
    );
    tx.commit().await?;
    Ok(result)
}

// Prepare only after acquiring the owned unit, before executing its first effect.
pub(crate) async fn prepare(conn: &Connection, height: u64) -> Result<Option<StageTicket>> {
    ensure!(
        !conn.is_autocommit(),
        "closure stage admission requires an owned transaction"
    );
    let progress = progress(conn, height).await?;
    let state = frontier(conn).await?;
    ensure!(
        state.status == Status::Ready
            && state.authenticated_height == height
            && state.closed_height < height
            && state.authenticated_id == Some(progress.plan.decision)
            && state.context == Some(progress.plan.context),
        "closure stage does not belong to unfinished decision"
    );
    ensure!(
        canonical_position(conn, progress.plan.context.chain).await? == progress.position,
        "closure cannot resume over untracked canonical effects"
    );
    Ok((!progress.remaining.is_empty()).then_some(StageTicket(progress)))
}

async fn validate_application_source(conn: &Connection, record: &StageRecord) -> Result<()> {
    let WorkItem::Execute { decision: height } = record.action else {
        return Ok(());
    };
    let certified = load(conn, height).await?;
    let command = &certified.decision().descriptor.command;
    if matches!(
        record.outcome,
        StageOutcome::UnrecognizedBatch | StageOutcome::ReplacedAnchorBatch
    ) {
        ensure!(
            matches!(command, Command::Batch { .. }),
            "block cannot be skipped as unrecognized batch"
        );
        return Ok(());
    }
    let input = CanonicalInput::bitcoin(&certified.input().transactions()?)?;
    match (command, record.applications.as_slice()) {
        (
            Command::Batch {
                anchor_height,
                anchor_hash,
            },
            [application],
        ) => {
            let ApplicationSource::Batch {
                anchor_height: applied_height,
                anchor_hash: applied_hash,
                exclusions,
            } = &application.source
            else {
                anyhow::bail!("batch stage has a non-batch application");
            };
            ensure!(
                applied_height == anchor_height
                    && *applied_hash == anchor_hash.to_byte_array()
                    && exclusions.consensus_height == height
                    && application.input == Some(input),
                "batch stage differs from certified input"
            );
        }
        (
            Command::Block {
                height,
                hash,
                parent,
                ..
            },
            [transactions, lifecycle],
        ) => {
            ensure!(
                transactions.source
                    == (ApplicationSource::BlockTransactions {
                        height: *height,
                        hash: hash.to_byte_array(),
                        parent_hash: parent.to_byte_array()
                    })
                    && transactions.input == Some(input)
                    && lifecycle.source
                        == (ApplicationSource::BlockLifecycle {
                            height: *height,
                            hash: hash.to_byte_array()
                        }),
                "block stage differs from certified input or lifecycle"
            );
        }
        _ => anyhow::bail!("stage application count differs from certified command"),
    }
    Ok(())
}

pub(crate) async fn commit_stage(
    conn: &Connection,
    ticket: StageTicket,
    outcome: StageOutcome,
    remaining: Vec<WorkItem>,
    observation: &RegistrationSnapshot,
) -> Result<StageRecord> {
    ensure!(
        !conn.is_autocommit(),
        "closure stage requires its owned transaction"
    );
    let previous = ticket.0;
    ensure!(
        progress(conn, previous.plan.height).await? == previous,
        "closure stage ticket is stale"
    );
    let output = canonical_position(conn, previous.plan.context.chain).await?;
    let action = previous.remaining[0];
    let mut applications = Vec::new();
    if outcome == StageOutcome::Applied {
        let mut rows = conn.query("SELECT record FROM canonical_applications WHERE ordinal > ?1 AND ordinal <= ?2 ORDER BY ordinal",
            params![previous.position.ordinal, output.ordinal]).await?;
        while let Some(row) = rows.next().await? {
            applications.push(CanonicalApplication::decode(&row.get::<Vec<u8>>(0)?)?);
        }
    }
    let index = previous
        .stage
        .checked_add(1)
        .context("closure stage overflow")?;
    ensure!(
        observation.position
            == (ObservationPosition {
                context: previous.plan.context,
                height: previous.plan.height,
                decision: previous.plan.decision,
                stage: index,
                lineage: output.lineage
            }),
        "closure observation position differs"
    );
    let record = StageRecord {
        height: previous.plan.height,
        stage: index,
        plan: previous.plan.id()?,
        previous: previous.head,
        action,
        input: previous.position,
        output,
        outcome,
        applications,
        observation: observation.id()?,
        remaining,
    };
    record.validate()?;
    advance(&previous, &record)?;
    validate_application_source(conn, &record).await?;
    for work in &record.remaining {
        if let WorkItem::Execute { decision } = work {
            let exists = conn
                .query(
                    "SELECT 1 FROM certified_decisions WHERE height = ?1",
                    [decision.to_be_bytes().to_vec()],
                )
                .await?
                .next()
                .await?
                .is_some();
            ensure!(exists, "closure work lacks a retained certified decision");
        }
    }
    registrations::record(conn, observation).await?;
    conn.execute("INSERT INTO closure_stages (height, stage, stage_id, observation_id, record) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![record.height.to_be_bytes().to_vec(), index.to_be_bytes().to_vec(), record.id()?.to_vec(),
            record.observation.to_vec(), record.encode()?]).await?;
    Ok(record)
}

// Startup uses the full chain; normal stage commits only inspect the current
// head and its predecessor, avoiding quadratic scans during a long replay.
pub(crate) async fn recover(conn: &Connection, height: u64) -> Result<Progress> {
    let mut progress = initial_progress(plan(conn, height).await?)?;
    let certified = load(conn, height).await?;
    ensure!(
        certified.decision().id()? == progress.plan.decision
            && certified.decision().descriptor.context == progress.plan.context,
        "closure plan decision differs"
    );
    let mut rows = conn
        .query(
            "SELECT stage FROM closure_stages WHERE height = ?1 ORDER BY stage",
            [height.to_be_bytes().to_vec()],
        )
        .await?;
    let mut previous_observation = if height == 1 {
        registrations::at(conn, 0, 0).await?
    } else {
        let row = conn.query("SELECT stage FROM registration_observations WHERE height = ?1 ORDER BY stage DESC LIMIT 1",
            [(height - 1).to_be_bytes().to_vec()]).await?.next().await?.context("prior closure observation missing")?;
        registrations::at(conn, height - 1, u64::from_be_bytes(fixed(row.get(0)?)?)).await?
    };
    ensure!(
        previous_observation.position.lineage == progress.position.lineage,
        "closure input observation differs"
    );
    while let Some(row) = rows.next().await? {
        let index = u64::from_be_bytes(fixed(row.get(0)?)?);
        let record = stage(conn, height, index).await?;
        let observation = registrations::at(conn, height, index).await?;
        ensure!(
            observation.position.context == progress.plan.context
                && observation.position.decision == progress.plan.decision,
            "stage observation authority context differs"
        );
        observation.verify_successor(Some(&previous_observation))?;
        validate_application_source(conn, &record).await?;
        progress = advance(&progress, &record)?;
        previous_observation = observation;
    }
    let state = frontier(conn).await?;
    if state.authenticated_height == height && state.closed_height < height {
        ensure!(
            canonical_position(conn, progress.plan.context.chain).await? == progress.position,
            "unfinished closure has unjournaled canonical effects"
        );
        ensure!(
            registrations::latest(conn).await? == Some(previous_observation),
            "unfinished closure has an unjournaled registration observation"
        );
    }
    Ok(progress)
}

#[cfg(test)]
mod tests;
