use anyhow::{Context, Result, ensure};
use bitcoin::hashes::Hash;
use libsql::{Connection, TransactionBehavior, params};

use super::{
    Status, branch, closure, committee, durable_writer, fixed, frontier, load, registrations,
};
use crate::database::queries::select_block_latest;
use crate::protocol::coordinator::closure_record::ClosureRecord;
use crate::protocol::identity::domain_digest;

#[derive(Debug, thiserror::Error)]
#[error("completed execution cannot establish the next historical committee: {0}")]
pub(crate) struct InvalidNextAuthority(String);

pub(crate) async fn completed(conn: &Connection, height: u64) -> Result<ClosureRecord> {
    let row = conn
        .query(
            "SELECT closure_id, record, next_committee FROM decision_closures WHERE height = ?1",
            [height.to_be_bytes().to_vec()],
        )
        .await?
        .next()
        .await?
        .context("completed decision closure unavailable")?;
    let record = ClosureRecord::decode(&row.get::<Vec<u8>>(1)?)?;
    ensure!(
        record.height == height
            && record.id()? == fixed::<32>(row.get(0)?)?
            && record.next_committee == fixed::<32>(row.get(2)?)?,
        "closure record binding differs"
    );
    let certified = load(conn, height).await?;
    ensure!(
        certified.decision().id()? == record.decision
            && certified.decision().descriptor.context == record.context,
        "closure decision differs"
    );
    let progress = closure::progress(conn, height).await?;
    ensure!(
        progress.plan.id()? == record.plan
            && progress.plan.previous_closure == record.previous
            && progress.stage == record.stages
            && progress.head == record.stage_head
            && progress.remaining.is_empty()
            && progress.position == record.output,
        "closure completion differs from recorded stages"
    );
    let observation = registrations::at(conn, height, record.stages).await?;
    ensure!(
        observation.id()? == record.observation
            && observation.position.context == record.context
            && observation.position.decision == record.decision
            && observation.position.lineage == record.output.lineage,
        "closure observation differs"
    );
    let next = height
        .checked_add(1)
        .context("committee height exhausted")?;
    let authority = committee(conn, next).await?;
    ensure!(
        authority.id()? == record.next_committee && authority == observation.authority()?,
        "completed closure authority differs"
    );
    let tip = branch::tip_at(conn, height)
        .await?
        .context("completed closure lacks certified Bitcoin branch")?;
    ensure!(
        tip.0 == record.bitcoin_height && tip.1.to_byte_array() == record.bitcoin_hash,
        "completed closure branch differs"
    );
    ensure!(
        record.output.storage_height == record.bitcoin_height,
        "closure output height differs from Bitcoin tip"
    );
    let previous = if height == 1 {
        domain_digest(
            b"kontor/genesis-closure/v1",
            &committee(conn, 1).await?.encode()?,
        )
    } else {
        let row = conn
            .query(
                "SELECT closure_id FROM decision_closures WHERE height = ?1",
                [(height - 1).to_be_bytes().to_vec()],
            )
            .await?
            .next()
            .await?
            .context("prior completed closure missing")?;
        fixed(row.get(0)?)?
    };
    ensure!(
        record.previous == previous,
        "completed closure predecessor differs"
    );
    Ok(record)
}

pub(crate) async fn publish(conn: &Connection, height: u64) -> Result<ClosureRecord> {
    durable_writer(conn).await?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let state = frontier(&tx).await?;
    ensure!(
        state.status == Status::Ready && height > 0,
        "closure publication lacks ready history"
    );
    if height <= state.closed_height {
        let record = completed(&tx, height).await?;
        tx.commit().await?;
        return Ok(record);
    }
    ensure!(
        state.authenticated_height == height && state.closed_height.checked_add(1) == Some(height),
        "closure publication does not follow closed frontier"
    );
    let predecessor = if state.closed_height == 0 {
        domain_digest(
            b"kontor/genesis-closure/v1",
            &committee(&tx, 1).await?.encode()?,
        )
    } else {
        completed(&tx, state.closed_height).await?.id()?
    };
    ensure!(
        state.closure_id == Some(predecessor),
        "preceding closure frontier differs"
    );
    let progress = closure::recover(&tx, height).await?;
    ensure!(
        progress.stage > 0 && progress.remaining.is_empty(),
        "closure work remains unfinished"
    );
    ensure!(
        Some(progress.plan.context) == state.context
            && Some(progress.plan.decision) == state.authenticated_id
            && Some(progress.plan.previous_closure) == state.closure_id,
        "closure publication frontier differs"
    );
    let observation = registrations::at(&tx, height, progress.stage).await?;
    let authority = observation
        .authority()
        .map_err(|error| InvalidNextAuthority(error.to_string()))?;
    let tip = branch::tip(&tx)
        .await?
        .context("closure lacks certified Bitcoin branch")?;
    let applied = select_block_latest(&tx)
        .await?
        .context("closure lacks applied Bitcoin tip")?;
    ensure!(
        progress.position.storage_height == tip.0
            && applied.height == tip.0
            && applied.hash == tip.1,
        "closure has not restored the certified Bitcoin tip"
    );
    let record = ClosureRecord {
        context: progress.plan.context,
        height,
        decision: progress.plan.decision,
        previous: progress.plan.previous_closure,
        plan: progress.plan.id()?,
        stages: progress.stage,
        stage_head: progress.head,
        output: progress.position,
        bitcoin_height: tip.0,
        bitcoin_hash: tip.1.to_byte_array(),
        observation: observation.id()?,
        next_committee: authority.id()?,
    };
    tx.execute(
        "INSERT INTO historical_committees (height, committee_id, record) VALUES (?1, ?2, ?3)",
        params![
            authority.height.to_be_bytes().to_vec(),
            record.next_committee.to_vec(),
            authority.encode()?
        ],
    )
    .await?;
    tx.execute("INSERT INTO decision_closures (height, closure_id, record, next_committee) VALUES (?1, ?2, ?3, ?4)",
        params![height.to_be_bytes().to_vec(), record.id()?.to_vec(), record.encode()?, record.next_committee.to_vec()]).await?;
    tx.execute("UPDATE certified_history_state SET closed_height = ?1, closure_id = ?2 WHERE singleton = 1",
        params![height.to_be_bytes().to_vec(), record.id()?.to_vec()]).await?;
    tx.commit().await?;
    Ok(record)
}
