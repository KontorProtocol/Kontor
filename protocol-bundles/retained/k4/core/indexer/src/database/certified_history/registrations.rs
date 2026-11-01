use anyhow::{Context, Result, ensure};
use libsql::{Connection, params};

use super::{Status, fixed, frontier};
use crate::database::canonical_history::{self, HistoryState};
use crate::protocol::coordinator::registration_history::RegistrationSnapshot;

pub(crate) async fn at(conn: &Connection, height: u64, stage: u64) -> Result<RegistrationSnapshot> {
    let row = conn.query(
        "SELECT observation_id, record FROM registration_observations WHERE height = ?1 AND stage = ?2",
        params![height.to_be_bytes().to_vec(), stage.to_be_bytes().to_vec()],
    ).await?.next().await?.context("registration observation unavailable")?;
    let snapshot = RegistrationSnapshot::decode(&row.get::<Vec<u8>>(1)?)?;
    ensure!(
        snapshot.position.height == height
            && snapshot.position.stage == stage
            && snapshot.id()? == fixed::<32>(row.get(0)?)?,
        "registration observation binding differs"
    );
    Ok(snapshot)
}

pub(crate) async fn latest(conn: &Connection) -> Result<Option<RegistrationSnapshot>> {
    let row = conn.query("SELECT height, stage FROM registration_observations ORDER BY height DESC, stage DESC LIMIT 1", ())
        .await?.next().await?;
    match row {
        None => Ok(None),
        Some(row) => Ok(Some(
            at(
                conn,
                u64::from_be_bytes(fixed(row.get(0)?)?),
                u64::from_be_bytes(fixed(row.get(1)?)?),
            )
            .await?,
        )),
    }
}

// The caller must abort its entire owned unit on error. Registration continuity
// must commit with rollback/application effects, never in a later transaction.
pub(crate) async fn record(conn: &Connection, snapshot: &RegistrationSnapshot) -> Result<()> {
    ensure!(
        !conn.is_autocommit(),
        "registration observation requires its owned transaction"
    );
    let synchronous: i64 = conn
        .query("PRAGMA synchronous", ())
        .await?
        .next()
        .await?
        .context("missing synchronous setting")?
        .get(0)?;
    ensure!(
        synchronous >= 2,
        "registration observation requires durable writer setup"
    );
    let state = frontier(conn).await?;
    let position = snapshot.position;
    ensure!(
        state.context == Some(position.context),
        "registration observation context differs"
    );
    if position.height == 0 {
        ensure!(
            state.status == Status::Initializing
                && position.stage == 0
                && Some(position.decision) == state.genesis,
            "invalid genesis observation position"
        );
    } else {
        ensure!(
            state.status == Status::Ready
                && position.height == state.authenticated_height
                && position.height > state.closed_height
                && Some(position.decision) == state.authenticated_id,
            "observation does not belong to the unfinished decision"
        );
    }
    let HistoryState::Ready(cursor) = canonical_history::state(conn).await? else {
        anyhow::bail!("registration observation lacks canonical lineage");
    };
    ensure!(
        cursor.authentic
            && cursor.chain == position.context.chain
            && cursor.lineage == position.lineage,
        "registration observation lineage differs from committed stage"
    );
    let previous = latest(conn).await?;
    if previous.as_ref().is_some_and(|previous| {
        previous.position.height == position.height && previous.position.stage == position.stage
    }) {
        ensure!(
            previous.as_ref() == Some(snapshot),
            "conflicting registration observation retry"
        );
        return Ok(());
    }
    snapshot.verify_successor(previous.as_ref())?;
    conn.execute("INSERT INTO registration_observations (height, stage, observation_id, record) VALUES (?1, ?2, ?3, ?4)",
        params![position.height.to_be_bytes().to_vec(), position.stage.to_be_bytes().to_vec(), snapshot.id()?.to_vec(), snapshot.encode()?]).await?;
    Ok(())
}
