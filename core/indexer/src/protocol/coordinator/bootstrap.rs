use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use libsql::Connection;

use super::baseline::Baseline;
use super::genesis::bind_identity;
use super::linked::{begin_canonical_unit, finish_canonical_unit, observe_registrations};
use super::registration_history::{ObservationPosition, RegistrationSnapshot};
use super::selection::{ApplicationPosition, select_legacy_p1};
use crate::database::certified_history::{self, Status, closure, registrations};
use crate::protocol::identity::domain_digest;
use crate::protocol::operations::GenesisEnvelope;
use crate::runtime::ownership::OwnerService;
use crate::runtime::pool::LinkedSession;

#[derive(Debug, thiserror::Error)]
#[error(
    "certified history unavailable; preserve this database for inspection and rebuild from authenticated history"
)]
pub(crate) struct HistoryUnavailable;

pub(crate) async fn prepare(
    conn: &Connection,
    network: Network,
    starting_block_height: u64,
    genesis: &GenesisEnvelope,
) -> Result<(Baseline, bool)> {
    certified_history::initialize(conn).await?;
    let state = certified_history::frontier(conn).await?;
    if state.status == Status::Unavailable {
        return Err(HistoryUnavailable.into());
    }
    let chain = bind_identity(conn, network, starting_block_height, genesis).await?;
    let baseline = Baseline::current(chain)?;
    certified_history::begin_baseline(conn, &baseline, starting_block_height).await?;
    let initialize = state.status != Status::Ready;
    if !initialize {
        ensure!(
            conn.query("SELECT 1 FROM blocks WHERE height = 0", ())
                .await?
                .next()
                .await?
                .is_some(),
            "certified genesis is missing its native block"
        );
        verify_genesis(conn, &baseline).await?;
    }
    Ok((baseline, initialize))
}

async fn verify_genesis(conn: &Connection, baseline: &Baseline) -> Result<()> {
    ensure!(
        certified_history::protocol(conn, baseline.context.protocol).await? == baseline.manifest,
        "stored baseline manifest differs"
    );
    let observation = registrations::at(conn, 0, 0).await?;
    observation.verify_successor(None)?;
    baseline.require_context(observation.position.context)?;
    ensure!(
        observation.position.height == 0
            && observation.position.stage == 0
            && observation.position.decision
                == certified_history::genesis_predecessor(baseline.context)?,
        "initial committee has invalid genesis provenance"
    );
    let authority = observation.authority()?;
    ensure!(
        authority == certified_history::committee(conn, 1).await?,
        "initial committee differs from genesis observation"
    );
    let state = certified_history::frontier(conn).await?;
    if state.closed_height == 0 {
        ensure!(
            state.closure_id
                == Some(domain_digest(
                    b"kontor/genesis-closure/v1",
                    &authority.encode()?
                )),
            "genesis closure identity differs"
        );
    }
    if state.authenticated_height == 0 {
        let position = closure::canonical_position(conn, baseline.context.chain).await?;
        ensure!(
            position.lineage == observation.position.lineage,
            "canonical execution advanced without a certified decision"
        );
    }
    Ok(())
}

pub(crate) async fn complete(
    service: &OwnerService,
    session: &LinkedSession,
    network: Network,
    baseline: &Baseline,
) -> Result<()> {
    let state = certified_history::frontier(&session.conn).await?;
    baseline.require_context(state.context.context("missing certified genesis context")?)?;
    if state.status == Status::Ready {
        return verify_genesis(&session.conn, baseline).await;
    }
    ensure!(
        state.status == Status::Initializing && state.authenticated_height == 0,
        "cannot publish genesis authority after consensus begins"
    );
    ensure!(
        session.executor.execution_definition? == baseline.manifest.executor,
        "genesis executor differs from protocol manifest"
    );
    let selection =
        select_legacy_p1(&session.conn, network, ApplicationPosition::Committee).await?;
    let lease = begin_canonical_unit(service, session, &selection, network, false).await?;
    let result = async {
        let observed = observe_registrations(session, &selection, network, vec![]).await?;
        let position = closure::canonical_position(&session.conn, baseline.context.chain).await?;
        RegistrationSnapshot::observe(
            None,
            ObservationPosition {
                context: baseline.context,
                height: 0,
                decision: certified_history::genesis_predecessor(baseline.context)?,
                stage: 0,
                lineage: position.lineage,
            },
            observed,
        )
    }
    .await;
    let observation = finish_canonical_unit(lease, result, false).await?;
    certified_history::finish_genesis(&session.conn, &observation).await
}

#[cfg(test)]
mod tests;
