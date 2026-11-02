use anyhow::{Context, Result, ensure};
use libsql::Connection;

use super::{Frontier, Status, activation, committee, fixed, protocol};
use crate::protocol::canonical_codec::Decoder;
use crate::protocol::coordinator::activation::EraTransition;
use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol::coordinator::closure_record::ClosureRecord;
use crate::protocol::identity::ProtocolId;

pub(crate) async fn genesis(conn: &Connection) -> Result<EraContext> {
    let bytes = conn
        .query(
            "SELECT context FROM certified_bitcoin_boundary WHERE singleton = 1",
            (),
        )
        .await?
        .next()
        .await?
        .context("immutable genesis context unavailable")?
        .get::<Vec<u8>>(0)?;
    let mut input = Decoder::new(&bytes);
    let context = EraContext::decode(&mut input)?;
    input.finish()?;
    ensure!(context.codec == 1, "unsupported genesis history codec");
    Ok(context)
}

pub(crate) async fn selected_protocol(conn: &Connection) -> Result<ProtocolId> {
    match activation::current(conn).await? {
        Some(active) => Ok(active.target()?.id()?),
        None => Ok(genesis(conn).await?.protocol),
    }
}

pub(crate) async fn at(conn: &Connection, height: u64) -> Result<Option<EraTransition>> {
    let row = conn
        .query(
            "SELECT record FROM completed_protocol_eras WHERE height = ?1",
            [height.to_be_bytes().to_vec()],
        )
        .await?
        .next()
        .await?;
    let Some(row) = row else { return Ok(None) };
    let transition = EraTransition::decode(&row.get::<Vec<u8>>(0)?)?;
    ensure!(transition.height == height, "completed era height differs");
    Ok(Some(transition))
}

pub(crate) async fn next_context(conn: &Connection, record: &ClosureRecord) -> Result<EraContext> {
    let Some(transition) = at(conn, record.height).await? else {
        return Ok(record.context);
    };
    let target = protocol(conn, transition.next.protocol).await?;
    ensure!(
        EraTransition::derive(
            record.context,
            record.height,
            record.decision,
            record.output.lineage,
            &target
        )? == Some(transition.clone()),
        "completed era differs from closure"
    );
    Ok(transition.next)
}

pub(super) async fn verify_frontier(
    conn: &Connection,
    state: &Frontier,
    genesis: EraContext,
) -> Result<()> {
    let row = conn
        .query(
            "SELECT height FROM completed_protocol_eras ORDER BY height DESC LIMIT 1",
            (),
        )
        .await?
        .next()
        .await?;
    let expected = if let Some(row) = row {
        let height = u64::from_be_bytes(fixed(row.get(0)?)?);
        ensure!(
            height <= state.closed_height,
            "ordering era exceeds closed history"
        );
        let row = conn
            .query(
                "SELECT closure_id, record FROM decision_closures WHERE height = ?1",
                [height.to_be_bytes().to_vec()],
            )
            .await?
            .next()
            .await?
            .context("ordering era lacks completed closure")?;
        let record = ClosureRecord::decode(&row.get::<Vec<u8>>(1)?)?;
        ensure!(
            record.height == height && record.id()? == fixed::<32>(row.get(0)?)?,
            "ordering era closure binding differs"
        );
        next_context(conn, &record).await?
    } else {
        genesis
    };
    ensure!(
        state.context == Some(expected),
        "ordering context differs from completed era history"
    );
    if state.status == Status::Ready {
        let next = state
            .closed_height
            .checked_add(1)
            .context("committee height exhausted")?;
        ensure!(
            committee(conn, next).await?.context == expected,
            "next committee differs from ordering context"
        );
    }
    Ok(())
}
