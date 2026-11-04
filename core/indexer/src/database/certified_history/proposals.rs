use anyhow::{Context, Result, ensure};
use libsql::{Connection, TransactionBehavior, params};
use malachitebft_core_consensus::ProposedValue;
use malachitebft_core_types::{Round, Validity};

use super::{Status, durable_writer, fixed, frontier};
use crate::consensus::{Address, Ctx, Height, Value, ValueId};
use crate::protocol::coordinator::certified_input::{Descriptor, EraContext, ExactInput};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Inserted,
    Existing,
    Conflict,
    Stale,
}

impl Admission {
    pub(crate) fn accepted(self) -> bool {
        matches!(self, Self::Inserted | Self::Existing)
    }
}

pub(crate) async fn accept_normal(
    conn: &Connection,
    proposal: &ProposedValue<Ctx>,
) -> Result<Admission> {
    ensure!(proposal.validity == Validity::Valid && proposal.valid_round == Round::Nil);
    let round = proposal.round.as_u32().context("nil proposal round")?;
    accept(
        conn,
        proposal.height,
        &proposal.value,
        Some((round, proposal.proposer)),
    )
    .await
}

pub(crate) async fn accept_synced(
    conn: &Connection,
    height: Height,
    value: &Value,
) -> Result<Admission> {
    // The engine checks the certificate's expected ID after our reply. These
    // bodies must not replace a normal slot or be treated as certified history.
    accept(conn, height, value, None).await
}

async fn accept(
    conn: &Connection,
    height: Height,
    value: &Value,
    slot: Option<(u32, Address)>,
) -> Result<Admission> {
    durable_writer(conn).await?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let state = frontier(&tx).await?;
    if state.status != Status::Ready
        || state.context != Some(value.descriptor().context)
        || state.closed_height != state.authenticated_height
        || state.authenticated_height.checked_add(1) != Some(height.as_u64())
    {
        tx.rollback().await?;
        return Ok(Admission::Stale);
    }
    if let Some((round, proposer)) = slot
        && let Some(existing) = normal_identity(&tx, height, Round::new(round)).await?
    {
        let result = if existing == (proposer, value.id()) {
            Admission::Existing
        } else {
            Admission::Conflict
        };
        tx.rollback().await?;
        return Ok(result);
    }
    let inserted = tx.execute(
        "INSERT INTO consensus_proposal_inputs (height, value_id, descriptor, body) VALUES (?1, ?2, ?3, ?4) ON CONFLICT (height, value_id) DO NOTHING",
        params![height.as_u64().to_be_bytes().to_vec(), value.id().0.to_vec(), value.descriptor_bytes(), value.input().body()],
    ).await?;
    if let Some((round, proposer)) = slot {
        tx.execute(
            "INSERT INTO consensus_proposal_slots (height, round, proposer, value_id) VALUES (?1, ?2, ?3, ?4)",
            params![height.as_u64().to_be_bytes().to_vec(), i64::from(round), proposer.into_inner().to_vec(), value.id().0.to_vec()],
        ).await?;
    }
    tx.commit().await?;
    Ok(if inserted > 0 || slot.is_some() {
        Admission::Inserted
    } else {
        Admission::Existing
    })
}

pub(crate) async fn exact(
    conn: &Connection,
    height: Height,
    id: ValueId,
    context: EraContext,
) -> Result<Option<Value>> {
    let row = conn.query(
        "SELECT descriptor, body FROM consensus_proposal_inputs WHERE height = ?1 AND value_id = ?2",
        params![height.as_u64().to_be_bytes().to_vec(), id.0.to_vec()],
    ).await?.next().await?;
    row.map(|row| {
        let descriptor = Descriptor::decode(&row.get::<Vec<u8>>(0)?)?;
        ensure!(
            descriptor.context == context,
            "staged proposal context differs"
        );
        let value = Value::from_input(ExactInput::validate(descriptor, row.get(1)?)?)?;
        ensure!(value.id() == id, "staged proposal ID differs");
        Ok(value)
    })
    .transpose()
}

pub(crate) async fn normal(
    conn: &Connection,
    height: Height,
    round: Round,
    context: EraContext,
) -> Result<Option<ProposedValue<Ctx>>> {
    let Some((proposer, id)) = normal_identity(conn, height, round).await? else {
        return Ok(None);
    };
    let value = exact(conn, height, id, context)
        .await?
        .context("proposal slot lacks its body")?;
    Ok(Some(ProposedValue {
        height,
        round,
        valid_round: Round::Nil,
        proposer,
        value,
        validity: Validity::Valid,
    }))
}

pub(crate) async fn has_normal(conn: &Connection, height: Height, round: Round) -> Result<bool> {
    Ok(normal_identity(conn, height, round).await?.is_some())
}

async fn normal_identity(
    conn: &Connection,
    height: Height,
    round: Round,
) -> Result<Option<(Address, ValueId)>> {
    let Some(number) = round.as_u32() else {
        return Ok(None);
    };
    let row = conn.query(
        "SELECT proposer, value_id FROM consensus_proposal_slots WHERE height = ?1 AND round = ?2",
        params![height.as_u64().to_be_bytes().to_vec(), i64::from(number)],
    ).await?.next().await?;
    let Some(row) = row else { return Ok(None) };
    let proposer = Address::new(fixed(row.get(0)?)?);
    let id = ValueId::new(fixed(row.get(1)?)?);
    Ok(Some((proposer, id)))
}

pub(super) async fn retire(conn: &Connection, height: u64) -> Result<()> {
    ensure!(
        !conn.is_autocommit(),
        "proposal retirement requires decision transaction"
    );
    let height = height.to_be_bytes().to_vec();
    conn.execute(
        "DELETE FROM consensus_proposal_slots WHERE height <= ?1",
        [height.clone()],
    )
    .await?;
    conn.execute(
        "DELETE FROM consensus_proposal_inputs WHERE height <= ?1",
        [height],
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
