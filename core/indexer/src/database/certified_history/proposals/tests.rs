use anyhow::Result;
use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;

use super::*;
use crate::database::certified_history::{append, tests::prepared};
use crate::database::connection::new_connection;
use crate::protocol::coordinator::certified_decision::{AuthenticatedDecision, tests::proof};

fn proposal(value: Value) -> ProposedValue<Ctx> {
    ProposedValue {
        height: Height::new(1),
        round: Round::new(0),
        valid_round: Round::Nil,
        proposer: Address::new([1; 20]),
        value,
        validity: Validity::Valid,
    }
}

fn alternative(context: EraContext) -> Result<Value> {
    let mut block = genesis_block(Network::Regtest);
    block.header.nonce += 1;
    Ok(Value::from_input(ExactInput::block(
        context,
        1,
        serialize(&block),
    )?)?)
}

#[tokio::test]
async fn restart_preserves_normal_choice_and_exact_sync_bodies() -> Result<()> {
    let (directory, conn, authority, input, _, _) = prepared().await?;
    let first = proposal(Value::from_input(input)?);
    let other = alternative(authority.context)?;
    assert_eq!(accept_normal(&conn, &first).await?, Admission::Inserted);
    assert_eq!(accept_normal(&conn, &first).await?, Admission::Existing);
    let competing = proposal(other.clone());
    assert_eq!(accept_normal(&conn, &competing).await?, Admission::Conflict);
    assert!(
        exact(&conn, first.height, other.id(), authority.context)
            .await?
            .is_none()
    );
    assert_eq!(
        accept_synced(&conn, first.height, &other).await?,
        Admission::Inserted
    );
    assert_eq!(
        accept_synced(&conn, first.height, &other).await?,
        Admission::Existing
    );
    drop(conn);
    let conn = new_connection(directory.path(), "certified.db").await?;
    let retained = normal(&conn, first.height, first.round, authority.context)
        .await?
        .unwrap();
    assert_eq!(retained.value, first.value);
    assert_eq!(retained.proposer, first.proposer);
    assert_eq!(
        exact(&conn, first.height, other.id(), authority.context).await?,
        Some(other)
    );
    let mut next_round = first.clone();
    next_round.round = Round::new(1);
    assert_eq!(
        accept_normal(&conn, &next_round).await?,
        Admission::Inserted
    );
    Ok(())
}

#[tokio::test]
async fn failed_slot_write_rolls_back_input_and_allows_retry() -> Result<()> {
    let (_directory, conn, _, input, _, _) = prepared().await?;
    let first = proposal(Value::from_input(input)?);
    conn.execute_batch("CREATE TRIGGER interrupt_slot BEFORE INSERT ON consensus_proposal_slots BEGIN SELECT RAISE(ABORT, 'injected slot failure'); END").await?;
    assert!(accept_normal(&conn, &first).await.is_err());
    assert!(conn.is_autocommit());
    assert!(
        exact(
            &conn,
            first.height,
            first.value.id(),
            first.value.descriptor().context
        )
        .await?
        .is_none()
    );
    conn.execute_batch("DROP TRIGGER interrupt_slot").await?;
    assert_eq!(accept_normal(&conn, &first).await?, Admission::Inserted);
    Ok(())
}

#[tokio::test]
async fn decision_and_retirement_commit_atomically() -> Result<()> {
    let (directory, conn, authority, input, decision, keys) = prepared().await?;
    let first = proposal(Value::from_input(input.clone())?);
    let certified = AuthenticatedDecision::verify(
        decision.clone(),
        input,
        proof(&decision, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    assert!(accept_normal(&conn, &first).await?.accepted());
    assert!(
        accept_synced(&conn, first.height, &alternative(authority.context)?)
            .await?
            .accepted()
    );
    conn.execute_batch("CREATE TRIGGER interrupt_retirement BEFORE DELETE ON consensus_proposal_inputs BEGIN SELECT RAISE(ABORT, 'injected retirement failure'); END").await?;
    assert!(append(&conn, &certified).await.is_err());
    assert_eq!(frontier(&conn).await?.authenticated_height, 0);
    assert!(
        normal(&conn, first.height, first.round, authority.context)
            .await?
            .is_some()
    );
    conn.execute_batch("DROP TRIGGER interrupt_retirement")
        .await?;
    append(&conn, &certified).await?;
    drop(conn);
    let conn = new_connection(directory.path(), "certified.db").await?;
    assert_eq!(frontier(&conn).await?.authenticated_height, 1);
    assert!(
        conn.query("SELECT 1 FROM consensus_proposal_inputs", ())
            .await?
            .next()
            .await?
            .is_none()
    );
    assert!(
        normal(&conn, first.height, first.round, authority.context)
            .await?
            .is_none()
    );
    append(&conn, &certified).await?;
    assert_eq!(accept_normal(&conn, &first).await?, Admission::Stale);
    Ok(())
}

#[tokio::test]
async fn wrong_context_and_stale_height_cannot_be_staged() -> Result<()> {
    let (_directory, conn, authority, input, _, _) = prepared().await?;
    let first = proposal(Value::from_input(input)?);
    let mut wrong_height = first.clone();
    wrong_height.height = Height::new(2);
    assert_eq!(accept_normal(&conn, &wrong_height).await?, Admission::Stale);
    let mut context = authority.context;
    context.era[0] ^= 1;
    let wrong_context = alternative(context)?;
    assert_eq!(
        accept_synced(&conn, first.height, &wrong_context).await?,
        Admission::Stale
    );
    assert!(accept_normal(&conn, &first).await?.accepted());
    assert!(
        exact(&conn, first.height, first.value.id(), context)
            .await
            .is_err()
    );
    Ok(())
}
