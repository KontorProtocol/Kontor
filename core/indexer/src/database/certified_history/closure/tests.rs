use bitcoin::{Network, blockdata::constants::genesis_block, consensus::serialize};
use tempfile::TempDir;

use super::*;
use crate::database::certified_history::tests::{observed, prepared};
use crate::database::certified_history::{append, initialize};
use crate::database::connection::new_connection;
use crate::protocol::coordinator::certified_decision::AuthenticatedDecision;
use crate::protocol::coordinator::certified_decision::tests::proof;
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::identity::{ExecutionDefinitionId, ExecutionIdentity};

async fn commit_stage(
    conn: &Connection,
    ticket: StageTicket,
    outcome: StageOutcome,
    items: Vec<WorkItem>,
    observation: &RegistrationSnapshot,
) -> Result<StageRecord> {
    let ordinary = ticket.remaining_after();
    let mut cursor = ordinary;
    let mut expected = Vec::new();
    while let Some((item, after)) = work::next(conn, cursor).await? {
        expected.push(item);
        cursor = after;
    }
    let remaining = if expected == items {
        ordinary
    } else {
        let draft = work::begin(conn, ticket.0.work_origin()?).await?;
        let draft = work::append(conn, draft, &items).await?;
        work::publish(conn, draft).await?
    };
    super::commit_stage(conn, ticket, outcome, remaining, observation).await
}

async fn fixture() -> Result<(TempDir, Connection, Vec<CanonicalApplication>)> {
    let (directory, conn, authority, input, decision, keys) = prepared().await?;
    let canonical_input = CanonicalInput::bitcoin(&input.transactions()?)?;
    let certified = AuthenticatedDecision::verify(
        decision.clone(),
        input,
        proof(&decision, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    append(&conn, &certified).await?;
    let initial = begin(&conn, 1).await?;
    let Command::Block {
        height,
        hash,
        parent,
        ..
    } = certified.decision().descriptor.command
    else {
        panic!("fixture must start with a certified block");
    };
    let application = CanonicalApplication {
        chain: authority.context.chain,
        ordinal: initial.position.ordinal + 1,
        parent_lineage: initial.position.lineage,
        execution: ExecutionIdentity::Baseline(ExecutionDefinitionId([17; 32])),
        storage_height: height,
        source: ApplicationSource::BlockTransactions {
            height,
            hash: hash.to_byte_array(),
            parent_hash: parent.to_byte_array(),
        },
        input: Some(canonical_input),
    };
    let lifecycle = CanonicalApplication {
        ordinal: application.ordinal + 1,
        parent_lineage: application.lineage()?,
        source: ApplicationSource::BlockLifecycle {
            height,
            hash: hash.to_byte_array(),
        },
        input: None,
        ..application.clone()
    };
    conn.execute("CREATE TABLE stage_effect (value INTEGER)", ())
        .await?;
    Ok((directory, conn, vec![application, lifecycle]))
}

async fn observation(conn: &Connection, ticket: &StageTicket) -> Result<RegistrationSnapshot> {
    let previous = registrations::latest(conn).await?.unwrap();
    let output = canonical_position(conn, previous.position.context.chain).await?;
    RegistrationSnapshot::observe(
        Some(&previous),
        ticket.observation_position(output.lineage)?,
        observed(&previous),
    )
}

async fn apply(conn: &Connection, applications: &[CanonicalApplication]) -> Result<StageRecord> {
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let ticket = prepare(&unit, 1).await?.unwrap();
    assert_eq!(ticket.action(), WorkItem::Execute { decision: 1 });
    unit.execute("INSERT INTO stage_effect VALUES (1)", ())
        .await?;
    for application in applications {
        canonical_history::append(&unit, application).await?;
    }
    let observed = observation(&unit, &ticket).await?;
    let record = commit_stage(
        &unit,
        ticket,
        StageOutcome::Applied,
        vec![WorkItem::Finality],
        &observed,
    )
    .await?;
    unit.commit().await?;
    Ok(record)
}

#[tokio::test]
async fn closure_stage_effects_observation_and_worklist_commit_atomically() -> Result<()> {
    let (directory, conn, application) = fixture().await?;
    let before = progress(&conn, 1).await?;
    conn.execute_batch("CREATE TRIGGER interrupt_stage BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'stage commit interruption'); END;").await?;
    assert!(apply(&conn, &application).await.is_err());
    // Dropping libsql's uncommitted transaction rolls back the stage and observation.
    assert!(conn.is_autocommit());
    assert_eq!(recover(&conn, 1).await?, before);
    assert_eq!(
        registrations::latest(&conn).await?.unwrap().position.height,
        0
    );
    assert_eq!(
        conn.query("SELECT COUNT(*) FROM stage_effect", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get::<i64>(0)?,
        0
    );
    conn.execute_batch("DROP TRIGGER interrupt_stage").await?;
    let record = apply(&conn, &application).await?;
    assert_eq!(record.applications, application);
    let after = recover(&conn, 1).await?;
    assert_eq!(after.stage, 1);
    assert_eq!(after.next.map(|next| next.0), Some(WorkItem::Finality));
    assert_eq!(begin(&conn, 1).await?, after);
    drop(conn);
    let reopened = new_connection(directory.path(), "certified.db").await?;
    initialize(&reopened).await?;
    assert_eq!(recover(&reopened, 1).await?, after);
    let unit = reopened
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let ticket = prepare(&unit, 1).await?.unwrap();
    assert_eq!(ticket.action(), WorkItem::Finality);
    let observed = observation(&unit, &ticket).await?;
    commit_stage(
        &unit,
        ticket,
        StageOutcome::FinalityEvaluated,
        vec![],
        &observed,
    )
    .await?;
    unit.commit().await?;
    let unit = reopened
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    assert!(prepare(&unit, 1).await?.is_none());
    unit.rollback().await?;
    assert_eq!(
        reopened
            .query("SELECT COUNT(*) FROM stage_effect", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get::<i64>(0)?,
        1
    );
    assert_eq!(recover(&reopened, 1).await?.stage, 2);
    Ok(())
}

#[tokio::test]
async fn closure_stage_rejects_stale_tickets_and_untracked_effects() -> Result<()> {
    let (_directory, conn, application) = fixture().await?;
    assert!(prepare(&conn, 1).await.is_err());
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let stale = prepare(&unit, 1).await?.unwrap();
    unit.rollback().await?;
    apply(&conn, &application).await?;
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let observed = observation(&unit, &stale).await;
    assert!(observed.is_err());
    let latest = registrations::latest(&unit).await?.unwrap();
    assert!(
        commit_stage(&unit, stale, StageOutcome::Applied, vec![], &latest)
            .await
            .is_err()
    );
    unit.rollback().await?;
    let mut stray = application.last().unwrap().clone();
    stray.ordinal += 1;
    stray.parent_lineage = progress(&conn, 1).await?.position.lineage;
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    canonical_history::append(&unit, &stray).await?;
    assert!(prepare(&unit, 1).await.is_err());
    assert!(recover(&unit, 1).await.is_err());
    unit.rollback().await?;
    recover(&conn, 1).await?;
    Ok(())
}

#[tokio::test]
async fn closure_stage_rejects_substituted_inputs_and_invented_work() -> Result<()> {
    let (_directory, conn, application) = fixture().await?;
    for variant in 0..5 {
        let unit = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let ticket = prepare(&unit, 1).await?.unwrap();
        let mut applications = application.clone();
        if variant == 0 {
            applications[0].input = Some(CanonicalInput::Bitcoin([99; 32]));
        }
        if variant == 1 {
            applications[0].source = ApplicationSource::BlockLifecycle {
                height: applications[0].storage_height,
                hash: [0; 32],
            };
            applications[0].input = None;
        }
        applications[1].parent_lineage = applications[0].lineage()?;
        for application in &applications {
            canonical_history::append(&unit, application).await?;
        }
        let observed = observation(&unit, &ticket).await?;
        let work = if variant == 2 {
            vec![WorkItem::Execute { decision: 2 }]
        } else if variant == 4 {
            vec![]
        } else {
            vec![WorkItem::Finality]
        };
        let outcome = if variant == 3 {
            StageOutcome::UnrecognizedBatch
        } else {
            StageOutcome::Applied
        };
        assert!(
            commit_stage(&unit, ticket, outcome, work, &observed)
                .await
                .is_err()
        );
        unit.rollback().await?;
    }
    assert_eq!(recover(&conn, 1).await?.stage, 0);
    Ok(())
}

#[tokio::test]
async fn closure_recovery_detects_corrupt_records_and_missing_stages() -> Result<()> {
    let (_directory, conn, application) = fixture().await?;
    let original = apply(&conn, &application).await?;
    let bytes = original.encode()?;
    for end in 0..bytes.len() {
        assert!(StageRecord::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(StageRecord::decode(&trailing).is_err());
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let ticket = prepare(&unit, 1).await?.unwrap();
    let observed = observation(&unit, &ticket).await?;
    commit_stage(
        &unit,
        ticket,
        StageOutcome::FinalityEvaluated,
        vec![],
        &observed,
    )
    .await?;
    unit.commit().await?;
    conn.execute(
        "UPDATE closure_stages SET record = x'00' WHERE stage = ?1",
        [1u64.to_be_bytes().to_vec()],
    )
    .await?;
    assert!(recover(&conn, 1).await.is_err());
    conn.execute(
        "UPDATE closure_stages SET record = ?1 WHERE stage = ?2",
        params![bytes, 1u64.to_be_bytes().to_vec()],
    )
    .await?;
    recover(&conn, 1).await?;
    conn.execute(
        "DELETE FROM closure_stages WHERE stage = ?1",
        [1u64.to_be_bytes().to_vec()],
    )
    .await?;
    assert!(recover(&conn, 1).await.is_err());
    assert!(progress(&conn, 1).await.is_err());
    Ok(())
}

#[tokio::test]
async fn closure_rollback_and_replay_preserve_prior_stage_records() -> Result<()> {
    let (_directory, conn, authority, _, mut decision, keys) = prepared().await?;
    let block = genesis_block(Network::Regtest);
    let input = ExactInput::block(authority.context, 1, serialize(&block))?;
    let commitment = CanonicalInput::bitcoin(&input.transactions()?)?;
    decision.descriptor = input.descriptor().clone();
    let certified = AuthenticatedDecision::verify(
        decision.clone(),
        input,
        proof(&decision, &keys, &[0, 1, 2], 0),
        &authority,
    )?;
    append(&conn, &certified).await?;
    let initial = begin(&conn, 1).await?;
    let transactions = CanonicalApplication {
        chain: authority.context.chain,
        ordinal: 1,
        parent_lineage: initial.position.lineage,
        execution: ExecutionIdentity::Baseline(ExecutionDefinitionId([17; 32])),
        storage_height: 1,
        source: ApplicationSource::BlockTransactions {
            height: 1,
            hash: block.block_hash().to_byte_array(),
            parent_hash: block.header.prev_blockhash.to_byte_array(),
        },
        input: Some(commitment),
    };
    let lifecycle = CanonicalApplication {
        ordinal: 2,
        parent_lineage: transactions.lineage()?,
        source: ApplicationSource::BlockLifecycle {
            height: 1,
            hash: block.block_hash().to_byte_array(),
        },
        input: None,
        ..transactions.clone()
    };
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let ticket = prepare(&unit, 1).await?.unwrap();
    canonical_history::append(&unit, &transactions).await?;
    let observed = observation(&unit, &ticket).await?;
    assert!(
        commit_stage(
            &unit,
            ticket,
            StageOutcome::Applied,
            vec![WorkItem::Finality],
            &observed
        )
        .await
        .is_err()
    );
    unit.rollback().await?;

    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let ticket = prepare(&unit, 1).await?.unwrap();
    canonical_history::append(&unit, &transactions).await?;
    canonical_history::append(&unit, &lifecycle).await?;
    let observed = observation(&unit, &ticket).await?;
    let first = commit_stage(
        &unit,
        ticket,
        StageOutcome::Applied,
        vec![WorkItem::Finality],
        &observed,
    )
    .await?;
    unit.commit().await?;

    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let ticket = prepare(&unit, 1).await?.unwrap();
    let observed = observation(&unit, &ticket).await?;
    commit_stage(
        &unit,
        ticket,
        StageOutcome::FinalityEvaluated,
        vec![
            WorkItem::Rollback { height: 0 },
            WorkItem::Execute { decision: 1 },
            WorkItem::Finality,
        ],
        &observed,
    )
    .await?;
    unit.commit().await?;
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let ticket = prepare(&unit, 1).await?.unwrap();
    canonical_history::rollback(&unit, 0).await?;
    let observed = observation(&unit, &ticket).await?;
    commit_stage(
        &unit,
        ticket,
        StageOutcome::RolledBack,
        vec![WorkItem::Execute { decision: 1 }, WorkItem::Finality],
        &observed,
    )
    .await?;
    unit.commit().await?;
    assert_eq!(recover(&conn, 1).await?.position, initial.position);
    assert_eq!(stage(&conn, 1, 1).await?, first);
    let unit = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let ticket = prepare(&unit, 1).await?.unwrap();
    canonical_history::append(&unit, &transactions).await?;
    canonical_history::append(&unit, &lifecycle).await?;
    let observed = observation(&unit, &ticket).await?;
    let replay = commit_stage(
        &unit,
        ticket,
        StageOutcome::Applied,
        vec![WorkItem::Finality],
        &observed,
    )
    .await?;
    unit.commit().await?;
    assert_eq!(replay.output, first.output);
    assert_ne!(replay.id()?, first.id()?);
    assert_eq!(recover(&conn, 1).await?.stage, 4);
    assert_eq!(stage(&conn, 1, 1).await?, first);
    Ok(())
}
