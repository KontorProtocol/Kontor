use libsql::{Builder, Database};
use tempfile::TempDir;

use super::*;
use crate::protocol::coordinator::application_closure::CanonicalPosition;
use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol::coordinator::manifest::ProtocolManifest;
use crate::protocol::identity::{
    ChainId, ExecutionDefinitionId, ExecutionIdentity, MigrationDefinitionId, ProtocolId,
};

async fn database() -> Result<(TempDir, Database, Connection)> {
    let directory = TempDir::new()?;
    let db = Builder::new_local(directory.path().join("controls.db"))
        .build()
        .await?;
    let conn = db.connect()?;
    conn.execute_batch(include_str!("../../sql/schema.sql"))
        .await?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
        .await?;
    canonical_history::initialize(&conn).await?;
    conn.execute_batch(include_str!("../../sql/upgrade_control.sql"))
        .await?;
    conn.execute("BEGIN", ()).await?;
    canonical_history::bind_genesis(&conn, ChainId([1; 32])).await?;
    conn.execute("COMMIT", ()).await?;
    Ok((directory, db, conn))
}

fn state(head: [u8; 32], nonce: u64) -> Result<ControlState> {
    let manifest = ProtocolManifest {
        chain: ChainId([1; 32]),
        protocol_number: 1,
        predecessor: ProtocolId([0; 32]),
        executor: ExecutionDefinitionId([2; 32]),
        consensus: [3; 32],
        transaction_formats: vec![0],
        host_abis: vec![1],
        bridge_schema: 1,
        state_schema: 1,
        certificate_codec: 1,
        control_codec: 1,
        parameters_root: [4; 32],
        native_contracts_root: [5; 32],
        migration: MigrationDefinitionId([6; 32]),
        input_state_schema: 1,
        output_state_schema: 1,
    };
    Ok(ControlState {
        context: EraContext {
            chain: manifest.chain,
            era: [7; 32],
            protocol: manifest.id()?,
            codec: 1,
        },
        current_manifest: manifest,
        head,
        nonce,
        pending: None,
    })
}

async fn append_effect(conn: &Connection, height: u64, seed: u8) -> Result<CanonicalApplication> {
    let HistoryState::Ready(cursor) = canonical_history::state(conn).await? else {
        panic!()
    };
    let decision = cursor.ordinal + 1;
    let control = [seed.wrapping_add(100); 32];
    let application = CanonicalApplication {
        chain: cursor.chain,
        ordinal: cursor.ordinal + 1,
        parent_lineage: cursor.lineage,
        execution: ExecutionIdentity::Baseline(ExecutionDefinitionId([2; 32])),
        storage_height: height,
        source: ApplicationSource::UpgradeControl {
            decision,
            action: [seed; 32],
            control,
        },
        input: None,
    };
    canonical_history::append(conn, &application).await?;
    record(
        conn,
        &application,
        &state(control, decision)?,
        Position { decision, stage: 1 },
    )
    .await?;
    Ok(application)
}

async fn origin(conn: &Connection, decision: u64) -> Result<WorkOrigin> {
    let HistoryState::Ready(cursor) = canonical_history::state(conn).await? else {
        panic!()
    };
    Ok(WorkOrigin {
        height: decision,
        closure: [20; 32],
        previous: [21; 32],
        input: CanonicalPosition {
            ordinal: cursor.ordinal,
            lineage: cursor.lineage,
            storage_height: cursor.storage_height,
        },
    })
}

#[tokio::test]
async fn rollback_preserves_target_height_and_retraction_is_prefix_scoped() -> Result<()> {
    let (_directory, db, conn) = database().await?;
    conn.execute("BEGIN", ()).await?;
    append_effect(&conn, 100, 1).await?;
    append_effect(&conn, 100, 2).await?;
    let retained = current(&conn).await?.unwrap();
    append_effect(&conn, 101, 3).await?;
    let removed = current(&conn).await?.unwrap();
    conn.execute("COMMIT", ()).await?;
    let at = Position {
        decision: 12,
        stage: 4,
    };
    conn.execute("BEGIN", ()).await?;
    assert_eq!(
        retract_at(&conn, origin(&conn, 12).await?, at, 100).await?,
        1
    );
    canonical_history::rollback(&conn, 100).await?;
    conn.execute("COMMIT", ()).await?;
    let reopened = db.connect()?;
    assert_eq!(current(&reopened).await?, Some(retained));
    assert_ne!(current(&reopened).await?, Some(removed));
    assert!(!is_retracted(&reopened, [2; 32], at).await?);
    for before in [
        Position {
            decision: 11,
            stage: u64::MAX,
        },
        Position {
            decision: 12,
            stage: 3,
        },
    ] {
        assert!(!is_retracted(&reopened, [3; 32], before).await?);
        assert_eq!(reference_floor(&reopened, before).await?, 0);
    }
    assert!(is_retracted(&reopened, [3; 32], at).await?);
    assert_eq!(reference_floor(&reopened, at).await?, 12);
    assert_eq!(
        reference_floor(
            &reopened,
            Position {
                decision: 13,
                stage: 0
            }
        )
        .await?,
        12
    );
    conn.execute("BEGIN", ()).await?;
    assert_eq!(
        retract_at(
            &conn,
            origin(&conn, 13).await?,
            Position {
                decision: 13,
                stage: 1
            },
            100
        )
        .await?,
        0
    );
    conn.execute("COMMIT", ()).await?;
    assert_eq!(
        reference_floor(
            &conn,
            Position {
                decision: 13,
                stage: 1
            }
        )
        .await?,
        12
    );
    Ok(())
}

#[tokio::test]
async fn failed_undo_restores_effects_and_does_not_publish_invalidation() -> Result<()> {
    let (_directory, db, conn) = database().await?;
    conn.execute("BEGIN", ()).await?;
    append_effect(&conn, 100, 1).await?;
    append_effect(&conn, 101, 2).await?;
    conn.execute("COMMIT", ()).await?;
    let before = current(&conn).await?;
    let before_history = canonical_history::state(&conn).await?;
    let at = Position {
        decision: 12,
        stage: 3,
    };
    let rollback_origin = origin(&conn, 12).await?;
    conn.execute("BEGIN", ()).await?;
    assert!(canonical_history::rollback(&conn, 99).await.is_err());
    conn.execute("ROLLBACK", ()).await?;
    assert_eq!(current(&conn).await?, before);
    conn.execute_batch("CREATE TRIGGER fail_undo BEFORE UPDATE ON canonical_history_state BEGIN SELECT RAISE(ABORT, 'injected undo failure'); END;").await?;
    conn.execute("BEGIN", ()).await?;
    assert_eq!(retract_at(&conn, rollback_origin, at, 99).await?, 2);
    assert!(canonical_history::rollback(&conn, 99).await.is_err());
    conn.execute("ROLLBACK", ()).await?;
    let reopened = db.connect()?;
    assert_eq!(current(&reopened).await?, before);
    assert_eq!(canonical_history::state(&reopened).await?, before_history);
    assert_eq!(reference_floor(&reopened, at).await?, 0);
    assert!(!is_retracted(&reopened, [1; 32], at).await?);
    conn.execute_batch("DROP TRIGGER fail_undo").await?;
    conn.execute("BEGIN", ()).await?;
    assert_eq!(retract_at(&conn, rollback_origin, at, 99).await?, 2);
    canonical_history::rollback(&conn, 99).await?;
    conn.execute("COMMIT", ()).await?;
    assert_eq!(current(&reopened).await?, None);
    assert_eq!(reference_floor(&reopened, at).await?, 12);
    Ok(())
}

#[tokio::test]
async fn duplicate_or_retracted_action_cannot_return_with_a_different_envelope() -> Result<()> {
    let (_directory, _db, conn) = database().await?;
    conn.execute("BEGIN", ()).await?;
    let original = append_effect(&conn, 100, 1).await?;
    conn.execute("COMMIT", ()).await?;
    let at = Position {
        decision: 12,
        stage: 2,
    };
    conn.execute("BEGIN", ()).await?;
    assert!(
        record(
            &conn,
            &original,
            &state([101; 32], 1)?,
            Position {
                decision: 1,
                stage: 1
            }
        )
        .await
        .is_err()
    );
    conn.execute("ROLLBACK", ()).await?;
    conn.execute("BEGIN", ()).await?;
    retract_at(&conn, origin(&conn, 12).await?, at, 99).await?;
    canonical_history::rollback(&conn, 99).await?;
    conn.execute("COMMIT", ()).await?;
    conn.execute("BEGIN", ()).await?;
    let HistoryState::Ready(cursor) = canonical_history::state(&conn).await? else {
        panic!()
    };
    let substituted = CanonicalApplication {
        ordinal: cursor.ordinal + 1,
        parent_lineage: cursor.lineage,
        source: ApplicationSource::UpgradeControl {
            decision: 13,
            action: [1; 32],
            control: [99; 32],
        },
        ..original
    };
    canonical_history::append(&conn, &substituted).await?;
    assert!(
        record(
            &conn,
            &substituted,
            &state([99; 32], 1)?,
            Position {
                decision: 13,
                stage: 1
            }
        )
        .await
        .is_err()
    );
    conn.execute("ROLLBACK", ()).await?;
    assert_eq!(current(&conn).await?, None);
    Ok(())
}

#[tokio::test]
async fn rollback_retracts_more_than_one_page_without_losing_dispositions() -> Result<()> {
    let (_directory, db, conn) = database().await?;
    conn.execute("BEGIN", ()).await?;
    for seed in 1..=70 {
        append_effect(&conn, 100 + u64::from(seed), seed).await?;
    }
    conn.execute("COMMIT", ()).await?;
    let at = Position {
        decision: 100,
        stage: 2,
    };
    conn.execute("BEGIN", ()).await?;
    assert_eq!(
        retract_at(&conn, origin(&conn, 100).await?, at, 100).await?,
        70
    );
    canonical_history::rollback(&conn, 100).await?;
    conn.execute("COMMIT", ()).await?;
    let reopened = db.connect()?;
    assert_eq!(current(&reopened).await?, None);
    for seed in 1..=70 {
        assert!(is_retracted(&reopened, [seed; 32], at).await?);
    }
    Ok(())
}

#[tokio::test]
async fn reconstruction_uses_historical_prefix_and_checks_the_same_rollback() -> Result<()> {
    let (_directory, _db, conn) = database().await?;
    conn.execute("BEGIN", ()).await?;
    let original = append_effect(&conn, 100, 1).await?;
    let rollback_origin = origin(&conn, 12).await?;
    conn.execute("COMMIT", ()).await?;
    let at = Position {
        decision: 12,
        stage: 2,
    };
    conn.execute("BEGIN", ()).await?;
    retract_at(&conn, rollback_origin, at, 99).await?;
    canonical_history::rollback(&conn, 99).await?;
    conn.execute("COMMIT", ()).await?;

    conn.execute("BEGIN", ()).await?;
    assert_eq!(append_effect(&conn, 100, 1).await?, original);
    conn.execute("COMMIT", ()).await?;
    conn.execute("BEGIN", ()).await?;
    assert!(
        retract_at(&conn, rollback_origin, Position { stage: 3, ..at }, 99)
            .await
            .is_err()
    );
    conn.execute("ROLLBACK", ()).await?;
    assert!(current(&conn).await?.is_some());
    conn.execute("BEGIN", ()).await?;
    assert_eq!(retract_at(&conn, rollback_origin, at, 99).await?, 1);
    canonical_history::rollback(&conn, 99).await?;
    conn.execute("COMMIT", ()).await?;
    assert_eq!(current(&conn).await?, None);
    Ok(())
}
