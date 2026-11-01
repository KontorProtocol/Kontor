use anyhow::{Result, anyhow, bail, ensure};
use libsql::{Connection, TransactionBehavior, params};

use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::canonical_codec::{Decoder, Encoder};
use crate::protocol::identity::ChainId;
use crate::protocol::migration_work::MigrationWork;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ApplicationCursor {
    pub(crate) chain: ChainId,
    pub(crate) ordinal: u64,
    pub(crate) lineage: [u8; 32],
    pub(crate) storage_height: u64,
    pub(crate) authentic: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryState {
    PendingGenesis,
    Unavailable,
    Ready(ApplicationCursor),
}

pub(crate) async fn initialize(conn: &Connection) -> Result<()> {
    ensure!(
        conn.is_autocommit(),
        "history installation requires an idle writer"
    );
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    tx.execute_batch(include_str!("sql/canonical_history.sql"))
        .await?;
    tx.commit().await?;
    Ok(())
}

fn digest(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("invalid canonical history digest"))
}

pub(crate) async fn state(conn: &Connection) -> Result<HistoryState> {
    let row = conn
        .query(
            "SELECT status, chain_id, ordinal, lineage, storage_height, authentic
         FROM canonical_history_state WHERE singleton = 1",
            (),
        )
        .await?
        .next()
        .await?
        .ok_or_else(|| anyhow!("missing canonical history state"))?;
    match row.get::<String>(0)?.as_str() {
        "pending" => Ok(HistoryState::PendingGenesis),
        "unavailable" => Ok(HistoryState::Unavailable),
        "ready" => Ok(HistoryState::Ready(ApplicationCursor {
            chain: ChainId(digest(row.get(1)?)?),
            ordinal: row.get(2)?,
            lineage: digest(row.get(3)?)?,
            storage_height: row.get(4)?,
            authentic: row.get::<i64>(5)? == 1,
        })),
        _ => bail!("invalid canonical history status"),
    }
}

pub(crate) async fn bind_genesis(conn: &Connection, chain: ChainId) -> Result<()> {
    ensure!(
        !conn.is_autocommit(),
        "genesis identity requires its owned transaction"
    );
    match state(conn).await? {
        HistoryState::PendingGenesis => {
            let populated = conn
                .query(
                    "SELECT EXISTS(SELECT 1 FROM blocks)
                    OR EXISTS(SELECT 1 FROM contracts) OR EXISTS(SELECT 1 FROM contract_state)
                    OR EXISTS(SELECT 1 FROM transactions) OR EXISTS(SELECT 1 FROM signers)
                    OR EXISTS(SELECT 1 FROM checkpoints) OR EXISTS(SELECT 1 FROM batches)",
                    (),
                )
                .await?
                .next()
                .await?
                .ok_or_else(|| anyhow!("missing genesis emptiness check"))?;
            ensure!(
                populated.get::<i64>(0)? == 0,
                "cannot bind genesis over untracked state"
            );
            // The initial parent is the canonical genesis identity itself, before
            // any initialization stage has committed an application record.
            conn.execute(
                "UPDATE canonical_history_state SET status = 'ready', chain_id = ?1,
                 lineage = ?1, authentic = 1 WHERE singleton = 1 AND status = 'pending'",
                [chain.0.to_vec()],
            )
            .await?;
        }
        HistoryState::Ready(cursor) => {
            ensure!(cursor.chain == chain, "genesis configuration changed")
        }
        HistoryState::Unavailable => bail!("authentic canonical history is unavailable"),
    }
    Ok(())
}

async fn ready_cursor(conn: &Connection) -> Result<ApplicationCursor> {
    match state(conn).await? {
        HistoryState::Ready(cursor) => Ok(cursor),
        _ => bail!("authentic canonical history has not been initialized"),
    }
}

async fn verify_tail(conn: &Connection, cursor: ApplicationCursor) -> Result<()> {
    let row = conn
        .query(
            "SELECT ordinal, record, lineage, storage_height, authentic
         FROM canonical_applications ORDER BY ordinal DESC LIMIT 1",
            (),
        )
        .await?
        .next()
        .await?;
    match row {
        None => ensure!(
            cursor.ordinal == 0
                && cursor.lineage == cursor.chain.0
                && cursor.storage_height == 0
                && cursor.authentic,
            "invalid empty history cursor"
        ),
        Some(row) => {
            let record = CanonicalApplication::decode(&row.get::<Vec<u8>>(1)?)?;
            ensure!(
                record.ordinal == row.get::<u64>(0)?
                    && record.ordinal == cursor.ordinal
                    && record.chain == cursor.chain
                    && record.lineage()? == cursor.lineage
                    && digest(row.get(2)?)? == cursor.lineage
                    && row.get::<u64>(3)? == cursor.storage_height
                    && record.storage_height == cursor.storage_height
                    && (row.get::<i64>(4)? == 1) == cursor.authentic,
                "canonical history cursor does not match its tail"
            );
        }
    }
    Ok(())
}

async fn update_cursor(conn: &Connection, cursor: ApplicationCursor) -> Result<()> {
    let changed = conn.execute(
        "UPDATE canonical_history_state SET ordinal = ?1, lineage = ?2,
         storage_height = ?3, authentic = ?4 WHERE singleton = 1 AND status = 'ready' AND chain_id = ?5",
        params![cursor.ordinal, cursor.lineage.to_vec(), cursor.storage_height,
            cursor.authentic, cursor.chain.0.to_vec()],
    ).await?;
    ensure!(
        changed == 1,
        "canonical history state changed during application"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MigrationReceipt {
    pub(crate) application: CanonicalApplication,
    pub(crate) work: MigrationWork,
}

pub(crate) async fn append_migration(
    conn: &Connection,
    record: &CanonicalApplication,
    work: MigrationWork,
) -> Result<ApplicationCursor> {
    append_record(conn, record, Some(work)).await
}

pub(crate) async fn append(
    conn: &Connection,
    record: &CanonicalApplication,
) -> Result<ApplicationCursor> {
    append_record(conn, record, None).await
}

/// Metadata shares the caller's effects transaction. Any error must abort that unit.
async fn append_record(
    conn: &Connection,
    record: &CanonicalApplication,
    work: Option<MigrationWork>,
) -> Result<ApplicationCursor> {
    ensure!(
        !conn.is_autocommit(),
        "canonical application requires its owned transaction"
    );
    let cursor = ready_cursor(conn).await?;
    verify_tail(conn, cursor).await?;
    let ordinal = cursor
        .ordinal
        .checked_add(1)
        .ok_or_else(|| anyhow!("application ordinal overflow"))?;
    ensure!(
        ordinal <= i64::MAX as u64 && record.storage_height <= i64::MAX as u64,
        "canonical position exceeds database range"
    );
    ensure!(
        record.chain == cursor.chain
            && record.parent_lineage == cursor.lineage
            && record.ordinal == ordinal
            && record.storage_height >= cursor.storage_height,
        "application is not the next canonical position"
    );
    let encoded = record.encode()?;
    let lineage = record.lineage()?;
    let authentic = cursor.authentic && record.input.is_none_or(|input| input.authentic());
    let migration = matches!(record.source, ApplicationSource::Migration { .. });
    ensure!(
        migration == work.is_some(),
        "migration result must accompany its application"
    );
    ensure!(
        !migration || authentic,
        "migration requires authentic canonical input history"
    );
    conn.execute(
        "INSERT INTO canonical_applications (ordinal, storage_height, record, lineage, authentic)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            ordinal,
            record.storage_height,
            encoded,
            lineage.to_vec(),
            authentic
        ],
    )
    .await?;
    if let Some(work) = work {
        let mut encoded_work = Encoder::default();
        work.encode(&mut encoded_work)?;
        conn.execute(
            "INSERT INTO migration_applications (application_key, ordinal, work) VALUES (?1, ?2, ?3)",
            params![record.migration_key()?.to_vec(), ordinal, encoded_work.finish()],
        )
        .await?;
    }
    if let ApplicationSource::Genesis { stage } = record.source {
        conn.execute(
            "INSERT INTO genesis_applications (stage, ordinal) VALUES (?1, ?2)",
            params![stage, ordinal],
        )
        .await?;
    }
    let next = ApplicationCursor {
        chain: cursor.chain,
        ordinal,
        lineage,
        storage_height: record.storage_height,
        authentic,
    };
    update_cursor(conn, next).await?;
    Ok(next)
}

pub(crate) async fn genesis_stage_applied(conn: &Connection, stage: u32) -> Result<bool> {
    let cursor = ready_cursor(conn).await?;
    verify_tail(conn, cursor).await?;
    let row = conn
        .query(
            "SELECT a.ordinal, a.record, a.lineage FROM genesis_applications g
         JOIN canonical_applications a ON a.ordinal = g.ordinal WHERE g.stage = ?1",
            [stage],
        )
        .await?
        .next()
        .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let record = CanonicalApplication::decode(&row.get::<Vec<u8>>(1)?)?;
    ensure!(
        record.ordinal == row.get::<u64>(0)?
            && record.ordinal <= cursor.ordinal
            && record.chain == cursor.chain
            && record.source == (ApplicationSource::Genesis { stage })
            && record.lineage()? == digest(row.get(2)?)?,
        "invalid genesis progress marker"
    );
    Ok(true)
}

pub(crate) async fn surviving_migration_result(
    conn: &Connection,
    key: [u8; 32],
) -> Result<Option<MigrationReceipt>> {
    let cursor = ready_cursor(conn).await?;
    verify_tail(conn, cursor).await?;
    let row = conn
        .query(
            "SELECT a.ordinal, a.record, a.lineage, a.authentic, m.work FROM migration_applications m
         JOIN canonical_applications a ON a.ordinal = m.ordinal WHERE m.application_key = ?1",
            [key.to_vec()],
        )
        .await?
        .next()
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let record = CanonicalApplication::decode(&row.get::<Vec<u8>>(1)?)?;
    ensure!(
        record.ordinal == row.get::<u64>(0)?
            && record.ordinal <= cursor.ordinal
            && record.chain == cursor.chain
            && record.migration_key()? == key
            && record.lineage()? == digest(row.get(2)?)?
            && row.get::<i64>(3)? == 1,
        "invalid surviving migration marker"
    );
    let bytes: Vec<u8> = row.get(4)?;
    let mut decoder = Decoder::new(&bytes);
    let work = MigrationWork::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(Some(MigrationReceipt {
        application: record,
        work,
    }))
}

pub(crate) async fn rollback(conn: &Connection, height: u64) -> Result<()> {
    ensure!(
        !conn.is_autocommit(),
        "history rollback requires the state rollback transaction"
    );
    let cursor = match state(conn).await? {
        HistoryState::Ready(cursor) => cursor,
        HistoryState::Unavailable | HistoryState::PendingGenesis => return Ok(()),
    };
    verify_tail(conn, cursor).await?;
    let first: Option<u64> = conn
        .query(
            "SELECT MIN(ordinal) FROM canonical_applications WHERE storage_height > ?1",
            [height],
        )
        .await?
        .next()
        .await?
        .ok_or_else(|| anyhow!("missing rollback aggregate"))?
        .get(0)?;
    let Some(first) = first else {
        return Ok(());
    };
    let mut retained = ApplicationCursor {
        chain: cursor.chain,
        ordinal: 0,
        lineage: cursor.chain.0,
        storage_height: 0,
        authentic: true,
    };
    if first > 1 {
        let row = conn.query(
            "SELECT record, lineage, storage_height, authentic FROM canonical_applications WHERE ordinal = ?1",
            [first - 1],
        ).await?.next().await?.ok_or_else(|| anyhow!("canonical prefix has a gap"))?;
        let record = CanonicalApplication::decode(&row.get::<Vec<u8>>(0)?)?;
        retained = ApplicationCursor {
            chain: cursor.chain,
            ordinal: first - 1,
            lineage: digest(row.get(1)?)?,
            storage_height: row.get(2)?,
            authentic: row.get::<i64>(3)? == 1,
        };
        ensure!(
            record.ordinal == retained.ordinal
                && record.chain == retained.chain
                && record.lineage()? == retained.lineage
                && record.storage_height == retained.storage_height
                && retained.storage_height <= height,
            "invalid surviving canonical prefix"
        );
    }
    let mut expected = retained;
    let mut rows = conn
        .query(
            "SELECT ordinal, record, lineage, storage_height, authentic
         FROM canonical_applications WHERE ordinal >= ?1 ORDER BY ordinal",
            [first],
        )
        .await?;
    while let Some(row) = rows.next().await? {
        let record = CanonicalApplication::decode(&row.get::<Vec<u8>>(1)?)?;
        let authentic = expected.authentic && record.input.is_none_or(|input| input.authentic());
        ensure!(
            record.ordinal == row.get::<u64>(0)?
                && record.ordinal == expected.ordinal + 1
                && record.chain == cursor.chain
                && record.parent_lineage == expected.lineage
                && record.lineage()? == digest(row.get(2)?)?
                && record.storage_height == row.get::<u64>(3)?
                && record.storage_height > height
                && record.storage_height >= expected.storage_height
                && authentic == (row.get::<i64>(4)? == 1),
            "rollback would remove a noncontiguous canonical suffix"
        );
        expected = ApplicationCursor {
            chain: cursor.chain,
            ordinal: record.ordinal,
            lineage: record.lineage()?,
            storage_height: record.storage_height,
            authentic,
        };
    }
    drop(rows);
    ensure!(
        expected == cursor,
        "rollback suffix does not reach the canonical cursor"
    );
    conn.execute(
        "DELETE FROM canonical_applications WHERE ordinal >= ?1",
        [first],
    )
    .await?;
    update_cursor(conn, retained).await
}

#[cfg(test)]
mod tests {
    use libsql::{Builder, Connection, Database};
    use tempfile::TempDir;

    use super::{
        ApplicationCursor, HistoryState, append as append_plain, append_migration, bind_genesis,
        genesis_stage_applied, initialize, ready_cursor, rollback, state,
        surviving_migration_result,
    };
    use crate::protocol::canonical_application::{
        ApplicationSource, CanonicalApplication, DecisionExclusions,
    };
    use crate::protocol::canonical_input::CanonicalInput;
    use crate::protocol::identity::{
        ChainId, ExecutionDefinitionId, ExecutionIdentity, MigrationDefinitionId, PlanId,
    };

    use crate::protocol::migration_work::MigrationWork;
    use anyhow::Result;

    async fn append(conn: &Connection, record: &CanonicalApplication) -> Result<ApplicationCursor> {
        if matches!(record.source, ApplicationSource::Migration { .. }) {
            append_migration(conn, record, MigrationWork::default()).await
        } else {
            append_plain(conn, record).await
        }
    }

    async fn surviving_migration(
        conn: &Connection,
        key: [u8; 32],
    ) -> Result<Option<CanonicalApplication>> {
        Ok(surviving_migration_result(conn, key)
            .await?
            .map(|receipt| receipt.application))
    }

    async fn database() -> (TempDir, Database, Connection) {
        let dir = TempDir::new().unwrap();
        let database = Builder::new_local(dir.path().join("history.db"))
            .build()
            .await
            .unwrap();
        let conn = database.connect().unwrap();
        conn.execute_batch(include_str!("sql/schema.sql"))
            .await
            .unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;
            CREATE TABLE test_effect (key TEXT PRIMARY KEY, value INTEGER);",
        )
        .await
        .unwrap();
        (dir, database, conn)
    }

    async fn bind(conn: &Connection) {
        initialize(conn).await.unwrap();
        conn.execute("BEGIN", ()).await.unwrap();
        bind_genesis(conn, ChainId([1; 32])).await.unwrap();
        conn.execute("COMMIT", ()).await.unwrap();
    }

    fn record(cursor: ApplicationCursor, height: u64, migration: bool) -> CanonicalApplication {
        CanonicalApplication {
            chain: cursor.chain,
            ordinal: cursor.ordinal + 1,
            parent_lineage: cursor.lineage,
            execution: ExecutionIdentity::Baseline(ExecutionDefinitionId([2; 32])),
            storage_height: height,
            source: if migration {
                ApplicationSource::Migration {
                    anchor_height: height,
                    anchor_hash: [3; 32],
                    plan: PlanId([4; 32]),
                    definition: MigrationDefinitionId([5; 32]),
                    checkpoint: None,
                }
            } else {
                ApplicationSource::Batch {
                    anchor_height: height,
                    anchor_hash: [3; 32],
                    exclusions: DecisionExclusions {
                        consensus_height: 99,
                        direct: vec![],
                        effective: vec![],
                    },
                }
            },
            input: (!migration).then(|| CanonicalInput::bitcoin(&[]).unwrap()),
        }
    }

    #[tokio::test]
    async fn effects_marker_and_cursor_commit_or_rollback_together() {
        let (_dir, database, conn) = database().await;
        bind(&conn).await;
        let initial = ready_cursor(&conn).await.unwrap();
        let migration = record(initial, 1, true);
        let key = migration.migration_key().unwrap();
        let observer = database.connect().unwrap();
        conn.execute("BEGIN", ()).await.unwrap();
        conn.execute("INSERT INTO test_effect VALUES ('migration', 1)", ())
            .await
            .unwrap();
        append(&conn, &migration).await.unwrap();
        assert_eq!(
            state(&observer).await.unwrap(),
            HistoryState::Ready(initial)
        );
        assert!(surviving_migration(&observer, key).await.unwrap().is_none());
        conn.execute("ROLLBACK", ()).await.unwrap();
        assert_eq!(state(&conn).await.unwrap(), HistoryState::Ready(initial));
        let rows = conn
            .query("SELECT * FROM test_effect", ())
            .await
            .unwrap()
            .next()
            .await
            .unwrap();
        assert!(rows.is_none());

        conn.execute("BEGIN", ()).await.unwrap();
        conn.execute("INSERT INTO test_effect VALUES ('migration', 1)", ())
            .await
            .unwrap();
        append(&conn, &migration).await.unwrap();
        conn.execute("COMMIT", ()).await.unwrap();
        let reopened = database.connect().unwrap();
        assert_eq!(
            surviving_migration(&reopened, key).await.unwrap(),
            Some(migration.clone())
        );
        assert_eq!(ready_cursor(&reopened).await.unwrap().ordinal, 1);
        assert_eq!(
            reopened
                .query("SELECT value FROM test_effect", ())
                .await
                .unwrap()
                .next()
                .await
                .unwrap()
                .unwrap()
                .get::<i64>(0)
                .unwrap(),
            1
        );
        conn.execute("BEGIN", ()).await.unwrap();
        assert!(append(&conn, &migration).await.is_err());
        conn.execute("ROLLBACK", ()).await.unwrap();
        assert_eq!(ready_cursor(&conn).await.unwrap().ordinal, 1);
    }

    #[tokio::test]
    async fn rollback_keeps_every_anchor_entry_then_removes_markers_below_anchor() {
        let (_dir, _database, conn) = database().await;
        bind(&conn).await;
        conn.execute("BEGIN", ()).await.unwrap();
        let first = record(ready_cursor(&conn).await.unwrap(), 1, false);
        let first_cursor = append(&conn, &first).await.unwrap();
        let migration = record(first_cursor, 1, true);
        let key = migration.migration_key().unwrap();
        let anchor_cursor = append(&conn, &migration).await.unwrap();
        append(&conn, &record(anchor_cursor, 2, false))
            .await
            .unwrap();
        conn.execute("COMMIT", ()).await.unwrap();
        conn.execute("BEGIN", ()).await.unwrap();
        rollback(&conn, 1).await.unwrap();
        conn.execute("COMMIT", ()).await.unwrap();
        assert_eq!(ready_cursor(&conn).await.unwrap(), anchor_cursor);
        assert_eq!(
            surviving_migration(&conn, key).await.unwrap(),
            Some(migration.clone())
        );
        conn.execute("BEGIN", ()).await.unwrap();
        rollback(&conn, 0).await.unwrap();
        assert!(surviving_migration(&conn, key).await.unwrap().is_none());
        assert_eq!(ready_cursor(&conn).await.unwrap().ordinal, 0);
        assert_eq!(append(&conn, &first).await.unwrap(), first_cursor);
        assert_eq!(append(&conn, &migration).await.unwrap(), anchor_cursor);
        conn.execute("COMMIT", ()).await.unwrap();
    }

    #[tokio::test]
    async fn legacy_state_is_preserved_and_cannot_claim_authentic_history() {
        let (_dir, _database, conn) = database().await;
        conn.execute(
            "INSERT INTO blocks (height, hash, relevant) VALUES (1, 'old', 0)",
            (),
        )
        .await
        .unwrap();
        initialize(&conn).await.unwrap();
        assert_eq!(state(&conn).await.unwrap(), HistoryState::Unavailable);
        conn.execute("BEGIN", ()).await.unwrap();
        assert!(bind_genesis(&conn, ChainId([1; 32])).await.is_err());
        rollback(&conn, 0).await.unwrap();
        conn.execute("ROLLBACK", ()).await.unwrap();
        initialize(&conn).await.unwrap();
        assert_eq!(state(&conn).await.unwrap(), HistoryState::Unavailable);
        assert_eq!(
            conn.query("SELECT hash FROM blocks", ())
                .await
                .unwrap()
                .next()
                .await
                .unwrap()
                .unwrap()
                .get::<String>(0)
                .unwrap(),
            "old"
        );
    }

    #[tokio::test]
    async fn untracked_writes_after_installation_cannot_be_adopted_as_genesis() {
        let (_dir, _database, conn) = database().await;
        initialize(&conn).await.unwrap();
        conn.execute(
            "INSERT INTO blocks (height, hash, relevant) VALUES (0, 'untracked', 0)",
            (),
        )
        .await
        .unwrap();
        conn.execute("BEGIN", ()).await.unwrap();
        assert!(bind_genesis(&conn, ChainId([1; 32])).await.is_err());
        conn.execute("ROLLBACK", ()).await.unwrap();
        assert_eq!(state(&conn).await.unwrap(), HistoryState::PendingGenesis);
        initialize(&conn).await.unwrap();
        assert_eq!(state(&conn).await.unwrap(), HistoryState::Unavailable);
        assert!(
            conn.query("SELECT 1 FROM blocks WHERE hash = 'untracked'", ())
                .await
                .unwrap()
                .next()
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn genesis_resume_rejects_identity_substitution() {
        let (_dir, _database, conn) = database().await;
        initialize(&conn).await.unwrap();
        assert_eq!(state(&conn).await.unwrap(), HistoryState::PendingGenesis);
        assert!(bind_genesis(&conn, ChainId([1; 32])).await.is_err());
        conn.execute("BEGIN", ()).await.unwrap();
        bind_genesis(&conn, ChainId([1; 32])).await.unwrap();
        conn.execute("ROLLBACK", ()).await.unwrap();
        assert_eq!(state(&conn).await.unwrap(), HistoryState::PendingGenesis);
        conn.execute("BEGIN", ()).await.unwrap();
        bind_genesis(&conn, ChainId([1; 32])).await.unwrap();
        conn.execute("COMMIT", ()).await.unwrap();
        conn.execute("BEGIN", ()).await.unwrap();
        bind_genesis(&conn, ChainId([1; 32])).await.unwrap();
        assert!(bind_genesis(&conn, ChainId([2; 32])).await.is_err());
        conn.execute("ROLLBACK", ()).await.unwrap();
        assert_eq!(ready_cursor(&conn).await.unwrap().chain, ChainId([1; 32]));
    }

    #[tokio::test]
    async fn migration_rejects_synthetic_ancestry_and_rollback_rejects_middle_removal() {
        let (_dir, _database, conn) = database().await;
        bind(&conn).await;
        conn.execute("BEGIN", ()).await.unwrap();
        let mut first = record(ready_cursor(&conn).await.unwrap(), 1, false);
        first.input = Some(CanonicalInput::synthetic(&[]).unwrap());
        let cursor = append(&conn, &first).await.unwrap();
        assert!(!cursor.authentic);
        assert!(append(&conn, &record(cursor, 1, true)).await.is_err());
        let cursor = append(&conn, &record(cursor, 2, false)).await.unwrap();
        append(&conn, &record(cursor, 3, false)).await.unwrap();
        conn.execute("COMMIT", ()).await.unwrap();
        conn.execute("BEGIN", ()).await.unwrap();
        conn.execute(
            "UPDATE canonical_applications SET storage_height = 4 WHERE ordinal = 1",
            (),
        )
        .await
        .unwrap();
        assert!(rollback(&conn, 2).await.is_err());
        conn.execute("ROLLBACK", ()).await.unwrap();
        assert_eq!(ready_cursor(&conn).await.unwrap().ordinal, 3);
    }

    #[tokio::test]
    async fn genesis_stage_marker_is_durable_and_unique() {
        let (_dir, database, conn) = database().await;
        bind(&conn).await;
        assert!(!genesis_stage_applied(&conn, 0).await.unwrap());
        conn.execute("BEGIN", ()).await.unwrap();
        let first = CanonicalApplication {
            source: ApplicationSource::Genesis { stage: 0 },
            input: None,
            ..record(ready_cursor(&conn).await.unwrap(), 0, false)
        };
        append(&conn, &first).await.unwrap();
        conn.execute("COMMIT", ()).await.unwrap();
        let reopened = database.connect().unwrap();
        assert!(genesis_stage_applied(&reopened, 0).await.unwrap());
        assert!(!genesis_stage_applied(&reopened, 1).await.unwrap());
        conn.execute("BEGIN", ()).await.unwrap();
        let duplicate = CanonicalApplication {
            source: ApplicationSource::Genesis { stage: 0 },
            input: None,
            ..record(ready_cursor(&conn).await.unwrap(), 0, false)
        };
        assert!(append(&conn, &duplicate).await.is_err());
        conn.execute("ROLLBACK", ()).await.unwrap();
        assert_eq!(ready_cursor(&conn).await.unwrap().ordinal, 1);
    }

    #[tokio::test]
    async fn failure_after_marker_before_cursor_aborts_the_whole_unit() {
        let (_dir, _database, conn) = database().await;
        bind(&conn).await;
        let initial = ready_cursor(&conn).await.unwrap();
        let migration = record(initial, 1, true);
        conn.execute_batch(
            "CREATE TEMP TRIGGER fail_cursor BEFORE UPDATE ON canonical_history_state
            WHEN NEW.ordinal > 0 BEGIN SELECT RAISE(ABORT, 'injected cursor failure'); END;",
        )
        .await
        .unwrap();
        conn.execute("BEGIN", ()).await.unwrap();
        conn.execute("INSERT INTO test_effect VALUES ('migration', 1)", ())
            .await
            .unwrap();
        assert!(append(&conn, &migration).await.is_err());
        conn.execute("ROLLBACK", ()).await.unwrap();
        assert_eq!(ready_cursor(&conn).await.unwrap(), initial);
        assert!(
            surviving_migration(&conn, migration.migration_key().unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            conn.query("SELECT * FROM test_effect", ())
                .await
                .unwrap()
                .next()
                .await
                .unwrap()
                .is_none()
        );
    }
}
