use std::env;
use std::fs;
use std::future::pending;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::{BlockHash, Network, hashes::Hash};
use indexer_types::BlockRow;
use libsql::{Builder, Connection, params};
use tempfile::TempDir;
use tokio::process::Command;
use tokio::sync::Notify;
use tokio::time::{sleep, timeout};

use super::{MigrationRejected, MigrationRequest, apply};
use crate::database::canonical_history::{self, ApplicationCursor, HistoryState};
use crate::database::connection::new_connection;
use crate::database::queries::{get_checkpoint_latest, insert_block};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::canonical_input::CanonicalInput;
use crate::protocol::coordinator::linked::{
    begin_canonical_unit, finish_canonical_unit, link_runtime,
};
use crate::protocol::coordinator::selection::{
    ApplicationPosition, ExecutionSelection, select_legacy_p1,
};
use crate::protocol::identity::{ChainId, ExecutionIdentity, PlanId};
use crate::protocol::v1::migration_definition;
use crate::runtime::bundle_session::BundleSession;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::HostFailure;
use crate::runtime::pool::LinkedSession;
use crate::runtime::{ComponentCache, Runtime, Storage};

async fn fixture(
    qualification: bool,
) -> Result<(TempDir, LinkedSession, OwnerService, MigrationRequest)> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "migration.db").await?;
    conn.execute("BEGIN", ()).await?;
    canonical_history::bind_genesis(&conn, ChainId([1; 32])).await?;
    let hash = BlockHash::from_byte_array([2; 32]);
    insert_block(&conn, BlockRow::builder().height(1).hash(hash).build()).await?;
    conn.execute("INSERT INTO contract_state (contract_id, height, size, path, value) VALUES (1, 1, 7, ?1, ?2)",
        params![b"migration-input".as_slice(), b"payload".as_slice()]).await?;
    conn.execute("COMMIT", ()).await?;
    let mut runtime = Runtime::new(
        ComponentCache::new(),
        Storage::builder().height(0).conn(conn.clone()).build(),
    )
    .await?;
    runtime.network = Network::Regtest;
    let mut executor = link_runtime(runtime, true);
    if qualification {
        let bundle = executor
            .owner
            .clone()
            .downcast::<BundleSession>()
            .map_err(|_| anyhow!("wrong executor"))?;
        executor.operations.migration = bundle.migration_qualification();
    }
    let execution = ExecutionIdentity::Baseline(executor.execution_definition?);
    conn.execute("BEGIN", ()).await?;
    let cursor = ready(&conn).await?;
    let cursor = canonical_history::append(
        &conn,
        &CanonicalApplication {
            chain: cursor.chain,
            ordinal: 1,
            parent_lineage: cursor.lineage,
            execution,
            storage_height: 1,
            source: ApplicationSource::BlockTransactions {
                height: 1,
                hash: hash.to_byte_array(),
                parent_hash: [0; 32],
            },
            input: Some(CanonicalInput::bitcoin(&[])?),
        },
    )
    .await?;
    let cursor = canonical_history::append(
        &conn,
        &CanonicalApplication {
            chain: cursor.chain,
            ordinal: 2,
            parent_lineage: cursor.lineage,
            execution,
            storage_height: 1,
            source: ApplicationSource::BlockLifecycle {
                height: 1,
                hash: hash.to_byte_array(),
            },
            input: None,
        },
    )
    .await?;
    conn.execute("COMMIT", ()).await?;
    let checkpoint = get_checkpoint_latest(&conn)
        .await?
        .map(|row| -> Result<[u8; 32]> {
            hex::decode(row.hash)?
                .try_into()
                .map_err(|_| anyhow!("bad checkpoint"))
        })
        .transpose()?;
    let definition = if qualification {
        migration_definition::qualification(executor.execution_definition?, false)
    } else {
        migration_definition::noop(executor.execution_definition?)
    };
    Ok((
        dir,
        LinkedSession::new(conn, executor),
        OwnerService::new(),
        MigrationRequest {
            expected: cursor,
            execution,
            plan: PlanId([3; 32]),
            anchor_height: 1,
            anchor_hash: hash,
            checkpoint,
            definition,
        },
    ))
}

async fn ready(conn: &Connection) -> Result<ApplicationCursor> {
    match canonical_history::state(conn).await? {
        HistoryState::Ready(cursor) => Ok(cursor),
        _ => Err(anyhow!("fixture history unavailable")),
    }
}

async fn selection(
    session: &LinkedSession,
    request: &MigrationRequest,
) -> Result<ExecutionSelection> {
    select_legacy_p1(
        &session.conn,
        Network::Regtest,
        ApplicationPosition::Migration {
            anchor_height: request.anchor_height,
            anchor_hash: request.anchor_hash,
        },
    )
    .await
}

async fn live_value(session: &LinkedSession, key: &[u8]) -> Result<Option<Vec<u8>>> {
    Ok(session.conn.query("SELECT s.value FROM current_contract_state c JOIN contract_state s USING (contract_id, path, height) WHERE c.contract_id = 1 AND c.path = ?1", [key])
        .await?.next().await?.map(|row| row.get(0)).transpose()?)
}

#[tokio::test]
#[ignore = "subprocess entry point for the migration crash recovery test"]
async fn migration_crash_child() -> Result<()> {
    let dir = PathBuf::from(
        env::var_os("KONTOR_MIGRATION_CRASH_DIR").context("missing crash directory")?,
    );
    let stage = env::var("KONTOR_MIGRATION_CRASH_STAGE")?;
    ensure!(
        stage == "after-effects" || stage == "after-commit",
        "invalid crash stage"
    );
    let conn = new_connection(&dir, "migration.db").await?;
    let expected = ready(&conn).await?;
    let checkpoint = get_checkpoint_latest(&conn).await?.unwrap();
    let mut runtime = Runtime::new(
        ComponentCache::new(),
        Storage::builder().height(0).conn(conn.clone()).build(),
    )
    .await?;
    runtime.network = Network::Regtest;
    let mut executor = link_runtime(runtime, true);
    let bundle = executor
        .owner
        .clone()
        .downcast::<BundleSession>()
        .map_err(|_| anyhow!("wrong executor"))?;
    let call = bundle.migration_qualification();
    let ready_path = dir.join("crash-ready");
    if stage == "after-effects" {
        let ready_path = ready_path.clone();
        executor.operations.migration = Arc::new(move |owner, selected, definition, input| {
            let call = call.clone();
            let ready_path = ready_path.clone();
            Box::pin(async move {
                let outcome = call(owner, selected, definition, input).await?;
                assert!(outcome.is_ok());
                fs::write(ready_path, "effects written").expect("signal crash parent");
                pending().await
            })
        });
    } else {
        executor.operations.migration = call;
    }
    let definition = executor.execution_definition?;
    let request = MigrationRequest {
        expected,
        execution: ExecutionIdentity::Baseline(definition),
        plan: PlanId([3; 32]),
        anchor_height: 1,
        anchor_hash: BlockHash::from_byte_array([2; 32]),
        checkpoint: Some(
            hex::decode(checkpoint.hash)?
                .try_into()
                .map_err(|_| anyhow!("bad checkpoint"))?,
        ),
        definition: migration_definition::qualification(definition, false),
    };
    let session = LinkedSession::new(conn, executor);
    let service = OwnerService::new();
    apply(
        &service,
        &session,
        &selection(&session, &request).await?,
        Network::Regtest,
        &request,
    )
    .await?;
    ensure!(stage == "after-commit", "unexpected completed migration");
    fs::write(ready_path, "commit completed")?;
    pending().await
}

#[tokio::test]
async fn migration_coordinator_process_crash_preserves_atomicity_and_retry() -> Result<()> {
    for stage in ["after-effects", "after-commit"] {
        let (dir, mut session, service, request) = fixture(true).await?;
        let child_log = fs::File::create(dir.path().join("crash-child.log"))?;
        let mut child = Command::new(env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "protocol::coordinator::migration::tests::migration_crash_child",
                "--nocapture",
            ])
            .env("KONTOR_MIGRATION_CRASH_DIR", dir.path())
            .env("KONTOR_MIGRATION_CRASH_STAGE", stage)
            .stdout(Stdio::from(child_log.try_clone()?))
            .stderr(Stdio::from(child_log))
            .kill_on_drop(true)
            .spawn()?;
        timeout(Duration::from_secs(20), async {
            while !dir.path().join("crash-ready").exists() {
                ensure!(
                    child.try_wait()?.is_none(),
                    "crash child exited before fence: {}",
                    fs::read_to_string(dir.path().join("crash-child.log"))?
                );
                sleep(Duration::from_millis(10)).await;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await??;
        // Kill the process without dropping its runtime or SQL connections, so
        // recovery exercises the database journal rather than Rust cleanup.
        child.kill().await?;
        assert!(!child.wait().await?.success());
        let reopened = new_connection(dir.path(), "migration.db").await?;
        let cursor = ready(&reopened).await?;
        if stage == "after-effects" {
            assert_eq!(cursor, request.expected);
            assert_eq!(
                get_checkpoint_latest(&reopened).await?.unwrap().hash,
                hex::encode_upper(request.checkpoint.unwrap())
            );
            assert_eq!(
                live_value(&session, b"migration-input").await?,
                Some(b"payload".to_vec())
            );
            assert_eq!(live_value(&session, b"migration-output").await?, None);
        } else {
            assert_eq!(cursor.ordinal, request.expected.ordinal + 1);
            assert_eq!(live_value(&session, b"migration-input").await?, None);
            assert_eq!(
                live_value(&session, b"migration-output").await?,
                Some(b"payload".to_vec())
            );
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let call = session.executor.operations.migration.clone();
        session.executor.operations.migration =
            Arc::new(move |owner, selected, definition, input| {
                observed.fetch_add(1, Ordering::SeqCst);
                call(owner, selected, definition, input)
            });
        let receipt = apply(
            &service,
            &session,
            &selection(&session, &request).await?,
            Network::Regtest,
            &request,
        )
        .await?;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            usize::from(stage == "after-effects")
        );
        assert_eq!(receipt.application.ordinal, 3);
        assert_eq!(
            canonical_history::surviving_migration_result(
                &reopened,
                receipt.application.migration_key()?
            )
            .await?,
            Some(receipt)
        );
        assert_eq!(
            live_value(&session, b"migration-output").await?,
            Some(b"payload".to_vec())
        );
        service.shutdown();
    }
    Ok(())
}

#[tokio::test]
async fn migration_coordinator_cancellation_quarantines_unsettled_effects() -> Result<()> {
    let (dir, mut session, service, request) = fixture(true).await?;
    let call = session.executor.operations.migration.clone();
    let effects_written = Arc::new(Notify::new());
    let entered = effects_written.clone();
    session.executor.operations.migration = Arc::new(move |owner, selected, definition, input| {
        let call = call.clone();
        let entered = entered.clone();
        Box::pin(async move {
            let outcome = call(owner, selected, definition, input).await?;
            assert!(outcome.is_ok());
            entered.notify_one();
            pending().await
        })
    });
    let selected = selection(&session, &request).await?;
    let mut applying = Box::pin(apply(
        &service,
        &session,
        &selected,
        Network::Regtest,
        &request,
    ));
    timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut applying => panic!("migration returned before cancellation: {result:?}"),
            () = effects_written.notified() => {}
        }
    })
    .await?;
    assert!(live_value(&session, b"migration-output").await?.is_some());
    drop(applying);
    assert!(service.is_fatal());
    assert!(session.canonical_busy.load(Ordering::SeqCst));
    assert_eq!(service.quarantined_roots().await, 1);
    assert!(service.reserve_root_capacity().await.is_err());

    // An abandoned canonical root is quarantined rather than reused. Its
    // uncommitted writes must remain invisible to a separate connection.
    let reader = Builder::new_local(dir.path().join("migration.db"))
        .build()
        .await?
        .connect()?;
    assert_eq!(ready(&reader).await?, request.expected);
    assert_eq!(
        get_checkpoint_latest(&reader).await?.unwrap().hash,
        hex::encode_upper(request.checkpoint.unwrap())
    );
    let mut rows = reader.query("SELECT path, value FROM current_contract_state c JOIN contract_state s USING (contract_id, path, height) WHERE c.contract_id = 1", ()).await?;
    let row = rows.next().await?.unwrap();
    assert_eq!(row.get::<Vec<u8>>(0)?, b"migration-input");
    assert_eq!(row.get::<Vec<u8>>(1)?, b"payload");
    assert!(rows.next().await?.is_none());
    assert!(
        reader
            .query("SELECT 1 FROM migration_applications", ())
            .await?
            .next()
            .await?
            .is_none()
    );
    service.shutdown();
    Ok(())
}

#[tokio::test]
async fn migration_coordinator_commits_effects_and_returns_stored_result_on_retry() -> Result<()> {
    let (_dir, mut session, service, request) = fixture(true).await?;
    let call = session.executor.operations.migration.clone();
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    session.executor.operations.migration = Arc::new(move |owner, selected, definition, input| {
        observed.fetch_add(1, Ordering::SeqCst);
        call(owner, selected, definition, input)
    });
    let first = apply(
        &service,
        &session,
        &selection(&session, &request).await?,
        Network::Regtest,
        &request,
    )
    .await?;
    assert_eq!(first.application.ordinal, 3);
    assert!(first.work.write_operations > 0);
    assert_eq!(
        live_value(&session, b"migration-output").await?,
        Some(b"payload".to_vec())
    );
    assert_eq!(live_value(&session, b"migration-input").await?, None);
    let cursor = ready(&session.conn).await?;
    assert_eq!(cursor.lineage, first.application.lineage()?);
    let output_height: u64 = session
        .conn
        .query(
            "SELECT height FROM current_contract_state WHERE path = ?1",
            [b"migration-output".as_slice()],
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert_eq!(
        output_height, 1,
        "migration used a stale executor storage height"
    );
    assert_ne!(
        get_checkpoint_latest(&session.conn).await?.unwrap().hash,
        hex::encode_upper(request.checkpoint.unwrap())
    );
    let repeat = apply(
        &service,
        &session,
        &selection(&session, &request).await?,
        Network::Regtest,
        &request,
    )
    .await?;
    assert_eq!(repeat, first);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(ready(&session.conn).await?, cursor);
    assert!(session.conn.is_autocommit());
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn migration_coordinator_metadata_failures_rollback_effects_and_checkpoint() -> Result<()> {
    for trigger in [
        "CREATE TEMP TRIGGER fail_migration BEFORE INSERT ON canonical_applications BEGIN SELECT RAISE(ABORT, 'application failure'); END",
        "CREATE TEMP TRIGGER fail_migration BEFORE INSERT ON migration_applications BEGIN SELECT RAISE(ABORT, 'marker failure'); END",
        "CREATE TEMP TRIGGER fail_migration BEFORE UPDATE ON canonical_history_state BEGIN SELECT RAISE(ABORT, 'cursor failure'); END",
    ] {
        let (_dir, session, service, request) = fixture(true).await?;
        let checkpoint = get_checkpoint_latest(&session.conn).await?;
        session.conn.execute_batch(trigger).await?;
        assert!(
            apply(
                &service,
                &session,
                &selection(&session, &request).await?,
                Network::Regtest,
                &request
            )
            .await
            .is_err()
        );
        assert_eq!(
            live_value(&session, b"migration-input").await?,
            Some(b"payload".to_vec())
        );
        assert_eq!(live_value(&session, b"migration-output").await?, None);
        assert_eq!(ready(&session.conn).await?, request.expected);
        assert_eq!(get_checkpoint_latest(&session.conn).await?, checkpoint);
        assert!(
            canonical_history::surviving_migration_result(
                &session.conn,
                request.application()?.migration_key()?
            )
            .await?
            .is_none()
        );
        assert!(session.conn.is_autocommit());
        assert!(!service.is_fatal());
        assert_eq!(service.active_roots().await, 0);
        session
            .conn
            .execute("DROP TRIGGER fail_migration", ())
            .await?;
        apply(
            &service,
            &session,
            &selection(&session, &request).await?,
            Network::Regtest,
            &request,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn migration_coordinator_rejects_budget_and_production_test_registry() -> Result<()> {
    for qualification in [false, true] {
        let (_dir, session, service, mut request) = fixture(qualification).await?;
        request.definition = migration_definition::qualification(
            session.executor.execution_definition?,
            qualification,
        );
        let error = apply(
            &service,
            &session,
            &selection(&session, &request).await?,
            Network::Regtest,
            &request,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<MigrationRejected>(),
            Some(if qualification {
                &MigrationRejected::Budget
            } else {
                &MigrationRejected::UnknownDefinition
            })
        );
        assert_eq!(ready(&session.conn).await?, request.expected);
        assert_eq!(
            live_value(&session, b"migration-input").await?,
            Some(b"payload".to_vec())
        );
        assert_eq!(live_value(&session, b"migration-output").await?, None);
        assert!(session.conn.is_autocommit());
    }
    Ok(())
}

#[tokio::test]
async fn migration_coordinator_rejects_changed_prestate_checkpoint_and_uncommitted_entry()
-> Result<()> {
    let (_dir, session, service, mut request) = fixture(false).await?;
    request.expected.lineage[0] ^= 1;
    assert!(
        apply(
            &service,
            &session,
            &selection(&session, &request).await?,
            Network::Regtest,
            &request
        )
        .await
        .is_err()
    );
    request.expected.lineage[0] ^= 1;
    request.checkpoint = None;
    assert!(
        apply(
            &service,
            &session,
            &selection(&session, &request).await?,
            Network::Regtest,
            &request
        )
        .await
        .is_err()
    );
    session.conn.execute("BEGIN", ()).await?;
    assert!(
        apply(
            &service,
            &session,
            &selection(&session, &request).await?,
            Network::Regtest,
            &request
        )
        .await
        .is_err()
    );
    ensure!(
        !session.conn.is_autocommit(),
        "migration settled someone else's transaction"
    );
    session.conn.execute("ROLLBACK", ()).await?;
    assert_eq!(ready(&session.conn).await?, request.expected);
    assert!(!service.is_fatal());
    Ok(())
}

async fn rollback(service: &OwnerService, session: &LinkedSession, height: u64) -> Result<()> {
    let selected = select_legacy_p1(
        &session.conn,
        Network::Regtest,
        ApplicationPosition::Maintenance {
            rollback_height: Some(height),
        },
    )
    .await?;
    let lease = begin_canonical_unit(service, session, &selected, Network::Regtest, false).await?;
    let result = async {
        (session.executor.operations.maintenance)(
            session.executor.owner.clone(),
            selected.envelope(),
        )
        .await
        .map_err(HostFailure::from)?;
        canonical_history::rollback(&session.conn, height).await
    }
    .await;
    finish_canonical_unit(lease, result, true).await
}

#[tokio::test]
async fn migration_coordinator_retry_survives_later_work_and_rollback_to_anchor() -> Result<()> {
    let (_dir, session, service, request) = fixture(true).await?;
    let receipt = apply(
        &service,
        &session,
        &selection(&session, &request).await?,
        Network::Regtest,
        &request,
    )
    .await?;
    session.conn.execute("BEGIN", ()).await?;
    let hash = BlockHash::from_byte_array([4; 32]);
    insert_block(
        &session.conn,
        BlockRow::builder().height(2).hash(hash).build(),
    )
    .await?;
    let current = ready(&session.conn).await?;
    canonical_history::append(
        &session.conn,
        &CanonicalApplication {
            chain: current.chain,
            ordinal: current.ordinal + 1,
            parent_lineage: current.lineage,
            execution: request.execution,
            storage_height: 2,
            source: ApplicationSource::BlockTransactions {
                height: 2,
                hash: hash.to_byte_array(),
                parent_hash: request.anchor_hash.to_byte_array(),
            },
            input: Some(CanonicalInput::bitcoin(&[])?),
        },
    )
    .await?;
    session.conn.execute("COMMIT", ()).await?;
    let later = ready(&session.conn).await?;
    assert_eq!(
        apply(
            &service,
            &session,
            &selection(&session, &request).await?,
            Network::Regtest,
            &request
        )
        .await?,
        receipt
    );
    assert_eq!(ready(&session.conn).await?, later);
    rollback(&service, &session, 1).await?;
    assert_eq!(
        apply(
            &service,
            &session,
            &selection(&session, &request).await?,
            Network::Regtest,
            &request
        )
        .await?,
        receipt
    );
    rollback(&service, &session, 0).await?;
    assert!(
        canonical_history::surviving_migration_result(
            &session.conn,
            receipt.application.migration_key()?
        )
        .await?
        .is_none()
    );
    assert!(
        apply(
            &service,
            &session,
            &selection(&session, &request).await?,
            Network::Regtest,
            &request
        )
        .await
        .is_err()
    );
    assert_eq!(ready(&session.conn).await?.ordinal, 0);
    Ok(())
}

#[tokio::test]
async fn migration_coordinator_reopen_returns_durable_result_without_reexecution() -> Result<()> {
    let (dir, session, service, request) = fixture(true).await?;
    let receipt = apply(
        &service,
        &session,
        &selection(&session, &request).await?,
        Network::Regtest,
        &request,
    )
    .await?;
    drop(session);
    drop(service);
    let conn = new_connection(dir.path(), "migration.db").await?;
    let mut runtime = Runtime::new(
        ComponentCache::new(),
        Storage::builder().height(0).conn(conn.clone()).build(),
    )
    .await?;
    runtime.network = Network::Regtest;
    let mut executor = link_runtime(runtime, true);
    executor.operations.migration =
        Arc::new(|_, _, _, _| Box::pin(async { Err((2, "retry executed a routine".into())) }));
    let session = LinkedSession::new(conn, executor);
    let service = OwnerService::new();
    assert_eq!(
        apply(
            &service,
            &session,
            &selection(&session, &request).await?,
            Network::Regtest,
            &request
        )
        .await?,
        receipt
    );
    assert_eq!(
        live_value(&session, b"migration-output").await?,
        Some(b"payload".to_vec())
    );
    assert!(session.conn.is_autocommit());
    Ok(())
}
