use std::collections::BTreeSet;
use std::future::pending;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::runtime::Handle;

use anyhow::{Result, anyhow, ensure};
use bitcoin::Network;
use libsql::{AuthAction, Authorization};
use libsql::{Connection, params};
use tokio::sync::Notify;
use tokio::time::timeout;

use super::{begin_canonical_unit, finish_canonical_unit, read_only_factory, read_snapshot};
use crate::database::canonical_history::{self, HistoryState};
use crate::database::certified_history;
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::coordinator::activation_execution::tests::fixture;
use crate::protocol::coordinator::selection::{
    ApplicationPosition, select_canonical, select_view_in_snapshot,
};
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::{LinkedSession, new_linked};

const LIMIT: Duration = Duration::from_secs(10);

async fn advance(writer: &LinkedSession) -> Result<()> {
    let conn = &writer.conn;
    conn.execute("BEGIN", ()).await?;
    record_advance(writer).await?;
    conn.execute("COMMIT", ()).await?;
    Ok(())
}

async fn advance_owned(writer: &LinkedSession, service: &OwnerService) -> Result<()> {
    let selected = select_canonical(
        &writer.conn,
        Network::Regtest,
        ApplicationPosition::Committee,
    )
    .await?;
    let lease = begin_canonical_unit(service, writer, &selected, Network::Regtest, false).await?;
    let result = record_advance(writer).await;
    finish_canonical_unit(lease, result, true).await
}

async fn record_advance(writer: &LinkedSession) -> Result<()> {
    let conn = &writer.conn;
    let selected = select_canonical(conn, Network::Regtest, ApplicationPosition::View).await?;
    let HistoryState::Ready(cursor) = canonical_history::state(conn).await? else {
        return Err(anyhow!("missing fixture cursor"));
    };
    canonical_history::append(
        conn,
        &CanonicalApplication {
            chain: cursor.chain,
            ordinal: cursor.ordinal + 1,
            parent_lineage: cursor.lineage,
            execution: selected.execution_identity(writer.executor.execution_definition?)?,
            storage_height: cursor.storage_height,
            source: ApplicationSource::BlockLifecycle {
                height: cursor.storage_height,
                hash: [7; 32],
            },
            input: None,
        },
    )
    .await?;
    conn.execute("UPDATE read_probe SET value = 2", ()).await?;
    Ok(())
}

async fn value(conn: &Connection) -> Result<i64> {
    Ok(conn
        .query("SELECT value FROM read_probe", ())
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?)
}

#[tokio::test]
async fn concurrent_readers_keep_their_snapshot_while_writer_commits() -> Result<()> {
    concurrent_readers(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_linked_readers_progress_during_canonical_finalization() -> Result<()> {
    concurrent_readers(true).await
}

async fn concurrent_readers(canonical: bool) -> Result<()> {
    let (dir, writer, service, _) = Box::pin(fixture()).await?;
    writer
        .conn
        .execute_batch("CREATE TABLE read_probe(value INTEGER); INSERT INTO read_probe VALUES(1)")
        .await?;
    let pool = new_linked(
        dir.path().to_path_buf(),
        "activation.db".into(),
        read_only_factory(Network::Regtest, 25_000)?,
        2,
    )?;
    let before = canonical_history::state(&writer.conn).await?;
    let release = Arc::new(Notify::new());
    let mut readers = Vec::new();
    for _ in 0..2 {
        let entered = Arc::new(Notify::new());
        let started = entered.clone();
        let release = release.clone();
        let object = pool.get().await?;
        let service = service.clone();
        readers.push(tokio::spawn(async move {
            read_snapshot(
                &service,
                object,
                Network::Regtest,
                move |conn, executor, selected| async move {
                    assert_eq!(value(&conn).await?, 1);
                    assert_eq!(
                        selected.canonical_execution(),
                        Some(executor.execution_definition?)
                    );
                    started.notify_one();
                    release.notified().await;
                    assert_eq!(value(&conn).await?, 1);
                    assert_eq!(canonical_history::state(&conn).await?, before);
                    Ok(())
                },
            )
            .await
        }));
        timeout(LIMIT, entered.notified()).await?;
    }
    assert_eq!(service.active_roots().await, 2);
    if canonical {
        timeout(LIMIT, advance_owned(&writer, &service)).await??;
        assert!(!writer.canonical_busy.load(Ordering::SeqCst));
        assert_eq!(service.active_roots().await, 2);
    } else {
        timeout(LIMIT, advance(&writer)).await??;
    }
    release.notify_waiters();
    for reader in readers {
        timeout(LIMIT, reader).await???;
    }
    read_snapshot(
        &service,
        pool.get().await?,
        Network::Regtest,
        move |conn, _, _| async move {
            assert_eq!(value(&conn).await?, 2);
            assert_ne!(canonical_history::state(&conn).await?, before);
            Ok(())
        },
    )
    .await?;
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn writer_commit_during_executor_construction_does_not_change_read_selection() -> Result<()> {
    let (dir, writer, service, _) = Box::pin(fixture()).await?;
    writer
        .conn
        .execute_batch("CREATE TABLE read_probe(value INTEGER); INSERT INTO read_probe VALUES(1)")
        .await?;
    let factory = read_only_factory(Network::Regtest, 25_000)?;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let started = entered.clone();
    let resume = release.clone();
    let factory: SessionFactory = Arc::new(move |conn| {
        let factory = factory.clone();
        let entered = started.clone();
        let release = resume.clone();
        Box::pin(async move {
            ensure!(!conn.conn.is_autocommit());
            entered.notify_one();
            release.notified().await;
            factory(conn).await
        })
    });
    let pool = new_linked(dir.path().to_path_buf(), "activation.db".into(), factory, 1)?;
    let object = pool.get().await?;
    let task = tokio::spawn(async move {
        read_snapshot(
            &service,
            object,
            Network::Regtest,
            |conn, _, _| async move {
                assert_eq!(value(&conn).await?, 1);
                Ok(())
            },
        )
        .await
    });
    timeout(LIMIT, entered.notified()).await?;
    timeout(LIMIT, advance(&writer)).await??;
    release.notify_one();
    timeout(LIMIT, task).await???;
    let object = pool.get().await?;
    assert!(object.conn.is_autocommit() && object.snapshot.is_idle());
    Ok(())
}

#[tokio::test]
async fn view_selection_omits_ordering_validation_but_preserves_manifest_validation() -> Result<()>
{
    let (dir, writer, _service, _) = Box::pin(fixture()).await?;
    let pool = new_linked(
        dir.path().to_path_buf(),
        "activation.db".into(),
        read_only_factory(Network::Regtest, 25_000)?,
        1,
    )?;
    let item = pool.get().await?;
    assert!(
        select_view_in_snapshot(&item.conn, Network::Regtest)
            .await
            .is_err()
    );
    let tables = Arc::new(Mutex::new(BTreeSet::new()));
    let queried = tables.clone();
    item.conn.authorizer(Some(Arc::new(move |context| {
        if let AuthAction::Read { table_name, .. } = context.action {
            queried.lock().unwrap().insert(table_name.to_owned());
        }
        Authorization::Allow
    })))?;
    item.conn.execute("BEGIN", ()).await?;
    let selected = select_view_in_snapshot(&item.conn, Network::Regtest).await?;
    item.conn.execute("ROLLBACK", ()).await?;
    item.conn.authorizer(None)?;
    for forbidden in [
        "completed_protocol_eras",
        "decision_closures",
        "historical_committees",
    ] {
        assert!(
            !tables.lock().unwrap().contains(forbidden),
            "view selection read {forbidden}"
        );
    }
    writer
        .conn
        .execute("UPDATE certified_history_state SET context = X'00'", ())
        .await?;
    assert!(certified_history::frontier(&writer.conn).await.is_err());
    item.conn.execute("BEGIN", ()).await?;
    assert_eq!(
        select_view_in_snapshot(&item.conn, Network::Regtest).await?,
        selected
    );
    item.conn.execute("ROLLBACK", ()).await?;
    writer
        .conn
        .execute(
            "UPDATE certified_protocols SET manifest = X'00' WHERE protocol_id = ?1",
            params![selected.protocol_id().unwrap().0.to_vec()],
        )
        .await?;
    item.conn.execute("BEGIN", ()).await?;
    assert!(
        select_view_in_snapshot(&item.conn, Network::Regtest)
            .await
            .is_err()
    );
    item.conn.execute("ROLLBACK", ()).await?;
    Ok(())
}

#[tokio::test]
async fn hook_construction_failure_closes_snapshot_and_removes_registration() -> Result<()> {
    let (dir, _writer, service, _) = Box::pin(fixture()).await?;
    let factory = read_only_factory(Network::Regtest, 25_000)?;
    let fail = Arc::new(AtomicBool::new(true));
    let factory: SessionFactory = Arc::new(move |conn| {
        let factory = factory.clone();
        let fail = fail.clone();
        Box::pin(async move {
            let mut executor = factory(conn).await?;
            let original = executor.make_root;
            executor.make_root = Arc::new(move |selection, adapter| {
                if fail.swap(false, Ordering::SeqCst) {
                    return Err((0, "injected hook failure".into()));
                }
                original(selection, adapter)
            });
            Ok(executor)
        })
    });
    let pool = new_linked(dir.path().to_path_buf(), "activation.db".into(), factory, 1)?;
    let result = read_snapshot(
        &service,
        pool.get().await?,
        Network::Regtest,
        |_, _, _| async { Ok(()) },
    )
    .await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("hook construction")
    );
    assert_eq!(service.active_roots().await, 0);
    assert_eq!(service.quarantined_roots().await, 0);
    let item = timeout(LIMIT, pool.get()).await??;
    assert!(item.conn.is_autocommit() && item.snapshot.is_idle());
    read_snapshot(&service, item, Network::Regtest, |_, _, _| async { Ok(()) }).await?;
    Ok(())
}

#[tokio::test]
async fn cancellation_before_executor_claim_releases_snapshot_for_reuse() -> Result<()> {
    let (dir, _writer, service, _) = Box::pin(fixture()).await?;
    let factory = read_only_factory(Network::Regtest, 25_000)?;
    let entered = Arc::new(Notify::new());
    let started = entered.clone();
    let pause = Arc::new(AtomicBool::new(true));
    let factory: SessionFactory = Arc::new(move |conn| {
        let factory = factory.clone();
        let started = started.clone();
        let pause = pause.clone();
        Box::pin(async move {
            let mut executor = factory(conn).await?;
            let original = executor.make_root;
            executor.make_root = Arc::new(move |selection, adapter| {
                let mut hooks = original(selection, adapter)?;
                let prepare = hooks.prepare;
                let started = started.clone();
                let pause = pause.clone();
                hooks.prepare = Arc::new(move |owner| {
                    let prepare = prepare.clone();
                    let started = started.clone();
                    let pause = pause.clone();
                    Box::pin(async move {
                        if pause.swap(false, Ordering::SeqCst) {
                            started.notify_one();
                            pending::<()>().await;
                        }
                        prepare(owner).await
                    })
                });
                Ok(hooks)
            });
            Ok(executor)
        })
    });
    let pool = new_linked(dir.path().to_path_buf(), "activation.db".into(), factory, 1)?;
    let object = pool.get().await?;
    let owned = service.clone();
    let request = tokio::spawn(async move {
        read_snapshot(&owned, object, Network::Regtest, |_, _, _| async { Ok(()) }).await
    });
    timeout(LIMIT, entered.notified()).await?;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    let object = timeout(LIMIT, pool.get()).await??;
    assert!(object.conn.is_autocommit() && object.snapshot.is_idle());
    assert_eq!(service.active_roots().await, 0);
    read_snapshot(&service, object, Network::Regtest, |_, _, _| async {
        Ok(())
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_between_selection_queries_uses_one_snapshot() -> Result<()> {
    let (dir, writer, service, _) = Box::pin(fixture()).await?;
    writer
        .conn
        .execute_batch("CREATE TABLE read_probe(value INTEGER); INSERT INTO read_probe VALUES(1)")
        .await?;
    let pool = new_linked(
        dir.path().to_path_buf(),
        "activation.db".into(),
        read_only_factory(Network::Regtest, 25_000)?,
        1,
    )?;
    let item = pool.get().await?;
    let (selected, selecting) = mpsc::channel();
    let (committed, committing) = mpsc::channel();
    let committing = Mutex::new(committing);
    let once = AtomicBool::new(false);
    item.conn.authorizer(Some(Arc::new(move |context| {
        if matches!(
            context.action,
            AuthAction::Read {
                table_name: "certified_protocols",
                ..
            }
        ) && !once.swap(true, Ordering::SeqCst)
        {
            selected.send(()).unwrap();
            committing.lock().unwrap().recv_timeout(LIMIT).unwrap();
        }
        Authorization::Allow
    })))?;
    let runtime = Handle::current();
    let writing = thread::spawn(move || -> Result<()> {
        selecting.recv_timeout(LIMIT)?;
        let result = runtime.block_on(advance(&writer));
        committed.send(())?;
        result
    });
    let result = read_snapshot(&service, item, Network::Regtest, |conn, _, _| async move {
        conn.authorizer(None)?;
        assert_eq!(value(&conn).await?, 1);
        Ok(())
    })
    .await;
    writing.join().expect("writer thread panicked")?;
    result?;
    Ok(())
}

#[tokio::test]
async fn cleanup_panic_after_hook_failure_quarantines_the_registered_read() -> Result<()> {
    let (dir, _writer, service, _) = Box::pin(fixture()).await?;
    let factory = read_only_factory(Network::Regtest, 25_000)?;
    let factory: SessionFactory = Arc::new(move |conn| {
        let factory = factory.clone();
        Box::pin(async move {
            let mut executor = factory(conn).await?;
            executor.make_root = Arc::new(|_, _| Err((0, "injected hook failure".into())));
            executor.recycle = Arc::new(|_| Box::pin(async { panic!("injected recycle panic") }));
            Ok(executor)
        })
    });
    let pool = new_linked(dir.path().to_path_buf(), "activation.db".into(), factory, 1)?;
    let result = read_snapshot(
        &service,
        pool.get().await?,
        Network::Regtest,
        |_, _, _| async { Ok(()) },
    )
    .await;
    assert!(format!("{:#}", result.unwrap_err()).contains("cleanup panicked"));
    assert_eq!(service.quarantined_roots().await, 1);
    assert_eq!(pool.status().available, 0);
    Ok(())
}
