use std::collections::BTreeMap;
use std::future::pending;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use deadpool::managed::{Object, Pool};
use libsql::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::Notify;
use tokio::time::timeout;

use super::NETWORK;
use crate::config::DEFAULT_VIEW_GAS_LIMIT;
use crate::database::connection::new_connection;
use crate::protocol::coordinator::linked::{
    RetainedFactory, execute_view, read_snapshot, retained_session_factory,
    retained_session_factory_with_callbacks,
};
use crate::protocol::session::HostError;
use crate::protocol::storage_callbacks::StorageCallbacks;
use crate::protocol::storage_rows::CursorOwner;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::{HostFailure, SessionFactory};
use crate::runtime::pool::{LinkedManager, new_linked};

const LIMIT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy)]
enum CallbackMode {
    Pass,
    Pending,
    Fail,
    Panic,
}

#[derive(Clone)]
struct CallbackProbe {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    dropped: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}

impl CallbackProbe {
    fn new() -> Self {
        Self {
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            dropped: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct CallbackInFlight(Arc<AtomicBool>);

impl Drop for CallbackInFlight {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct CursorProbe {
    entered: Arc<Notify>,
    dropped: Arc<AtomicBool>,
    advances: Arc<AtomicUsize>,
}

impl CursorProbe {
    fn new() -> Self {
        Self {
            entered: Arc::new(Notify::new()),
            dropped: Arc::new(AtomicBool::new(false)),
            advances: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct HeldCursor {
    // Field order drops the opaque SQL cursor before marking the callback drained.
    _owner: CursorOwner,
    _drained: CallbackInFlight,
}

fn cursor_decorator(
    probe: CursorProbe,
) -> Arc<dyn Fn(StorageCallbacks) -> StorageCallbacks + Send + Sync> {
    Arc::new(move |mut callbacks| {
        let original = callbacks.9.1.clone();
        let probe = probe.clone();
        callbacks.9.1 = Arc::new(move |owner| {
            let ordinal = probe.advances.fetch_add(1, Ordering::SeqCst) + 1;
            if ordinal != 2 {
                return original(owner);
            }
            let probe = probe.clone();
            Box::pin(async move {
                let _held = HeldCursor {
                    _owner: owner,
                    _drained: CallbackInFlight(probe.dropped.clone()),
                };
                probe.entered.notify_one();
                pending().await
            })
        });
        callbacks
    })
}

fn factory(graph: &str, mode: CallbackMode, probe: CallbackProbe) -> Result<SessionFactory> {
    let decorate: Arc<dyn Fn(StorageCallbacks) -> StorageCallbacks + Send + Sync> =
        Arc::new(move |mut callbacks| {
            let original = callbacks.7.4.clone();
            let probe = probe.clone();
            callbacks.7.4 = Arc::new(move |contract_id| {
                let original = original.clone();
                let probe = probe.clone();
                Box::pin(async move {
                    probe.calls.fetch_add(1, Ordering::SeqCst);
                    let _in_flight = CallbackInFlight(probe.dropped.clone());
                    match mode {
                        CallbackMode::Pass => original(contract_id).await,
                        CallbackMode::Pending => {
                            probe.entered.notify_one();
                            probe.release.notified().await;
                            original(contract_id).await
                        }
                        CallbackMode::Fail => Err("qualification storage callback failed".into()),
                        CallbackMode::Panic => panic!("qualification storage callback panicked"),
                    }
                })
            });
            callbacks
        });
    factory_with_decorator(graph, decorate)
}

fn factory_with_decorator(
    graph: &str,
    decorate: Arc<dyn Fn(StorageCallbacks) -> StorageCallbacks + Send + Sync>,
) -> Result<SessionFactory> {
    match graph {
        "first" => retained_session_factory_with_callbacks(
            NETWORK,
            Some(DEFAULT_VIEW_GAS_LIMIT),
            kontor_executor_first::factory,
            kontor_executor_first::execution_definition(),
            decorate,
        ),
        "second" => retained_session_factory_with_callbacks(
            NETWORK,
            Some(DEFAULT_VIEW_GAS_LIMIT),
            kontor_executor_second::factory,
            kontor_executor_second::execution_definition(),
            decorate,
        ),
        _ => anyhow::bail!("unknown retained graph {graph}"),
    }
}

fn pool(
    path: &Path,
    graph: &str,
    mode: CallbackMode,
    probe: CallbackProbe,
) -> Result<Pool<LinkedManager>> {
    new_linked(
        path.to_path_buf(),
        "qualification.db".into(),
        factory(graph, mode, probe)?,
        1,
    )
}

fn constructor_panics() -> std::result::Result<RetainedFactory, HostError> {
    panic!("qualification executor constructor panicked")
}

fn session_export_panics() -> std::result::Result<RetainedFactory, HostError> {
    Ok(Arc::new(|_, _, _| {
        Box::pin(async { panic!("qualification executor session export panicked") })
    }))
}

pub(super) async fn qualify_export_panics() -> Result<Value> {
    let constructor_error = retained_session_factory(
        NETWORK,
        None,
        constructor_panics,
        kontor_executor_first::execution_definition(),
    )
    .err()
    .context("constructor panic escaped the factory boundary")?;
    let constructor = constructor_error
        .downcast_ref::<HostFailure>()
        .context("constructor panic lost its host failure type")?;
    ensure!(
        constructor.tag == 1 && constructor.message == "executor factory export panicked",
        "constructor panic lost its export classification"
    );

    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "export-panic.db").await?;
    let factory = retained_session_factory(
        NETWORK,
        None,
        session_export_panics,
        kontor_executor_first::execution_definition(),
    )?;
    let session_error = factory(conn)
        .await
        .err()
        .context("session panic escaped the factory boundary")?;
    let session = session_error
        .downcast_ref::<HostFailure>()
        .context("session panic lost its host failure type")?;
    ensure!(
        session.tag == 1 && session.message == "executor session export panicked",
        "session panic lost its export classification"
    );
    Ok(json!({"constructor_tag": 1, "session_tag": 1}))
}

pub(super) async fn qualify_graph(graph: &str, path: &Path, writer: &Connection) -> Result<Value> {
    let address = ("counter".into(), 3, 7);

    let pending_probe = CallbackProbe::new();
    let pending_pool = pool(path, graph, CallbackMode::Pending, pending_probe.clone())?;
    let object = pending_pool.get().await?;
    let service = OwnerService::new();
    let entered = pending_probe.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    let call_service = service.clone();
    let call_address = address.clone();
    let pending_view = tokio::spawn(async move {
        execute_view(&call_service, object, NETWORK, call_address, "get()".into()).await
    });
    timeout(LIMIT, entered)
        .await
        .context("real storage callback did not start")?;
    ensure!(
        timeout(POLL, pending_pool.get()).await.is_err(),
        "read session was reused while a storage callback was pending"
    );
    pending_view.abort();
    ensure!(
        pending_view.await.is_err_and(|error| error.is_cancelled()),
        "pending view task was not cancelled"
    );
    let reused = timeout(LIMIT, pending_pool.get()).await??;
    ensure!(
        pending_probe.dropped.load(Ordering::SeqCst),
        "read session returned before its storage callback was dropped"
    );
    ensure!(
        reused.conn.is_autocommit(),
        "cancelled view retained a SQL transaction"
    );
    drop(reused);
    ensure!(
        service.active_roots().await == 0,
        "cancelled callback retained owner root"
    );
    service.shutdown();

    let mut faults = BTreeMap::new();
    for mode in [CallbackMode::Fail, CallbackMode::Panic] {
        let probe = CallbackProbe::new();
        let pool = pool(path, graph, mode, probe.clone())?;
        let service = OwnerService::new();
        let object = pool.get().await?;
        let original_id = Object::id(&object);
        let result = execute_view(&service, object, NETWORK, address.clone(), "get()".into()).await;
        ensure!(
            probe.calls.load(Ordering::SeqCst) > 0,
            "storage fault was not exercised"
        );
        match mode {
            CallbackMode::Fail => ensure!(
                matches!(&result, Ok(Err((false, message))) if message.contains("qualification storage callback failed")),
                "storage failure lost its nondeterministic classification: {result:?}"
            ),
            CallbackMode::Panic => ensure!(
                matches!(&result, Ok(Err((false, _))) | Err(_)),
                "storage panic became a deterministic guest result: {result:?}"
            ),
            _ => unreachable!(),
        }
        let error = match &result {
            Ok(Err((false, message))) => message.clone(),
            Err(error) => format!("{error:#}"),
            _ => anyhow::bail!("storage fault did not return a host-classified error"),
        };
        let reused = timeout(LIMIT, pool.get()).await??;
        let same_session = Object::id(&reused) == original_id;
        match mode {
            CallbackMode::Fail => ensure!(
                same_session,
                "ordinary callback failure discarded a clean read session"
            ),
            CallbackMode::Panic => ensure!(
                !same_session,
                "callback panic returned a poisoned read session"
            ),
            _ => unreachable!(),
        }
        ensure!(
            reused.conn.is_autocommit(),
            "storage fault returned a live SQL transaction"
        );
        faults.insert(
            if matches!(mode, CallbackMode::Fail) {
                "failure"
            } else {
                "panic"
            },
            json!({"error": error, "same_session": same_session}),
        );
        drop(reused);
        ensure!(
            service.active_roots().await == 0,
            "storage fault retained owner root"
        );
        service.shutdown();
    }

    writer
        .execute(
            "CREATE TABLE ownership_cursor_probe (k INTEGER PRIMARY KEY)",
            (),
        )
        .await?;
    writer
        .execute("INSERT INTO ownership_cursor_probe (k) VALUES (1)", ())
        .await?;
    let cursor_probe = CursorProbe::new();
    let cursor_pool = new_linked(
        path.to_path_buf(),
        "qualification.db".into(),
        factory_with_decorator(graph, cursor_decorator(cursor_probe.clone()))?,
        1,
    )?;
    let object = cursor_pool.get().await?;
    let service = OwnerService::new();
    let observed = cursor_probe.entered.notified();
    tokio::pin!(observed);
    observed.as_mut().enable();
    let call_service = service.clone();
    let call_address = address.clone();
    let held_cursor = tokio::spawn(async move {
        execute_view(
            &call_service,
            object,
            NETWORK,
            call_address,
            "entry-page(none, 2)".into(),
        )
        .await
    });
    timeout(LIMIT, observed)
        .await
        .context("guest storage cursor did not reach its second row advance")?;
    ensure!(
        cursor_probe.advances.load(Ordering::SeqCst) == 2,
        "guest cursor did not advance the expected number of rows"
    );
    writer
        .execute("INSERT INTO ownership_cursor_probe (k) VALUES (2)", ())
        .await?;
    ensure!(
        timeout(POLL, cursor_pool.get()).await.is_err(),
        "read session was reused with a live cursor"
    );
    held_cursor.abort();
    ensure!(
        held_cursor.await.is_err_and(|error| error.is_cancelled()),
        "held cursor task was not cancelled"
    );
    let reused = timeout(LIMIT, cursor_pool.get()).await??;
    ensure!(
        cursor_probe.dropped.load(Ordering::SeqCst),
        "read session returned before the guest cursor was dropped"
    );
    ensure!(
        reused.conn.is_autocommit(),
        "held cursor left a SQL transaction"
    );
    let count: i64 = reused
        .conn
        .query("SELECT COUNT(*) FROM ownership_cursor_probe", ())
        .await?
        .next()
        .await?
        .context("cursor count missing")?
        .get(0)?;
    ensure!(count == 2, "reused view retained a stale SQL snapshot");
    let page = execute_view(
        &service,
        reused,
        NETWORK,
        address,
        "entry-page(none, 2)".into(),
    )
    .await?;
    ensure!(
        page.as_ref().is_ok_and(|value| value.contains("alpha")),
        "guest cursor failed after pool reuse: {page:?}"
    );
    ensure!(
        service.active_roots().await == 0,
        "held cursor retained owner root"
    );
    service.shutdown();

    Ok(json!({"pending_callback_cancelled": true, "faults": faults,
        "held_guest_cursor_released": true}))
}

pub(super) async fn qualify_node_capacity(service: &OwnerService) -> Result<Value> {
    let dir = TempDir::new()?;
    let _writer = new_connection(dir.path(), "qualification.db").await?;
    let first = pool(
        dir.path(),
        "first",
        CallbackMode::Pass,
        CallbackProbe::new(),
    )?;
    let second = pool(
        dir.path(),
        "second",
        CallbackMode::Pass,
        CallbackProbe::new(),
    )?;
    let mut held = Vec::new();
    for pool in [&first, &second] {
        let object = pool.get().await?;
        let entered = Arc::new(Notify::new());
        let observed = entered.notified();
        tokio::pin!(observed);
        observed.as_mut().enable();
        let started = entered.clone();
        let call_service = service.clone();
        held.push(tokio::spawn(async move {
            read_snapshot(&call_service, object, NETWORK, move |_, _, _| async move {
                started.notify_one();
                pending::<Result<()>>().await
            })
            .await
        }));
        timeout(LIMIT, observed)
            .await
            .context("retained graph root did not start")?;
    }
    ensure!(
        service.active_roots().await == 2,
        "both graph roots were not live"
    );
    let mut permits = Vec::new();
    for _ in 0..62 {
        permits.push(timeout(LIMIT, service.reserve_root_capacity()).await??);
    }
    ensure!(
        timeout(POLL, service.reserve_root_capacity())
            .await
            .is_err(),
        "admission capacity was not shared across retained graphs"
    );
    let first_call = held.remove(0);
    first_call.abort();
    ensure!(
        first_call.await.is_err_and(|error| error.is_cancelled()),
        "first graph root caller was not cancelled"
    );
    let released = timeout(LIMIT, service.reserve_root_capacity()).await??;
    drop(released);
    let mut driver = service.take_driver().context("node owner driver missing")?;
    service.shutdown();
    ensure!(
        service.reserve_root_capacity().await.is_err(),
        "shutdown left admission open"
    );
    ensure!(
        timeout(POLL, &mut driver).await.is_err(),
        "shutdown finished while a retained graph root was live"
    );
    for task in held {
        task.abort();
        let _ = timeout(LIMIT, task)
            .await
            .context("root did not stop after shutdown")?;
    }
    timeout(LIMIT, driver)
        .await??
        .context("owner driver failed after shutdown")?;
    ensure!(
        service.active_roots().await == 0,
        "shutdown retained a graph root"
    );
    let first_reused = timeout(LIMIT, first.get()).await??;
    let second_reused = timeout(LIMIT, second.get()).await??;
    ensure!(
        first_reused.conn.is_autocommit() && second_reused.conn.is_autocommit(),
        "shutdown returned a SQL transaction to a read pool"
    );
    drop(permits);
    Ok(json!({"both_graphs_live": true, "shared_capacity": 64,
        "shutdown_drained_roots": true}))
}
