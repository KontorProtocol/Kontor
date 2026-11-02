use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use libsql::Connection;
use tempfile::TempDir;

use super::reopen_execution;
use crate::bitcoin_client::Client;
use crate::database::certified_history::{closure, completion};
use crate::database::connection::new_connection;
use crate::protocol::coordinator::application_closure::WorkItem;
use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol_qualification::snapshot::full_state;
use crate::reactor::PruneConfig;
use crate::reactor::execution::{ExecutionContext, ExecutionStep};
use crate::reactor::executor::RuntimeExecutor;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::LinkedSession;
use crate::stopper::Shutdown;

async fn open(
    path: &Path,
    factory: &SessionFactory,
    service: &OwnerService,
    network: Network,
    context: EraContext,
) -> Result<ExecutionContext<RuntimeExecutor>> {
    let conn = new_connection(path, "callbacks.db").await?;
    let session = LinkedSession::new(conn.clone(), factory(conn).await?);
    let client = Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?;
    Ok(ExecutionContext::new(
        RuntimeExecutor::new(client),
        session,
        network,
        service.clone(),
        context,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        0,
        None,
    ))
}

// Both copies start at the same durable point before the failed parent's verdict.
// They get fresh real executor sessions and never construct a consensus engine.
pub(super) async fn compare(
    source: &ExecutionContext<RuntimeExecutor>,
    factory: &SessionFactory,
    height: u64,
) -> Result<()> {
    let reference_dir = TempDir::new()?;
    let interrupted_dir = TempDir::new()?;
    let frozen = reference_dir.path().join("callbacks.db");
    ensure!(source.session.conn.is_autocommit());
    ensure!(source.owner_service.active_roots().await == 0);
    source
        .session
        .conn
        .execute(
            "VACUUM INTO ?1",
            [frozen.to_str().context("snapshot path is not UTF-8")?],
        )
        .await?;
    fs::copy(&frozen, interrupted_dir.path().join("callbacks.db"))?;
    let mut reference = open(
        reference_dir.path(),
        factory,
        &source.owner_service,
        source.network,
        source.protocol_context,
    )
    .await?;
    ensure!(reference.recover(&Shutdown::new().signal()).await?);
    let expected = full_state(&reference.db_conn()).await?;
    let expected_tip = (reference.last_height, reference.last_hash);
    let expected_closure = completion::completed(&reference.db_conn(), height).await?;
    drop(reference);

    let mut interrupted = open(
        interrupted_dir.path(),
        factory,
        &source.owner_service,
        source.network,
        source.protocol_context,
    )
    .await?;
    let conn = interrupted.db_conn();
    ensure!(full_state(&conn).await? != expected);
    let cancelled = Shutdown::new();
    cancelled.cancel();
    ensure!(!interrupted.recover(&cancelled.signal()).await?);
    let mut pages = 0;
    let mut rollbacks = 0;
    let mut replayed = 0;
    let mut failed_replay = false;
    for _ in 0..64 {
        let before = closure::progress(&conn, height).await?;
        let is_replay = matches!(before.next, Some((WorkItem::Replay { .. }, _)));
        if is_replay && !failed_replay {
            let before_state = full_state(&conn).await?;
            interrupt_stage(&conn).await?;
            ensure!(interrupted.step_certified_closure(height).await.is_err());
            ensure!(interrupted.session.conn.is_autocommit());
            ensure!(source.owner_service.active_roots().await == 0);
            ensure!(full_state(&conn).await? == before_state);
            conn.execute_batch("DROP TRIGGER interrupt_replay_stage")
                .await?;
            interrupted = reopen_execution(interrupted, factory, interrupted_dir.path()).await?;
            ensure!(!interrupted.recover(&cancelled.signal()).await?);
            ensure!(closure::progress(&conn, height).await? == before);
            failed_replay = true;
        }
        let step = interrupted.step_certified_closure(height).await?;
        let reopen = match step {
            ExecutionStep::Planning => {
                pages += 1;
                true
            }
            ExecutionStep::RolledBack(_) => {
                rollbacks += 1;
                true
            }
            ExecutionStep::Batch { .. } if is_replay => {
                replayed += 1;
                true
            }
            ExecutionStep::Complete => break,
            _ => false,
        };
        if reopen {
            let committed = closure::progress(&conn, height).await?;
            interrupted = reopen_execution(interrupted, factory, interrupted_dir.path()).await?;
            ensure!(!interrupted.recover(&cancelled.signal()).await?);
            ensure!(closure::progress(&conn, height).await? == committed);
        }
    }
    ensure!(pages > 1 && rollbacks == 1 && replayed == 2 && failed_replay);
    ensure!(interrupted.recover(&Shutdown::new().signal()).await?);
    ensure!((interrupted.last_height, interrupted.last_hash) == expected_tip);
    ensure!(completion::completed(&conn, height).await? == expected_closure);
    let actual = full_state(&conn).await?;
    if actual != expected {
        let actual = actual
            .as_object()
            .context("recovery snapshot is not an object")?;
        let expected = expected
            .as_object()
            .context("reference snapshot is not an object")?;
        let differing: Vec<_> = expected
            .iter()
            .filter(|(table, rows)| actual.get(*table) != Some(*rows))
            .map(|(table, _)| table.as_str())
            .collect();
        anyhow::bail!("interrupted recovery differs in tables {differing:?}");
    }
    ensure!(source.owner_service.active_roots().await == 0);
    Ok(())
}

async fn interrupt_stage(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE TRIGGER interrupt_replay_stage BEFORE INSERT ON closure_stages BEGIN SELECT RAISE(ABORT, 'injected replay stage failure'); END").await?;
    Ok(())
}
