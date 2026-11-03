use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use libsql::Connection;
use serde_json::{Value as Json, json};
use stdlib::KeyPath;
use tempfile::TempDir;

use super::DATABASE;
use super::fixture::{open, seed, snapshot};
use crate::build_record;
use crate::consensus::Height;
use crate::database::certified_history::{self, activation, closure, completion, eras};
use crate::protocol::coordinator::application_closure::WorkItem;
use crate::protocol::coordinator::migration::{MigrationAttemptWork, MigrationRejected};
use crate::protocol_qualification::snapshot::full_state;
use crate::reactor::consensus_state::certified_startup;
use crate::reactor::execution::{ExecutionContext, ExecutionStep};
use crate::reactor::executor::RuntimeExecutor;
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;

async fn gated(conn: &Connection) -> Result<()> {
    let frontier = certified_history::frontier(conn).await?;
    ensure!(frontier.authenticated_height == 1 && frontier.closed_height == 0);
    ensure!(certified_startup(conn).await.is_err());
    ensure!(certified_history::committee(conn, 2).await.is_err());
    ensure!(eras::at(conn, 1).await?.is_none());
    Ok(())
}

async fn prepare_resume(execution: &mut ExecutionContext<RuntimeExecutor>) -> Result<()> {
    let cancelled = Shutdown::new();
    cancelled.cancel();
    ensure!(!execution.recover(&cancelled.signal()).await?);
    Ok(())
}

// This deliberately invalid input tests migration rejection. It is not a claim
// that P1 can produce the reserved P2 field, or an operator repair procedure.
async fn rejected_input(path: &Path, service: &OwnerService) -> Result<()> {
    let mut execution = open(path, service).await?;
    prepare_resume(&mut execution).await?;
    let conn = execution.db_conn();
    let key = KeyPath::new().push_interned(5);
    conn.execute("INSERT INTO contract_state (contract_id,height,path,value,size,deleted) VALUES (1,1,?1,x'06',1,0)", [key.as_bytes()]).await?;
    let before = full_state(&conn).await?;
    for _ in 0..2 {
        let error = execution
            .step_certified_closure(1)
            .await
            .err()
            .context("invalid migration unexpectedly succeeded")?;
        ensure!(
            error.downcast_ref::<MigrationRejected>() == Some(&MigrationRejected::InvalidOperation),
            "unexpected migration error: {error:#}"
        );
        ensure!(
            error
                .downcast_ref::<MigrationAttemptWork>()
                .is_some_and(|work| work.0.is_some())
        );
        ensure!(full_state(&conn).await? == before);
        ensure!(conn.is_autocommit() && service.active_roots().await == 0);
        gated(&conn).await?;
        drop(execution);
        execution = open(path, service).await?;
        prepare_resume(&mut execution).await?;
    }
    Ok(())
}

pub(crate) async fn run() -> Result<Json> {
    let service = OwnerService::new();
    let result = async {
        let mut result = exercise(&service).await?;
        result["build_record"] = build_record::qualify()?;
        result["finality_replay"] = super::replay::run(&service).await?;
        result["token_count"] = super::token_count::run(&service).await?;
        result["empty_successor"] = super::committee::run(&service).await?;
        result["successor_support"] = Box::pin(super::support::run(&service)).await?;
        result["unsupported_cancel"] = super::unsupported::run(&service).await?;
        result["process_crashes"] = super::crash::run(&service).await?;
        Ok(result)
    }
    .await;
    service.shutdown();
    result
}

async fn exercise(service: &OwnerService) -> Result<Json> {
    let seed_dir = TempDir::new()?;
    let reference_dir = TempDir::new()?;
    let interrupted_dir = TempDir::new()?;
    let rejected_dir = TempDir::new()?;
    let target = seed(seed_dir.path(), service, 1).await?;
    let seeded = open(seed_dir.path(), service).await?;
    snapshot(&seeded.db_conn(), reference_dir.path()).await?;
    fs::copy(
        reference_dir.path().join(DATABASE),
        interrupted_dir.path().join(DATABASE),
    )?;
    drop(seeded);

    let mut reference = open(reference_dir.path(), service).await?;
    ensure!(reference.recover(&Shutdown::new().signal()).await?);
    let expected = full_state(&reference.db_conn()).await?;
    let expected_closure = completion::completed(&reference.db_conn(), 1).await?;
    let expected_activation = activation::current(&reference.db_conn())
        .await?
        .context("reference activation")?;
    ensure!(expected_activation.target()?.id()? == target);
    drop(reference);

    let mut interrupted = open(interrupted_dir.path(), service).await?;
    prepare_resume(&mut interrupted).await?;
    let conn = interrupted.db_conn();
    for _ in 0..16 {
        if matches!(
            closure::progress(&conn, 1).await?.next,
            Some((WorkItem::Activate { .. }, _))
        ) {
            break;
        }
        ensure!(!matches!(
            interrupted.step_certified_closure(1).await?,
            ExecutionStep::Complete
        ));
    }
    ensure!(matches!(
        closure::progress(&conn, 1).await?.next,
        Some((WorkItem::Activate { .. }, _))
    ));
    snapshot(&conn, rejected_dir.path()).await?;
    drop(interrupted);
    interrupted = open(interrupted_dir.path(), service).await?;
    prepare_resume(&mut interrupted).await?;
    let before = full_state(&conn).await?;
    gated(&conn).await?;
    conn.execute_batch("CREATE TRIGGER interrupt_activation BEFORE INSERT ON canonical_protocol_activations BEGIN SELECT RAISE(ABORT, 'injected activation persistence failure'); END").await?;
    let error = interrupted
        .step_certified_closure(1)
        .await
        .err()
        .context("injected persistence failure unexpectedly succeeded")?;
    ensure!(
        format!("{error:#}").contains("injected activation persistence failure"),
        "unexpected failure: {error:#}"
    );
    ensure!(
        full_state(&conn).await? == before,
        "migration leaked persistent writes"
    );
    ensure!(conn.is_autocommit() && service.active_roots().await == 0);
    ensure!(activation::current(&conn).await?.is_none());
    gated(&conn).await?;
    conn.execute_batch("DROP TRIGGER interrupt_activation")
        .await?;
    drop(interrupted);
    interrupted = open(interrupted_dir.path(), service).await?;
    prepare_resume(&mut interrupted).await?;
    ensure!(matches!(
        interrupted.step_certified_closure(1).await?,
        ExecutionStep::Activation
    ));
    ensure!(
        activation::current(&conn)
            .await?
            .context("committed activation")?
            .target()?
            .id()?
            == target
    );
    gated(&conn).await?;
    drop(interrupted);
    interrupted = open(interrupted_dir.path(), service).await?;
    ensure!(interrupted.recover(&Shutdown::new().signal()).await?);
    ensure!(
        full_state(&conn).await? == expected,
        "reopened activation differs from uninterrupted execution"
    );
    ensure!(completion::completed(&conn, 1).await? == expected_closure);
    let (context, height, _) = certified_startup(&conn).await?;
    ensure!(context.protocol == target && height == Height::new(2));
    ensure!(service.active_roots().await == 0);
    drop(interrupted);
    rejected_input(rejected_dir.path(), service).await?;
    Ok(json!({
        "schema": 1, "actual_p2_migration": true,
        "activation_write_failure_atomic": true, "reopened_state_matches": true,
        "invalid_input_rejected_after_reopen": true, "successor_gated_until_closure": true,
        "closed_decisions": 1, "successor_height": 2,
        "scope": "seeded accepted schedule; linked executors; database reopen, killed-process recovery, migration and replay"
    }))
}
