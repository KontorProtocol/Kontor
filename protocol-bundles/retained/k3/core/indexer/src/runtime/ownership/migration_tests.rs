use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Error, Result, anyhow, bail};
use bitcoin::{BlockHash, Network, hashes::Hash};
use futures_util::poll;
use indexer_types::BlockRow;
use libsql::params;
use tempfile::TempDir;
use tokio::time::timeout;

use super::{NODE_ADMISSION_CAPACITY, OwnerService};
use crate::database::canonical_history::{self, ApplicationCursor, HistoryState};
use crate::database::connection::new_connection;
use crate::database::migration_input::MigrationInput;
use crate::database::queries::insert_block;
use crate::protocol::coordinator::linked::{begin_unit, link_runtime, read_only_factory};
use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
use crate::protocol::identity::ChainId;
use crate::protocol::migration_work::MigrationWork;
use crate::protocol::v1::migration::{MigrationContext, MigrationFailure};
use crate::protocol::v1::migration_definition;
use crate::runtime::bundle_session::BundleSession;
use crate::runtime::pool::{LinkedSession, new_linked};
use crate::runtime::{ComponentCache, Runtime, Storage};

#[tokio::test]
async fn migration_root_releases_input_before_writer_settlement_with_one_available_slot()
-> Result<()> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "root.db").await?;
    conn.execute("BEGIN", ()).await?;
    canonical_history::bind_genesis(&conn, ChainId([1; 32])).await?;
    conn.execute("COMMIT", ()).await?;
    let HistoryState::Ready(cursor) = canonical_history::state(&conn).await? else {
        bail!("fixture genesis is absent");
    };
    let hash = BlockHash::from_byte_array([2; 32]);
    insert_block(&conn, BlockRow::builder().height(1).hash(hash).build()).await?;
    let mut runtime = Runtime::new(
        ComponentCache::new(),
        Storage::builder().height(1).conn(conn.clone()).build(),
    )
    .await?;
    runtime.network = Network::Regtest;
    let session = LinkedSession::new(conn.clone(), link_runtime(runtime, true));
    let service = OwnerService::new();
    let views = new_linked(
        dir.path().to_path_buf(),
        "root.db".into(),
        read_only_factory(Network::Regtest, 1_000_000)?,
        1,
    )?;
    let held_view = views.get().await?;
    let mut waiting_view = Box::pin(views.get());
    assert!(poll!(waiting_view.as_mut()).is_pending());
    let mut reserved = Vec::new();
    for _ in 0..NODE_ADMISSION_CAPACITY - 1 {
        reserved.push(service.reserve_root_capacity().await?);
    }
    timeout(Duration::from_secs(5), async {
        for reject_pin in [false, true] {
            let input = MigrationInput::open(&conn).await?;
            let selection = select_legacy_p1(
                &conn,
                Network::Regtest,
                ApplicationPosition::Migration {
                    anchor_height: 1,
                    anchor_hash: hash,
                },
            )
            .await?;
            let capacity = service.reserve_root_capacity().await?;
            let mut lease = service
                .begin_linked_migration_reserved(
                    &session,
                    capacity,
                    selection.clone(),
                    input.clone(),
                )
                .await?;
            begin_unit(&session, &selection, Network::Regtest).await?;
            let mut expected = cursor;
            if reject_pin {
                expected.lineage = [9; 32];
            }
            let result = input.pin(expected, 1, hash).await;
            assert_eq!(result.is_err(), reject_pin);
            if !reject_pin {
                assert!(input.point(1, b"absent").await?.is_none());
            }
            lease.drain().await?;
            assert!(!conn.is_autocommit(), "reader cleanup committed the writer");
            assert!(input.point(1, b"absent").await.is_err());
            lease.settle(!reject_pin).await?;
            lease.complete().await?;
            assert!(conn.is_autocommit());
            assert_eq!(service.active_roots().await, 0);
            assert!(!service.is_fatal());
        }
        Ok::<_, Error>(())
    })
    .await??;
    assert!(poll!(waiting_view.as_mut()).is_pending());
    drop(held_view);
    drop(timeout(Duration::from_secs(5), waiting_view).await??);
    Ok(())
}

async fn context_fixture() -> Result<(
    TempDir,
    LinkedSession,
    OwnerService,
    ApplicationCursor,
    BlockHash,
)> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "context.db").await?;
    conn.execute("BEGIN", ()).await?;
    canonical_history::bind_genesis(&conn, ChainId([1; 32])).await?;
    conn.execute("COMMIT", ()).await?;
    let HistoryState::Ready(cursor) = canonical_history::state(&conn).await? else {
        bail!("fixture genesis is absent");
    };
    let hash = BlockHash::from_byte_array([2; 32]);
    insert_block(&conn, BlockRow::builder().height(1).hash(hash).build()).await?;
    conn.execute("INSERT INTO signers (id, height) VALUES (1, 1), (2, 1)", ())
        .await?;
    for key in [b"b", b"d"] {
        conn.execute(
            "INSERT INTO contract_state (contract_id, height, path, value, size, deleted) VALUES (1, 1, ?1, ?2, 8, 0)",
            params![key.as_slice(), b"original".as_slice()],
        ).await?;
    }
    let mut runtime = Runtime::new(
        ComponentCache::new(),
        Storage::builder().height(1).conn(conn.clone()).build(),
    )
    .await?;
    runtime.network = Network::Regtest;
    Ok((
        dir,
        LinkedSession::new(conn, link_runtime(runtime, true)),
        OwnerService::new(),
        cursor,
        hash,
    ))
}

#[tokio::test]
async fn migration_context_preserves_input_and_charges_rolled_back_duplicate_and_deleted_writes()
-> Result<()> {
    let (_dir, session, service, cursor, hash) = context_fixture().await?;
    let input = MigrationInput::open(&session.conn).await?;
    let selection = select_legacy_p1(
        &session.conn,
        Network::Regtest,
        ApplicationPosition::Migration {
            anchor_height: 1,
            anchor_hash: hash,
        },
    )
    .await?;
    let mut lease = service
        .begin_linked_migration_reserved(
            &session,
            service.reserve_root_capacity().await?,
            selection.clone(),
            input.clone(),
        )
        .await?;
    begin_unit(&session, &selection, Network::Regtest).await?;
    input.pin(cursor, 1, hash).await?;
    let exported = session
        .executor
        .owner
        .clone()
        .downcast::<BundleSession>()
        .map_err(|_| anyhow!("wrong fixture executor"))?;
    let runtime = exported.test_runtime().await;
    let budget = MigrationWork {
        computation_steps: 6,
        read_operations: 12,
        read_bytes: 38,
        write_operations: 7,
        write_bytes: 34,
    };
    let mut context = MigrationContext::new(
        &runtime.storage,
        input.callbacks(),
        budget,
        runtime.storage.bundle_owner.clone().unwrap(),
    )
    .await?;
    context.set(1, b"b", b"new", (None, None)).await?;
    context.set(1, b"a", b"before", (None, None)).await?;
    context.set(1, b"z", b"after", (None, None)).await?;
    context.delete(1, b"d").await?;
    context.begin_nested().await?;
    context.set(1, b"b", b"temp", (None, None)).await?;
    context.finish_nested(false).await?;
    assert_eq!(context.current_value(1, b"b").await?, Some(b"new".to_vec()));
    context.set(1, b"b", b"new", (None, None)).await?;
    context.delete(1, b"missing").await?;
    let first = context.input_next(1, None).await?.unwrap();
    assert_eq!(context.input_key(&first).await?, b"b");
    assert_eq!(context.input_value(&first).await?, b"original");
    assert_eq!(first.deposit(), (None, None));
    let second = context.input_next(1, Some(b"b")).await?.unwrap();
    assert_eq!(context.input_key(&second).await?, b"d");
    assert_eq!(context.input_value(&second).await?, b"original");
    assert!(context.input_next(1, Some(b"d")).await?.is_none());
    assert!(context.input_point(1, b"a").await?.is_none());
    assert_eq!(context.finish()?, budget);
    drop(runtime);
    lease.drain().await?;
    lease.settle(true).await?;
    lease.complete().await?;
    assert!(session.conn.is_autocommit());
    Ok(())
}

#[tokio::test]
async fn migration_budget_failure_is_sticky_and_outer_rollback_restores_input() -> Result<()> {
    let (_dir, session, service, cursor, hash) = context_fixture().await?;
    let input = MigrationInput::open(&session.conn).await?;
    let selection = select_legacy_p1(
        &session.conn,
        Network::Regtest,
        ApplicationPosition::Migration {
            anchor_height: 1,
            anchor_hash: hash,
        },
    )
    .await?;
    let mut lease = service
        .begin_linked_migration_reserved(
            &session,
            service.reserve_root_capacity().await?,
            selection.clone(),
            input.clone(),
        )
        .await?;
    begin_unit(&session, &selection, Network::Regtest).await?;
    input.pin(cursor, 1, hash).await?;
    let exported = session
        .executor
        .owner
        .clone()
        .downcast::<BundleSession>()
        .map_err(|_| anyhow!("wrong fixture executor"))?;
    let runtime = exported.test_runtime().await;
    let mut context = MigrationContext::new(
        &runtime.storage,
        input.callbacks(),
        MigrationWork {
            computation_steps: 2,
            read_operations: 1,
            read_bytes: 1,
            write_operations: 1,
            write_bytes: 8,
        },
        runtime.storage.bundle_owner.clone().unwrap(),
    )
    .await?;
    context.begin_nested().await?;
    context.set(1, b"b", b"changed", (None, None)).await?;
    context.finish_nested(false).await?;
    assert_eq!(context.delete(1, b"d").await, Err(MigrationFailure::Budget));
    assert_eq!(context.step(0), Err(MigrationFailure::Budget));
    assert_eq!(context.finish(), Err(MigrationFailure::Budget));
    drop(runtime);
    lease.drain().await?;
    lease.settle(false).await?;
    lease.complete().await?;
    let value: Vec<u8> = session
        .conn
        .query(
            "SELECT value FROM contract_state WHERE path = ?1",
            [b"d".as_slice()],
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert_eq!(value, b"original");
    assert_eq!(
        canonical_history::state(&session.conn).await?,
        HistoryState::Ready(cursor)
    );
    Ok(())
}

#[tokio::test]
async fn retained_migration_operation_requires_exact_definition() -> Result<()> {
    let (_dir, session, service, cursor, hash) = context_fixture().await?;
    let input = MigrationInput::open(&session.conn).await?;
    let selection = select_legacy_p1(
        &session.conn,
        Network::Regtest,
        ApplicationPosition::Migration {
            anchor_height: 1,
            anchor_hash: hash,
        },
    )
    .await?;
    let mut lease = service
        .begin_linked_migration_reserved(
            &session,
            service.reserve_root_capacity().await?,
            selection.clone(),
            input.clone(),
        )
        .await?;
    begin_unit(&session, &selection, Network::Regtest).await?;
    input.pin(cursor, 1, hash).await?;
    let definition = migration_definition::noop(session.executor.execution_definition?);
    let selection = selection.envelope();
    let call = &session.executor.operations.migration;
    assert_eq!(
        call(
            session.executor.owner.clone(),
            selection.clone(),
            definition.encode()?,
            input.callbacks()
        )
        .await
        .map_err(|(_, message)| anyhow!(message))?,
        Ok([0; 5])
    );
    let mut changed = definition;
    changed.budget.write_operations = 1;
    assert_eq!(
        call(
            session.executor.owner.clone(),
            selection,
            changed.encode()?,
            input.callbacks()
        )
        .await
        .map_err(|(_, message)| anyhow!(message))?,
        Err(0)
    );
    lease.drain().await?;
    lease.settle(false).await?;
    lease.complete().await?;
    Ok(())
}

#[tokio::test]
async fn migration_updates_depositor_footprints_with_nested_and_outer_rollback() -> Result<()> {
    let (_dir, session, service, cursor, hash) = context_fixture().await?;
    let input = MigrationInput::open(&session.conn).await?;
    let selection = select_legacy_p1(
        &session.conn,
        Network::Regtest,
        ApplicationPosition::Migration {
            anchor_height: 1,
            anchor_hash: hash,
        },
    )
    .await?;
    let mut lease = service
        .begin_linked_migration_reserved(
            &session,
            service.reserve_root_capacity().await?,
            selection.clone(),
            input.clone(),
        )
        .await?;
    begin_unit(&session, &selection, Network::Regtest).await?;
    input.pin(cursor, 1, hash).await?;
    let exported = session
        .executor
        .owner
        .clone()
        .downcast::<BundleSession>()
        .map_err(|_| anyhow!("wrong fixture executor"))?;
    let runtime = exported.test_runtime().await;
    let mut context = MigrationContext::new(
        &runtime.storage,
        input.callbacks(),
        MigrationWork {
            computation_steps: 2,
            read_operations: 7,
            read_bytes: 67,
            write_operations: 7,
            write_bytes: 73,
        },
        runtime.storage.bundle_owner.clone().unwrap(),
    )
    .await?;
    context.set(1, b"b", b"new", (Some(1), Some(10))).await?;
    assert_eq!(runtime.storage.footprint().total_gas(1).await?, 10);
    context.begin_nested().await?;
    context.set(1, b"b", b"new", (Some(2), Some(20))).await?;
    assert_eq!(runtime.storage.footprint().total_gas(1).await?, 0);
    assert_eq!(runtime.storage.footprint().total_gas(2).await?, 20);
    context.finish_nested(false).await?;
    assert_eq!(runtime.storage.footprint().total_gas(1).await?, 10);
    assert_eq!(runtime.storage.footprint().total_gas(2).await?, 0);
    context.delete(1, b"b").await?;
    assert_eq!(runtime.storage.footprint().total_gas(1).await?, 0);
    let work = context.finish()?;
    assert_eq!((work.write_operations, work.write_bytes), (7, 73));
    drop(runtime);
    lease.drain().await?;
    lease.settle(false).await?;
    lease.complete().await?;
    let value: Vec<u8> = session
        .conn
        .query(
            "SELECT value FROM contract_state WHERE path = ?1",
            [b"b".as_slice()],
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert_eq!(value, b"original");
    Ok(())
}

#[tokio::test]
async fn migration_rejects_large_value_before_issuing_byte_read() -> Result<()> {
    let (_dir, session, service, cursor, hash) = context_fixture().await?;
    let input = MigrationInput::open(&session.conn).await?;
    let selection = select_legacy_p1(
        &session.conn,
        Network::Regtest,
        ApplicationPosition::Migration {
            anchor_height: 1,
            anchor_hash: hash,
        },
    )
    .await?;
    let mut lease = service
        .begin_linked_migration_reserved(
            &session,
            service.reserve_root_capacity().await?,
            selection.clone(),
            input.clone(),
        )
        .await?;
    begin_unit(&session, &selection, Network::Regtest).await?;
    input.pin(cursor, 1, hash).await?;
    let exported = session
        .executor
        .owner
        .clone()
        .downcast::<BundleSession>()
        .map_err(|_| anyhow!("wrong fixture executor"))?;
    let runtime = exported.test_runtime().await;
    let mut callbacks = input.callbacks();
    let called = Arc::new(AtomicBool::new(false));
    let observed = called.clone();
    callbacks.2 = Arc::new(move |_, _, _, _| {
        observed.store(true, Ordering::SeqCst);
        Box::pin(async { Err("unexpected byte read".into()) })
    });
    let mut context = MigrationContext::new(
        &runtime.storage,
        callbacks,
        MigrationWork {
            computation_steps: 10,
            read_operations: 1,
            read_bytes: 8,
            ..MigrationWork::default()
        },
        runtime.storage.bundle_owner.clone().unwrap(),
    )
    .await?;
    let row = context.input_point(1, b"b").await?.unwrap();
    assert_eq!(
        context.input_value(&row).await,
        Err(MigrationFailure::Budget)
    );
    assert!(!called.load(Ordering::SeqCst));
    assert_eq!(context.finish(), Err(MigrationFailure::Budget));
    drop(runtime);
    lease.drain().await?;
    lease.settle(false).await?;
    lease.complete().await?;
    Ok(())
}

#[tokio::test]
async fn migration_footprint_overflow_fails_before_row_write() -> Result<()> {
    let (_dir, session, service, cursor, hash) = context_fixture().await?;
    session
        .conn
        .execute(
            "UPDATE contract_state SET depositor = 1, deposited_gas = ?1 WHERE path = ?2",
            params![i64::MAX, b"b".as_slice()],
        )
        .await?;
    session
        .conn
        .execute(
            "INSERT INTO depositor_footprint (depositor, total_gas) VALUES (1, ?1)",
            [i64::MAX],
        )
        .await?;
    let input = MigrationInput::open(&session.conn).await?;
    let selection = select_legacy_p1(
        &session.conn,
        Network::Regtest,
        ApplicationPosition::Migration {
            anchor_height: 1,
            anchor_hash: hash,
        },
    )
    .await?;
    let mut lease = service
        .begin_linked_migration_reserved(
            &session,
            service.reserve_root_capacity().await?,
            selection.clone(),
            input.clone(),
        )
        .await?;
    begin_unit(&session, &selection, Network::Regtest).await?;
    input.pin(cursor, 1, hash).await?;
    let exported = session
        .executor
        .owner
        .clone()
        .downcast::<BundleSession>()
        .map_err(|_| anyhow!("wrong fixture executor"))?;
    let runtime = exported.test_runtime().await;
    let mut context = MigrationContext::new(
        &runtime.storage,
        input.callbacks(),
        MigrationWork {
            computation_steps: 0,
            read_operations: 2,
            read_bytes: 17,
            write_operations: 2,
            write_bytes: 18,
        },
        runtime.storage.bundle_owner.clone().unwrap(),
    )
    .await?;
    let result = context.set(1, b"c", b"x", (Some(1), Some(1))).await;
    assert!(matches!(result, Err(MigrationFailure::InvalidOperation(_))));
    assert!(context.finish().is_err());
    assert_eq!(
        runtime.storage.footprint().total_gas(1).await?,
        i64::MAX as u64
    );
    assert!(runtime.storage.get(100, 1, b"c").await?.is_none());
    drop(runtime);
    lease.drain().await?;
    lease.settle(false).await?;
    lease.complete().await?;
    Ok(())
}
