use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use bitcoin::Network;
use deadpool::managed::{Object, Pool};
use indexer_types::Block;
use libsql::Connection;

use super::committee::materialize_committee;
use super::selection::{ApplicationPosition, ExecutionSelection, select_legacy_p1};
use crate::consensus::ValidatorSet;
use crate::database::queries::insert_block_execution_usage;
use crate::database::storage_callbacks_v1::storage_callbacks;
use crate::protocol::operations::{AddressEnvelope, ViewOutcome};
use crate::runtime::bundle_session::BundleSession;
use crate::runtime::fuel::ExecutionUsage;
use crate::runtime::ownership::adapter::{
    ExecutorOperations, ExecutorSession, HostFailure, OwnerAdapter, Payload, RootHooks,
    SessionFactory,
};
use crate::runtime::ownership::{LinkedOperation, OwnerService};
use crate::runtime::pool::{LinkedManager, LinkedSession, new_linked};
use crate::runtime::{BundleOwner, ComponentCache, Runtime, SelectionSource, Storage};

pub(crate) fn link_runtime(runtime: Runtime, canonical: bool) -> ExecutorSession {
    let origin = runtime.executor_version();
    let network = runtime.network;
    let conn = runtime.storage.conn.clone();
    let session = BundleSession::new(runtime);
    let operations = ExecutorOperations {
        begin_unit: session.begin_unit(),
        lifecycle: session.lifecycle(),
        contract_wit: session.contract_wit(),
        view: session.view(),
        committee: session.committee(),
    };
    let retained = session.clone();
    let make_root = Arc::new(
        move |selection: ExecutionSelection, adapter: OwnerAdapter| {
            selection
                .ensure_runtime(network, origin)
                .map_err(|error| (0, format!("{error:#}")))?;
            let owner = BundleOwner::new(
                adapter.root,
                adapter.submit_guest,
                adapter.submit_blocking,
                adapter.check_commit,
                adapter.report_failure,
                adapter.fuel_yield_interval,
            );
            let source: SelectionSource = if !canonical && selection.is_public_view() {
                let conn = conn.clone();
                Arc::new(move || {
                    let conn = conn.clone();
                    Box::pin(async move {
                        let selection = select_legacy_p1(&conn, network, ApplicationPosition::View)
                            .await
                            .map_err(|error| (0, format!("{error:#}")))?;
                        selection
                            .ensure_runtime(network, origin)
                            .map_err(|error| (0, format!("{error:#}")))?;
                        Ok(selection.envelope())
                    })
                })
            } else {
                let selection = selection.envelope();
                Arc::new(move || {
                    let selection = selection.clone();
                    Box::pin(async move { Ok(selection) })
                })
            };
            let (prepare, inspect_canonical_drain, settle, reset) =
                retained.root_hooks(owner, canonical, source);
            Ok(RootHooks {
                prepare,
                inspect_canonical_drain,
                settle,
                reset,
            })
        },
    );
    ExecutorSession {
        origin,
        operations,
        owner: session.clone(),
        make_root,
        recycle: session.recycle(),
    }
}

pub(crate) fn read_only_factory(network: Network, view_gas_limit: u64) -> Result<SessionFactory> {
    let engine = Runtime::new_engine()?;
    let linkers = Runtime::new_linkers(&engine)?;
    let cache = ComponentCache::new();
    Ok(Arc::new(move |conn| {
        let engine = engine.clone();
        let linkers = linkers.clone();
        let cache = cache.clone();
        Box::pin(async move {
            let callbacks = storage_callbacks(&conn);
            let storage = Storage::builder().host(callbacks.into()).conn(conn).build();
            let mut runtime = Runtime::new_with(engine, linkers, cache, storage).await?;
            runtime.network = network;
            runtime.view_gas_limit = view_gas_limit;
            Ok(link_runtime(runtime, false))
        })
    }))
}

pub(crate) fn new_read_pool(
    data_dir: PathBuf,
    filename: String,
    network: Network,
    view_gas_limit: u64,
) -> Result<Pool<LinkedManager>> {
    new_linked(
        data_dir,
        filename,
        read_only_factory(network, view_gas_limit)?,
        std::thread::available_parallelism()?.into(),
    )
}

// The closure and its result stay in the node graph. Only the typed operations
// inside ExecutorSession cross into the retained implementation.
pub(crate) async fn read_snapshot<T, F, Fut>(
    service: &OwnerService,
    object: Object<LinkedManager>,
    network: Network,
    read: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Connection, ExecutorSession, ExecutionSelection) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T>> + Send + 'static,
{
    let capacity = service.reserve_root_capacity().await?;
    let selection = select_legacy_p1(&object.conn, network, ApplicationPosition::View).await?;
    let conn = object.conn.clone();
    let executor = object.executor.clone();
    let operation: LinkedOperation = Box::new(move |_, _| {
        Box::pin(async move {
            // Root preparation pins its selection after opening this snapshot,
            // so a writer advancing while admission waits cannot mix contexts.
            let selected = select_legacy_p1(&conn, network, ApplicationPosition::View)
                .await
                .map_err(|error| (0, format!("{error:#}")))?;
            selected
                .verify_view(&conn, network, executor.origin)
                .await
                .map_err(|error| (0, format!("{error:#}")))?;
            let result = read(conn, executor, selected).await;
            // Preserve node-local error types (including HTTP status errors).
            // These read-only jobs always roll back regardless of their result.
            Ok((Box::new(result) as Payload, false))
        })
    });
    let mut handle = service
        .start_linked_pooled_reserved(object, capacity, selection, operation)
        .await?;
    *handle
        .result()
        .await?
        .downcast::<Result<T>>()
        .map_err(|_| anyhow!("node read operation returned the wrong payload type"))?
}

pub(crate) async fn execute_view(
    service: &OwnerService,
    object: Object<LinkedManager>,
    network: Network,
    address: AddressEnvelope,
    expression: String,
) -> Result<ViewOutcome> {
    read_snapshot(
        service,
        object,
        network,
        move |_, executor, selection| async move {
            (executor.operations.view)(executor.owner, selection.envelope(), address, expression)
                .await
                .map_err(HostFailure::from)
                .map_err(Into::into)
        },
    )
    .await
}

pub(crate) async fn begin_unit(
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
) -> Result<()> {
    selection.ensure_runtime(network, session.origin())?;
    (session.executor.operations.begin_unit)(session.executor.owner.clone(), selection.envelope())
        .await
        .map_err(HostFailure::from)?;
    selection.verify_base(&session.conn).await
}

pub(crate) async fn run_block_lifecycle(
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
    block: &Block,
) -> Result<()> {
    selection.ensure_runtime(network, session.origin())?;
    selection.ensure_execution(network, block.height)?;
    selection.ensure_block(block.height, block.hash)?;
    let (user_fuel, system_fuel, deposit_fuel) = (session.executor.operations.lifecycle)(
        session.executor.owner.clone(),
        selection.envelope(),
    )
    .await
    .map_err(HostFailure::from)?;
    insert_block_execution_usage(
        &session.conn,
        block.height,
        ExecutionUsage {
            user_fuel,
            system_fuel,
            deposit_fuel,
        },
    )
    .await
}

pub(crate) async fn derive_committee(
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
) -> Result<ValidatorSet> {
    selection
        .verify_committee(&session.conn, network, session.origin())
        .await?;
    let members = (session.executor.operations.committee)(
        session.executor.owner.clone(),
        selection.envelope(),
    )
    .await
    .map_err(HostFailure::from)?;
    materialize_committee(members)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_VIEW_GAS_LIMIT;
    use crate::consensus::{Validator, signing::PrivateKey};
    use crate::database::queries::insert_block;
    use crate::reactor::executor::{Executor, NoopExecutor};
    use crate::reg_tester::random_x_only_pubkey;
    use crate::runtime::pool::new_linked;
    use crate::runtime::staking::address as staking_address;
    use crate::runtime::{Decimal, GenesisValidator};
    use crate::test_utils::{new_mock_block_hash, test_runtime_with_genesis};
    use indexer_types::BlockRow;
    use libsql::Value;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::sync::Notify;
    use tokio::time::timeout;

    async fn lifecycle_state(conn: &Connection) -> Result<Vec<Vec<Vec<Value>>>> {
        let mut state = Vec::new();
        for table in [
            "blocks",
            "contract_state",
            "contract_results",
            "depositor_footprint",
            "block_execution_usage",
            "signers",
        ] {
            let mut rows = conn
                .query(&format!("SELECT * FROM {table} ORDER BY rowid"), ())
                .await?;
            let mut values = Vec::new();
            while let Some(row) = rows.next().await? {
                values.push(
                    (0..rows.column_count())
                        .map(|i| row.get_value(i))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            state.push(values);
        }
        Ok(state)
    }

    #[tokio::test]
    async fn linked_lifecycle_preserves_state_usage_and_atomic_settlement() -> Result<()> {
        let key = PrivateKey::from([7; 32]).public_key();
        let (mut runtime, _dir, _name) = test_runtime_with_genesis(&[GenesisValidator {
            x_only_pubkey: random_x_only_pubkey(),
            ed25519_pubkey: key.as_bytes().to_vec(),
            stake: Decimal::from("100"),
        }])
        .await?;
        let block = Block {
            height: 2,
            hash: new_mock_block_hash(2),
            prev_hash: new_mock_block_hash(1),
            transactions: Vec::new(),
        };
        let conn = runtime.storage.conn.clone();
        let selection = select_legacy_p1(
            &conn,
            Network::Regtest,
            ApplicationPosition::Block {
                height: block.height,
                hash: block.hash,
                consensus_height: 2,
            },
        )
        .await?;
        let before = lifecycle_state(&conn).await?;
        runtime.storage.savepoint().await?;
        insert_block(
            &conn,
            BlockRow::builder()
                .height(block.height)
                .hash(block.hash)
                .build(),
        )
        .await?;
        let previous = runtime.start_usage();
        NoopExecutor
            .run_block_lifecycle(&selection, &mut runtime, &block)
            .await?;
        let usage = runtime.finish_usage(previous)?;
        assert!(usage.system_fuel > 0);
        insert_block_execution_usage(&conn, block.height, usage).await?;
        let expected = lifecycle_state(&conn).await?;
        assert_ne!(before, expected);
        runtime.storage.rollback().await?;
        assert_eq!(lifecycle_state(&conn).await?, before);

        let session = LinkedSession::new(conn.clone(), link_runtime(runtime, true));
        let service = OwnerService::new();
        assert!(
            run_block_lifecycle(&session, &selection, Network::Regtest, &block)
                .await
                .is_err()
        );
        for commit in [false, true] {
            let capacity = service.reserve_root_capacity().await?;
            let mut lease = service
                .begin_linked_canonical_reserved(&session, capacity, selection.clone(), false)
                .await?;
            assert!(
                run_block_lifecycle(&session, &selection, Network::Regtest, &block)
                    .await
                    .is_err()
            );
            begin_unit(&session, &selection, Network::Regtest).await?;
            insert_block(
                &conn,
                BlockRow::builder()
                    .height(block.height)
                    .hash(block.hash)
                    .build(),
            )
            .await?;
            let unchanged = lifecycle_state(&conn).await?;
            let mut wrong_block = block.clone();
            wrong_block.hash = new_mock_block_hash(3);
            assert!(
                run_block_lifecycle(&session, &selection, Network::Regtest, &wrong_block)
                    .await
                    .is_err()
            );
            let mut wrong_selection = selection.envelope();
            wrong_selection.3.0 = 4;
            assert!(
                (session.executor.operations.lifecycle)(
                    session.executor.owner.clone(),
                    wrong_selection
                )
                .await
                .is_err()
            );
            assert_eq!(lifecycle_state(&conn).await?, unchanged);
            run_block_lifecycle(&session, &selection, Network::Regtest, &block).await?;
            assert_eq!(lifecycle_state(&conn).await?, expected);
            lease.drain().await?;
            lease.settle(commit).await?;
            lease.complete().await?;
            assert!(conn.is_autocommit());
            assert_eq!(
                lifecycle_state(&conn).await?,
                if commit {
                    expected.clone()
                } else {
                    before.clone()
                }
            );
            assert!(
                run_block_lifecycle(&session, &selection, Network::Regtest, &block)
                    .await
                    .is_err()
            );
            assert_eq!(service.active_roots().await, 0);
        }
        Ok(())
    }

    #[tokio::test]
    async fn node_pool_routes_real_views_and_releases_read_snapshot() -> Result<()> {
        let key = PrivateKey::from([7; 32]).public_key();
        let (mut runtime, dir, name) = test_runtime_with_genesis(&[GenesisValidator {
            x_only_pubkey: random_x_only_pubkey(),
            ed25519_pubkey: key.as_bytes().to_vec(),
            stake: Decimal::from("100.9999999"),
        }])
        .await?;
        let address = staking_address();
        let expected = runtime
            .execute(None, None, &address, "get-active-set()")
            .await?;
        let error = runtime
            .execute(None, None, &address, "missing-function()")
            .await
            .unwrap_err();
        let address = (address.name, address.height, address.tx_index);
        let original = read_only_factory(Network::Regtest, DEFAULT_VIEW_GAS_LIMIT)?;
        let entered = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let first = Arc::new(AtomicBool::new(true));
        let gate_entered = entered.clone();
        let gate_resume = resume.clone();
        let factory: SessionFactory = Arc::new(move |conn| {
            let original = original.clone();
            let entered = gate_entered.clone();
            let resume = gate_resume.clone();
            let first = first.clone();
            Box::pin(async move {
                let mut executor = original(conn).await?;
                let make_root = executor.make_root.clone();
                executor.make_root = Arc::new(move |selection, adapter| {
                    let mut hooks = make_root(selection, adapter)?;
                    let prepare = hooks.prepare;
                    let entered = entered.clone();
                    let resume = resume.clone();
                    let first = first.clone();
                    hooks.prepare = Arc::new(move |owner| {
                        let prepare = prepare.clone();
                        let entered = entered.clone();
                        let resume = resume.clone();
                        let first = first.clone();
                        Box::pin(async move {
                            if first.swap(false, Ordering::SeqCst) {
                                entered.notify_one();
                                resume.notified().await;
                            }
                            prepare(owner).await
                        })
                    });
                    Ok(hooks)
                });
                Ok(executor)
            })
        });
        let pool = new_linked(dir.path().to_path_buf(), name, factory, 1)?;
        let service = OwnerService::new();
        let waiting_service = service.clone();
        let object = pool.get().await?;
        let request_address = address.clone();
        let waiting_view = tokio::spawn(async move {
            execute_view(
                &waiting_service,
                object,
                Network::Regtest,
                request_address,
                "get-active-set()".into(),
            )
            .await
        });
        timeout(Duration::from_secs(5), entered.notified()).await?;
        insert_block(
            &runtime.storage.conn,
            BlockRow::builder()
                .height(2)
                .hash(new_mock_block_hash(2))
                .build(),
        )
        .await?;
        resume.notify_one();
        assert_eq!(waiting_view.await??, Ok(expected));
        assert_eq!(
            execute_view(
                &service,
                pool.get().await?,
                Network::Regtest,
                address,
                "missing-function()".into()
            )
            .await?,
            Err((true, format!("{error:?}")))
        );
        let object = pool.get().await?;
        assert!(object.conn.is_autocommit());
        assert!(
            object
                .conn
                .execute("CREATE TABLE forbidden (id INTEGER)", ())
                .await
                .is_err()
        );
        assert_eq!(service.active_roots().await, 0);

        let conn = runtime.storage.conn.clone();
        let session = LinkedSession::new(conn, link_runtime(runtime, true));
        let selection = select_legacy_p1(
            &session.conn,
            Network::Regtest,
            ApplicationPosition::Committee,
        )
        .await?;
        assert!(
            derive_committee(&session, &selection, Network::Regtest)
                .await
                .is_err()
        );
        let capacity = service.reserve_root_capacity().await?;
        let mut lease = service
            .begin_linked_canonical_reserved(&session, capacity, selection.clone(), false)
            .await?;
        begin_unit(&session, &selection, Network::Regtest).await?;
        assert!(
            begin_unit(&session, &selection, Network::Regtest)
                .await
                .is_err()
        );
        let committee = derive_committee(&session, &selection, Network::Regtest).await?;
        assert_eq!(committee.validators.as_ref(), &[Validator::new(key, 100)]);
        lease.drain().await?;
        lease.settle(false).await?;
        lease.complete().await?;
        assert!(session.conn.is_autocommit());
        Ok(())
    }
}
