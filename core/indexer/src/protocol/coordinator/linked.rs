use std::sync::Arc;

use anyhow::{Result, anyhow};
use bitcoin::Network;
use deadpool::managed::Object;

use super::committee::materialize_committee;
use super::selection::{ApplicationPosition, ExecutionSelection, select_legacy_p1};
use crate::consensus::ValidatorSet;
use crate::database::storage_callbacks_v1::storage_callbacks;
use crate::protocol::operations::{AddressEnvelope, ViewOutcome};
use crate::runtime::bundle_session::BundleSession;
use crate::runtime::ownership::adapter::{
    ExecutorOperations, ExecutorSession, HostFailure, OwnerAdapter, Payload, RootHooks,
    SessionFactory,
};
use crate::runtime::ownership::{LinkedOperation, OwnerService};
use crate::runtime::pool::{LinkedManager, LinkedSession};
use crate::runtime::{BundleOwner, ComponentCache, Runtime, Storage};

pub(crate) fn link_runtime(runtime: Runtime, canonical: bool) -> ExecutorSession {
    let origin = runtime.executor_version();
    let network = runtime.network;
    let session = BundleSession::new(runtime);
    let operations = ExecutorOperations {
        begin_unit: session.begin_unit(),
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
            let (prepare, inspect_canonical_drain, settle, reset) =
                retained.root_hooks(owner, canonical, selection.envelope());
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

pub(crate) async fn execute_view(
    service: &OwnerService,
    object: Object<LinkedManager>,
    network: Network,
    address: AddressEnvelope,
    expression: String,
) -> Result<ViewOutcome> {
    let capacity = service.reserve_root_capacity().await?;
    let selection = select_legacy_p1(&object.conn, network, ApplicationPosition::View).await?;
    let conn = object.conn.clone();
    let origin = object.origin();
    let view = object.executor.operations.view.clone();
    let selected = selection.clone();
    let operation: LinkedOperation = Box::new(move |owner, _| {
        Box::pin(async move {
            // Preparation has opened the owned read transaction. A selection
            // made before admission must still describe that pinned snapshot.
            selected
                .verify_view(&conn, network, origin)
                .await
                .map_err(|error| (0, format!("{error:#}")))?;
            let outcome = view(owner, selected.envelope(), address, expression).await?;
            Ok((Box::new(outcome) as Payload, false))
        })
    });
    let mut handle = service
        .start_linked_pooled_reserved(object, capacity, selection, operation)
        .await?;
    handle
        .result()
        .await?
        .downcast::<ViewOutcome>()
        .map(|outcome| *outcome)
        .map_err(|_| anyhow!("node view operation returned the wrong payload type"))
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
    use crate::reg_tester::random_x_only_pubkey;
    use crate::runtime::pool::new_linked;
    use crate::runtime::staking::address as staking_address;
    use crate::runtime::{Decimal, GenesisValidator};
    use crate::test_utils::test_runtime_with_genesis;

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
        let factory = read_only_factory(Network::Regtest, DEFAULT_VIEW_GAS_LIMIT)?;
        let pool = new_linked(dir.path().to_path_buf(), name, factory, 1)?;
        let service = OwnerService::new();
        assert_eq!(
            execute_view(
                &service,
                pool.get().await?,
                Network::Regtest,
                address.clone(),
                "get-active-set()".into()
            )
            .await?,
            Ok(expected)
        );
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
