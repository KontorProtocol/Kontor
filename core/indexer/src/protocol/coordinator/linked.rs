use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use bitcoin::{BlockHash, Network, Txid, hashes::Hash};
use deadpool::managed::{Object, Pool};
#[cfg(kontor_linked)]
use futures_util::FutureExt;
use indexer_types::Block;
#[cfg(test)]
use indexer_types::Transaction;
#[cfg(kontor_linked)]
use kontor_executor_first::{execution_definition as first_definition, factory as first_factory};
#[cfg(all(kontor_linked, kontor_observer))]
use kontor_executor_observer::{
    execution_definition as observer_definition, factory as observer_factory, registration_observer,
};
use libsql::Connection;
#[cfg(kontor_linked)]
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::committee::materialize_committee;
use super::genesis::bind_identity;
use super::selection::{
    ApplicationPosition, ExecutionSelection, ExecutorVersion, select_legacy_p1,
};
use crate::consensus::ValidatorSet;
use crate::database::canonical_history::{self, HistoryState};
use crate::database::queries::{insert_block_execution_usage, insert_transaction_execution_usage};
use crate::database::storage_contract::StorageContract;
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::canonical_codec::CodecError;
use crate::protocol::canonical_input::CanonicalInput;
use crate::protocol::identity::DefinitionReference;
use crate::protocol::identity::{ExecutionDefinitionId, ExecutionIdentity};
#[cfg(any(test, feature = "protocol-qualification"))]
use crate::protocol::operations::{AddressEnvelope, ViewOutcome};
use crate::protocol::operations::{GenesisEnvelope, RecognitionCall, SessionOwner};
use crate::protocol::registration::RegistrationObservation;
#[cfg(kontor_linked)]
use crate::protocol::session::{HostError, HostFuture};
use crate::protocol::session::{SelectionSource, SessionExports};
#[cfg(kontor_linked)]
use crate::protocol::storage_callbacks::StorageCallbacks;
use crate::protocol::v1::definition::REFERENCE;
use crate::protocol::v1::definition::execution_definition;
#[cfg(not(kontor_node))]
use crate::runtime::bundle_session::BundleSession;
use crate::runtime::fuel::ExecutionUsage;
use crate::runtime::ownership::adapter::{
    ExecutorOperations, ExecutorSession, HostFailure, OwnerAdapter, Payload, RootHooks,
    SessionFactory,
};
use crate::runtime::ownership::{LinkedCanonicalRootLease, LinkedOperation, OwnerService};
use crate::runtime::pool::{LinkedManager, LinkedSession, new_linked};
#[cfg(not(kontor_node))]
use crate::runtime::{ComponentCache, Runtime, Storage};

#[cfg(not(kontor_node))]
pub(crate) fn link_runtime(runtime: Runtime, canonical: bool) -> ExecutorSession {
    let origin = runtime.executor_version();
    let network = runtime.network;
    let conn = runtime.storage.conn.clone();
    let (exports, registrations) = BundleSession::export_observer(runtime);
    let mut session = adapt_session(
        origin,
        execution_definition(),
        network,
        conn,
        canonical,
        exports,
    );
    session.operations.registrations = Some(registrations);
    session
}

fn adapt_session(
    origin: ExecutorVersion,
    execution_definition: Result<ExecutionDefinitionId, CodecError>,
    network: Network,
    conn: Connection,
    canonical: bool,
    exports: SessionExports,
) -> ExecutorSession {
    let (operations, owner, roots, recycle) = exports;
    let (
        initialize,
        inspect,
        maintenance,
        recognize,
        transaction,
        begin_unit,
        lifecycle,
        contract_wit,
        view,
        committee,
        migration,
    ) = operations;
    let operations = ExecutorOperations {
        initialize,
        inspect,
        maintenance,
        recognize,
        transaction,
        begin_unit,
        lifecycle,
        contract_wit,
        view,
        committee,
        migration,
        registrations: None,
    };
    let make_root = Arc::new(
        move |selection: ExecutionSelection, adapter: OwnerAdapter| {
            selection
                .ensure_runtime(network, origin)
                .map_err(|error| (0, format!("{error:#}")))?;
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
            let (prepare, inspect_canonical_drain, settle, reset) = roots(
                (
                    adapter.root,
                    adapter.submit_guest,
                    adapter.submit_blocking,
                    adapter.check_commit,
                    adapter.report_failure,
                    adapter.fuel_yield_interval,
                ),
                canonical,
                source,
            );
            Ok(RootHooks {
                prepare,
                inspect_canonical_drain,
                settle,
                reset,
            })
        },
    );
    ExecutorSession {
        execution_definition,
        origin,
        operations,
        owner,
        make_root,
        recycle,
    }
}

#[cfg(not(kontor_linked))]
pub(crate) fn session_factory(
    network: Network,
    view_gas_limit: Option<u64>,
) -> Result<SessionFactory> {
    let storage_contract = StorageContract::resolve(&DefinitionReference::decode(REFERENCE)?)?;
    let engine = Runtime::new_engine()?;
    let linkers = Runtime::new_linkers(&engine)?;
    let cache = ComponentCache::new();
    Ok(Arc::new(move |conn| {
        let engine = engine.clone();
        let linkers = linkers.clone();
        let cache = cache.clone();
        Box::pin(async move {
            let callbacks = storage_contract.callbacks(&conn);
            let storage = Storage::builder()
                .host(callbacks.into())
                .conn(conn)
                .height(if view_gas_limit.is_some() { 1 } else { 0 })
                .build();
            let mut runtime = Runtime::new_with(engine, linkers, cache, storage).await?;
            runtime.network = network;
            if let Some(limit) = view_gas_limit {
                runtime.view_gas_limit = limit;
            }
            Ok(link_runtime(runtime, view_gas_limit.is_none()))
        })
    }))
}

#[cfg(kontor_linked)]
pub(crate) fn session_factory(
    network: Network,
    view_gas_limit: Option<u64>,
) -> Result<SessionFactory> {
    #[cfg(kontor_observer)]
    let reference = observer_definition();
    #[cfg(not(kontor_observer))]
    let reference = first_definition();
    if reference != REFERENCE {
        return Err(anyhow!(
            "linked executor does not match its registered definition"
        ));
    }
    session_factory_for_definition(network, execution_definition()?, view_gas_limit)
}

#[derive(Debug, thiserror::Error)]
#[error("execution definition {0:?} is not linked for production")]
pub(crate) struct UnavailableExecutionDefinition(pub(crate) ExecutionDefinitionId);

pub(crate) fn session_factory_for_definition(
    network: Network,
    definition: ExecutionDefinitionId,
    view_gas_limit: Option<u64>,
) -> Result<SessionFactory> {
    #[cfg(not(kontor_linked))]
    if definition == execution_definition()? {
        return session_factory(network, view_gas_limit);
    }
    #[cfg(kontor_linked)]
    {
        let first_id = DefinitionReference::decode(first_definition())?.id()?;
        #[cfg(kontor_observer)]
        {
            let observer_id = DefinitionReference::decode(observer_definition())?.id()?;
            if first_id == observer_id {
                return Err(anyhow!(
                    "distinct executor factories claim the same definition"
                ));
            }
            if definition == observer_id {
                return Ok(with_registration_observer(retained_session_factory(
                    network,
                    view_gas_limit,
                    observer_factory,
                    observer_definition(),
                )?));
            }
        }
        if definition == first_id {
            return retained_session_factory(
                network,
                view_gas_limit,
                first_factory,
                first_definition(),
            );
        }
    }
    // The historical second graph is qualification-only. Merely linking a
    // library never grants it a production mapping, and unknown IDs never fall
    // back to the node's default executor.
    Err(UnavailableExecutionDefinition(definition).into())
}

#[cfg(all(kontor_linked, kontor_observer))]
pub(crate) fn with_registration_observer(factory: SessionFactory) -> SessionFactory {
    Arc::new(move |conn| {
        let factory = factory.clone();
        Box::pin(async move {
            let mut session = factory(conn).await?;
            let observer = catch_unwind(AssertUnwindSafe(|| {
                registration_observer(session.owner.clone())
            }))
            .map_err(|_| HostFailure::from((1, "registration export panicked".into())))?
            .map_err(HostFailure::from)?;
            session.operations.registrations = Some(observer);
            Ok(session)
        })
    })
}

#[cfg(kontor_linked)]
pub(crate) type RetainedFactory =
    Arc<dyn Fn(StorageCallbacks, [u8; 4], Option<u64>) -> HostFuture<SessionExports> + Send + Sync>;

#[cfg(kontor_linked)]
pub(crate) fn retained_session_factory(
    network: Network,
    view_gas_limit: Option<u64>,
    constructor: fn() -> Result<RetainedFactory, HostError>,
    definition: &[u8],
) -> Result<SessionFactory> {
    let reference = DefinitionReference::decode(definition)?;
    let storage_contract = StorageContract::resolve(&reference)?;
    let definition = reference.id()?;
    let factory = catch_unwind(constructor)
        .map_err(|_| HostFailure::from((1, "executor factory export panicked".into())))?
        .map_err(HostFailure::from)?;
    Ok(Arc::new(move |conn| {
        let factory = factory.clone();
        Box::pin(async move {
            let callbacks = storage_contract.callbacks(&conn);
            // Catch both construction and polling panics at the graph boundary.
            // Neither may be interpreted as a deterministic guest rejection.
            let exports = AssertUnwindSafe(async move {
                factory(callbacks, network.magic().to_bytes(), view_gas_limit).await
            })
            .catch_unwind()
            .await
            .map_err(|_| HostFailure::from((1, "executor session export panicked".into())))?
            .map_err(HostFailure::from)?;
            Ok(adapt_session(
                ExecutorVersion::LegacyP1,
                Ok(definition),
                network,
                conn,
                view_gas_limit.is_none(),
                exports,
            ))
        })
    }))
}

#[cfg(all(kontor_linked, feature = "protocol-qualification"))]
pub(crate) fn retained_session_factory_with_callbacks(
    network: Network,
    view_gas_limit: Option<u64>,
    constructor: fn() -> Result<RetainedFactory, HostError>,
    definition: &[u8],
    decorate: Arc<dyn Fn(StorageCallbacks) -> StorageCallbacks + Send + Sync>,
) -> Result<SessionFactory> {
    let reference = DefinitionReference::decode(definition)?;
    let storage_contract = StorageContract::resolve(&reference)?;
    let definition = reference.id()?;
    let factory = catch_unwind(constructor)
        .map_err(|_| HostFailure::from((1, "executor factory export panicked".into())))?
        .map_err(HostFailure::from)?;
    Ok(Arc::new(move |conn| {
        let factory = factory.clone();
        let decorate = decorate.clone();
        Box::pin(async move {
            let callbacks = decorate(storage_contract.callbacks(&conn));
            // Catch both construction and polling panics at the graph boundary.
            // Neither may be interpreted as a deterministic guest rejection.
            let exports = AssertUnwindSafe(async move {
                factory(callbacks, network.magic().to_bytes(), view_gas_limit).await
            })
            .catch_unwind()
            .await
            .map_err(|_| HostFailure::from((1, "executor session export panicked".into())))?
            .map_err(HostFailure::from)?;
            Ok(adapt_session(
                ExecutorVersion::LegacyP1,
                Ok(definition),
                network,
                conn,
                view_gas_limit.is_none(),
                exports,
            ))
        })
    }))
}

pub(crate) fn read_only_factory(network: Network, view_gas_limit: u64) -> Result<SessionFactory> {
    session_factory(network, Some(view_gas_limit))
}

pub(crate) async fn canonical_session(conn: Connection, network: Network) -> Result<LinkedSession> {
    let factory = session_factory(network, None)?;
    let executor = factory(conn.clone()).await?;
    Ok(LinkedSession::new(conn, executor))
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

#[cfg(any(test, feature = "protocol-qualification"))]
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

pub(crate) async fn begin_canonical_unit(
    service: &OwnerService,
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
    simulation: bool,
) -> Result<LinkedCanonicalRootLease> {
    let capacity = service.reserve_root_capacity().await?;
    let mut lease = service
        .begin_linked_canonical_reserved(session, capacity, selection.clone(), simulation)
        .await?;
    if let Err(error) = begin_unit(session, selection, network).await {
        lease.drain().await?;
        if !session.conn.is_autocommit() {
            lease.settle(false).await?;
        }
        lease.complete().await?;
        return Err(error);
    }
    Ok(lease)
}

pub(crate) async fn finish_canonical_unit<T>(
    mut lease: LinkedCanonicalRootLease,
    result: Result<T>,
    commit: bool,
) -> Result<T> {
    lease.drain().await?;
    lease.settle(commit && result.is_ok()).await?;
    lease.complete().await?;
    result
}

pub(crate) async fn initialize(
    service: &OwnerService,
    session: &LinkedSession,
    network: Network,
    starting_block_height: u64,
    genesis: GenesisEnvelope,
) -> Result<()> {
    bind_identity(&session.conn, network, starting_block_height, &genesis).await?;
    let steps = (session.executor.operations.initialize)(session.executor.owner.clone(), genesis)
        .map_err(HostFailure::from)?;
    for (index, (commit, step)) in steps.into_iter().enumerate() {
        let selection = select_legacy_p1(
            &session.conn,
            network,
            ApplicationPosition::Initialization { step: index as u64 },
        )
        .await?;
        let lease = begin_canonical_unit(service, session, &selection, network, false).await?;
        let result = async {
            let stage = u32::try_from(index)?;
            let history = canonical_history::state(&session.conn).await?;
            let record_stage = commit
                && matches!(history, HistoryState::Ready(_))
                && !canonical_history::genesis_stage_applied(&session.conn, stage).await?;
            step(session.executor.owner.clone(), selection.envelope())
                .await
                .map_err(HostFailure::from)?;
            if record_stage {
                let HistoryState::Ready(cursor) = history else {
                    unreachable!()
                };
                canonical_history::append(
                    &session.conn,
                    &CanonicalApplication {
                        chain: cursor.chain,
                        ordinal: cursor
                            .ordinal
                            .checked_add(1)
                            .ok_or_else(|| anyhow!("genesis application ordinal overflow"))?,
                        parent_lineage: cursor.lineage,
                        execution: ExecutionIdentity::Baseline(
                            session.executor.execution_definition?,
                        ),
                        storage_height: 0,
                        source: ApplicationSource::Genesis { stage },
                        input: None,
                    },
                )
                .await?;
            }
            Ok(())
        }
        .await;
        finish_canonical_unit(lease, result, commit).await?;
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct PreparedTransaction {
    origin: ExecutorVersion,
    network: Network,
    parsed: SessionOwner,
    pub(crate) txid: Txid,
    pub(crate) index: u32,
    pub(crate) batchable: bool,
    pub(crate) inputs: Vec<(u32, u64)>,
}

#[derive(Clone)]
pub(crate) struct TransactionRecognizer {
    origin: ExecutorVersion,
    network: Network,
    recognize: RecognitionCall,
}

impl TransactionRecognizer {
    pub(crate) fn new(
        origin: ExecutorVersion,
        network: Network,
        recognize: RecognitionCall,
    ) -> Self {
        Self {
            origin,
            network,
            recognize,
        }
    }

    pub(crate) fn recognize(
        &self,
        selection: &ExecutionSelection,
        raw: Vec<u8>,
    ) -> Result<Result<Option<PreparedTransaction>, String>> {
        selection.ensure_runtime(self.network, self.origin)?;
        Ok((self.recognize)(selection.envelope(), raw)
            .map_err(HostFailure::from)?
            .map(|recognized| {
                recognized.map(|(parsed, txid, batchable, inputs)| PreparedTransaction {
                    origin: self.origin,
                    network: self.network,
                    parsed,
                    txid: Txid::from_byte_array(txid),
                    index: 0,
                    batchable,
                    inputs,
                })
            }))
    }
}

pub(crate) struct PreparedBlock {
    pub(crate) height: u64,
    pub(crate) hash: BlockHash,
    pub(crate) prev_hash: BlockHash,
    pub(crate) input: Option<CanonicalInput>,
    pub(crate) transactions: Vec<PreparedTransaction>,
}

impl PreparedBlock {
    pub(crate) fn header(&self) -> Block {
        Block {
            height: self.height,
            hash: self.hash,
            prev_hash: self.prev_hash,
            transactions: Vec::new(),
        }
    }
}

impl PreparedTransaction {
    pub(crate) fn payload(
        &self,
        selection: &ExecutionSelection,
        network: Network,
    ) -> Result<SessionOwner> {
        selection.ensure_runtime(network, self.origin)?;
        selection.ensure_runtime(self.network, self.origin)?;
        Ok(self.parsed.clone())
    }

    pub(crate) fn eligible_for(&self, selection: &ExecutionSelection) -> bool {
        self.batchable && selection.ensure_runtime(self.network, self.origin).is_ok()
    }

    #[cfg(test)]
    pub(crate) fn fixture(transaction: Transaction) -> Self {
        let index = transaction.index;
        let origin = ExecutorVersion::LegacyP1;
        let network = Network::Regtest;
        let (parsed, txid, batchable, inputs) =
            Runtime::recognition_fixture(origin.tag(), network.magic().to_bytes(), transaction);
        Self {
            origin,
            network,
            parsed,
            txid: Txid::from_byte_array(txid),
            index,
            batchable,
            inputs,
        }
    }
}

#[cfg(any(test, feature = "protocol-qualification"))]
pub(crate) fn recognize_transaction(
    executor: &ExecutorSession,
    selection: &ExecutionSelection,
    network: Network,
    raw: Vec<u8>,
) -> Result<Result<Option<PreparedTransaction>, String>> {
    TransactionRecognizer::new(
        executor.origin,
        network,
        executor.operations.recognize.clone(),
    )
    .recognize(selection, raw)
}

pub(crate) async fn execute_transaction(
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
    transaction: &PreparedTransaction,
    tx_index: u32,
    tx_id: u64,
) -> Result<Vec<Vec<Option<String>>>> {
    selection.ensure_runtime(network, session.origin())?;
    selection.ensure_execution(network, selection.envelope().3.1)?;
    let ((user_fuel, system_fuel, deposit_fuel), failures) =
        (session.executor.operations.transaction)(
            session.executor.owner.clone(),
            selection.envelope(),
            transaction.payload(selection, network)?,
            tx_index,
            tx_id,
        )
        .await
        .map_err(HostFailure::from)?;
    insert_transaction_execution_usage(
        &session.conn,
        tx_id,
        ExecutionUsage {
            user_fuel,
            system_fuel,
            deposit_fuel,
        },
    )
    .await?;
    Ok(failures)
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

pub(crate) async fn observe_registrations(
    session: &LinkedSession,
    selection: &ExecutionSelection,
    network: Network,
    watched: Vec<String>,
) -> Result<RegistrationObservation> {
    selection
        .verify_committee(&session.conn, network, session.origin())
        .await?;
    let observer = session
        .executor
        .operations
        .registrations
        .as_ref()
        .ok_or_else(|| anyhow!("selected executor does not expose registration observation"))?;
    observer(
        session.executor.owner.clone(),
        selection.envelope(),
        watched,
    )
    .await
    .map_err(HostFailure::from)
    .map_err(Into::into)
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

    #[test]
    fn unavailable_definition_has_no_default_factory_fallback() {
        let definition = ExecutionDefinitionId([0xff; 32]);
        for limit in [None, Some(0)] {
            let result = session_factory_for_definition(Network::Regtest, definition, limit);
            let error = result.err().expect("unknown definition acquired a factory");
            assert_eq!(
                error
                    .downcast_ref::<UnavailableExecutionDefinition>()
                    .unwrap()
                    .0,
                definition
            );
        }
    }

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
    async fn maintenance_requires_selection_and_preserves_rollback_atomicity() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime_with_genesis(&[GenesisValidator {
            x_only_pubkey: random_x_only_pubkey(),
            ed25519_pubkey: PrivateKey::from([7; 32]).public_key().as_bytes().to_vec(),
            stake: Decimal::from("100"),
        }])
        .await?;
        let conn = runtime.storage.conn.clone();
        let before = lifecycle_state(&conn).await?;
        insert_block(
            &conn,
            BlockRow::builder()
                .height(2)
                .hash(new_mock_block_hash(2))
                .build(),
        )
        .await?;
        let with_block = lifecycle_state(&conn).await?;
        assert_ne!(before, with_block);
        let session = LinkedSession::new(conn.clone(), link_runtime(runtime, true));
        let service = OwnerService::new();
        let maintenance = session.executor.operations.maintenance.clone();
        let selection = select_legacy_p1(
            &conn,
            Network::Regtest,
            ApplicationPosition::Maintenance {
                rollback_height: Some(1),
            },
        )
        .await?;
        assert!(
            maintenance(session.executor.owner.clone(), selection.envelope())
                .await
                .is_err()
        );
        for commit in [false, true] {
            let capacity = service.reserve_root_capacity().await?;
            let mut lease = service
                .begin_linked_canonical_reserved(&session, capacity, selection.clone(), false)
                .await?;
            assert!(
                maintenance(session.executor.owner.clone(), selection.envelope())
                    .await
                    .is_err()
            );
            begin_unit(&session, &selection, Network::Regtest).await?;
            let mut changed_target = selection.envelope();
            changed_target.3.1 = 0;
            assert!(
                maintenance(session.executor.owner.clone(), changed_target)
                    .await
                    .is_err()
            );
            let mut changed_purpose = selection.envelope();
            changed_purpose.3 = (1, 0, None, 0);
            assert!(
                maintenance(session.executor.owner.clone(), changed_purpose)
                    .await
                    .is_err()
            );
            assert_eq!(lifecycle_state(&conn).await?, with_block);
            maintenance(session.executor.owner.clone(), selection.envelope())
                .await
                .map_err(HostFailure::from)?;
            assert_eq!(lifecycle_state(&conn).await?, before);
            lease.drain().await?;
            lease.settle(commit).await?;
            lease.complete().await?;
            assert!(conn.is_autocommit());
            assert_eq!(service.active_roots().await, 0);
            assert_eq!(
                lifecycle_state(&conn).await?,
                if commit {
                    before.clone()
                } else {
                    with_block.clone()
                }
            );
        }
        assert!(selection.verify_base(&conn).await.is_err());
        let reconstruct = select_legacy_p1(
            &conn,
            Network::Regtest,
            ApplicationPosition::Maintenance {
                rollback_height: None,
            },
        )
        .await?;
        let capacity = service.reserve_root_capacity().await?;
        let mut lease = service
            .begin_linked_canonical_reserved(&session, capacity, reconstruct.clone(), false)
            .await?;
        begin_unit(&session, &reconstruct, Network::Regtest).await?;
        maintenance(session.executor.owner.clone(), reconstruct.envelope())
            .await
            .map_err(HostFailure::from)?;
        lease.drain().await?;
        lease.settle(true).await?;
        lease.complete().await?;
        assert!(conn.is_autocommit());
        assert_eq!(lifecycle_state(&conn).await?, before);
        assert_eq!(service.active_roots().await, 0);
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
