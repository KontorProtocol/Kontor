use super::super::bundle_session::BundleSession;
use super::super::pool::new_linked;
use super::adapter::{ExecutorSession, RootHooks, SessionAction, SessionFactory};
use super::*;
use crate::consensus::signing::PrivateKey;
use crate::database::connection::new_connection;
use crate::protocol::coordinator::linked::link_runtime;
use crate::protocol::coordinator::selection::{
    ApplicationPosition, ExecutorVersion, select_legacy_p1,
};
use crate::protocol::session::GuestFactory;
use crate::protocol::v1::committee::derive_committee;
use crate::protocol::v1::definition::execution_definition;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::call::CallOutcome;
use crate::runtime::fuel::ExecutionUsage;
use crate::runtime::staking::address as staking_address;
use crate::runtime::storage::BlockingGate;
use crate::runtime::wit::{Signer, kontor::built_in::context::HolderRef};
use crate::runtime::{ComponentSource, GenesisValidator};
use crate::runtime::{
    ContractAddress, Decimal, ExecutionError, Linkers, Storage, native_provenance, to_wave_expr,
    token,
};
use crate::test_utils::{test_runtime, test_runtime_with_genesis};
use bitcoin::Network;
use deadpool::managed::Pool;
use indexer_types::Payment;
use libsql::Connection;
use std::future::{pending, poll_fn};
use std::sync::atomic::AtomicUsize;
use std::task::Poll;
use tempfile::TempDir;
use tokio::sync::{Barrier, Notify};
use tokio::time::timeout;
use wasmtime::component::{Component, Linker};

const PURE_LOOP_COMPONENT: &str = r#"
        (component
          (core module $code
            (func (export "run") (param $count i32) (result i32)
              (local $total i32)
              (block $done
                (loop $again
                  local.get $count i32.eqz br_if $done
                  local.get $total i32.const 1 i32.add local.set $total
                  local.get $count i32.const 1 i32.sub local.set $count
                  br $again))
              local.get $total))
          (core instance $code (instantiate $code))
          (func (export "run") (param "count" u32) (result u32)
            (canon lift (core func $code "run"))))
    "#;

type YieldObservations = Arc<Mutex<Vec<(u32, Val, u64, bool)>>>;
type DeepAdmission = (
    mpsc::Sender<Admission>,
    Arc<AtomicBool>,
    Arc<InvocationBudget>,
);

#[derive(Debug, PartialEq)]
struct PaidReceiptSnapshot {
    outcome: std::result::Result<String, String>,
    usage: ExecutionUsage,
    receipt: (u64, String, u64, Option<String>),
    payer: Option<Decimal>,
    burner: Option<Decimal>,
}

struct ReleaseBlockingGate(Arc<BlockingGate>);

impl Drop for ReleaseBlockingGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct ReleaseAsyncGate(Arc<AsyncGate>);

impl Drop for ReleaseAsyncGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn rooted_store(runtime: &Runtime, kind: RootKind, fuel: u64) -> Result<InvocationStore> {
    let mut runtime = runtime.clone();
    let (sender, _receiver) = mpsc::channel(1);
    runtime.ownership = Some(ChildContext::root(
        RootId(99),
        kind,
        sender,
        Arc::new(AtomicU8::new(RootState::Running as u8)),
        Arc::new(BlockingRegistry::default()),
        Arc::new(AtomicBool::new(false)),
    ));
    runtime.make_store(fuel)
}

async fn run_pure_loop(
    runtime: &Runtime,
    component: &Component,
    kind: RootKind,
    count: u32,
    fuel: u64,
) -> Result<(Val, u64, bool)> {
    let (observation, _store) =
        run_pure_loop_in_store(rooted_store(runtime, kind, fuel)?, component, count, None).await?;
    Ok(observation)
}

async fn run_pure_loop_in_store(
    mut store: InvocationStore,
    component: &Component,
    count: u32,
    first_yield: Option<&AtomicBool>,
) -> Result<((Val, u64, bool), InvocationStore)> {
    let linker = Linker::<Runtime>::new(&store.data().engine);
    let instance = linker.instantiate_async(&mut store, component).await?;
    let run = instance
        .get_func(&mut store, "run")
        .context("pure loop export missing")?;
    let mut results = [Val::U32(0)];
    let args = [Val::U32(count)];
    let yielded = {
        let invocation = run.call_async(&mut store, &args, &mut results);
        tokio::pin!(invocation);
        match poll_fn(|cx| Poll::Ready(invocation.as_mut().poll(cx))).await {
            Poll::Ready(result) => {
                result?;
                false
            }
            Poll::Pending => {
                if let Some(first_yield) = first_yield {
                    first_yield.store(true, Ordering::SeqCst);
                }
                timeout(Duration::from_secs(10), invocation.as_mut()).await??;
                true
            }
        }
    };
    Ok(((results[0].clone(), store.get_fuel()?, yielded), store))
}

fn nested_yield_guest(
    mut runtime: Runtime,
    owner: ChildContext,
    component: Arc<Component>,
    depth: u32,
    observations: YieldObservations,
    leaf_count: u32,
    fuel: u64,
    first_yield: Option<Arc<AtomicBool>>,
) -> BoxFuture<'static, GuestCompletion> {
    Box::pin(async move {
        runtime.ownership = Some(owner.clone());
        runtime.storage.ownership = Some(owner.clone());
        let (observation, store) = run_pure_loop_in_store(
            runtime.make_store(fuel).expect("nested Store"),
            &component,
            if depth == 2 { leaf_count } else { 200_000 },
            if depth == 2 {
                first_yield.as_deref()
            } else {
                None
            },
        )
        .await
        .expect("nested pure guest call");
        observations
            .lock()
            .await
            .push((depth, observation.0, observation.1, observation.2));
        if depth < 2 {
            let child_runtime = runtime.clone();
            let child_component = component.clone();
            let child_observations = observations.clone();
            let child = owner
                .run_guest(move |next| {
                    nested_yield_guest(
                        child_runtime,
                        next,
                        child_component,
                        depth + 1,
                        child_observations,
                        leaf_count,
                        fuel,
                        first_yield,
                    )
                })
                .await
                .expect("nested child completed");
            assert!(matches!(&child.result, Ok(Ok(()))));
        }
        GuestCompletion {
            result: Ok(Ok(())),
            results: Vec::new(),
            store,
            host_panicked: false,
        }
    })
}

fn nested_depth64_guest(
    mut runtime: Runtime,
    owner: ChildContext,
    depth: u32,
    ready: Arc<Mutex<Option<oneshot::Sender<DeepAdmission>>>>,
    gate: Arc<Notify>,
) -> BoxFuture<'static, GuestCompletion> {
    Box::pin(async move {
        runtime.ownership = Some(owner.clone());
        runtime.storage.ownership = Some(owner.clone());
        let store = runtime.make_store(1_000_000).expect("nested Store");
        if depth == 63 {
            let budget = store
                .data()
                .invocation_budget
                .as_ref()
                .expect("root invocation budget")
                .clone();
            let sender = ready
                .lock()
                .await
                .take()
                .expect("depth 63 admission sender");
            assert!(
                sender
                    .send((owner.sender.clone(), owner.slot.clone(), budget))
                    .is_ok(),
                "admission observer dropped"
            );
            gate.notified().await;
        }
        if depth < 64 {
            let child_runtime = runtime.clone();
            let child_ready = ready.clone();
            let child_gate = gate.clone();
            let child = owner
                .run_guest(move |next| {
                    nested_depth64_guest(child_runtime, next, depth + 1, child_ready, child_gate)
                })
                .await
                .expect("nested child completed");
            assert!(matches!(&child.result, Ok(Ok(()))));
        }
        GuestCompletion {
            result: Ok(Ok(())),
            results: Vec::new(),
            store,
            host_panicked: false,
        }
    })
}

async fn one_object_pool(dir: &TempDir) -> Result<Pool<Manager>> {
    new_connection(dir.path(), "owner.db").await?;
    Ok(Pool::builder(Manager::new(
        dir.path().to_path_buf(),
        "owner.db".into(),
        Network::Regtest,
        100_000,
    )?)
    .max_size(1)
    .build()?)
}

async fn paid_receipt_snapshot(
    runtime: &mut Runtime,
    signer: &Signer,
    address: &ContractAddress,
    expr: &str,
) -> Result<PaidReceiptSnapshot> {
    let before = runtime.start_usage();
    let outcome = match runtime.execute_api(Some(signer), address, expr).await {
        Ok(value) => Ok(value),
        Err(ExecutionError::Deterministic(error)) => Err(error.to_string()),
        Err(error) => return Err(anyhow!("nondeterministic paid oracle: {error}")),
    };
    let usage = runtime.finish_usage(before)?;
    let mut rows = runtime
        .storage
        .conn
        .query(
            "SELECT contract_id, status, gas, value FROM contract_results ORDER BY id",
            (),
        )
        .await?;
    let row = rows.next().await?.context("paid receipt missing")?;
    let receipt = (
        row.get::<u64>(0)?,
        row.get::<String>(1)?,
        row.get::<u64>(2)?,
        row.get::<Option<String>>(3)?,
    );
    ensure!(rows.next().await?.is_none(), "duplicate paid receipt");
    drop(rows);
    Ok(PaidReceiptSnapshot {
        outcome,
        usage,
        receipt,
        payer: token::api::balance(runtime, HolderRef::from(signer)).await?,
        burner: token::api::balance(runtime, HolderRef::Burner).await?,
    })
}

async fn seeded_paid_oracle_with_name()
-> Result<(Runtime, TempDir, String, Signer, ContractAddress)> {
    let (mut runtime, dir, name) = test_runtime().await?;
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    token::api::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&signer),
        Decimal::from("1000000000000"),
    )
    .await??;
    runtime
        .publish(
            &signer,
            Payment {
                signer_id: signer.signer_id().context("test payer missing")?,
                gas_limit: runtime.gas_limit_for_non_procs,
            },
            "ownership-paid-oracle",
            include_bytes!("../../../../../test-contracts/binaries/error_test.wasm.br"),
            &native_provenance()?,
        )
        .await
        .map_err(anyhow::Error::from)?;
    runtime
        .storage
        .conn
        .execute("DELETE FROM contract_results", ())
        .await?;
    Ok((
        runtime,
        dir,
        name,
        signer,
        ContractAddress {
            name: "ownership-paid-oracle".to_string(),
            height: 0,
            tx_index: 0,
        },
    ))
}

async fn seeded_paid_oracle() -> Result<(Runtime, TempDir, Signer, ContractAddress)> {
    let (runtime, dir, _name, signer, address) = seeded_paid_oracle_with_name().await?;
    Ok((runtime, dir, signer, address))
}

async fn seeded_nested_paid_oracle()
-> Result<(Runtime, TempDir, Signer, ContractAddress, ContractAddress)> {
    let (mut runtime, dir, signer, leaf) = seeded_paid_oracle().await?;
    let mut next = leaf.clone();
    for index in 0..2 {
        let name = format!("ownership-proxy-{index}");
        runtime
            .publish(
                &signer,
                Payment {
                    signer_id: signer.signer_id().context("test payer missing")?,
                    gas_limit: runtime.gas_limit_for_non_procs,
                },
                &name,
                include_bytes!("../../../../../test-contracts/binaries/proxy.wasm.br"),
                &native_provenance()?,
            )
            .await
            .map_err(anyhow::Error::from)?;
        let address = ContractAddress {
            name,
            height: 0,
            tx_index: 0,
        };
        runtime
            .execute_api(
                Some(&signer),
                &address,
                &format!("set-contract-address({})", to_wave_expr(next)),
            )
            .await
            .map_err(anyhow::Error::from)?;
        next = address;
    }
    runtime
        .storage
        .conn
        .execute("DELETE FROM contract_results", ())
        .await?;
    Ok((runtime, dir, signer, next, leaf))
}

async fn receipt_count(runtime: &Runtime) -> Result<i64> {
    let mut rows = runtime
        .storage
        .conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    Ok(rows
        .next()
        .await?
        .context("receipt count missing")?
        .get(0)?)
}

async fn checkpoint_hash(conn: &Connection) -> Result<Option<String>> {
    let mut rows = conn
        .query(
            "SELECT hash FROM checkpoints ORDER BY height DESC LIMIT 1",
            (),
        )
        .await?;
    rows.next()
        .await?
        .map(|row| row.get(0))
        .transpose()
        .map_err(Into::into)
}

#[tokio::test]
async fn dropped_view_keeps_pool_object_until_guest_store_is_joined() -> Result<()> {
    let dir = TempDir::new()?;
    let pool = one_object_pool(&dir).await?;
    let object = pool.get().await?;
    let service = OwnerService::new();
    let started = Arc::new(Notify::new());
    let child_started = started.clone();
    let handle = service
        .start_pooled(object, move |runtime| {
            Box::pin(async move {
                let owner = runtime.ownership.clone().expect("owned runtime context");
                let store = runtime.make_store(1_000_000)?;
                owner
                    .run_guest(|child| async move {
                        let mut store = store;
                        store.data_mut().ownership = Some(child);
                        child_started.notify_one();
                        pending().await
                    })
                    .await?;
                Ok(RootOutcome {
                    value: (),
                    commit: false,
                })
            })
        })
        .await?;
    timeout(Duration::from_secs(2), started.notified()).await?;
    drop(handle);
    assert_eq!(pool.status().available, 0);
    let object = timeout(Duration::from_secs(2), pool.get()).await??;
    assert!(object.storage.conn.is_autocommit());
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn cancelling_view_with_live_row_cursor_releases_snapshot_before_pool_reuse() -> Result<()> {
    let dir = TempDir::new()?;
    let writer = new_connection(dir.path(), "owner.db").await?;
    writer
        .execute(
            "CREATE TABLE ownership_cursor_probe (k INTEGER PRIMARY KEY)",
            (),
        )
        .await?;
    writer
        .execute("INSERT INTO ownership_cursor_probe (k) VALUES (1)", ())
        .await?;
    let pool = one_object_pool(&dir).await?;
    let object = pool.get().await?;
    let service = OwnerService::new();
    let cursor_open = Arc::new(Notify::new());
    let observed = cursor_open.notified();
    tokio::pin!(observed);
    observed.as_mut().enable();
    let opened = cursor_open.clone();
    let handle = service
        .start_pooled(object, move |runtime| {
            Box::pin(async move {
                let mut rows = runtime
                    .storage
                    .conn
                    .query("SELECT k FROM ownership_cursor_probe ORDER BY k", ())
                    .await?;
                ensure!(
                    rows.next()
                        .await?
                        .context("cursor row missing")?
                        .get::<i64>(0)?
                        == 1,
                    "unexpected first cursor row"
                );
                opened.notify_one();
                pending::<()>().await;
                drop(rows);
                Ok(RootOutcome {
                    value: (),
                    commit: false,
                })
            })
        })
        .await?;
    timeout(Duration::from_secs(10), observed).await?;
    writer
        .execute("INSERT INTO ownership_cursor_probe (k) VALUES (2)", ())
        .await?;
    drop(handle);
    let object = timeout(Duration::from_secs(4), pool.get()).await??;
    assert!(object.storage.conn.is_autocommit());
    assert!(object.storage.savepoint_stack.is_empty().await);
    let mut rows = object
        .storage
        .conn
        .query("SELECT COUNT(*) FROM ownership_cursor_probe", ())
        .await?;
    assert_eq!(
        rows.next()
            .await?
            .context("cursor count missing")?
            .get::<i64>(0)?,
        2
    );
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn owned_native_view_matches_direct_guest_result() -> Result<()> {
    let (mut seed, dir, name) = test_runtime().await?;
    let before = seed.start_usage();
    let baseline = token::api::balance(&mut seed, HolderRef::Burner).await?;
    let baseline_usage = seed.finish_usage(before)?;
    drop(seed);
    let pool = Pool::builder(Manager::new(
        dir.path().to_path_buf(),
        name,
        Network::Regtest,
        100_000,
    )?)
    .max_size(1)
    .build()?;
    let object = pool.get().await?;
    let service = OwnerService::new();
    let mut handle = service
        .start_pooled(object, |runtime| {
            Box::pin(async move {
                let before = runtime.start_usage();
                let value = token::api::balance(runtime, HolderRef::Burner).await?;
                let usage = runtime.finish_usage(before)?;
                Ok(RootOutcome {
                    value: (value, usage),
                    commit: false,
                })
            })
        })
        .await?;
    assert_eq!(handle.result().await?, (baseline, baseline_usage));
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn owned_paid_call_matches_direct_value_fuel_receipt_and_settlement() -> Result<()> {
    let (mut runtime, _dir, signer, address) = seeded_paid_oracle().await?;
    let contract_id = runtime
        .storage
        .contract_id(&address)
        .await?
        .context("paid oracle contract missing")?;
    let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
    let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
    runtime.storage.savepoint().await?;
    let direct =
        paid_receipt_snapshot(&mut runtime, &signer, &address, "write-result-payload(1)").await?;
    assert_eq!(direct.outcome, Ok("\"é\\n\"".to_string()));
    assert_eq!(direct.receipt.0, contract_id);
    assert_eq!(direct.receipt.1, "Ok");
    assert!(direct.receipt.2 > 0);
    assert!(direct.payer.as_ref() < payer_before.as_ref());
    assert!(direct.burner.as_ref() > burner_before.as_ref());
    runtime.storage.rollback().await?;
    assert!(runtime.storage.conn.is_autocommit());
    let owned = OwnedRuntimeSession::new(runtime);
    let owned_value = owned
        .run(true, move |runtime| {
            Box::pin(async move {
                paid_receipt_snapshot(runtime, &signer, &address, "write-result-payload(1)").await
            })
        })
        .await?;
    assert_eq!(owned_value, direct);
    let checkout = owned.session.checkout().await?;
    let recovered = checkout.runtime.as_ref().context("owned runtime missing")?;
    assert!(recovered.storage.conn.is_autocommit());
    let mut rows = recovered
        .storage
        .conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    assert_eq!(
        rows.next()
            .await?
            .context("receipt count missing")?
            .get::<i64>(0)?,
        1
    );
    Ok(())
}

fn linked_runtime_session(
    runtime: Runtime,
    canonical: bool,
) -> (LinkedSession, Arc<BundleSession>) {
    let conn = runtime.storage.conn.clone();
    let executor = link_runtime(runtime, canonical);
    let retained = executor
        .owner
        .clone()
        .downcast::<BundleSession>()
        .unwrap_or_else(|_| panic!("unexpected bundle session type"));
    (LinkedSession::new(conn, executor), retained)
}

#[tokio::test]
async fn bundle_callbacks_preserve_real_paid_call_and_release_context() -> Result<()> {
    let (mut runtime, _dir, signer, address) = seeded_paid_oracle().await?;
    runtime.storage.savepoint().await?;
    let direct =
        paid_receipt_snapshot(&mut runtime, &signer, &address, "write-result-payload(1)").await?;
    runtime.storage.rollback().await?;
    let selection = select_legacy_p1(
        &runtime.storage.conn,
        runtime.network,
        ApplicationPosition::View,
    )
    .await?;
    let envelope = selection.envelope();
    let (session, retained) = linked_runtime_session(runtime, false);
    let service = OwnerService::new();
    let owned = LinkedStatefulSession::new(session);
    let capacity = service.reserve_root_capacity().await?;
    let operation: LinkedOperation = Box::new(move |opaque, _| {
        Box::pin(async move {
            let session = opaque
                .downcast::<BundleSession>()
                .map_err(|_| (2, "unexpected executor session".into()))?;
            let mut runtime = session.runtime.lock().await;
            assert_eq!(
                runtime.bundle_owner.as_ref().unwrap().fuel_yield_interval(),
                Some(API_FUEL_YIELD_INTERVAL)
            );
            assert!(runtime.selected_context.is_some());
            drop(
                runtime
                    .bind_selection(&envelope)
                    .map_err(|error| (0, error.to_string()))?,
            );
            assert!(runtime.selected_context.is_some());
            let mut changed = envelope.clone();
            changed.2.1 += 1;
            assert!(runtime.bind_selection(&changed).is_err());
            runtime.component_cache.clear();
            let value =
                paid_receipt_snapshot(&mut runtime, &signer, &address, "write-result-payload(1)")
                    .await
                    .map_err(|error| (0, format!("{error:#}")))?;
            Ok((Box::new(value) as Payload, true))
        })
    });
    let mut handle = service
        .start_linked_stateful_reserved(&owned, capacity, selection, operation)
        .await?;
    let value = handle
        .result()
        .await?
        .downcast::<PaidReceiptSnapshot>()
        .map_err(|_| anyhow!("unexpected receipt payload"))?;
    assert_eq!(*value, direct);
    let checkout = owned.checkout().await?;
    assert!(checkout.value.as_ref().unwrap().conn.is_autocommit());
    let recovered = retained.runtime.lock().await;
    assert!(recovered.bundle_owner.is_none());
    assert!(recovered.storage.bundle_owner.is_none());
    assert!(recovered.selected_context.is_none());
    assert_eq!(receipt_count(&recovered).await?, 1);
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn bundle_canonical_hooks_preserve_paid_settlement_and_rollback() -> Result<()> {
    let (runtime, _dir, signer, address) = seeded_paid_oracle().await?;
    let (session, retained) = linked_runtime_session(runtime, true);
    let service = OwnerService::new();
    for commit in [false, true] {
        let selection = select_legacy_p1(
            &session.conn,
            Network::Regtest,
            ApplicationPosition::Committee,
        )
        .await?;
        let capacity = service.reserve_root_capacity().await?;
        let lease = service
            .begin_linked_canonical_reserved(&session, capacity, selection, false)
            .await?;
        {
            let mut runtime = retained.runtime.lock().await;
            assert_eq!(
                runtime.bundle_owner.as_ref().unwrap().fuel_yield_interval(),
                None
            );
            runtime.storage.savepoint().await?;
            let result =
                paid_receipt_snapshot(&mut runtime, &signer, &address, "write-result-payload(1)")
                    .await?;
            assert_eq!(result.receipt.1, "Ok");
        }
        let lease = lease.drain().await?.require_settlement()?;
        assert!(!session.conn.is_autocommit());
        assert!(retained.runtime.lock().await.selected_context.is_some());
        let lease = lease.settle(commit).await?;
        assert!(retained.runtime.lock().await.selected_context.is_some());
        lease.complete().await?;
        assert!(session.conn.is_autocommit());
        let runtime = retained.runtime.lock().await;
        assert_eq!(receipt_count(&runtime).await?, i64::from(commit));
        assert!(runtime.bundle_owner.is_none());
        assert!(runtime.selected_context.is_none());
        assert!(runtime.storage.savepoint_stack.is_empty().await);
        assert_eq!(service.active_roots().await, 0);
    }
    (session.executor.recycle)(session.executor.owner.clone())
        .await
        .map_err(|error| anyhow!("recycle failed: {error:?}"))?;
    Ok(())
}

#[tokio::test]
async fn bundle_typed_operations_preserve_views_and_committee() -> Result<()> {
    let key = PrivateKey::from([7; 32]).public_key();
    let (mut runtime, _dir, _name) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: key.as_bytes().to_vec(),
        stake: Decimal::from("100.9999999"),
    }])
    .await?;
    let address = staking_address();
    let expected_view = runtime
        .execute(None, None, &address, "get-active-set()")
        .await?;
    let error = runtime
        .execute(None, None, &address, "missing-function()")
        .await
        .unwrap_err();
    let expected_error = (
        matches!(&error, ExecutionError::Deterministic(_)),
        format!("{error:?}"),
    );
    let expected_committee = derive_committee(&mut runtime).await?;
    let selection = select_legacy_p1(
        &runtime.storage.conn,
        runtime.network,
        ApplicationPosition::View,
    )
    .await?;
    let envelope = selection.envelope();
    let address = (address.name, address.height, address.tx_index);
    let (linked, retained) = linked_runtime_session(runtime, false);
    let view = retained.view();
    assert!(
        view(
            retained.clone(),
            envelope.clone(),
            address.clone(),
            "get-active-set()".into()
        )
        .await
        .is_err()
    );
    let service = OwnerService::new();
    let owned = LinkedStatefulSession::new(linked.clone());
    let operation: LinkedOperation = Box::new(move |opaque, _| {
        Box::pin(async move {
            assert_eq!(
                view(
                    opaque.clone(),
                    envelope.clone(),
                    address.clone(),
                    "get-active-set()".into()
                )
                .await?,
                Ok(expected_view)
            );
            assert_eq!(
                view(
                    opaque.clone(),
                    envelope.clone(),
                    address.clone(),
                    "missing-function()".into()
                )
                .await?,
                Err(expected_error)
            );
            let mut changed = envelope.clone();
            changed.2.1 += 1;
            assert!(
                view(
                    opaque.clone(),
                    changed,
                    address.clone(),
                    "get-active-set()".into()
                )
                .await
                .is_err()
            );
            let mut wrong_purpose = envelope.clone();
            wrong_purpose.3 = (1, 0, None, 0);
            assert!(
                view(
                    opaque.clone(),
                    wrong_purpose,
                    address.clone(),
                    "get-active-set()".into()
                )
                .await
                .is_err()
            );
            assert_eq!(
                view(Arc::new(()), envelope, address, "get-active-set()".into())
                    .await
                    .unwrap_err()
                    .0,
                2
            );
            Ok((Box::new(()) as Payload, false))
        })
    });
    let capacity = service.reserve_root_capacity().await?;
    let mut handle = service
        .start_linked_stateful_reserved(&owned, capacity, selection, operation)
        .await?;
    handle.result().await?;
    drop(owned.checkout().await?);
    drop(owned);
    assert!(retained.runtime.lock().await.selected_context.is_none());

    // The canonical session uses the same real runtime after the view root
    // has finished cleanup, with canonical settlement hooks instead.
    drop(linked);
    let runtime = Arc::try_unwrap(retained)
        .map_err(|_| anyhow!("view callbacks retained session"))?
        .runtime
        .into_inner();
    let (session, retained) = linked_runtime_session(runtime, true);
    let selection = select_legacy_p1(
        &session.conn,
        Network::Regtest,
        ApplicationPosition::Committee,
    )
    .await?;
    let envelope = selection.envelope();
    let capacity = service.reserve_root_capacity().await?;
    let lease = service
        .begin_linked_canonical_reserved(&session, capacity, selection, false)
        .await?;
    retained.runtime.lock().await.storage.savepoint().await?;
    let committee = retained.committee();
    assert_eq!(
        committee(retained.clone(), envelope.clone())
            .await
            .map_err(|error| anyhow!("{error:?}"))?,
        expected_committee
    );
    let lease = lease.drain().await?.require_settlement()?;
    let lease = lease.settle(false).await?;
    lease.complete().await?;
    assert!(committee(retained.clone(), envelope).await.is_err());
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn rollback_failure_quarantines_writer_without_durable_receipt_or_checkpoint() -> Result<()> {
    let (runtime, dir, name, signer, address) = seeded_paid_oracle_with_name().await?;
    let committed = new_connection(dir.path(), &name).await?;
    let checkpoint_before = checkpoint_hash(&committed).await?;
    let mut rows = committed
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    assert_eq!(
        rows.next()
            .await?
            .context("receipt count missing")?
            .get::<i64>(0)?,
        0
    );
    drop(rows);
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let pending_checkpoint = checkpoint_before.clone();
    let result = owned
        .run(false, move |runtime| {
            Box::pin(async move {
                runtime
                    .execute_api(Some(&signer), &address, "write-result-payload(1)")
                    .await
                    .map_err(anyhow::Error::from)?;
                ensure!(
                    receipt_count(runtime).await? == 1,
                    "paid receipt was not staged"
                );
                ensure!(
                    checkpoint_hash(&runtime.get_storage_conn()).await? != pending_checkpoint,
                    "state write did not stage a checkpoint"
                );
                runtime
                    .storage
                    .fail_rollback_once
                    .store(true, Ordering::SeqCst);
                Ok(())
            })
        })
        .await;
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("quarantined")),
        "rollback failure returned a success: {result:?}"
    );
    assert_eq!(service.quarantined_roots().await, 1);
    assert!(owned.session.checkout().await.is_err());
    let mut rows = committed
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    assert_eq!(
        rows.next()
            .await?
            .context("receipt count missing")?
            .get::<i64>(0)?,
        0
    );
    drop(rows);
    assert_eq!(checkpoint_hash(&committed).await?, checkpoint_before);
    Ok(())
}

async fn injected_outer_commit_error_has_one_durable_result(after_commit: bool) -> Result<()> {
    let (mut runtime, dir, name, signer, address) = seeded_paid_oracle_with_name().await?;
    let committed = new_connection(dir.path(), &name).await?;
    let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
    let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
    let checkpoint_before = checkpoint_hash(&runtime.get_storage_conn()).await?;
    let engine = runtime.engine.clone();
    let linkers = runtime.linkers.clone();
    let cache = runtime.component_cache.clone();
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let (staged_sender, staged_receiver) = oneshot::channel();
    let call_signer = signer.clone();
    let result = owned
        .run(true, move |runtime| {
            Box::pin(async move {
                if after_commit {
                    runtime
                        .storage
                        .fail_outer_commit_after_once
                        .store(true, Ordering::SeqCst);
                } else {
                    runtime
                        .storage
                        .fail_outer_commit_before_once
                        .store(true, Ordering::SeqCst);
                }
                let staged = paid_receipt_snapshot(
                    runtime,
                    &call_signer,
                    &address,
                    "write-result-payload(1)",
                )
                .await?;
                let staged_checkpoint = checkpoint_hash(&runtime.get_storage_conn()).await?;
                let _ = staged_sender.send((staged, staged_checkpoint));
                Ok(())
            })
        })
        .await;
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("quarantined")),
        "uncertain outer commit returned success: {result:?}"
    );
    let (staged, staged_checkpoint) = staged_receiver.await?;
    assert_eq!(staged.outcome, Ok("\"é\\n\"".to_string()));
    assert!(staged.payer.as_ref() < payer_before.as_ref());
    assert!(staged.burner.as_ref() > burner_before.as_ref());
    assert_ne!(staged_checkpoint, checkpoint_before);
    assert_eq!(service.quarantined_roots().await, 1);
    assert!(owned.session.checkout().await.is_err());
    assert!(
        timeout(
            Duration::from_secs(2),
            owned.run(false, |_runtime| Box::pin(async { Ok(()) }))
        )
        .await?
        .is_err(),
        "poisoned stateful session executed again"
    );

    let mut observer = Runtime::new_with(
        engine,
        linkers,
        cache,
        Storage::builder().conn(committed).build(),
    )
    .await?;
    assert_eq!(receipt_count(&observer).await?, i64::from(after_commit));
    assert_eq!(
        token::api::balance(&mut observer, HolderRef::from(&signer)).await?,
        if after_commit {
            staged.payer
        } else {
            payer_before
        }
    );
    assert_eq!(
        token::api::balance(&mut observer, HolderRef::Burner).await?,
        if after_commit {
            staged.burner
        } else {
            burner_before
        }
    );
    assert_eq!(
        checkpoint_hash(&observer.get_storage_conn()).await?,
        if after_commit {
            staged_checkpoint
        } else {
            checkpoint_before
        }
    );
    if after_commit {
        let mut rows = observer
            .storage
            .conn
            .query(
                "SELECT contract_id, status, gas, value FROM contract_results ORDER BY id",
                (),
            )
            .await?;
        let row = rows.next().await?.context("durable paid receipt missing")?;
        assert_eq!(
            (
                row.get::<u64>(0)?,
                row.get::<String>(1)?,
                row.get::<u64>(2)?,
                row.get::<Option<String>>(3)?,
            ),
            staged.receipt
        );
        assert!(rows.next().await?.is_none(), "duplicate durable receipt");
    }
    Ok(())
}

#[tokio::test]
async fn failure_before_outer_commit_quarantines_without_settlement() -> Result<()> {
    injected_outer_commit_error_has_one_durable_result(false).await
}

#[tokio::test]
async fn error_after_durable_outer_commit_quarantines_without_double_settlement() -> Result<()> {
    injected_outer_commit_error_has_one_durable_result(true).await
}

#[tokio::test]
async fn paid_out_of_fuel_matches_with_and_without_api_yielding() -> Result<()> {
    let (mut runtime, _dir, signer, address) = seeded_paid_oracle().await?;
    ensure!(runtime.ownership.is_none(), "direct oracle has an owner");
    let contract_id = runtime
        .storage
        .contract_id(&address)
        .await?
        .context("out-of-fuel oracle contract missing")?;
    let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
    let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
    runtime.storage.savepoint().await?;
    let direct =
        paid_receipt_snapshot(&mut runtime, &signer, &address, "trap-out-of-fuel()").await?;
    assert!(direct.outcome.is_err());
    assert_eq!(direct.receipt.0, contract_id);
    assert_eq!(direct.receipt.1, "OutOfFuel");
    assert!(direct.receipt.2 > 0);
    assert!(direct.receipt.3.is_none());
    assert!(direct.usage.user_fuel >= API_FUEL_YIELD_INTERVAL);
    assert!(direct.payer.as_ref() < payer_before.as_ref());
    assert!(direct.burner.as_ref() > burner_before.as_ref());
    runtime.storage.rollback().await?;
    assert!(runtime.storage.conn.is_autocommit());
    let owned = OwnedRuntimeSession::new(runtime);
    let owned_value = owned
        .run(true, move |runtime| {
            Box::pin(async move {
                ensure!(
                    runtime
                        .ownership
                        .as_ref()
                        .and_then(ChildContext::fuel_yield_interval)
                        == Some(API_FUEL_YIELD_INTERVAL),
                    "owned paid oracle did not enable API yielding"
                );
                paid_receipt_snapshot(runtime, &signer, &address, "trap-out-of-fuel()").await
            })
        })
        .await?;
    assert_eq!(owned_value, direct);
    let checkout = owned.session.checkout().await?;
    let recovered = checkout.runtime.as_ref().context("owned runtime missing")?;
    assert!(recovered.storage.conn.is_autocommit());
    let mut rows = recovered
        .storage
        .conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    assert_eq!(
        rows.next()
            .await?
            .context("out-of-fuel receipt count missing")?
            .get::<i64>(0)?,
        1
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_after_real_payment_hold_rolls_back_without_receipt() -> Result<()> {
    let (mut runtime, _dir, signer, _address) = seeded_paid_oracle().await?;
    let service = OwnerService::new();
    let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
    let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
    let payment = Payment {
        signer_id: signer.signer_id().context("test payer missing")?,
        gas_limit: runtime.gas_limit_for_non_procs,
    };
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let held = Arc::new(Notify::new());
    let observed = held.notified();
    tokio::pin!(observed);
    observed.as_mut().enable();
    let host_held = held.clone();
    let call_signer = signer.clone();
    let expected_payer = payer_before;
    let handle = service
        .start_stateful(&owned.session, move |runtime| {
            Box::pin(async move {
                runtime
                    .with_payment(&payment, 1_000_000, async |runtime| {
                        let current = token::api::balance(runtime, HolderRef::from(&call_signer))
                            .await
                            .map_err(ExecutionError::NonDeterministic)?;
                        if !matches!(
                            (current.as_ref(), expected_payer.as_ref()),
                            (Some(current), Some(expected)) if current < expected
                        ) {
                            return Err(ExecutionError::NonDeterministic(anyhow!(
                                "payment hold did not reduce payer balance"
                            )));
                        }
                        host_held.notify_one();
                        pending::<Result<CallOutcome, ExecutionError>>().await
                    })
                    .await
                    .map_err(anyhow::Error::from)?;
                Ok(RootOutcome {
                    value: (),
                    commit: true,
                })
            })
        })
        .await?;
    timeout(Duration::from_secs(10), observed).await?;
    drop(handle);
    let mut checkout = timeout(Duration::from_secs(4), owned.session.checkout()).await??;
    let recovered = checkout
        .runtime
        .as_mut()
        .context("restored runtime missing")?;
    assert_eq!(
        token::api::balance(recovered, HolderRef::from(&signer)).await?,
        payer_before
    );
    assert_eq!(
        token::api::balance(recovered, HolderRef::Burner).await?,
        burner_before
    );
    assert_eq!(receipt_count(recovered).await?, 0);
    assert!(recovered.storage.conn.is_autocommit());
    assert!(recovered.storage.savepoint_stack.is_empty().await);
    assert!(recovered.stack.is_empty().await);
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn cancelling_after_paid_settlement_before_outer_commit_rolls_back_once() -> Result<()> {
    let (mut runtime, _dir, signer, address) = seeded_paid_oracle().await?;
    let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
    let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
    let checkpoint_before = checkpoint_hash(&runtime.get_storage_conn()).await?;
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let settled = Arc::new(Notify::new());
    let observed = settled.notified();
    tokio::pin!(observed);
    observed.as_mut().enable();
    let after_settlement = settled.clone();
    let call_signer = signer.clone();
    let handle = service
        .start_stateful(&owned.session, move |runtime| {
            Box::pin(async move {
                let value = runtime
                    .execute_api(Some(&call_signer), &address, "write-result-payload(1)")
                    .await
                    .map_err(anyhow::Error::from)?;
                ensure!(value == "\"é\\n\"", "unexpected paid result: {value}");
                ensure!(
                    receipt_count(runtime).await? == 1,
                    "paid receipt was not staged"
                );
                after_settlement.notify_one();
                pending::<()>().await;
                Ok(RootOutcome {
                    value: (),
                    commit: true,
                })
            })
        })
        .await?;
    timeout(Duration::from_secs(10), observed).await?;
    drop(handle);
    let mut checkout = timeout(Duration::from_secs(4), owned.session.checkout()).await??;
    let recovered = checkout
        .runtime
        .as_mut()
        .context("restored runtime missing")?;
    assert_eq!(receipt_count(recovered).await?, 0);
    assert_eq!(
        checkpoint_hash(&recovered.get_storage_conn()).await?,
        checkpoint_before
    );
    assert_eq!(
        token::api::balance(recovered, HolderRef::from(&signer)).await?,
        payer_before
    );
    assert_eq!(
        token::api::balance(recovered, HolderRef::Burner).await?,
        burner_before
    );
    assert!(recovered.storage.conn.is_autocommit());
    assert!(recovered.storage.savepoint_stack.is_empty().await);
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn cancelling_between_footprint_update_and_state_write_restores_floor() -> Result<()> {
    let (mut runtime, _dir, signer, address) = seeded_paid_oracle().await?;
    let contract_id = runtime
        .storage
        .contract_id(&address)
        .await?
        .context("paid oracle contract missing")?;
    let depositor = signer.signer_id().context("test payer missing")?;
    let floor_before = runtime.storage.footprint().total_gas(depositor).await?;
    let checkpoint_before = checkpoint_hash(&runtime.get_storage_conn()).await?;
    let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let updated = Arc::new(Notify::new());
    let observed = updated.notified();
    tokio::pin!(observed);
    observed.as_mut().enable();
    let host_updated = updated.clone();
    let handle = service
        .start_stateful(&owned.session, move |runtime| {
            Box::pin(async move {
                runtime
                    .storage
                    .footprint()
                    .on_set(contract_id, b"cancel-gap", Some(depositor), Some(17))
                    .await?;
                ensure!(
                    runtime.storage.footprint().total_gas(depositor).await? == floor_before + 17,
                    "footprint update was not staged"
                );
                host_updated.notify_one();
                pending::<()>().await;
                runtime
                    .storage
                    .set(
                        contract_id,
                        b"cancel-gap",
                        b"value",
                        Some(depositor),
                        Some(17),
                    )
                    .await?;
                Ok(RootOutcome {
                    value: (),
                    commit: true,
                })
            })
        })
        .await?;
    timeout(Duration::from_secs(10), observed).await?;
    drop(handle);
    let mut checkout = timeout(Duration::from_secs(4), owned.session.checkout()).await??;
    let runtime = checkout
        .runtime
        .as_mut()
        .context("restored runtime missing")?;
    assert_eq!(
        runtime.storage.footprint().total_gas(depositor).await?,
        floor_before
    );
    assert_eq!(
        checkpoint_hash(&runtime.get_storage_conn()).await?,
        checkpoint_before
    );
    assert_eq!(receipt_count(runtime).await?, 0);
    assert_eq!(
        token::api::balance(runtime, HolderRef::from(&signer)).await?,
        payer_before
    );
    assert!(runtime.storage.conn.is_autocommit());
    assert!(runtime.storage.savepoint_stack.is_empty().await);
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn cancelling_real_nested_host_write_joins_all_stores_and_rolls_back() -> Result<()> {
    let (mut runtime, _dir, signer, root, leaf) = seeded_nested_paid_oracle().await?;
    let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
    let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
    let observed_guest = Arc::new(Mutex::new(None));
    let guest_observation = observed_guest.clone();
    let entered = Arc::new(Notify::new());
    let host_entered = entered.clone();
    let mut user = runtime.linkers.user.clone();
    user.allow_shadowing(true)
        .instance("kontor:built-in/testing")?
        .func_wrap_async("host-error", move |store, (): ()| {
            let depth = store.data().ownership.as_ref().map(|owner| owner.depth);
            let interval = store
                .data()
                .ownership
                .as_ref()
                .and_then(ChildContext::fuel_yield_interval);
            let budget = store.data().invocation_budget.clone();
            let guest_observation = guest_observation.clone();
            let host_entered = host_entered.clone();
            Box::new(async move {
                *guest_observation.lock().await = Some((depth, interval, budget));
                host_entered.notify_one();
                pending::<()>().await;
                Ok((String::new(),))
            })
        })?;
    runtime.linkers = Arc::new(Linkers {
        user,
        native: runtime.linkers.native.clone(),
    });
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let observed = entered.notified();
    tokio::pin!(observed);
    observed.as_mut().enable();
    let call_signer = signer.clone();
    let handle = service
        .start_stateful(&owned.session, move |runtime| {
            Box::pin(async move {
                let value = runtime
                    .execute_api(Some(&call_signer), &root, "chain-probe(false)")
                    .await
                    .map_err(anyhow::Error::from)?;
                Ok(RootOutcome {
                    value,
                    commit: true,
                })
            })
        })
        .await?;
    timeout(Duration::from_secs(30), observed).await?;
    let (depth, interval, budget) = observed_guest
        .lock()
        .await
        .take()
        .context("nested guest observation missing")?;
    assert_eq!(depth, Some(3));
    assert_eq!(interval, Some(API_FUEL_YIELD_INTERVAL));
    let budget = budget.context("nested invocation budget missing")?;
    assert_eq!(budget.live(), 3);
    drop(handle);
    let mut checkout = timeout(Duration::from_secs(4), owned.session.checkout()).await??;
    let recovered = checkout
        .runtime
        .as_mut()
        .context("restored runtime missing")?;
    assert_eq!(budget.live(), 0);
    assert_eq!(receipt_count(recovered).await?, 0);
    assert_eq!(
        token::api::balance(recovered, HolderRef::from(&signer)).await?,
        payer_before
    );
    assert_eq!(
        token::api::balance(recovered, HolderRef::Burner).await?,
        burner_before
    );
    assert!(recovered.storage.conn.is_autocommit());
    assert!(recovered.storage.savepoint_stack.is_empty().await);
    assert!(recovered.stack.is_empty().await);
    assert_eq!(recovered.table.lock().await.iter_mut().count(), 0);
    assert_eq!(
        recovered
            .execute_api(None, &leaf, "storage-state()")
            .await?,
        "[0, 0, 0, 0]"
    );
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn caught_paid_host_panic_quarantines_writer_without_durable_receipt() -> Result<()> {
    let (runtime, _dir, signer, address) = seeded_paid_oracle().await?;
    let conn = runtime.get_storage_conn();
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let result = owned
        .run(true, move |runtime| {
            Box::pin(async move {
                runtime
                    .execute_api(Some(&signer), &address, "host-panic()")
                    .await
                    .map_err(anyhow::Error::from)
            })
        })
        .await;
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("host panic")),
        "unexpected owned host panic result: {result:?}"
    );
    assert!(
        timeout(Duration::from_secs(2), owned.session.checkout())
            .await?
            .is_err(),
        "caught host panic returned the writer to service"
    );
    assert!(conn.is_autocommit());
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    assert_eq!(
        rows.next()
            .await?
            .context("panic receipt count missing")?
            .get::<i64>(0)?,
        0
    );
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn swallowed_paid_host_panic_cannot_commit_writer() -> Result<()> {
    let (runtime, _dir, signer, address) = seeded_paid_oracle().await?;
    let conn = runtime.get_storage_conn();
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let result = owned
        .run(true, move |runtime| {
            Box::pin(async move {
                let error = runtime
                    .execute_api(Some(&signer), &address, "host-panic()")
                    .await
                    .expect_err("host panic must reach the caller");
                assert!(error.to_string().contains("host panic"));
                Ok(())
            })
        })
        .await;
    assert!(result.is_err(), "swallowed host panic committed the writer");
    assert!(
        timeout(Duration::from_secs(2), owned.session.checkout())
            .await?
            .is_err(),
        "swallowed host panic returned the writer to service"
    );
    assert!(conn.is_autocommit());
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    assert_eq!(
        rows.next()
            .await?
            .context("panic receipt count missing")?
            .get::<i64>(0)?,
        0
    );
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn canonical_lease_drains_native_guest_before_releasing_runtime() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let service = OwnerService::new();
    let mut lease = service.begin_canonical(&mut runtime, false).await?;
    let _balance = token::api::balance(&mut runtime, HolderRef::Burner).await?;
    lease.drain(&runtime).await?;
    lease.complete(&mut runtime).await?;
    assert_eq!(service.active_roots().await, 0);
    assert!(runtime.ownership.is_none());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn canonical_drain_waits_for_supervisor_runtime_release() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let service = OwnerService::new();
    let gate = Arc::new(AsyncGate::default());
    let _release = ReleaseAsyncGate(gate.clone());
    service.set_canonical_release_gate(gate.clone());
    let mut lease = service.begin_canonical(&mut runtime, false).await?;
    let mut drain = Box::pin(lease.drain(&runtime));
    timeout(Duration::from_secs(2), async {
        while !gate.entered.load(Ordering::SeqCst) {
            assert!(
                tokio::select! {
                    result = &mut drain => Some(result),
                    () = tokio::task::yield_now() => None,
                }
                .is_none(),
                "drain completed while supervisor retained the runtime"
            );
        }
    })
    .await?;
    assert!(drain.as_mut().now_or_never().is_none());
    gate.release();
    drain.await?;
    lease.complete(&mut runtime).await?;

    let mut next = service.begin_canonical(&mut runtime, false).await?;
    next.drain(&runtime).await?;
    next.complete(&mut runtime).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn canonical_and_simulation_children_keep_no_yield_policy() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let service = OwnerService::new();
    let component = Arc::new(Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?);
    for simulation in [false, true] {
        let mut lease = service.begin_canonical(&mut runtime, simulation).await?;
        let owner = runtime.ownership.clone().context("root context missing")?;
        assert_eq!(owner.fuel_yield_interval(), None);
        let (root_observation, root_store) =
            run_pure_loop_in_store(runtime.make_store(20_000_000)?, &component, 200_000, None)
                .await?;
        let observations = Arc::new(Mutex::new(vec![(
            0,
            root_observation.0,
            root_observation.1,
            root_observation.2,
        )]));
        let child_runtime = runtime.clone();
        let child_component = component.clone();
        let child_observations = observations.clone();
        let child = owner
            .run_guest(move |next| {
                nested_yield_guest(
                    child_runtime,
                    next,
                    child_component,
                    1,
                    child_observations,
                    200_000,
                    20_000_000,
                    None,
                )
            })
            .await?;
        ensure!(matches!(&child.result, Ok(Ok(()))), "nested call failed");
        drop(child);
        drop(root_store);
        for (depth, value, remaining, yielded) in observations.lock().await.iter() {
            assert!(!yielded, "depth {depth} yielded in canonical execution");
            assert_eq!(value, &Val::U32(200_000));
            assert!(*remaining < 20_000_000);
        }
        assert_eq!(observations.lock().await.len(), 3);
        lease.drain(&runtime).await?;
        lease.complete(&mut runtime).await?;
        assert!(runtime.ownership.is_none());
        assert_eq!(service.active_roots().await, 0);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn api_fuel_yield_preserves_pure_pulley_result_fuel_and_gas() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let component = Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?;
    let fuel = 20_000_000;
    let api = run_pure_loop(&runtime, &component, RootKind::Api, 200_000, fuel).await?;
    let canonical = run_pure_loop(&runtime, &component, RootKind::Canonical, 200_000, fuel).await?;
    let simulation =
        run_pure_loop(&runtime, &component, RootKind::Simulation, 200_000, fuel).await?;
    assert!(api.2, "API pure guest did not yield before completion");
    assert!(!canonical.2, "canonical pure guest yielded");
    assert!(!simulation.2, "simulation pure guest yielded");
    assert_eq!(api.0, Val::U32(200_000));
    assert_eq!((&api.0, api.1), (&canonical.0, canonical.1));
    assert_eq!((&canonical.0, canonical.1), (&simulation.0, simulation.1));
    assert_eq!(
        runtime.gas_consumed(fuel, api.1),
        runtime.gas_consumed(fuel, canonical.1)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn nested_api_children_inherit_actual_fuel_yields() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let mut handle = service
        .start_stateful(&owned.session, |runtime| {
            Box::pin(async move {
                let component = Arc::new(Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?);
                let owner = runtime.ownership.clone().context("root context missing")?;
                let (root_observation, root_store) = run_pure_loop_in_store(
                    runtime.make_store(20_000_000)?,
                    &component,
                    200_000,
                    None,
                )
                .await?;
                let observations = Arc::new(Mutex::new(vec![(
                    0,
                    root_observation.0,
                    root_observation.1,
                    root_observation.2,
                )]));
                let child_runtime = runtime.clone();
                let child_component = component.clone();
                let child_observations = observations.clone();
                let child = owner
                    .run_guest(move |next| {
                        nested_yield_guest(
                            child_runtime,
                            next,
                            child_component,
                            1,
                            child_observations,
                            200_000,
                            20_000_000,
                            None,
                        )
                    })
                    .await?;
                ensure!(matches!(&child.result, Ok(Ok(()))), "nested call failed");
                drop(child);
                drop(root_store);
                let values = observations.lock().await.clone();
                Ok(RootOutcome {
                    value: values,
                    commit: false,
                })
            })
        })
        .await?;
    let observations = handle.result().await?;
    assert_eq!(observations.len(), 3);
    let expected_fuel = observations[0].2;
    for (index, (depth, value, remaining, yielded)) in observations.into_iter().enumerate() {
        assert_eq!(depth as usize, index);
        assert!(yielded, "depth {depth} API child did not yield");
        assert_eq!(value, Val::U32(200_000));
        assert_eq!(remaining, expected_fuel);
    }
    assert!(expected_fuel < 20_000_000);
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_nested_yielding_api_guest_joins_before_runtime_reuse() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let leaf_yielded = Arc::new(AtomicBool::new(false));
    let observed_yield = leaf_yielded.clone();
    let handle = service
        .start_stateful(&owned.session, move |runtime| {
            Box::pin(async move {
                let component = Arc::new(Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?);
                let owner = runtime.ownership.clone().context("root context missing")?;
                let child_runtime = runtime.clone();
                let observations = Arc::new(Mutex::new(Vec::new()));
                owner
                    .run_guest(move |next| {
                        nested_yield_guest(
                            child_runtime,
                            next,
                            component,
                            1,
                            observations,
                            100_000_000,
                            2_000_000_000,
                            Some(observed_yield),
                        )
                    })
                    .await?;
                Ok(RootOutcome {
                    value: (),
                    commit: false,
                })
            })
        })
        .await?;
    timeout(Duration::from_secs(10), async {
        while !leaf_yielded.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    drop(handle);
    let mut checkout = timeout(Duration::from_secs(4), owned.session.checkout()).await??;
    let recovered = checkout
        .runtime
        .as_mut()
        .context("restored runtime missing")?;
    assert!(recovered.storage.conn.is_autocommit());
    assert!(recovered.storage.savepoint_stack.is_empty().await);
    assert!(recovered.stack.is_empty().await);
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_fuel_yielding_guest_joins_before_pool_reuse() -> Result<()> {
    let (seed, dir, name) = test_runtime().await?;
    drop(seed);
    let pool = Pool::builder(Manager::new(
        dir.path().to_path_buf(),
        name,
        Network::Regtest,
        100_000,
    )?)
    .max_size(1)
    .build()?;
    let object: Object<Manager> = pool.get().await?;
    let cached = Component::new(&object.engine, PURE_LOOP_COMPONENT)?;
    object
        .component_cache
        .put_selected(
            ComponentSource::new(u64::MAX, PURE_LOOP_COMPONENT.as_bytes()),
            object.executor_version,
            cached,
            PURE_LOOP_COMPONENT.len(),
        )
        .await?;
    let service = OwnerService::new();
    let entered = Arc::new(AtomicBool::new(false));
    let guest_entered = entered.clone();
    let handle = service
        .start_pooled(object, move |runtime| {
            Box::pin(async move {
                let component = Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?;
                let mut store = runtime.make_store(500_000_000)?;
                let linker = Linker::<Runtime>::new(&runtime.engine);
                let instance = linker.instantiate_async(&mut store, &component).await?;
                let run = instance
                    .get_func(&mut store, "run")
                    .context("pure loop export missing")?;
                let mut results = [Val::U32(0)];
                guest_entered.store(true, Ordering::SeqCst);
                run.call_async(&mut store, &[Val::U32(20_000_000)], &mut results)
                    .await?;
                Ok(RootOutcome {
                    value: (),
                    commit: false,
                })
            })
        })
        .await?;
    timeout(Duration::from_secs(10), async {
        while !entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(pool.status().available, 0);
    drop(handle);
    let object = timeout(Duration::from_secs(2), pool.get()).await??;
    assert!(object.storage.conn.is_autocommit());
    assert!(object.component_cache.get(&u64::MAX).await.is_some());
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn eight_view_roots_measure_normal_and_cancelled_drain() -> Result<()> {
    let (mut seed, dir, name) = test_runtime().await?;
    let baseline = token::api::balance(&mut seed, HolderRef::Burner).await?;
    drop(seed);
    let pool: Pool<Manager> = Pool::builder(Manager::new(
        dir.path().to_path_buf(),
        name,
        Network::Regtest,
        100_000,
    )?)
    .max_size(8)
    .build()?;
    let mut prewarmed = Vec::new();
    for _ in 0..8 {
        prewarmed.push(pool.get().await?);
    }
    for object in &mut prewarmed {
        assert_eq!(
            token::api::balance(object, HolderRef::Burner).await?,
            baseline
        );
    }
    drop(prewarmed);
    let unowned_started = Instant::now();
    let mut unowned = JoinSet::new();
    for _ in 0..8 {
        let mut object = pool.get().await?;
        unowned.spawn(async move { token::api::balance(&mut object, HolderRef::Burner).await });
    }
    while let Some(result) = unowned.join_next().await {
        assert_eq!(result??, baseline);
    }
    let unowned_elapsed = unowned_started.elapsed();
    assert_eq!(pool.status().available, 8);
    let service = OwnerService::new();
    let normal_started = Instant::now();
    let mut normal = Vec::new();
    for _ in 0..8 {
        let object = pool.get().await?;
        normal.push(
            service
                .start_pooled(object, |runtime| {
                    Box::pin(async move {
                        Ok(RootOutcome {
                            value: token::api::balance(runtime, HolderRef::Burner).await?,
                            commit: false,
                        })
                    })
                })
                .await?,
        );
    }
    for mut handle in normal {
        assert_eq!(handle.result().await?, baseline);
    }
    let normal_elapsed = normal_started.elapsed();

    let started = Arc::new(AtomicUsize::new(0));
    let mut cancelled = Vec::new();
    for _ in 0..8 {
        let object = pool.get().await?;
        let guest_started = started.clone();
        cancelled.push(
            service
                .start_pooled(object, move |runtime| {
                    Box::pin(async move {
                        let component = Component::new(&runtime.engine, PURE_LOOP_COMPONENT)?;
                        let mut store = runtime.make_store(2_000_000_000)?;
                        let linker = Linker::<Runtime>::new(&runtime.engine);
                        let instance = linker.instantiate_async(&mut store, &component).await?;
                        let run = instance
                            .get_func(&mut store, "run")
                            .context("pure loop export missing")?;
                        let mut results = [Val::U32(0)];
                        guest_started.fetch_add(1, Ordering::SeqCst);
                        run.call_async(&mut store, &[Val::U32(100_000_000)], &mut results)
                            .await?;
                        Ok(RootOutcome {
                            value: (),
                            commit: false,
                        })
                    })
                })
                .await?,
        );
    }
    timeout(Duration::from_secs(10), async {
        while started.load(Ordering::SeqCst) != 8 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(pool.status().available, 0);
    let cancelled_started = Instant::now();
    drop(cancelled);
    timeout(Duration::from_secs(5), async {
        while service.active_roots().await != 0 || pool.status().available != 8 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let cancelled_elapsed = cancelled_started.elapsed();
    println!(
        "eight view roots: unowned_ms={}, owned_ms={}, cancel_drain_ms={}",
        unowned_elapsed.as_millis(),
        normal_elapsed.as_millis(),
        cancelled_elapsed.as_millis()
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_publication_rolls_back_outer_root_transaction() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    token::api::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&signer),
        Decimal::from("1000000000000"),
    )
    .await??;
    let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
    let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
    let payment = Payment {
        signer_id: signer.signer_id().context("test payer identity missing")?,
        gas_limit: runtime.gas_limit_for_non_procs,
    };
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let published = Arc::new(Notify::new());
    let published_id = Arc::new(AtomicU64::new(0));
    let observed = published.notified();
    tokio::pin!(observed);
    observed.as_mut().enable();
    let after_publish = published.clone();
    let recorded_id = published_id.clone();
    let published_signer = signer.clone();
    let handle = service
        .start_stateful(&owned.session, move |runtime| {
            Box::pin(async move {
                runtime
                    .publish(
                        &published_signer,
                        payment,
                        "ownership-publish-cancel",
                        include_bytes!("../../../../../test-contracts/binaries/error_test.wasm.br"),
                        &native_provenance()?,
                    )
                    .await
                    .map_err(anyhow::Error::from)?;
                let address = ContractAddress {
                    name: "ownership-publish-cancel".to_string(),
                    height: 0,
                    tx_index: 0,
                };
                let contract_id = runtime
                    .storage
                    .contract_id(&address)
                    .await?
                    .context("published contract row missing before cancellation")?;
                assert!(runtime.component_cache.get(&contract_id).await.is_some());
                recorded_id.store(contract_id, Ordering::SeqCst);
                after_publish.notify_one();
                pending::<()>().await;
                Ok(RootOutcome {
                    value: (),
                    commit: true,
                })
            })
        })
        .await?;
    timeout(Duration::from_secs(10), observed).await?;
    drop(handle);
    let mut checkout = timeout(Duration::from_secs(2), owned.session.checkout()).await??;
    let recovered = checkout
        .runtime
        .as_mut()
        .context("restored runtime missing")?;
    let address = ContractAddress {
        name: "ownership-publish-cancel".to_string(),
        height: 0,
        tx_index: 0,
    };
    assert!(recovered.storage.contract_id(&address).await?.is_none());
    let mut receipts = recovered
        .storage
        .conn
        .query(
            "SELECT COUNT(*) FROM contract_results WHERE contract_id = ?",
            [published_id.load(Ordering::SeqCst)],
        )
        .await?;
    assert_eq!(
        receipts
            .next()
            .await?
            .context("publication receipt count missing")?
            .get::<i64>(0)?,
        0
    );
    assert!(
        recovered
            .component_cache
            .get(&published_id.load(Ordering::SeqCst))
            .await
            .is_none()
    );
    assert!(recovered.storage.conn.is_autocommit());
    assert_eq!(
        token::api::balance(recovered, HolderRef::from(&signer)).await?,
        payer_before
    );
    assert_eq!(
        token::api::balance(recovered, HolderRef::Burner).await?,
        burner_before
    );
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn cancelled_cold_publication_waits_for_decode_and_compile_workers() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    token::api::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&signer),
        Decimal::from("1000000000000"),
    )
    .await??;
    let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
    let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
    let receipts_before = receipt_count(&runtime).await?;
    let checkpoint_before = checkpoint_hash(&runtime.get_storage_conn()).await?;
    let gas_limit = runtime.gas_limit_for_non_procs;
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    for decode in [true, false] {
        let gate = Arc::new(BlockingGate::default());
        let _release = ReleaseBlockingGate(gate.clone());
        let name = if decode {
            "ownership-cold-decode-cancel"
        } else {
            "ownership-cold-compile-cancel"
        };
        let address = ContractAddress {
            name: name.to_string(),
            height: 0,
            tx_index: 0,
        };
        {
            let mut checkout = owned.session.checkout().await?;
            let runtime = checkout.runtime.as_mut().context("writer missing")?;
            runtime.storage.decode_gate = decode.then(|| gate.clone());
            runtime.compile_gate = (!decode).then(|| gate.clone());
        }
        let payment = Payment {
            signer_id: signer.signer_id().context("test payer missing")?,
            gas_limit,
        };
        let call_signer = signer.clone();
        let handle = service
            .start_stateful(&owned.session, move |runtime| {
                Box::pin(async move {
                    runtime
                        .publish(
                            &call_signer,
                            payment,
                            name,
                            include_bytes!(
                                "../../../../../test-contracts/binaries/error_test.wasm.br"
                            ),
                            &native_provenance()?,
                        )
                        .await
                        .map_err(anyhow::Error::from)?;
                    Ok(RootOutcome {
                        value: (),
                        commit: true,
                    })
                })
            })
            .await?;
        timeout(Duration::from_secs(30), async {
            while !gate.entered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        drop(handle);
        let retained = timeout(Duration::from_millis(100), owned.session.checkout())
            .await
            .is_err();
        gate.release();
        let mut checkout = timeout(Duration::from_secs(5), owned.session.checkout()).await??;
        assert!(
            retained,
            "cold worker released the writer before it finished"
        );
        let runtime = checkout.runtime.as_mut().context("writer missing")?;
        assert!(runtime.storage.contract_id(&address).await?.is_none());
        assert_eq!(receipt_count(runtime).await?, receipts_before);
        assert_eq!(
            checkpoint_hash(&runtime.get_storage_conn()).await?,
            checkpoint_before
        );
        assert_eq!(
            token::api::balance(runtime, HolderRef::from(&signer)).await?,
            payer_before
        );
        assert_eq!(
            token::api::balance(runtime, HolderRef::Burner).await?,
            burner_before
        );
        assert!(runtime.storage.conn.is_autocommit());
        assert!(runtime.storage.savepoint_stack.is_empty().await);
        runtime.storage.decode_gate = None;
        runtime.compile_gate = None;
        assert_eq!(service.active_roots().await, 0);
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_while_publication_guest_init_is_pending_rolls_back_everything() -> Result<()> {
    let (mut runtime, _dir, signer, _address) = seeded_paid_oracle().await?;
    let payer_before = token::api::balance(&mut runtime, HolderRef::from(&signer)).await?;
    let burner_before = token::api::balance(&mut runtime, HolderRef::Burner).await?;
    let checkpoint_before = checkpoint_hash(&runtime.get_storage_conn()).await?;
    let receipts_before = receipt_count(&runtime).await?;
    let mut rows = runtime
        .storage
        .conn
        .query("SELECT COALESCE(MAX(id), 0) + 1 FROM contracts", ())
        .await?;
    let next_contract_id: u64 = rows
        .next()
        .await?
        .context("next contract id missing")?
        .get(0)?;
    drop(rows);
    let gate = Arc::new(AsyncGate::default());
    runtime.init_host_gate = Some((next_contract_id, gate.clone()));
    let payment = Payment {
        signer_id: signer.signer_id().context("test payer missing")?,
        gas_limit: runtime.gas_limit_for_non_procs,
    };
    let service = OwnerService::new();
    let owned = OwnedRuntimeSession::with_service(runtime, service.clone());
    let call_signer = signer.clone();
    let handle = service
        .start_stateful(&owned.session, move |runtime| {
            Box::pin(async move {
                runtime
                    .publish(
                        &call_signer,
                        payment,
                        "ownership-init-cancel",
                        include_bytes!("../../../../../test-contracts/binaries/error_test.wasm.br"),
                        &native_provenance()?,
                    )
                    .await
                    .map_err(anyhow::Error::from)?;
                Ok(RootOutcome {
                    value: (),
                    commit: true,
                })
            })
        })
        .await?;
    let entered = timeout(Duration::from_secs(30), async {
        while !gate.entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    if entered.is_err() {
        gate.release();
        drop(handle);
        return Err(anyhow!(
            "publication init did not enter its storage host call"
        ));
    }
    drop(handle);
    let checkout = timeout(Duration::from_secs(5), owned.session.checkout()).await;
    gate.release();
    let mut checkout = checkout??;
    let runtime = checkout
        .runtime
        .as_mut()
        .context("restored writer missing")?;
    let address = ContractAddress {
        name: "ownership-init-cancel".to_string(),
        height: 0,
        tx_index: 0,
    };
    assert!(runtime.storage.contract_id(&address).await?.is_none());
    assert_eq!(receipt_count(runtime).await?, receipts_before);
    assert_eq!(
        checkpoint_hash(&runtime.get_storage_conn()).await?,
        checkpoint_before
    );
    assert_eq!(
        token::api::balance(runtime, HolderRef::from(&signer)).await?,
        payer_before
    );
    assert_eq!(
        token::api::balance(runtime, HolderRef::Burner).await?,
        burner_before
    );
    assert!(runtime.storage.conn.is_autocommit());
    assert!(runtime.storage.savepoint_stack.is_empty().await);
    assert!(runtime.stack.is_empty().await);
    assert_eq!(runtime.table.lock().await.iter_mut().count(), 0);
    assert!(runtime.invocation_budget.is_none());
    runtime.init_host_gate = None;
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn cancellation_and_commit_authorization_have_one_durable_outcome() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    runtime
        .storage
        .conn
        .execute(
            "CREATE TABLE ownership_commit_race (id INTEGER PRIMARY KEY)",
            (),
        )
        .await?;
    let mut runtime = runtime;

    for id in 1..=10i64 {
        let capacity = Arc::new(Semaphore::new(1)).acquire_owned().await?;
        let keeper = Arc::new(RootKeeper::new_stateful(
            RootId(id as u64),
            runtime,
            capacity,
        ));
        {
            let mut authority = keeper.authority.lock().await;
            let runtime = authority.as_mut().expect("root authority retained");
            runtime.storage.savepoint().await?;
            runtime
                .storage
                .conn
                .execute("INSERT INTO ownership_commit_race (id) VALUES (?)", [id])
                .await?;
        }
        let committed = if id == 1 {
            keeper.close();
            restore(
                &keeper,
                Ok(RootOutcome {
                    value: (),
                    commit: true,
                }),
            )
            .await?
            .is_ok()
        } else if id == 2 {
            let committed = restore(
                &keeper,
                Ok(RootOutcome {
                    value: (),
                    commit: true,
                }),
            )
            .await?
            .is_ok();
            keeper.close();
            committed
        } else {
            let barrier = Arc::new(Barrier::new(3));
            let cancellation_keeper = keeper.clone();
            let cancellation_barrier = barrier.clone();
            let cancellation = tokio::spawn(async move {
                cancellation_barrier.wait().await;
                cancellation_keeper.close();
            });
            let commit_keeper = keeper.clone();
            let commit_barrier = barrier.clone();
            let commit = tokio::spawn(async move {
                commit_barrier.wait().await;
                restore(
                    &commit_keeper,
                    Ok(RootOutcome {
                        value: (),
                        commit: true,
                    }),
                )
                .await
            });
            barrier.wait().await;
            cancellation.await?;
            commit.await??.is_ok()
        };
        if id == 1 {
            assert!(!committed, "cancellation won before authorization");
        } else if id == 2 {
            assert!(committed, "commit was authorized before cancellation");
        }
        let count = {
            let authority = keeper.authority.lock().await;
            let runtime = authority.as_ref().expect("root authority retained");
            let mut rows = runtime
                .storage
                .conn
                .query(
                    "SELECT COUNT(*) FROM ownership_commit_race WHERE id = ?",
                    [id],
                )
                .await?;
            rows.next()
                .await?
                .context("commit count missing")?
                .get::<i64>(0)?
        };
        assert_eq!(count, i64::from(committed));
        assert_eq!(
            RootState::load(&keeper.state),
            if committed {
                RootState::Committing
            } else {
                RootState::Closing
            }
        );
        runtime = match keeper
            .authority
            .lock()
            .await
            .take()
            .context("root authority missing after race")?
        {
            RootAuthority::Stateful(runtime) => runtime,
            RootAuthority::Pooled(_)
            | RootAuthority::LinkedPooled(_)
            | RootAuthority::LinkedStateful(_) => {
                unreachable!("race uses a stateful writer")
            }
        };
    }
    Ok(())
}

#[tokio::test]
async fn canonical_child_panic_cannot_commit_or_leave_reactor_waiting() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let service = OwnerService::new();
    let mut lease = service.begin_canonical(&mut runtime, false).await?;
    runtime.storage.savepoint().await?;
    let owner = runtime
        .ownership
        .clone()
        .expect("canonical context installed");
    let result = timeout(
        Duration::from_secs(2),
        owner.run_guest(|_| async { panic!("forced canonical child failure") }),
    )
    .await?;
    assert!(result.is_err());
    assert!(runtime.storage.commit().await.is_err());
    assert!(lease.drain(&runtime).await.is_err());
    drop(lease);
    assert!(service.is_fatal());
    Ok(())
}

#[tokio::test]
async fn abandoned_canonical_guest_cannot_commit() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let service = OwnerService::new();
    let mut lease = service.begin_canonical(&mut runtime, false).await?;
    runtime.storage.savepoint().await?;
    let mut store = runtime.make_store(1_000_000)?;
    let owner = runtime
        .ownership
        .clone()
        .expect("canonical context installed");
    let started = Arc::new(Notify::new());
    let observed = started.notified();
    tokio::pin!(observed);
    observed.as_mut().enable();
    let child_started = started.clone();
    let request = tokio::spawn(async move {
        owner
            .run_guest(|child| async move {
                store.data_mut().ownership = Some(child);
                child_started.notify_one();
                pending().await
            })
            .await
    });
    timeout(Duration::from_secs(2), observed).await?;
    request.abort();
    let _ = request.await;
    assert!(
        timeout(Duration::from_secs(2), lease.drain(&runtime))
            .await?
            .is_err()
    );
    assert!(runtime.storage.commit().await.is_err());
    drop(lease);
    assert!(service.is_fatal());
    Ok(())
}

#[tokio::test]
async fn stateful_session_retains_runtime_across_owned_calls() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let session = OwnedRuntimeSession::new(runtime);
    session
        .run(false, |runtime| {
            Box::pin(async move {
                runtime.node_label = "owned-session".to_string();
                Ok(())
            })
        })
        .await?;
    let label = session
        .run(false, |runtime| {
            Box::pin(async move { Ok(runtime.node_label.clone()) })
        })
        .await?;
    assert_eq!(label, "owned-session");
    Ok(())
}

#[tokio::test]
async fn dropped_stateful_call_releases_runtime_only_after_child_join() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let session = OwnedRuntimeSession::new(runtime);
    let started = Arc::new(Notify::new());
    let child_started = started.clone();
    let interrupted = session.clone();
    let request = tokio::spawn(async move {
        interrupted
            .run(false, move |runtime| {
                Box::pin(async move {
                    let owner = runtime.ownership.clone().expect("owned runtime context");
                    let store = runtime.make_store(1_000_000)?;
                    owner
                        .run_guest(|child| async move {
                            let mut store = store;
                            store.data_mut().ownership = Some(child);
                            child_started.notify_one();
                            pending().await
                        })
                        .await?;
                    Ok(())
                })
            })
            .await
    });
    timeout(Duration::from_secs(2), started.notified()).await?;
    request.abort();
    let _ = request.await;
    let _label = timeout(
        Duration::from_secs(2),
        session.run(false, |runtime| {
            Box::pin(async move { Ok(runtime.node_label.clone()) })
        }),
    )
    .await??;
    Ok(())
}

#[tokio::test]
async fn undelivered_store_retains_parent_slot() -> Result<()> {
    let dir = TempDir::new()?;
    let pool = one_object_pool(&dir).await?;
    let object = pool.get().await?;
    let store = object.make_store(1_000_000)?;
    let budget = store.data().invocation_budget.as_ref().unwrap().clone();
    let slot = Arc::new(AtomicBool::new(true));
    let (sender, receiver) = oneshot::channel();
    sender
        .send(GuestDelivery {
            completion: TaskCompletion::Local(GuestCompletion {
                result: Ok(Ok(())),
                results: Vec::new(),
                store,
                host_panicked: false,
            }),
            slot: SlotLease(slot.clone()),
        })
        .map_err(|_| anyhow!("delivery receiver closed"))?;
    assert!(slot.load(Ordering::SeqCst));
    assert_eq!(budget.live(), 1);
    drop(receiver);
    assert!(!slot.load(Ordering::SeqCst));
    assert_eq!(budget.live(), 0);
    Ok(())
}

#[tokio::test]
async fn reserved_permit_is_released_when_parent_is_aborted() -> Result<()> {
    let (sender, mut receiver) = mpsc::channel(1);
    let state = Arc::new(AtomicU8::new(RootState::Running as u8));
    let owner = ChildContext::root(
        RootId(1),
        RootKind::Api,
        sender.clone(),
        state.clone(),
        Arc::new(BlockingRegistry::default()),
        Arc::new(AtomicBool::new(false)),
    );
    let slot = owner.slot.clone();
    let permit = sender.reserve().await?;
    let parent =
        tokio::spawn(async move { owner.run_guest(|_| async move { pending().await }).await });
    timeout(Duration::from_secs(2), async {
        while !slot.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    state.store(RootState::Closing as u8, Ordering::SeqCst);
    receiver.close();
    parent.abort();
    let _ = parent.await;
    drop(permit);
    assert!(receiver.recv().await.is_none());
    assert!(!slot.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn depth64_parent_with_preclose_permit_drains_before_pool_reuse() -> Result<()> {
    let dir = TempDir::new()?;
    let pool = one_object_pool(&dir).await?;
    let object = pool.get().await?;
    let service = OwnerService::new();
    let (ready_tx, ready_rx) = oneshot::channel();
    let gate = Arc::new(Notify::new());
    let root_gate = gate.clone();
    let handle = service
        .start_pooled(object, move |runtime| {
            Box::pin(async move {
                let store = runtime.make_store(1_000_000)?;
                let owner = runtime.ownership.clone().context("root context missing")?;
                let child_runtime = runtime.clone();
                let ready = Arc::new(Mutex::new(Some(ready_tx)));
                let child = owner
                    .run_guest(move |next| {
                        nested_depth64_guest(child_runtime, next, 1, ready, root_gate)
                    })
                    .await?;
                ensure!(matches!(&child.result, Ok(Ok(()))), "nested call failed");
                drop(child);
                drop(store);
                Ok(RootOutcome {
                    value: (),
                    commit: false,
                })
            })
        })
        .await?;
    let (sender, slot, budget) = timeout(Duration::from_secs(20), ready_rx).await??;
    assert_eq!(budget.live(), 64);
    let permit = timeout(Duration::from_secs(2), sender.reserve()).await??;
    gate.notify_one();
    timeout(Duration::from_secs(2), async {
        while !slot.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    drop(handle);
    drop(permit);
    let object = timeout(Duration::from_secs(5), pool.get()).await??;
    assert_eq!(budget.live(), 0);
    assert!(object.storage.conn.is_autocommit());
    assert!(object.storage.savepoint_stack.is_empty().await);
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn panic_discards_pool_object_after_quiescence() -> Result<()> {
    let dir = TempDir::new()?;
    let pool = one_object_pool(&dir).await?;
    let object = pool.get().await?;
    let poisoned_id = Object::id(&object);
    let service = OwnerService::new();
    let mut handle = service
        .start_pooled(object, |_runtime| {
            Box::pin(async move {
                panic!("injected root panic");
                #[allow(unreachable_code)]
                Ok(RootOutcome {
                    value: (),
                    commit: false,
                })
            })
        })
        .await?;
    assert!(handle.result().await.is_err());
    timeout(Duration::from_secs(2), async {
        while service.active_roots().await != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let fresh = timeout(Duration::from_secs(2), pool.get()).await??;
    assert_ne!(Object::id(&fresh), poisoned_id);
    Ok(())
}

#[tokio::test]
async fn supervisor_panic_fences_live_pool_authority_and_fails_driver() -> Result<()> {
    let dir = TempDir::new()?;
    let pool = one_object_pool(&dir).await?;
    let object = pool.get().await?;
    let service = OwnerService::new();
    let gate = Arc::new(AsyncGate::default());
    let _release = ReleaseAsyncGate(gate.clone());
    *service
        .registry
        .supervisor_panic_after_root_entered
        .lock()
        .expect("supervisor panic gate lock poisoned") = Some(gate.clone());
    let operation_gate = gate.clone();
    let finished = Arc::new(AtomicBool::new(false));
    let operation_finished = finished.clone();
    let mut handle = service
        .start_pooled(object, move |runtime| {
            Box::pin(async move {
                assert!(!runtime.storage.conn.is_autocommit());
                operation_gate.wait().await;
                operation_finished.store(true, Ordering::SeqCst);
                Ok(RootOutcome {
                    value: (),
                    commit: false,
                })
            })
        })
        .await?;
    let driver = service.take_driver().context("owner driver missing")?;
    let reported = timeout(Duration::from_secs(2), driver).await??;
    assert!(
        reported
            .as_ref()
            .is_err_and(|error| error.to_string().contains("node supervisor panicked")),
        "supervisor panic did not fail the driver: {reported:?}"
    );
    assert!(
        timeout(Duration::from_secs(2), handle.result())
            .await?
            .is_err()
    );
    assert!(gate.entered.load(Ordering::SeqCst));
    assert!(service.is_fatal());
    assert_eq!(service.quarantined_roots().await, 1);
    assert_eq!(pool.status().available, 0);
    assert!(
        timeout(Duration::from_millis(100), pool.get())
            .await
            .is_err()
    );
    assert!(service.admission.reserve().await.is_err());
    gate.release();
    timeout(Duration::from_secs(2), async {
        while !finished.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(pool.status().available, 0);
    Ok(())
}

#[tokio::test]
async fn dropped_blocking_receiver_does_not_release_work_early() -> Result<()> {
    let registry = BlockingRegistry::default();
    let (release, blocked) = std::sync::mpsc::channel();
    let receiver = registry.spawn(move || blocked.recv())?;
    drop(receiver);
    assert!(
        timeout(Duration::from_millis(30), registry.wait_all())
            .await
            .is_err()
    );
    release.send(())?;
    timeout(Duration::from_secs(2), registry.wait_all()).await?;
    Ok(())
}

#[tokio::test]
async fn blocking_drain_closes_registration_before_empty_snapshot() -> Result<()> {
    let registry = BlockingRegistry::default();
    let (release, blocked) = std::sync::mpsc::channel();
    let receiver = registry.spawn(move || blocked.recv())?;
    registry.close_registration();
    assert!(registry.spawn(|| 1u8).is_err());
    assert!(
        timeout(Duration::from_millis(30), registry.wait_all())
            .await
            .is_err()
    );
    release.send(())?;
    timeout(Duration::from_secs(2), registry.wait_all()).await?;
    receiver.await???;
    assert!(registry.spawn(|| 2u8).is_err());
    Ok(())
}

#[tokio::test]
async fn root_capacity_retains_quarantined_authority() -> Result<()> {
    let service = OwnerService::new();
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut other_permits = Vec::new();
    for _ in 0..NODE_ADMISSION_CAPACITY - 1 {
        other_permits.push(service.reserve_root_capacity().await?);
    }
    let capacity = service.reserve_root_capacity().await?;
    let keeper = Arc::new(RootKeeper::new_stateful(RootId(99), runtime, capacity));
    service
        .registry
        .roots
        .lock()
        .await
        .insert(keeper.id, keeper.clone());
    keeper.quarantine();
    assert!(
        timeout(Duration::from_millis(30), service.reserve_root_capacity())
            .await
            .is_err()
    );
    keeper.quiescent.store(true, Ordering::SeqCst);
    service.registry.roots.lock().await.remove(&keeper.id);
    drop(keeper);
    let released = timeout(Duration::from_secs(2), service.reserve_root_capacity()).await??;
    drop(released);
    drop(other_permits);
    Ok(())
}

#[tokio::test]
async fn reported_bundle_failure_quarantines_even_if_guest_catches_error() -> Result<()> {
    let service = OwnerService::new();
    let (runtime, _dir, _name) = test_runtime().await?;
    let keeper = Arc::new(RootKeeper::new_stateful(
        RootId(100),
        runtime,
        service.reserve_root_capacity().await?,
    ));
    let (sender, _receiver) = mpsc::channel(1);
    let context = ChildContext::root(
        keeper.id,
        RootKind::Api,
        sender,
        keeper.state.clone(),
        keeper.blocking.clone(),
        keeper.caught_host_panic.clone(),
    );
    let adapter = OwnerAdapter::new(&keeper, context);
    assert!((adapter.check_commit)(adapter.root.clone()).is_ok());
    assert!((adapter.report_failure)(adapter.root.clone(), 2).is_ok());
    assert_eq!(RootState::load(&keeper.state), RootState::Quarantined);
    assert!((adapter.check_commit)(adapter.root.clone()).is_err());
    assert_eq!((adapter.check_commit)(Arc::new(7u8)).unwrap_err().0, 2);
    assert!((adapter.check_commit)(adapter.root.clone()).is_err());
    keeper.quiescent.store(true, Ordering::SeqCst);
    Ok(())
}

#[tokio::test]
async fn expired_tokens_only_allow_root_commit_check_during_settlement() -> Result<()> {
    let service = OwnerService::new();
    let (runtime, _dir, _name) = test_runtime().await?;
    let keeper = Arc::new(RootKeeper::new_stateful(
        RootId(102),
        runtime,
        service.reserve_root_capacity().await?,
    ));
    let (sender, _receiver) = mpsc::channel(1);
    let context = ChildContext::root(
        keeper.id,
        RootKind::Api,
        sender,
        keeper.state.clone(),
        keeper.blocking.clone(),
        keeper.caught_host_panic.clone(),
    );
    let adapter = OwnerAdapter::new(&keeper, context.clone());
    context.alive.store(false, Ordering::SeqCst);
    keeper
        .state
        .store(RootState::Committing as u8, Ordering::SeqCst);
    let guest: GuestFactory = Box::new(|_| Box::pin(async { (false, Box::new(1u8) as Payload) }));
    let guest_error = (adapter.submit_guest)(adapter.root.clone(), guest)
        .await
        .unwrap_err();
    assert_eq!(guest_error.0, 2);
    let blocking_error =
        (adapter.submit_blocking)(adapter.root.clone(), Box::new(|| Box::new(2u8) as Payload))
            .await
            .unwrap_err();
    assert_eq!(blocking_error.0, 2);
    assert!((adapter.check_commit)(adapter.root.clone()).is_ok());
    let expired_child = ChildContext {
        task: TaskId {
            root: keeper.id,
            local: 1,
        },
        depth: 1,
        alive: Arc::new(AtomicBool::new(false)),
        ..context
    };
    let child_adapter = OwnerAdapter::new(&keeper, expired_child);
    assert_eq!(
        (child_adapter.check_commit)(child_adapter.root.clone())
            .unwrap_err()
            .0,
        2
    );
    keeper.quiescent.store(true, Ordering::SeqCst);
    Ok(())
}

#[tokio::test]
async fn exported_host_panic_cannot_authorize_sql_commit() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let conn = runtime.storage.conn.clone();
    conn.execute(
        "CREATE TABLE host_panic_commit (id INTEGER PRIMARY KEY)",
        (),
    )
    .await?;
    let keeper = Arc::new(RootKeeper::new_stateful(
        RootId(101),
        runtime,
        Arc::new(Semaphore::new(1)).acquire_owned().await?,
    ));
    {
        let mut authority = keeper.authority.lock().await;
        let runtime: &mut Runtime = authority.as_mut().expect("root authority retained");
        runtime.storage.savepoint().await?;
        runtime
            .storage
            .conn
            .execute("INSERT INTO host_panic_commit (id) VALUES (1)", ())
            .await?;
    }
    keeper.caught_host_panic.store(true, Ordering::SeqCst);
    restore(
        &keeper,
        Ok(RootOutcome {
            value: (),
            commit: true,
        }),
    )
    .await??;
    let mut rows = conn
        .query("SELECT COUNT(*) FROM host_panic_commit", ())
        .await?;
    let count: i64 = rows.next().await?.context("count row missing")?.get(0)?;
    assert_eq!(count, 0);
    keeper.quarantine();
    Ok(())
}

#[tokio::test]
async fn linked_guest_runs_under_node_owner_and_returns_opaque_payload() -> Result<()> {
    let (runtime, dir, name) = test_runtime().await?;
    let selection = select_legacy_p1(
        &runtime.storage.conn,
        Network::Regtest,
        ApplicationPosition::View,
    )
    .await?;
    let factory: SessionFactory = Arc::new(|_| {
        Box::pin(async {
            let action: SessionAction = Arc::new(|_| Box::pin(async { Ok(()) }));
            let make_root = Arc::new(|_selection, _adapter| {
                let action: SessionAction = Arc::new(|_| Box::pin(async { Ok(()) }));
                Ok(RootHooks {
                    prepare: action.clone(),
                    inspect_canonical_drain: action,
                    settle: Arc::new(|_, _| Box::pin(async { Ok(()) })),
                    reset: Arc::new(|_, _, _| Box::pin(async { Ok(()) })),
                })
            });
            Ok(ExecutorSession {
                execution_definition: execution_definition(),
                origin: ExecutorVersion::LegacyP1,
                operations: Default::default(),
                owner: Arc::new(()),
                make_root,
                recycle: action,
            })
        })
    });
    let pool = new_linked(dir.path().to_path_buf(), name, factory, 1)?;
    let service = OwnerService::new();
    let capacity = service.reserve_root_capacity().await?;
    let mut object = pool.get().await?;
    object.conn.execute("BEGIN", ()).await?;
    object.snapshot.select(selection.clone())?;
    pool.manager()
        .select(&mut object, &selection, Network::Regtest)
        .await?;
    let object = AdmittedRead::new(object);
    let permit = service.reserve_read_start().await?;
    let operation: LinkedOperation = Box::new(|_, adapter| {
        Box::pin(async move {
            let guest: GuestFactory =
                Box::new(|_child| Box::pin(async { (false, Box::new(7u8) as Payload) }));
            let (panicked, payload) = (adapter.submit_guest)(adapter.root.clone(), guest).await?;
            if panicked {
                return Err((1, "guest unexpectedly panicked".into()));
            }
            let value = *payload
                .downcast::<u8>()
                .map_err(|_| (2, "opaque guest payload type mismatch".into()))?;
            let blocking = (adapter.submit_blocking)(
                adapter.root.clone(),
                Box::new(|| Box::new(9u8) as Payload),
            )
            .await?;
            let blocking_value = *blocking
                .downcast::<u8>()
                .map_err(|_| (2, "opaque blocking payload type mismatch".into()))?;
            if blocking_value != 9 {
                return Err((0, "blocking work returned the wrong value".into()));
            }
            Ok((Box::new(value) as Payload, true))
        })
    });
    let mut handle = service
        .start_linked_pooled_reserved(object, capacity, permit, selection, operation)
        .await?;
    let value = handle.result().await?;
    assert_eq!(
        *value
            .downcast::<u8>()
            .map_err(|_| anyhow!("root payload type mismatch"))?,
        7
    );
    assert_eq!(service.quarantined_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn linked_stateful_commit_uses_root_token_after_operation_returns() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let conn = runtime.storage.conn.clone();
    conn.execute(
        "CREATE TABLE linked_stateful_commit (id INTEGER PRIMARY KEY)",
        (),
    )
    .await?;
    let selection = select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::View).await?;
    let hook_conn = conn.clone();
    let make_root = Arc::new(move |_selection, adapter: OwnerAdapter| {
        let prepare_conn = hook_conn.clone();
        let prepare: SessionAction = Arc::new(move |_| {
            let conn = prepare_conn.clone();
            Box::pin(async move {
                conn.execute("BEGIN", ())
                    .await
                    .map(|_| ())
                    .map_err(|error| (0, error.to_string()))
            })
        });
        let settle_conn = hook_conn.clone();
        let check_commit = adapter.check_commit.clone();
        let root_token = adapter.root.clone();
        Ok(RootHooks {
            prepare,
            inspect_canonical_drain: Arc::new(|_| Box::pin(async { Ok(()) })),
            settle: Arc::new(move |_, commit| {
                let conn = settle_conn.clone();
                let check_commit = check_commit.clone();
                let root_token = root_token.clone();
                Box::pin(async move {
                    if commit {
                        check_commit(root_token)?;
                    }
                    conn.execute(if commit { "COMMIT" } else { "ROLLBACK" }, ())
                        .await
                        .map(|_| ())
                        .map_err(|error| (0, error.to_string()))
                })
            }),
            reset: Arc::new(|_, _, _| Box::pin(async { Ok(()) })),
        })
    });
    let executor = ExecutorSession {
        execution_definition: execution_definition(),
        origin: ExecutorVersion::LegacyP1,
        operations: Default::default(),
        owner: Arc::new(()),
        make_root,
        recycle: Arc::new(|_| Box::pin(async { Ok(()) })),
    };
    let session = LinkedStatefulSession::new(LinkedSession::new(conn.clone(), executor));
    let service = OwnerService::new();
    let operation_conn = conn.clone();
    let operation: LinkedOperation = Box::new(move |_, _| {
        Box::pin(async move {
            operation_conn
                .execute("INSERT INTO linked_stateful_commit (id) VALUES (1)", ())
                .await
                .map_err(|error| (0, error.to_string()))?;
            Ok((Box::new(7u8) as Payload, true))
        })
    });
    let mut handle = service
        .start_linked_stateful_reserved(
            &session,
            service.reserve_root_capacity().await?,
            selection,
            operation,
        )
        .await?;
    let value = handle.result().await?;
    assert_eq!(*value.downcast::<u8>().expect("root payload type"), 7);
    let mut rows = conn
        .query("SELECT COUNT(*) FROM linked_stateful_commit", ())
        .await?;
    assert_eq!(
        rows.next()
            .await?
            .context("commit count missing")?
            .get::<i64>(0)?,
        1
    );
    assert_eq!(service.quarantined_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn linked_canonical_cleanup_outlives_completion_caller() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let selection = select_legacy_p1(
        &runtime.storage.conn,
        Network::Regtest,
        ApplicationPosition::Committee,
    )
    .await?;
    let gate = Arc::new(AsyncGate::default());
    let make_root_gate = gate.clone();
    let executor = ExecutorSession {
        execution_definition: execution_definition(),
        origin: ExecutorVersion::LegacyP1,
        operations: Default::default(),
        owner: Arc::new(()),
        make_root: Arc::new(move |_, _| {
            let action: SessionAction = Arc::new(|_| Box::pin(async { Ok(()) }));
            let reset_gate = make_root_gate.clone();
            Ok(RootHooks {
                prepare: action.clone(),
                inspect_canonical_drain: action,
                settle: Arc::new(|_, _| Box::pin(async { Ok(()) })),
                reset: Arc::new(move |_, _, _| {
                    let gate = reset_gate.clone();
                    Box::pin(async move {
                        gate.wait().await;
                        Ok(())
                    })
                }),
            })
        }),
        recycle: Arc::new(|_| Box::pin(async { Ok(()) })),
    };
    let session = LinkedSession::new(runtime.storage.conn.clone(), executor);
    let service = OwnerService::new();
    let lease = service
        .begin_linked_canonical_reserved(
            &session,
            service.reserve_root_capacity().await?,
            selection,
            false,
        )
        .await?;
    assert!((lease.adapter().check_commit)(lease.adapter().root.clone()).is_ok());
    let DrainedCanonicalRoot::NoTransaction(lease) = lease.drain().await? else {
        return Err(anyhow!("unexpected transaction"));
    };
    let complete = tokio::spawn(lease.complete());
    timeout(Duration::from_secs(2), async {
        while !gate.entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    complete.abort();
    let _ = complete.await;
    assert!(session.canonical_busy.load(Ordering::SeqCst));
    assert_eq!(service.active_roots().await, 1);
    gate.release();
    timeout(Duration::from_secs(2), async {
        while session.canonical_busy.load(Ordering::SeqCst) || service.active_roots().await != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(service.quarantined_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn linked_canonical_settlement_selects_rollback_or_commit_once() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let conn = runtime.storage.conn.clone();
    conn.execute(
        "CREATE TABLE linked_canonical_settlement (id INTEGER PRIMARY KEY)",
        (),
    )
    .await?;
    let selection =
        select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::Committee).await?;
    let root_conn = conn.clone();
    let settlements = Arc::new(AtomicUsize::new(0));
    let root_settlements = settlements.clone();
    let executor = ExecutorSession {
        execution_definition: execution_definition(),
        origin: ExecutorVersion::LegacyP1,
        operations: Default::default(),
        owner: Arc::new(()),
        make_root: Arc::new(move |_, _| {
            let prepare_conn = root_conn.clone();
            let settle_conn = root_conn.clone();
            let count = root_settlements.clone();
            Ok(RootHooks {
                prepare: Arc::new(move |_| {
                    let conn = prepare_conn.clone();
                    Box::pin(async move {
                        conn.execute("BEGIN", ())
                            .await
                            .map_err(|error| (0, error.to_string()))?;
                        Ok(())
                    })
                }),
                inspect_canonical_drain: Arc::new(|_| Box::pin(async { Ok(()) })),
                settle: Arc::new(move |_, commit| {
                    let conn = settle_conn.clone();
                    let count = count.clone();
                    Box::pin(async move {
                        conn.execute(if commit { "COMMIT" } else { "ROLLBACK" }, ())
                            .await
                            .map_err(|error| (0, error.to_string()))?;
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                }),
                reset: Arc::new(|_, _, _| Box::pin(async { Ok(()) })),
            })
        }),
        recycle: Arc::new(|_| Box::pin(async { Ok(()) })),
    };
    let session = LinkedSession::new(conn.clone(), executor);
    let service = OwnerService::new();
    for (id, commit) in [(1i64, false), (2i64, true)] {
        let lease = service
            .begin_linked_canonical_reserved(
                &session,
                service.reserve_root_capacity().await?,
                selection.clone(),
                false,
            )
            .await?;
        conn.execute(
            "INSERT INTO linked_canonical_settlement (id) VALUES (?)",
            [id],
        )
        .await?;
        let lease = lease.drain().await?.require_settlement()?;
        let lease = lease.settle(commit).await?;
        lease.complete().await?;
    }
    let mut rows = conn
        .query("SELECT id FROM linked_canonical_settlement", ())
        .await?;
    assert_eq!(
        rows.next()
            .await?
            .context("committed row missing")?
            .get::<i64>(0)?,
        2
    );
    assert!(rows.next().await?.is_none());
    assert_eq!(settlements.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn linked_canonical_admission_rejects_wrong_selection_purpose() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let conn = runtime.storage.conn.clone();
    let action: SessionAction = Arc::new(|_| Box::pin(async { Ok(()) }));
    let executor = ExecutorSession {
        execution_definition: execution_definition(),
        origin: ExecutorVersion::LegacyP1,
        operations: Default::default(),
        owner: Arc::new(()),
        make_root: Arc::new(move |_, _| {
            let action: SessionAction = Arc::new(|_| Box::pin(async { Ok(()) }));
            Ok(RootHooks {
                prepare: action.clone(),
                inspect_canonical_drain: action,
                settle: Arc::new(|_, _| Box::pin(async { Ok(()) })),
                reset: Arc::new(|_, _, _| Box::pin(async { Ok(()) })),
            })
        }),
        recycle: action,
    };
    let session = LinkedSession::new(conn.clone(), executor);
    let service = OwnerService::new();
    let view = select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::View).await?;
    let preparation = select_legacy_p1(
        &conn,
        Network::Regtest,
        ApplicationPosition::Preparation {
            anchor_height: 0,
            anchor_hash: None,
        },
    )
    .await?;
    let committee =
        select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::Committee).await?;
    let simulation = select_legacy_p1(
        &conn,
        Network::Regtest,
        ApplicationPosition::Simulation { height: 0 },
    )
    .await?;
    for (selection, simulated) in [
        (view.clone(), false),
        (view, true),
        (preparation, false),
        (committee, true),
        (simulation.clone(), false),
    ] {
        assert!(
            service
                .begin_linked_canonical_reserved(
                    &session,
                    service.reserve_root_capacity().await?,
                    selection,
                    simulated,
                )
                .await
                .is_err()
        );
        assert!(!session.canonical_busy.load(Ordering::SeqCst));
        assert_eq!(service.active_roots().await, 0);
    }
    let lease = service
        .begin_linked_canonical_reserved(
            &session,
            service.reserve_root_capacity().await?,
            simulation,
            true,
        )
        .await?;
    let DrainedCanonicalRoot::NoTransaction(lease) = lease.drain().await? else {
        return Err(anyhow!("unexpected transaction"));
    };
    lease.complete().await?;
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

async fn blocking_worker_panic_fences_pooled_authority(abandon_receiver: bool) -> Result<()> {
    let dir = TempDir::new()?;
    let pool = one_object_pool(&dir).await?;
    let object = pool.get().await?;
    let poisoned_id = Object::id(&object);
    let service = OwnerService::new();
    let mut handle = service
        .start_pooled(object, move |runtime| {
            Box::pin(async move {
                let owner = runtime.ownership.clone().context("root owner missing")?;
                if abandon_receiver {
                    drop(
                        owner
                            .blocking
                            .spawn(|| -> () { panic!("injected abandoned blocking panic") }),
                    );
                } else {
                    let result: Result<()> = owner
                        .run_blocking(|| -> () { panic!("injected attached blocking panic") })
                        .await;
                    ensure!(result.is_err(), "blocking panic returned success");
                    ensure!(
                        runtime.storage.commit().await.is_err(),
                        "blocking panic allowed a root commit"
                    );
                }
                Ok(RootOutcome {
                    value: (),
                    commit: true,
                })
            })
        })
        .await?;
    ensure!(
        timeout(Duration::from_secs(5), handle.result())
            .await?
            .is_err(),
        "blocking panic returned an owned success"
    );
    timeout(Duration::from_secs(5), async {
        while service.active_roots().await != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let fresh = timeout(Duration::from_secs(5), pool.get()).await??;
    assert_ne!(Object::id(&fresh), poisoned_id);
    Ok(())
}

#[tokio::test]
async fn attached_blocking_panic_discards_pooled_authority() -> Result<()> {
    blocking_worker_panic_fences_pooled_authority(false).await
}

#[tokio::test]
async fn abandoned_blocking_panic_discards_pooled_authority() -> Result<()> {
    blocking_worker_panic_fences_pooled_authority(true).await
}

#[tokio::test]
async fn ordinary_blocking_error_keeps_pooled_authority_reusable() -> Result<()> {
    let dir = TempDir::new()?;
    let pool = one_object_pool(&dir).await?;
    let object = pool.get().await?;
    let original_id = Object::id(&object);
    let service = OwnerService::new();
    let mut handle = service
        .start_pooled(object, move |runtime| {
            Box::pin(async move {
                let owner = runtime.ownership.clone().context("root owner missing")?;
                let content = owner
                    .run_blocking(|| Err::<(), _>(anyhow!("ordinary content error")))
                    .await?;
                ensure!(content.is_err(), "ordinary blocking error was lost");
                Ok(RootOutcome {
                    value: (),
                    commit: false,
                })
            })
        })
        .await?;
    handle.result().await?;
    assert_eq!(service.active_roots().await, 0);
    let reused = timeout(Duration::from_secs(5), pool.get()).await??;
    assert_eq!(Object::id(&reused), original_id);
    Ok(())
}

#[tokio::test]
async fn canonical_blocking_panic_prevents_drain_and_commit() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let service = OwnerService::new();
    let mut lease = service.begin_canonical(&mut runtime, false).await?;
    let owner = runtime
        .ownership
        .clone()
        .context("canonical owner missing")?;
    let result: Result<()> = owner
        .run_blocking(|| -> () { panic!("injected canonical blocking panic") })
        .await;
    assert!(result.is_err());
    assert!(lease.drain(&runtime).await.is_err());
    assert!(runtime.storage.commit().await.is_err());
    drop(lease);
    assert!(service.is_fatal());
    Ok(())
}

#[tokio::test]
async fn drain_timeout_retains_capacity_until_blocking_work_finishes() -> Result<()> {
    let dir = TempDir::new()?;
    let pool = one_object_pool(&dir).await?;
    let object = pool.get().await?;
    let poisoned_id = Object::id(&object);
    let service = OwnerService::new();
    let started = Arc::new(Notify::new());
    let work_started = started.clone();
    let (release, blocked) = std::sync::mpsc::channel();
    let handle = service
        .start_pooled(object, move |runtime| {
            Box::pin(async move {
                let owner = runtime.ownership.clone().expect("owned runtime context");
                owner
                    .run_blocking(move || {
                        work_started.notify_one();
                        blocked.recv()
                    })
                    .await??;
                Ok(RootOutcome {
                    value: (),
                    commit: false,
                })
            })
        })
        .await?;
    timeout(Duration::from_secs(2), started.notified()).await?;
    drop(handle);
    timeout(Duration::from_secs(7), async {
        while service
            .registry
            .roots
            .lock()
            .await
            .values()
            .next()
            .is_some_and(|keeper| RootState::load(&keeper.state) != RootState::Quarantined)
        {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(pool.status().available, 0);
    assert_eq!(service.active_roots().await, 1);
    assert_eq!(service.quarantined_roots().await, 1);
    release.send(())?;
    timeout(Duration::from_secs(2), async {
        while service.active_roots().await != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(service.quarantined_roots().await, 0);
    let fresh = timeout(Duration::from_secs(2), pool.get()).await??;
    assert_ne!(Object::id(&fresh), poisoned_id);
    Ok(())
}

#[tokio::test]
async fn restoration_deadline_responds_while_authority_is_locked() -> Result<()> {
    let dir = TempDir::new()?;
    let pool = one_object_pool(&dir).await?;
    let object = pool.get().await?;
    let capacity = Arc::new(Semaphore::new(1)).acquire_owned().await?;
    let keeper = Arc::new(RootKeeper::new(RootId(9), object, capacity));
    let mut authority = keeper.authority.lock().await;
    authority
        .as_mut()
        .expect("root authority retained")
        .storage
        .savepoint()
        .await?;
    keeper.close();
    let (sender, receiver) = oneshot::channel();
    let restoring = keeper.clone();
    let task = tokio::spawn(async move {
        let mut response = Some(sender);
        restore_with_deadline(
            &restoring,
            Err::<RootOutcome<()>, _>(anyhow!("cancelled operation")),
            Some(Instant::now() + Duration::from_millis(30)),
            false,
            &mut response,
        )
        .await
    });
    assert!(timeout(Duration::from_secs(2), receiver).await??.is_err());
    assert_eq!(RootState::load(&keeper.state), RootState::Quarantined);
    assert_eq!(pool.status().available, 0);
    drop(authority);
    let restored = timeout(Duration::from_secs(2), task).await??;
    assert!(restored?.is_err());
    assert!(
        keeper
            .authority
            .lock()
            .await
            .as_ref()
            .expect("root authority retained")
            .storage
            .conn
            .is_autocommit()
    );
    Ok(())
}
