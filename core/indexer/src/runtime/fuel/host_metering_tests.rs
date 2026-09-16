use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use anyhow::{Error, Result};
use bitcoin::OutPoint;
use futures_util::{TryStreamExt, stream};
use libsql::{AuthAction, AuthContext, Authorization};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use wasmtime::component::{Accessor, Resource};
use wasmtime::{Store, Trap};

use super::{Fuel, FuelDiscriminants, FuelGauge};
use crate::database::queries::{
    create_contract_signer, insert_block, live_deposit_gas_sum, traversal_probe,
};
use indexer_types::{BlockRow, serialize};
use stdlib::KeyElement;

use crate::runtime::wit::kontor::built_in::{
    context::{
        HolderRef, HostKeysWithStore as KeysHost, HostProcContextWithStore as ContextHost,
        HostProcStorageWithStore as StorageHost, HostStorageRowsWithStore as RowsHost,
        HostTransactionWithStore as TransactionHost,
    },
    deposit::HostWithStore as DepositHost,
};
use crate::runtime::wit::{
    Holder, Keys, ProcContext, ProcStorage, Signer, StorageRows, Transaction,
};
use crate::runtime::{ContractAddress, ExecutionError, Runtime, TransactionContext};
use crate::test_utils::{new_mock_block_hash, test_runtime};

const BUDGET: u64 = 1_000_000;

mod history_benchmarks;

async fn host<R>(
    store: &mut Store<Runtime>,
    call: impl AsyncFnOnce(&Accessor<Runtime, Runtime>) -> Result<R>,
) -> Result<R> {
    store
        .run_concurrent(async |accessor| {
            let accessor = accessor.with_getter::<Runtime>(|runtime| runtime);
            call(&accessor).await
        })
        .await?
}

fn assert_exhausted(error: Error) {
    assert!(
        matches!(error.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)),
        "expected fuel exhaustion, got {error:#}"
    );
}

fn deny_storage_value_reads(context: &AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Read {
            table_name: "contract_state",
            column_name: "value",
        } => Authorization::Deny,
        _ => Authorization::Allow,
    }
}

#[tokio::test]
async fn point_read_budget_rejects_value_before_fetching() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let path = "point-value-budget".to_string().encode();
    let encoded = serialize(&vec![0u8; 4096])?;
    runtime.storage.set(1, &path, &encoded, None, None).await?;
    let budget = Fuel::StorageRead.cost()
        + Fuel::Path(path.len() as u64).cost()
        + Fuel::Get(encoded.len() - 1).cost();
    let mut store = runtime.make_store(budget)?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep();
    runtime
        .storage
        .conn
        .authorizer(Some(Arc::new(deny_storage_value_reads)))?;
    let result = host(&mut store, async |accessor| {
        <Runtime as StorageHost<Runtime>>::get_list_u8(accessor, Resource::new_borrow(rep), path)
            .await
    })
    .await;
    runtime.storage.conn.authorizer(None)?;
    assert_exhausted(result.unwrap_err());
    Ok(())
}

#[tokio::test]
async fn row_budget_rejects_value_before_fetching() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let root = "value-budget".to_string().encode();
    let member = 0u64.encode();
    let mut path = root.clone();
    path.extend_from_slice(&member);
    runtime
        .storage
        .set(1, &path, &serialize(&vec![0u8; 4096])?, None, None)
        .await?;
    let mut store = runtime.make_store(BUDGET)?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep();
    let cursor = host(&mut store, async |accessor| {
        <Runtime as StorageHost<Runtime>>::get_storage_rows(
            accessor,
            Resource::new_borrow(rep),
            root,
            None,
            None,
            false,
        )
        .await
    })
    .await?
    .rep();
    store.set_fuel(Fuel::StorageScan.cost() + Fuel::KeysNext(member.len() as u64).cost())?;
    // Denying the column distinguishes avoiding a value query from merely
    // avoiding the Rust copy after SQLite has already read the value.
    runtime
        .storage
        .conn
        .authorizer(Some(Arc::new(deny_storage_value_reads)))?;
    let (result, copied) =
        traversal_probe::measure_value_bytes(host(&mut store, async |accessor| {
            <Runtime as RowsHost<Runtime>>::next_list_u8(accessor, Resource::new_borrow(cursor))
                .await
        }))
        .await;
    runtime.storage.conn.authorizer(None)?;
    assert_exhausted(result.unwrap_err());
    assert_eq!(copied, 0, "unaffordable value crossed the SQL boundary");
    Ok(())
}

#[tokio::test]
async fn row_budget_is_refreshed_between_advances() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let root = "changing-row-budget".to_string().encode();
    for member in 0..2u64 {
        let mut path = root.clone();
        path.extend(member.encode());
        runtime
            .storage
            .set(1, &path, &serialize(&vec![7u8; 128])?, None, None)
            .await?;
    }
    let mut store = runtime.make_store(BUDGET)?;
    let cursor = store
        .data()
        .table
        .lock()
        .await
        .push(StorageRows {
            cursor: runtime.storage.storage_rows(1, root, None, None, false),
        })?
        .rep();
    assert_eq!(
        host(&mut store, async |accessor| {
            <Runtime as RowsHost<Runtime>>::next_list_u8(accessor, Resource::new_borrow(cursor))
                .await
        })
        .await?,
        Some((0u64.encode(), vec![7u8; 128]))
    );
    store.set_fuel(Fuel::StorageScan.cost())?;
    runtime
        .storage
        .conn
        .authorizer(Some(Arc::new(deny_storage_value_reads)))?;
    let (result, copied) =
        traversal_probe::measure_value_bytes(host(&mut store, async |accessor| {
            <Runtime as RowsHost<Runtime>>::next_list_u8(accessor, Resource::new_borrow(cursor))
                .await
        }))
        .await;
    assert_exhausted(result.unwrap_err());
    assert_eq!(copied, 0);
    runtime.storage.conn.authorizer(None)?;
    Ok(())
}

#[tokio::test]
async fn row_budget_includes_key_and_framing_at_exact_boundary() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let root = "row-byte-boundary".to_string().encode();
    let member = "a\0b".to_string().encode();
    let value = vec![9u8; 128];
    let raw = serialize(&value)?;
    let mut path = root.clone();
    path.extend_from_slice(&member);
    runtime.storage.set(1, &path, &raw, None, None).await?;
    let total = Fuel::StorageScan.cost() + Fuel::KeysNext((member.len() + raw.len()) as u64).cost();
    let mut store = runtime.make_store(BUDGET)?;
    for descending in [false, true] {
        for budget in [0, total - 1, total] {
            let cursor = store
                .data()
                .table
                .lock()
                .await
                .push(StorageRows {
                    cursor: runtime
                        .storage
                        .storage_rows(1, root.clone(), None, None, descending),
                })?
                .rep();
            store.set_fuel(budget)?;
            let (result, copied) =
                traversal_probe::measure_value_bytes(host(&mut store, async |accessor| {
                    <Runtime as RowsHost<Runtime>>::next_list_u8(
                        accessor,
                        Resource::new_borrow(cursor),
                    )
                    .await
                }))
                .await;
            if budget < total {
                assert_exhausted(result.unwrap_err());
                assert_eq!(copied, 0);
            } else {
                assert_eq!(result?, Some((member.clone(), value.clone())));
                assert_eq!(copied, raw.len());
                assert_eq!(store.get_fuel()?, 0);
                store.set_fuel(Fuel::StorageScan.cost())?;
                assert!(
                    host(&mut store, async |accessor| {
                        <Runtime as RowsHost<Runtime>>::next_list_u8(
                            accessor,
                            Resource::new_borrow(cursor),
                        )
                        .await
                    })
                    .await?
                    .is_none()
                );
                assert_eq!(store.get_fuel()?, 0);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn write_budget_preserves_encoding_and_rollback_at_exact_boundary() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let path = "write-byte-boundary".to_string().encode();
    let original = serialize(&vec![5u8; 3])?;
    runtime.storage.set(1, &path, &original, None, None).await?;
    let mut store = runtime.make_store(BUDGET)?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep();
    for len in [0, 127, 128, 4096] {
        let value = vec![2u8; len];
        let encoded = serialize(&value)?;
        let total = Fuel::StorageWrite.cost()
            + Fuel::Path(path.len() as u64).cost()
            + Fuel::Set(encoded.len() as u64).cost();
        for budget in [total - 1, total] {
            runtime.storage.savepoint().await?;
            store.set_fuel(budget)?;
            let result = host(&mut store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::set_list_u8(
                    accessor,
                    Resource::new_borrow(rep),
                    path.clone(),
                    value.clone(),
                )
                .await
            })
            .await;
            let stored = runtime.storage.get(BUDGET, 1, &path).await?;
            if budget < total {
                assert_exhausted(result.unwrap_err());
                assert_eq!(stored, Some(original.clone()));
            } else {
                result?;
                assert_eq!(stored, Some(encoded.clone()));
                assert_eq!(store.get_fuel()?, 0);
            }
            let remaining = store.get_fuel()?;
            runtime.storage.rollback().await?;
            assert_eq!(store.get_fuel()?, remaining);
            assert_eq!(
                runtime.storage.get(BUDGET, 1, &path).await?,
                Some(original.clone())
            );
        }
    }
    Ok(())
}

struct CountedSequence<'a>(&'a AtomicUsize);

impl Serialize for CountedSequence<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(4096))?;
        for _ in 0..4096 {
            self.0.fetch_add(1, Ordering::SeqCst);
            seq.serialize_element(&0u8)?;
        }
        seq.end()
    }
}

#[tokio::test]
async fn write_budget_stops_serialization_before_finishing() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut store = runtime.make_store(Fuel::StorageWrite.cost() + Fuel::Set(16).cost())?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep();
    let visited = AtomicUsize::new(0);
    let result = host(&mut store, async |accessor| {
        let runtime = accessor.with(|mut access| access.get().clone());
        runtime
            ._set_primitive(
                accessor,
                Resource::<ProcStorage>::new_borrow(rep),
                vec![],
                CountedSequence(&visited),
            )
            .await
    })
    .await;
    assert_exhausted(result.unwrap_err());
    assert!(
        visited.load(Ordering::SeqCst) <= 17,
        "serialized beyond the byte budget"
    );
    Ok(())
}

#[tokio::test]
async fn missing_reads_consume_fuel_on_every_attempt() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut store = runtime.make_store(BUDGET)?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep();
    for _ in 0..3 {
        runtime.storage.savepoint().await?;
        let before = store.get_fuel()?;
        assert_eq!(
            host(&mut store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::get_u64(
                    accessor,
                    Resource::new_borrow(rep),
                    vec![],
                )
                .await
            })
            .await?,
            None
        );
        runtime.storage.rollback().await?;
        assert!(
            store.get_fuel()? < before,
            "lookup fuel was free or refunded by rollback"
        );
    }
    Ok(())
}

#[tokio::test]
async fn exhausted_read_rejects_before_resource_or_database_access() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut store = runtime.make_store(0)?;
    let error = host(&mut store, async |accessor| {
        <Runtime as StorageHost<Runtime>>::get_u64(accessor, Resource::new_borrow(u32::MAX), vec![])
            .await
    })
    .await
    .unwrap_err();
    assert_exhausted(error);
    Ok(())
}

#[tokio::test]
async fn cursor_polls_require_fuel_even_at_end_of_stream() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut store = runtime.make_store(0)?;
    for rows in [false, true] {
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = polls.clone();
        let rep = if rows {
            store
                .data()
                .table
                .lock()
                .await
                .push(StorageRows {
                    cursor: runtime.storage.storage_rows(
                        1,
                        "empty-budget-scan".to_string().encode(),
                        None,
                        None,
                        false,
                    ),
                })?
                .rep()
        } else {
            store
                .data()
                .table
                .lock()
                .await
                .push(Keys {
                    stream: Box::pin(stream::poll_fn(move |_| {
                        observed.fetch_add(1, Ordering::SeqCst);
                        Poll::Ready(None)
                    })),
                })?
                .rep()
        };
        store.set_fuel(0)?;
        let error = host(&mut store, async |accessor| {
            if rows {
                <Runtime as RowsHost<Runtime>>::next_u64(accessor, Resource::new_borrow(u32::MAX))
                    .await
                    .map(|_| ())
            } else {
                <Runtime as KeysHost<Runtime>>::next(accessor, Resource::new_borrow(rep))
                    .await
                    .map(|_| ())
            }
        })
        .await
        .expect_err("an empty poll must still require fuel");
        assert_exhausted(error);
        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "stream advanced before fuel check"
        );
        store.set_fuel(BUDGET)?;
        for _ in 0..3 {
            let before = store.get_fuel()?;
            host(&mut store, async |accessor| {
                if rows {
                    assert!(
                        <Runtime as RowsHost<Runtime>>::next_u64(
                            accessor,
                            Resource::new_borrow(rep)
                        )
                        .await?
                        .is_none()
                    );
                } else {
                    assert!(
                        <Runtime as KeysHost<Runtime>>::next(accessor, Resource::new_borrow(rep))
                            .await?
                            .is_none()
                    );
                }
                Ok(())
            })
            .await?;
            assert!(store.get_fuel()? < before, "terminal poll was free");
        }
    }
    Ok(())
}

#[tokio::test]
async fn context_and_transaction_accessors_charge_each_call() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().build()),
            Some(OutPoint::null()),
            Some(vec![7; 32]),
        )
        .await;
    let mut store = runtime.make_store(BUDGET)?;
    let context = store
        .data()
        .table
        .lock()
        .await
        .push(ProcContext {
            contract_id: 1,
            signer: Signer::Nobody,
            payer: Holder {
                holder_ref: HolderRef::Burner,
            },
        })?
        .rep();
    let transaction = store.data().table.lock().await.push(Transaction {})?.rep();
    let holder = store
        .data()
        .table
        .lock()
        .await
        .push(Holder {
            holder_ref: HolderRef::Burner,
        })?
        .rep();
    for operation in 0..6 {
        for budget in [0, BUDGET] {
            store.set_fuel(budget)?;
            let result = host(&mut store, async |accessor| match operation {
                0 => <Runtime as ContextHost<Runtime>>::block_height(
                    accessor,
                    Resource::new_borrow(context),
                )
                .await
                .map(|_| ()),
                1 => <Runtime as ContextHost<Runtime>>::network(
                    accessor,
                    Resource::new_borrow(context),
                )
                .await
                .map(|_| ()),
                2 => <Runtime as TransactionHost<Runtime>>::id(
                    accessor,
                    Resource::new_borrow(transaction),
                )
                .await
                .map(|_| ()),
                3 => <Runtime as TransactionHost<Runtime>>::out_point(
                    accessor,
                    Resource::new_borrow(transaction),
                )
                .await
                .map(|_| ()),
                4 => <Runtime as TransactionHost<Runtime>>::op_return_data(
                    accessor,
                    Resource::new_borrow(transaction),
                )
                .await
                .map(|_| ()),
                _ => <Runtime as DepositHost<Runtime>>::storage_floor(
                    accessor,
                    Resource::new_borrow(holder),
                )
                .await
                .map(|_| ()),
            })
            .await;
            if budget == 0 {
                assert_exhausted(result.expect_err("accessor succeeded without fuel"));
            } else {
                result?;
                assert!(store.get_fuel()? < budget, "accessor {operation} was free");
            }
        }
    }
    Ok(())
}

async fn malformed_storage_call(
    accessor: &Accessor<Runtime, Runtime>,
    rep: u32,
    operation: usize,
    path: Vec<u8>,
) -> Result<()> {
    let resource = Resource::new_borrow(rep);
    match operation {
        0 => <Runtime as StorageHost<Runtime>>::get_u64(accessor, resource, path)
            .await
            .map(|_| ()),
        1 => <Runtime as StorageHost<Runtime>>::exists(accessor, resource, path)
            .await
            .map(|_| ()),
        2 => {
            <Runtime as StorageHost<Runtime>>::get_keys(accessor, resource, path, None, None, false)
                .await
                .map(|_| ())
        }
        3 => <Runtime as StorageHost<Runtime>>::get_storage_rows(
            accessor, resource, path, None, None, false,
        )
        .await
        .map(|_| ()),
        4 => <Runtime as StorageHost<Runtime>>::delete(accessor, resource, path)
            .await
            .map(|_| ()),
        _ => <Runtime as StorageHost<Runtime>>::set_u64(accessor, resource, path, 1).await,
    }
}

#[tokio::test]
async fn invalid_storage_paths_are_metered_by_input_size() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut store = runtime.make_store(BUDGET)?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep();
    for operation in 0..6 {
        let mut previous = 0;
        for size in [32, 4096] {
            store.set_fuel(BUDGET)?;
            // An unterminated string exercises validation through the entire input.
            let mut path = vec![b'a'; size];
            path[0] = 0x02;
            let error = host(&mut store, async |accessor| {
                malformed_storage_call(accessor, rep, operation, path).await
            })
            .await
            .unwrap_err();
            assert!(matches!(
                error.downcast_ref::<ExecutionError>(),
                Some(ExecutionError::Deterministic(_))
            ));
            let consumed = BUDGET - store.get_fuel()?;
            assert!(
                consumed > previous,
                "path work for operation {operation} was not metered by input size"
            );
            previous = consumed;
        }
    }
    Ok(())
}

#[tokio::test]
async fn oversized_storage_read_is_a_contract_fuel_failure() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    runtime
        .storage
        .insert_contract(
            "metered-reader",
            include_bytes!("../../../../../test-contracts/binaries/counter.wasm.br"),
        )
        .await?;
    let address = ContractAddress {
        name: "metered-reader".into(),
        height: 1,
        tx_index: 0,
    };
    let core = Signer::Core(Box::new(Signer::Nobody));
    runtime.execute_api(Some(&core), &address, "init()").await?;
    runtime
        .invoke(&address, None, None, "get-blob()", Some(BUDGET))
        .await?
        .result?;
    runtime
        .execute_api(Some(&core), &address, "fill-blob(1000000)")
        .await?;

    let gauge = FuelGauge::with_profiling();
    runtime.gauge = Some(gauge.clone());
    let outcome = runtime
        .invoke(&address, None, None, "get-blob()", Some(BUDGET))
        .await?;
    match outcome
        .result
        .expect_err("budget cannot afford this stored value")
    {
        ExecutionError::Deterministic(error) => assert_exhausted(error),
        error => panic!("a read budget failure must not stop the node: {error:#}"),
    }
    assert_eq!(
        gauge.report()?.profile.unwrap().per_type[&FuelDiscriminants::StorageRead].consumed_count,
        1
    );
    assert!(runtime.stack.is_empty().await);
    runtime.gauge = None;
    let value = runtime
        .invoke(&address, None, None, "get-blob()", Some(30 * BUDGET))
        .await?
        .result?;
    assert_eq!(value.len(), 1_000_002);
    Ok(())
}

#[tokio::test]
async fn transaction_data_charges_by_size_and_preserves_contents() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut store = runtime.make_store(BUDGET)?;
    let rep = store.data().table.lock().await.push(Transaction {})?.rep();
    let mut previous = 0;
    for size in [None, Some(0), Some(64), Some(4096)] {
        let payload = size.map(|size| vec![0x5a; size]);
        store.data_mut().op_return_data = payload.clone().map(Arc::from);
        store.set_fuel(BUDGET)?;
        let result = host(&mut store, async |accessor| {
            <Runtime as TransactionHost<Runtime>>::op_return_data(
                accessor,
                Resource::new_borrow(rep),
            )
            .await
        })
        .await?;
        assert_eq!(result, payload);
        let consumed = BUDGET - store.get_fuel()?;
        assert!(consumed > 0);
        if size.is_some_and(|size| size > 0) {
            assert!(consumed > previous);
        }
        previous = consumed;
        for budget in [consumed - 1, consumed] {
            store.set_fuel(budget)?;
            let result = host(&mut store, async |accessor| {
                <Runtime as TransactionHost<Runtime>>::op_return_data(
                    accessor,
                    Resource::new_borrow(rep),
                )
                .await
            })
            .await;
            if budget < consumed {
                assert_exhausted(result.unwrap_err());
                assert_eq!(store.get_fuel()?, budget);
            } else {
                assert_eq!(result?, payload);
                assert_eq!(store.get_fuel()?, 0);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn storage_read_budget_includes_base_and_encoded_value() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut store = runtime.make_store(BUDGET)?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep();
    assert!(
        host(&mut store, async |accessor| {
            <Runtime as StorageHost<Runtime>>::get_list_u8(
                accessor,
                Resource::new_borrow(rep),
                vec![],
            )
            .await
        })
        .await?
        .is_none()
    );
    let base = BUDGET - store.get_fuel()?;
    for size in [0, 1, 128, 4096] {
        let value = vec![0x5a_u8; size];
        let encoded = serialize(&value)?;
        runtime.storage.set(1, &[], &encoded, None, None).await?;
        let total = base + Fuel::Get(encoded.len()).cost();
        for budget in [total - 1, total] {
            store.set_fuel(budget)?;
            let result = host(&mut store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::get_list_u8(
                    accessor,
                    Resource::new_borrow(rep),
                    vec![],
                )
                .await
            })
            .await;
            if budget < total {
                assert_exhausted(result.unwrap_err());
            } else {
                assert_eq!(result?, Some(value.clone()));
                assert_eq!(store.get_fuel()?, 0);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn invalid_scalar_cursor_target_still_pays_for_polling() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let root = "compound-budget-scan".to_string().encode();
    let mut path = root.clone();
    path.extend(0u64.encode());
    path.extend(0u64.encode());
    runtime.storage.set(1, &path, &[0], None, None).await?;
    let mut store = runtime.make_store(BUDGET)?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(StorageRows {
            cursor: runtime.storage.storage_rows(1, root, None, None, false),
        })?
        .rep();
    let error = host(&mut store, async |accessor| {
        <Runtime as RowsHost<Runtime>>::next_u64(accessor, Resource::new_borrow(rep)).await
    })
    .await
    .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<ExecutionError>(),
        Some(ExecutionError::Deterministic(_))
    ));
    assert!(store.get_fuel()? < BUDGET);
    Ok(())
}

#[tokio::test]
async fn key_scan_skips_an_already_returned_child_subtree() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let root = "traversal".to_string().encode();
    for member in 0..3u64 {
        for field in 0..128u64 {
            let mut path = root.clone();
            member.encode_to(&mut path);
            field.encode_to(&mut path);
            runtime.storage.set(1, &path, &[0], None, None).await?;
        }
    }
    for descending in [false, true] {
        let (result, visited) = traversal_probe::measure(async {
            runtime
                .storage
                .keys(1, root.clone(), None, None, descending)
                .await?
                .try_collect::<Vec<_>>()
                .await
                .map_err(Error::from)
        })
        .await;
        let mut expected = (0..3u64).map(|n| n.encode()).collect::<Vec<_>>();
        if descending {
            expected.reverse();
        }
        assert_eq!(result?, expected);
        assert!(visited <= 99, "visited {visited} rows for three child keys");
    }
    Ok(())
}

#[tokio::test]
async fn delete_discovery_stops_when_its_budget_runs_out() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let root = "traversal".to_string().encode();
    let candidate = "some".to_string().encode();
    let mut prefix = root.clone();
    prefix.extend_from_slice(&candidate);
    for field in 0..32u64 {
        let mut path = prefix.clone();
        field.encode_to(&mut path);
        runtime.storage.set(1, &path, &[0; 10], None, None).await?;
    }
    let mut store = runtime.make_store(BUDGET)?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep();
    let entry = Fuel::StorageDelete.cost() + Fuel::Path(root.len() as u64).cost();
    store.set_fuel(entry + 100)?;
    let (result, visited) = traversal_probe::measure(host(&mut store, async |accessor| {
        <Runtime as StorageHost<Runtime>>::delete(accessor, Resource::new_borrow(rep), root.clone())
            .await
            .map(|_| ())
    }))
    .await;
    assert_exhausted(result.unwrap_err());
    assert!(
        visited <= 1,
        "discovered {visited} rows after budget exhaustion"
    );
    assert_eq!(
        runtime
            .storage
            .find_live_subtree(1, &root)
            .await?
            .try_collect::<Vec<_>>()
            .await?
            .len(),
        32
    );
    Ok(())
}

#[tokio::test]
async fn subtree_delete_preserves_deposits_at_the_budget_boundary() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let conn = runtime.storage.conn.clone();
    let alice = create_contract_signer(&conn, 1).await?;
    let bob = create_contract_signer(&conn, 1).await?;
    let root = "cleanup-budget".to_string().encode();
    let some = "some".to_string().encode();
    let mut paths = Vec::new();
    for member in 0..130u64 {
        let mut path = root.clone();
        path.extend_from_slice(&some);
        member.encode_to(&mut path);
        runtime
            .storage
            .footprint()
            .on_set(1, &path, Some(alice), Some(10))
            .await?;
        runtime
            .storage
            .set(1, &path, &[0], Some(alice), Some(10))
            .await?;
        paths.push(path);
    }
    insert_block(
        &conn,
        BlockRow::builder()
            .height(2)
            .hash(new_mock_block_hash(2))
            .build(),
    )
    .await?;
    runtime.storage.height = 2;
    for path in &paths {
        runtime
            .storage
            .footprint()
            .on_set(1, path, Some(bob), Some(20))
            .await?;
        runtime
            .storage
            .set(1, path, &[1], Some(bob), Some(20))
            .await?;
    }
    let first: Vec<_> = runtime
        .storage
        .find_live_subtree(1, &paths[0])
        .await?
        .try_collect()
        .await?;
    runtime.storage.footprint().on_free(&first).await?;
    runtime.storage.tombstone_rows(1, &first).await?;
    let mut store = runtime.make_store(BUDGET)?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep();
    let mut measured = None;
    for short in [false, true] {
        let budget = if short { measured.unwrap() - 1 } else { BUDGET };
        store.set_fuel(budget)?;
        runtime.storage.savepoint().await?;
        let changes = conn.total_changes();
        let result = host(&mut store, async |accessor| {
            <Runtime as StorageHost<Runtime>>::delete(
                accessor,
                Resource::new_borrow(rep),
                root.clone(),
            )
            .await
        })
        .await;
        if short {
            assert_exhausted(result.unwrap_err());
            assert_eq!(
                conn.total_changes(),
                changes,
                "underfunded discovery wrote state"
            );
            assert_eq!(runtime.storage.footprint().total_gas(alice).await?, 0);
            assert_eq!(runtime.storage.footprint().total_gas(bob).await?, 129 * 20);
        } else {
            assert!(result?);
            assert_eq!(runtime.storage.footprint().total_gas(alice).await?, 0);
            assert_eq!(runtime.storage.footprint().total_gas(bob).await?, 0);
            let spent = budget - store.get_fuel()?;
            if let Some(previous) = measured {
                assert_eq!(spent, previous);
            }
            measured = Some(spent);
        }
        for owner in [alice, bob] {
            assert_eq!(
                runtime.storage.footprint().total_gas(owner).await?,
                live_deposit_gas_sum(&conn, owner).await?
            );
        }
        let fuel_before_rollback = store.get_fuel()?;
        runtime.storage.rollback().await?;
        assert_eq!(store.get_fuel()?, fuel_before_rollback);
        assert_eq!(runtime.storage.footprint().total_gas(alice).await?, 0);
        assert_eq!(runtime.storage.footprint().total_gas(bob).await?, 129 * 20);
    }
    Ok(())
}

#[tokio::test]
async fn subtree_seeks_preserve_ranges_and_fuel_across_pruning() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let root = "seek-pruning".to_string().encode();
    let mut removed = Vec::new();
    for member in ["a", "a\0", "b", "c"] {
        let mut child = root.clone();
        member.to_string().encode_to(&mut child);
        if member == "a" {
            runtime.storage.set(1, &child, &[0], None, None).await?;
        }
        for field in 0..64u64 {
            let mut path = child.clone();
            field.encode_to(&mut path);
            runtime.storage.set(1, &path, &[0], None, None).await?;
        }
        if member == "b" {
            removed = runtime
                .storage
                .find_live_subtree(1, &child)
                .await?
                .try_collect()
                .await?;
        }
    }
    insert_block(
        &runtime.storage.conn,
        BlockRow::builder()
            .height(2)
            .hash(new_mock_block_hash(2))
            .build(),
    )
    .await?;
    runtime.storage.height = 2;
    runtime.storage.tombstone_rows(1, &removed).await?;
    let mut store = runtime.make_store(BUDGET)?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep();
    let mut before = None;
    for pruned in [false, true] {
        if pruned {
            assert!(runtime.storage.prune(0, 2).await? > 0);
        }
        let mut usage = Vec::new();
        for bounded in [false, true] {
            for descending in [false, true] {
                store.set_fuel(BUDGET)?;
                let keys = host(&mut store, async |accessor| {
                    <Runtime as StorageHost<Runtime>>::get_keys(
                        accessor,
                        Resource::new_borrow(rep),
                        root.clone(),
                        bounded.then(|| "a".to_string().encode()),
                        bounded.then(|| "c".to_string().encode()),
                        descending,
                    )
                    .await
                })
                .await?;
                let mut actual = Vec::new();
                while let Some(key) = host(&mut store, async |accessor| {
                    <Runtime as KeysHost<Runtime>>::next(accessor, Resource::new_borrow(keys.rep()))
                        .await
                })
                .await?
                {
                    actual.push(key);
                }
                store.data().table.lock().await.delete(keys)?;
                let mut expected = vec!["a", "a\0"];
                if !bounded {
                    expected.push("c");
                }
                if descending {
                    expected.reverse();
                }
                assert_eq!(
                    actual,
                    expected
                        .into_iter()
                        .map(|s| s.to_string().encode())
                        .collect::<Vec<_>>()
                );
                usage.push(BUDGET - store.get_fuel()?);
            }
        }
        runtime.storage.savepoint().await?;
        store.set_fuel(BUDGET)?;
        assert!(
            host(&mut store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::delete(
                    accessor,
                    Resource::new_borrow(rep),
                    root.clone(),
                )
                .await
            })
            .await?
        );
        usage.push(BUDGET - store.get_fuel()?);
        assert!(!runtime.storage.exists(1, &root).await?);
        runtime.storage.rollback().await?;
        if let Some(previous) = &before {
            assert_eq!(&usage, previous, "fuel depended on pruned history");
        }
        before = Some(usage);
    }
    Ok(())
}

#[tokio::test]
async fn subtree_delete_preserves_escaped_siblings_with_long_prefixes() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let root = "p".repeat(8192).encode();
    for member in ["a", "a\0", "b"] {
        let mut path = root.clone();
        member.to_string().encode_to(&mut path);
        runtime.storage.set(1, &path, &[0], None, None).await?;
    }
    let mut store = runtime.make_store(BUDGET)?;
    let rep = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep();
    let a = "a".to_string().encode();
    assert!(
        host(&mut store, async |accessor| {
            <Runtime as StorageHost<Runtime>>::delete(
                accessor,
                Resource::new_borrow(rep),
                [root.as_slice(), a.as_slice()].concat(),
            )
            .await
        })
        .await?
    );
    let remaining: Vec<_> = runtime
        .storage
        .keys(1, root.clone(), None, None, false)
        .await?
        .try_collect()
        .await?;
    assert_eq!(
        remaining,
        vec!["a\0".to_string().encode(), "b".to_string().encode()]
    );
    store.set_fuel(BUDGET)?;
    assert!(
        host(&mut store, async |accessor| {
            <Runtime as StorageHost<Runtime>>::delete(
                accessor,
                Resource::new_borrow(rep),
                root.clone(),
            )
            .await
        })
        .await?
    );
    assert!(!runtime.storage.exists(1, &root).await?);
    Ok(())
}
