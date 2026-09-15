use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use anyhow::Result;
use bitcoin::OutPoint;
use futures_util::stream;
use wasmtime::component::{Accessor, Resource};
use wasmtime::{Store, Trap};

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
use crate::runtime::{ExecutionError, Runtime, TransactionContext};
use crate::test_utils::test_runtime;

const BUDGET: u64 = 1_000_000;

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

fn assert_exhausted(error: anyhow::Error) {
    assert!(
        matches!(error.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)),
        "expected fuel exhaustion, got {error:#}"
    );
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
        assert!(store.get_fuel()? < before, "missing lookup was free");
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
                    stream: Box::pin(stream::poll_fn(move |_| {
                        observed.fetch_add(1, Ordering::SeqCst);
                        Poll::Ready(None)
                    })),
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
                <Runtime as RowsHost<Runtime>>::next_u64(accessor, Resource::new_borrow(rep))
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
        4 => <Runtime as StorageHost<Runtime>>::extend_path_with_match(
            accessor,
            resource,
            path,
            vec![],
        )
        .await
        .map(|_| ()),
        5 => <Runtime as StorageHost<Runtime>>::delete_matching_paths(
            accessor,
            resource,
            path,
            vec![],
        )
        .await
        .map(|_| ()),
        6 => <Runtime as StorageHost<Runtime>>::delete(accessor, resource, path)
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
    for operation in 0..8 {
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
