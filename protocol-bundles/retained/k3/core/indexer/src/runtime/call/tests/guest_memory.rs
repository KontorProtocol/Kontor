use anyhow::Result;
use indexer_types::Payment;
use libsql::params;
use wasmtime::{GcHeapOutOfMemory, Instance, Module, Store};

use super::funded;
use crate::protocol::v1::errors::is_deterministic;
use crate::runtime::guest_memory::{
    GuestMemoryLimitExceeded, GuestMemoryLimiter, GuestMemoryLimits,
};
use crate::runtime::{
    ContractAddress, ExecutionError, Runtime, TransactionContext, native_provenance,
};
use crate::test_utils::test_runtime;

const PAGE: usize = 65_536;

#[test]
fn table_and_store_count_limits_are_deterministic() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let limits = GuestMemoryLimits {
        per_root: PAGE,
        table_elements_per_root: 32,
        memories: 4,
        instances: 8,
        tables: 4,
        table_elements: 16,
    };
    for (name, wat, limits) in [
        (
            "instance count",
            "(module)",
            GuestMemoryLimits {
                instances: 0,
                ..limits
            },
        ),
        (
            "memory count",
            "(module (memory 0))",
            GuestMemoryLimits {
                memories: 0,
                ..limits
            },
        ),
        (
            "table count",
            "(module (table 0 funcref))",
            GuestMemoryLimits {
                tables: 0,
                ..limits
            },
        ),
        (
            "table minimum",
            "(module (table 1 funcref))",
            GuestMemoryLimits {
                table_elements: 0,
                ..limits
            },
        ),
        (
            "root table slots",
            "(module (table 1 funcref))",
            GuestMemoryLimits {
                table_elements_per_root: 0,
                ..limits
            },
        ),
    ] {
        let module = Module::new(&engine, wat)?;
        let mut store = Store::new(&engine, GuestMemoryLimiter::new_root(limits));
        store.limiter(|limiter| limiter);
        store.set_fuel(1_000_000)?;
        let error = Instance::new(&mut store, &module, &[]).unwrap_err();
        assert!(is_deterministic(&error), "{name}: {error:#}");
    }
    Ok(())
}

#[tokio::test]
async fn gc_quota_denial_is_deterministic_after_wasmtime_retries() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let module = Module::new(
        &engine,
        "(module (type $a (array (mut i32))) (func (export \"allocate\") (result i32) (array.len (array.new_default $a (i32.const 100000)))))",
    )?;
    let root = GuestMemoryLimiter::new_root(GuestMemoryLimits {
        per_root: PAGE,
        table_elements_per_root: 32,
        memories: 4,
        instances: 8,
        tables: 4,
        table_elements: 16,
    });
    let mut store = Store::new(&engine, root.new_child());
    store.limiter(|limiter| limiter);
    store.set_fuel(1_000_000)?;
    let instance = Instance::new(&mut store, &module, &[])?;
    let allocate = instance.get_typed_func::<(), i32>(&mut store, "allocate")?;
    let error = allocate.call(&mut store, ()).unwrap_err();
    assert!(
        error
            .chain()
            .any(|cause| cause.is::<GcHeapOutOfMemory<()>>()),
        "{error:#}"
    );
    assert!(!root.backing_failed());

    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.guest_memory_limiter = Some(root.new_child());
    assert!(matches!(
        runtime.classify_guest_memory_result::<()>(Err(ExecutionError::NonDeterministic(
            error.into()
        ))),
        Err(ExecutionError::Deterministic(_))
    ));
    assert_eq!(
        runtime.classify_guest_memory_result(Ok("42".to_string()))?,
        "42"
    );
    Ok(())
}

#[tokio::test]
async fn gc_heap_maximum_denial_is_deterministic() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let module = Module::new(
        &engine,
        "(module (type $a (array (mut i8))) (func (export \"allocate\") (param i32) local.get 0 array.new_default $a drop))",
    )?;
    let root = GuestMemoryLimiter::new_root(GuestMemoryLimits {
        per_root: 2 * PAGE,
        table_elements_per_root: 32,
        memories: 4,
        instances: 8,
        tables: 4,
        table_elements: 16,
    });
    let mut store = Store::new(&engine, root.new_child());
    store.limiter(|limiter| limiter);
    store.set_fuel(1_000_000)?;
    let instance = Instance::new(&mut store, &module, &[])?;
    let allocate = instance.get_typed_func::<i32, ()>(&mut store, "allocate")?;
    allocate.call(&mut store, 1)?;
    assert!(store.gc_heap_capacity() > 0);
    assert_eq!(root.admitted(), store.gc_heap_capacity());
    let error = allocate.call(&mut store, -65_536).unwrap_err();
    assert!(
        error
            .chain()
            .any(|cause| cause.is::<GcHeapOutOfMemory<()>>()),
        "{error:#}"
    );
    assert!(!root.backing_failed());

    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.guest_memory_limiter = Some(root.new_child());
    assert!(matches!(
        runtime.classify_guest_memory_result::<()>(Err(ExecutionError::NonDeterministic(
            error.into()
        ))),
        Err(ExecutionError::Deterministic(_))
    ));
    Ok(())
}

#[tokio::test]
async fn published_nested_calls_share_and_release_memory_across_cold_and_warm_loads() -> Result<()>
{
    published_nested_calls_share_and_release_limits(false).await
}

#[tokio::test]
async fn published_nested_calls_share_and_release_tables_across_cold_and_warm_loads() -> Result<()>
{
    published_nested_calls_share_and_release_limits(true).await
}

async fn published_nested_calls_share_and_release_limits(table_slots: bool) -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let signer = funded(&mut runtime).await?;
    let payment = Payment {
        signer_id: signer.signer_id().unwrap(),
        gas_limit: 100_000,
    };
    let provenance = native_provenance()?;
    let contracts = [
        (
            "memory-fib",
            include_bytes!("../../../../../../test-contracts/binaries/fib.wasm.br").as_slice(),
        ),
        (
            "memory-arith",
            include_bytes!("../../../../../../test-contracts/binaries/arith.wasm.br").as_slice(),
        ),
    ];
    let mut addresses = Vec::new();
    for (index, (name, bytes)) in contracts.into_iter().enumerate() {
        runtime
            .set_context(
                1,
                Some(TransactionContext::builder().tx_index(index as u32).build()),
                None,
                None,
            )
            .await;
        runtime
            .publish(&signer, payment.clone(), name, bytes, &provenance)
            .await?;
        addresses.push(ContractAddress {
            name: name.into(),
            height: 1,
            tx_index: index as u32,
        });
    }
    runtime.set_context(1, None, None, None).await;

    let table_limit = if table_slots {
        let mut slots = 0;
        for address in &addresses {
            let contract_id = runtime.storage.contract_id(address).await?.unwrap();
            let component = runtime.load_component(contract_id).await?;
            let mut store = runtime.make_store(1_000_000)?;
            runtime
                .linkers
                .user
                .instantiate_pre(&component)?
                .instantiate_async(&mut store)
                .await?;
            slots += store
                .data()
                .guest_memory_limiter
                .as_ref()
                .unwrap()
                .table_elements_admitted();
        }
        slots
    } else {
        16 * 1024 * 1024
    };
    runtime.guest_memory_limits = Some(GuestMemoryLimits {
        per_root: if table_slots { 50 * PAGE } else { 33 * PAGE },
        table_elements_per_root: if table_slots {
            table_limit - 1
        } else {
            table_limit
        },
        memories: 10_000,
        instances: 10_000,
        tables: 10_000,
        table_elements: 1_000_000,
    });
    let expression = format!("fib({}, 4)", stdlib::to_wave_expr(addresses[1].clone()));
    let parent_only = format!("fib({}, 0)", stdlib::to_wave_expr(addresses[1].clone()));
    assert_eq!(
        runtime
            .execute(
                Some(&signer),
                Some(payment.clone()),
                &addresses[0],
                &parent_only
            )
            .await?,
        "0"
    );

    let contract_id = runtime.storage.contract_id(&addresses[0]).await?.unwrap();
    let conn = runtime.get_storage_conn();
    let mut previous_gas = None;
    for cold in [true, false] {
        if cold {
            runtime.component_cache.clear();
        }
        let result = runtime
            .execute(
                Some(&signer),
                Some(payment.clone()),
                &addresses[0],
                &expression,
            )
            .await;
        match result {
            Err(ExecutionError::Deterministic(error)) => {
                if table_slots {
                    assert!(
                        error
                            .root_cause()
                            .to_string()
                            .contains("table minimum size")
                    );
                } else {
                    assert!(
                        error
                            .chain()
                            .any(|cause| cause.is::<GuestMemoryLimitExceeded>())
                    );
                }
            }
            result => panic!("cold={cold}: {result:?}"),
        }
        let mut rows = conn
            .query(
                "SELECT gas, status FROM contract_results WHERE contract_id = ? ORDER BY id DESC LIMIT 1",
                params![contract_id],
            )
            .await?;
        let row = rows.next().await?.expect("outer result");
        let gas = row.get::<u64>(0)?;
        if let Some(previous) = previous_gas {
            assert_eq!(gas, previous);
        }
        previous_gas = Some(gas);
        assert_eq!(row.get::<String>(1)?, "Other");
        assert!(runtime.stack.is_empty().await);
        assert!(runtime.storage.savepoint_stack.is_empty().await);
    }

    // Three sequential children fit only if each finished Store releases its quota.
    let limits = runtime.guest_memory_limits.as_mut().unwrap();
    limits.per_root = 50 * PAGE;
    if table_slots {
        limits.table_elements_per_root = table_limit;
    }
    assert_eq!(
        runtime
            .execute(Some(&signer), Some(payment), &addresses[0], &expression)
            .await?,
        "3"
    );
    let arith_id = runtime.storage.contract_id(&addresses[1]).await?.unwrap();
    let mut rows = conn
        .query(
            "SELECT COUNT(*) FROM contract_results WHERE contract_id = ? AND func = 'eval'",
            params![arith_id],
        )
        .await?;
    assert_eq!(rows.next().await?.unwrap().get::<u64>(0)?, 3);
    assert!(runtime.stack.is_empty().await);
    assert!(runtime.storage.savepoint_stack.is_empty().await);
    Ok(())
}
