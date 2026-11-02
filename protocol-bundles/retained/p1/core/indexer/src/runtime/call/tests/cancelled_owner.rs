use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::Notify;
use tokio::time::timeout;
use wasmtime::component::{Component, Val};

use crate::runtime::Runtime;
use crate::runtime::lowering::Linker;
use crate::test_utils::test_runtime;

#[tokio::test]
async fn detached_guest_keeps_the_store_reservation_until_completion() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let component = Component::new(
        &runtime.engine,
        include_str!("fixtures/abi-repeat-import.wat"),
    )?;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut linker = Linker::<Runtime>::new(&runtime.engine);
    let host_entered = entered.clone();
    let host_release = release.clone();
    let host_calls = calls.clone();
    linker
        .root()
        .func_wrap_async("accept", move |_, (_input,): (String,)| {
            let entered = host_entered.clone();
            let release = host_release.clone();
            let calls = host_calls.clone();
            Box::new(async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    entered.notify_one();
                    release.notified().await;
                }
                Ok(())
            })
        })?;
    let mut store = runtime.make_store(1_000_000)?;
    let budget = store.data().invocation_budget.as_ref().unwrap().clone();
    let instance = linker.instantiate_async(&mut store, &component).await?;
    let run = instance.get_func(&mut store, "run").unwrap();
    let outer = tokio::spawn(async move {
        runtime
            .call_guest(
                store,
                run,
                vec![Val::U32(8), Val::U32(2)],
                vec![Val::U32(0)],
                false,
            )
            .await
    });
    timeout(Duration::from_secs(10), entered.notified()).await?;
    assert_eq!(budget.live(), 1);
    outer.abort();
    assert!(outer.await.is_err());
    assert_eq!(budget.live(), 1);
    release.notify_one();
    timeout(Duration::from_secs(10), async {
        while budget.live() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}
