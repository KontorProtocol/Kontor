use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::Holder;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::wit::kontor::built_in::error::Error as WitError;

impl built_in::context::HostHolder for Runtime {}

impl<T> built_in::context::HostHolderWithStore<T> for Runtime {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<Holder>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn key(accessor: &Accessor<T, Self>, self_: Resource<Holder>) -> Result<String> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::HolderKey
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        let holder = table.get(&self_)?;
        Ok(holder.holder_ref.to_string())
    }

    async fn from_ref(
        accessor: &Accessor<T, Self>,
        ref_: HolderRef,
    ) -> Result<Result<Resource<Holder>, WitError>> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::HolderFromRef
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let holder = match Holder::from_holder_ref(ref_.clone(), &runtime).await {
            Ok(h) => h,
            Err(e) => {
                // Debug-level: a "signer not found" in view context is
                // a legitimate deterministic outcome (the contract sees
                // it as Err and decides what to do — usually return
                // None). The WIT result already carries the error to
                // the contract; logging is purely diagnostic.
                tracing::debug!("Holder::from_ref returning Err for {ref_:?}: {e:?}");
                return Ok(Err(e));
            }
        };
        let mut table = runtime.table.lock().await;
        Ok(Ok(table.push(holder)?))
    }

    async fn as_ref(accessor: &Accessor<T, Self>, self_: Resource<Holder>) -> Result<HolderRef> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::HolderAsRef
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        let holder = table.get(&self_)?;
        Ok(holder.holder_ref.clone())
    }
}
