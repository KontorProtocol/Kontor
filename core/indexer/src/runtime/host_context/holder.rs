use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::Holder;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::wit::kontor::built_in::error::Error as WitError;

impl built_in::context::HostHolder for Runtime {}

impl built_in::context::HostHolderWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Holder>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn key<T>(accessor: &Accessor<T, Self>, self_: Resource<Holder>) -> Result<String> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::HolderKey
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        let holder = table.get(&self_)?;
        Ok(holder.holder_ref.to_string())
    }

    async fn from_ref<T>(
        accessor: &Accessor<T, Self>,
        ref_: HolderRef,
    ) -> Result<Result<Resource<Holder>, WitError>> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::HolderFromRef
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let conn = runtime.get_storage_conn();
        let height = runtime.storage.height;
        let holder = match Holder::from_holder_ref(ref_.clone(), &conn, height).await {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("Holder::from_ref failed for {ref_:?}: {e:?}");
                return Ok(Err(e));
            }
        };
        let mut table = runtime.table.lock().await;
        Ok(Ok(table.push(holder)?))
    }

    async fn as_ref<T>(accessor: &Accessor<T, Self>, self_: Resource<Holder>) -> Result<HolderRef> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::HolderAsRef
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        let holder = table.get(&self_)?;
        Ok(holder.holder_ref.clone())
    }
}
