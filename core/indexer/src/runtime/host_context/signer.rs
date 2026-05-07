use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::wit::{Holder, Signer};

impl built_in::context::HostSigner for Runtime {}

impl built_in::context::HostSignerWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Signer>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn key<T>(accessor: &Accessor<T, Self>, self_: Resource<Signer>) -> Result<String> {
        accessor
            .with(|mut access| access.get().clone())
            ._signer_to_string(accessor, self_)
            .await
    }

    async fn as_holder<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<Signer>,
    ) -> Result<Resource<Holder>> {
        accessor
            .with(|mut access| access.get().clone())
            ._signer_as_holder(accessor, self_)
            .await
    }

    async fn as_ref<T>(accessor: &Accessor<T, Self>, self_: Resource<Signer>) -> Result<HolderRef> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::HolderAsRef
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        let signer = table.get(&self_)?;
        Ok(Self::_signer_to_holder_ref(signer))
    }
}
