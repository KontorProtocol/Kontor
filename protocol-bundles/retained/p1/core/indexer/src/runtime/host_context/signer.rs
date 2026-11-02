use anyhow::Result;
use wasmtime::component::{Access, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::wit::{Holder, Signer};

impl built_in::context::HostSigner for Runtime {
    async fn drop(&mut self, rep: Resource<Signer>) -> Result<()> {
        self._drop(rep).await
    }
}

impl<T: Send> built_in::context::HostSignerWithStore<T> for Runtime {
    async fn key(mut accessor: Access<'_, T, Self>, self_: Resource<Signer>) -> Result<String> {
        accessor
            .get()
            .clone()
            ._signer_to_string(&mut accessor, self_)
            .await
    }

    async fn as_holder(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<Signer>,
    ) -> Result<Resource<Holder>> {
        accessor
            .get()
            .clone()
            ._signer_as_holder(&mut accessor, self_)
            .await
    }

    async fn as_ref(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<Signer>,
    ) -> Result<HolderRef> {
        let runtime = accessor.get().clone();
        Fuel::HolderAsRef.consume(&mut accessor)?;
        let table = runtime.table.lock().await;
        let signer = table.get(&self_)?;
        Ok(Self::_signer_to_holder_ref(signer))
    }
}
