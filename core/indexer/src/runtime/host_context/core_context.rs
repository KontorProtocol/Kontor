use anyhow::Result;
use wasmtime::component::{Access, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{Contract, CoreContext, ProcContext, Signer};

impl built_in::context::HostCoreContext for Runtime {
    async fn drop(&mut self, rep: Resource<CoreContext>) -> Result<()> {
        self._drop(rep).await
    }
}

impl<T: Send> built_in::context::HostCoreContextWithStore<T> for Runtime {
    async fn proc_context(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        accessor
            .get()
            .clone()
            ._core_proc_context(&mut accessor, self_)
            .await
    }

    async fn signer_proc_context(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        accessor
            .get()
            .clone()
            ._core_signer_proc_context(&mut accessor, self_)
            .await
    }

    async fn core_signer(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .get()
            .clone()
            ._core_signer(&mut accessor, self_)
            .await
    }

    async fn contract(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<Contract>> {
        accessor
            .get()
            .clone()
            ._contract(&mut accessor, self_, Fuel::CoreContract)
            .await
    }
}
