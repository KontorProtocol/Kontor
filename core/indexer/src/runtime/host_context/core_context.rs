use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{CoreContext, ProcContext, Signer};

impl built_in::context::HostCoreContext for Runtime {}

impl built_in::context::HostCoreContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<CoreContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn proc_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._core_proc_context(accessor, self_)
            .await
    }

    async fn signer_proc_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._core_signer_proc_context(accessor, self_)
            .await
    }

    async fn core_signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .with(|mut access| access.get().clone())
            ._core_signer(accessor, self_)
            .await
    }
}
