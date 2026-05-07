use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{FallContext, ProcContext, Signer, ViewContext};

impl built_in::context::HostFallContext for Runtime {}

impl built_in::context::HostFallContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<FallContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<Signer>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._fall_signer(accessor, self_)
            .await
    }

    async fn proc_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<ProcContext>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._fall_proc_context(accessor, self_)
            .await
    }

    async fn view_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Resource<ViewContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._fall_view_context(accessor, self_)
            .await
    }
}
