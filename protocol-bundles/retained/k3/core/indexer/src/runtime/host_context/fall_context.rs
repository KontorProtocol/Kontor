use anyhow::Result;
use wasmtime::component::{Access, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{FallContext, Holder, ProcContext, Signer, ViewContext};

impl built_in::context::HostFallContext for Runtime {
    async fn drop(&mut self, rep: Resource<FallContext>) -> Result<()> {
        self._drop(rep).await
    }
}

impl<T: Send> built_in::context::HostFallContextWithStore<T> for Runtime {
    async fn signer(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<Signer>>> {
        accessor
            .get()
            .clone()
            ._fall_signer(&mut accessor, self_)
            .await
    }

    async fn payer(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<Holder>>> {
        accessor
            .get()
            .clone()
            ._fall_payer(&mut accessor, self_)
            .await
    }

    async fn proc_context(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<ProcContext>>> {
        accessor
            .get()
            .clone()
            ._fall_proc_context(&mut accessor, self_)
            .await
    }

    async fn view_context(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Resource<ViewContext>> {
        accessor
            .get()
            .clone()
            ._fall_view_context(&mut accessor, self_)
            .await
    }
}
