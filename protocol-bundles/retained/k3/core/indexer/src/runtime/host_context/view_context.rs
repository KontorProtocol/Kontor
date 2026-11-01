use anyhow::Result;
use wasmtime::component::{Access, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{Contract, ViewContext, ViewStorage};

impl built_in::context::HostViewContext for Runtime {
    async fn drop(&mut self, rep: Resource<ViewContext>) -> Result<()> {
        self._drop(rep).await
    }
}

impl<T: Send> built_in::context::HostViewContextWithStore<T> for Runtime {
    async fn storage(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<ViewContext>,
    ) -> Result<Resource<ViewStorage>> {
        accessor
            .get()
            .clone()
            ._view_storage(&mut accessor, self_)
            .await
    }

    async fn contract(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<ViewContext>,
    ) -> Result<Resource<Contract>> {
        accessor
            .get()
            .clone()
            ._contract(&mut accessor, self_, Fuel::ViewContract)
            .await
    }
}
