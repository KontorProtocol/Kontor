use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{Contract, ViewContext, ViewStorage};

impl built_in::context::HostViewContext for Runtime {}

impl<T> built_in::context::HostViewContextWithStore<T> for Runtime {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<ViewContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn storage(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
    ) -> Result<Resource<ViewStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._view_storage(accessor, self_)
            .await
    }

    async fn contract(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
    ) -> Result<Resource<Contract>> {
        accessor
            .with(|mut access| access.get().clone())
            ._contract(accessor, self_, Fuel::ViewContract)
            .await
    }
}
