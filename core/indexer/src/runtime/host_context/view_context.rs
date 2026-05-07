use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{ViewContext, ViewStorage};

impl built_in::context::HostViewContext for Runtime {}

impl built_in::context::HostViewContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ViewContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn storage<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
    ) -> Result<Resource<ViewStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._view_storage(accessor, self_)
            .await
    }
}
