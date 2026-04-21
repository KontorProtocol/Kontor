use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::Keys;
use crate::runtime::wit::kontor::built_in;

impl built_in::context::HostKeys for Runtime {}

impl built_in::context::HostKeysWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Keys>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn next<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<Keys>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._next(accessor, self_)
            .await
    }
}
