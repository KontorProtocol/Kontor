use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::IndexRows;
use crate::runtime::wit::kontor::built_in;

impl built_in::context::HostIndexRows for Runtime {}

impl<T> built_in::context::HostIndexRowsWithStore<T> for Runtime {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<IndexRows>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn next(
        accessor: &Accessor<T, Self>,
        self_: Resource<IndexRows>,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        accessor
            .with(|mut access| access.get().clone())
            ._next_index_row(accessor, self_)
            .await
    }
}
