use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::StorageRows;
use crate::runtime::wit::kontor::built_in;

impl built_in::context::HostStorageRows for Runtime {}

impl<T> built_in::context::HostStorageRowsWithStore<T> for Runtime {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<StorageRows>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn next(
        accessor: &Accessor<T, Self>,
        self_: Resource<StorageRows>,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        accessor
            .with(|mut access| access.get().clone())
            ._next_storage_row(accessor, self_)
            .await
    }
}
