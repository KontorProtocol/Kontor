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

    storage_methods! {T, StorageRows;
        fn next_str() -> Option<(Vec<u8>, String)> => _next_storage_row;
        fn next_u64() -> Option<(Vec<u8>, u64)> => _next_storage_row;
        fn next_s64() -> Option<(Vec<u8>, i64)> => _next_storage_row;
        fn next_bool() -> Option<(Vec<u8>, bool)> => _next_storage_row;
        fn next_list_u8() -> Option<(Vec<u8>, Vec<u8>)> => _next_storage_row;
    }
}
