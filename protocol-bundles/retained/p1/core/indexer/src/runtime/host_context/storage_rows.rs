use anyhow::Result;
use wasmtime::component::{Access, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::StorageRows;
use crate::runtime::wit::kontor::built_in;

impl built_in::context::HostStorageRows for Runtime {
    async fn drop(&mut self, rep: Resource<StorageRows>) -> Result<()> {
        self._drop(rep).await
    }
}

impl<T: Send> built_in::context::HostStorageRowsWithStore<T> for Runtime {
    storage_methods! {T, StorageRows;
        fn next_str() -> Option<(Vec<u8>, String)> => _next_storage_row;
        fn next_u64() -> Option<(Vec<u8>, u64)> => _next_storage_row;
        fn next_s64() -> Option<(Vec<u8>, i64)> => _next_storage_row;
        fn next_bool() -> Option<(Vec<u8>, bool)> => _next_storage_row;
        fn next_list_u8() -> Option<(Vec<u8>, Vec<u8>)> => _next_storage_row;
    }
}
