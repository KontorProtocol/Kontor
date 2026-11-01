use anyhow::Result;
use wasmtime::component::{Access, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{Keys, StorageRows, ViewStorage};

impl built_in::context::HostViewStorage for Runtime {
    async fn drop(&mut self, rep: Resource<ViewStorage>) -> Result<()> {
        self._drop(rep).await
    }
}

impl<T: Send> built_in::context::HostViewStorageWithStore<T> for Runtime {
    storage_methods! {T, ViewStorage;
        fn get_str(path: Vec<u8>) -> Option<String> => _get_primitive;
        fn get_u64(path: Vec<u8>) -> Option<u64> => _get_primitive;
        fn get_s64(path: Vec<u8>) -> Option<i64> => _get_primitive;
        fn get_bool(path: Vec<u8>) -> Option<bool> => _get_primitive;
        fn get_list_u8(path: Vec<u8>) -> Option<Vec<u8>> => _get_primitive;
        fn get_keys(path: Vec<u8>, lo: Option<Vec<u8>>, hi: Option<Vec<u8>>, descending: bool) -> Resource<Keys> => _get_keys;
        fn get_storage_rows(path: Vec<u8>, lo: Option<Vec<u8>>, hi: Option<Vec<u8>>, descending: bool) -> Resource<StorageRows> => _get_storage_rows;
        fn exists(path: Vec<u8>) -> bool => _exists;
    }
}
