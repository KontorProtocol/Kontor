use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{Keys, StorageRows, ViewStorage};

impl built_in::context::HostViewStorage for Runtime {}

impl<T> built_in::context::HostViewStorageWithStore<T> for Runtime {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<ViewStorage>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    storage_methods! {T, ViewStorage;
        fn get_str(path: Vec<u8>) -> Option<String> => _get_primitive;
        fn get_u64(path: Vec<u8>) -> Option<u64> => _get_primitive;
        fn get_s64(path: Vec<u8>) -> Option<i64> => _get_primitive;
        fn get_bool(path: Vec<u8>) -> Option<bool> => _get_primitive;
        fn get_list_u8(path: Vec<u8>) -> Option<Vec<u8>> => _get_primitive;
        fn get_keys(path: Vec<u8>, lo: Option<Vec<u8>>, hi: Option<Vec<u8>>, descending: bool) -> Resource<Keys> => _get_keys;
        fn get_storage_rows(path: Vec<u8>, lo: Option<Vec<u8>>, hi: Option<Vec<u8>>, descending: bool) -> Resource<StorageRows> => _get_storage_rows;
        fn exists(path: Vec<u8>) -> bool => _exists;
        fn extend_path_with_match(path: Vec<u8>, candidates: Vec<Vec<u8>>) -> Option<u32> => _extend_path_with_match;
    }
}
