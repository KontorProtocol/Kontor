use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{Keys, ProcStorage, StorageRows, ViewStorage};

impl built_in::context::HostProcStorage for Runtime {}

impl<T> built_in::context::HostProcStorageWithStore<T> for Runtime {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<ProcStorage>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    storage_methods! {T, ProcStorage;
        fn get_str(path: Vec<u8>) -> Option<String> => _get_primitive;
        fn get_u64(path: Vec<u8>) -> Option<u64> => _get_primitive;
        fn get_s64(path: Vec<u8>) -> Option<i64> => _get_primitive;
        fn get_bool(path: Vec<u8>) -> Option<bool> => _get_primitive;
        fn get_list_u8(path: Vec<u8>) -> Option<Vec<u8>> => _get_primitive;
        fn get_keys(path: Vec<u8>, lo: Option<Vec<u8>>, hi: Option<Vec<u8>>, descending: bool) -> Resource<Keys> => _get_keys;
        fn get_storage_rows(path: Vec<u8>, lo: Option<Vec<u8>>, hi: Option<Vec<u8>>, descending: bool) -> Resource<StorageRows> => _get_storage_rows;
        fn exists(path: Vec<u8>) -> bool => _exists;
        fn set_str(path: Vec<u8>, value: String) -> () => _set_primitive;
        fn set_u64(path: Vec<u8>, value: u64) -> () => _set_primitive;
        fn set_s64(path: Vec<u8>, value: i64) -> () => _set_primitive;
        fn set_bool(path: Vec<u8>, value: bool) -> () => _set_primitive;
        fn set_list_u8(path: Vec<u8>, value: Vec<u8>) -> () => _set_primitive;
        fn delete(path: Vec<u8>) -> bool => _delete;
        fn view_storage() -> Resource<ViewStorage> => _proc_view_storage;
    }

    async fn set_void(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, ())
            .await
    }
}
