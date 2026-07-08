use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{IndexRows, Keys, ProcStorage, ViewStorage};

impl built_in::context::HostProcStorage for Runtime {}

impl<T> built_in::context::HostProcStorageWithStore<T> for Runtime {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<ProcStorage>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn get_str(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_u64(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_s64(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_bool(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_list_u8(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_keys(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
        lo: Option<Vec<u8>>,
        hi: Option<Vec<u8>>,
        descending: bool,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(accessor, self_, path, lo, hi, descending)
            .await
    }

    async fn get_index_rows(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
        lo: Option<Vec<u8>>,
        hi: Option<Vec<u8>>,
        descending: bool,
    ) -> Result<Resource<IndexRows>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_index_rows(accessor, self_, path, lo, hi, descending)
            .await
    }

    async fn exists(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(accessor, self_, path)
            .await
    }

    async fn extend_path_with_match(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
        candidates: Vec<Vec<u8>>,
    ) -> Result<Option<u32>> {
        accessor
            .with(|mut access| access.get().clone())
            ._extend_path_with_match(accessor, self_, path, candidates)
            .await
    }

    async fn set_str(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
        value: String,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_u64(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
        value: u64,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_s64(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
        value: i64,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_bool(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
        value: bool,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_list_u8(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
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

    async fn delete(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: Vec<u8>,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._delete(accessor, self_, path)
            .await
    }

    async fn delete_matching_paths(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        base_path: Vec<u8>,
        candidates: Vec<Vec<u8>>,
    ) -> Result<u64> {
        accessor
            .with(|mut access| access.get().clone())
            ._delete_matching_paths(accessor, self_, base_path, candidates)
            .await
    }

    async fn view_storage(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
    ) -> Result<Resource<ViewStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_view_storage(accessor, self_)
            .await
    }
}
