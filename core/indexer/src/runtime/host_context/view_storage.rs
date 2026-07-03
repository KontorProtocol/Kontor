use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{IndexRows, Keys, ViewStorage};

impl built_in::context::HostViewStorage for Runtime {}

impl built_in::context::HostViewStorageWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ViewStorage>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn get_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: Vec<u8>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: Vec<u8>,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: Vec<u8>,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: Vec<u8>,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_list_u8<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_keys<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: Vec<u8>,
        after: Option<Vec<u8>>,
        from: Option<Vec<u8>>,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(accessor, self_, path, after, from)
            .await
    }

    async fn get_index_rows<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: Vec<u8>,
        after: Option<Vec<u8>>,
        from: Option<Vec<u8>>,
    ) -> Result<Resource<IndexRows>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_index_rows(accessor, self_, path, after, from)
            .await
    }

    async fn exists<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: Vec<u8>,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(accessor, self_, path)
            .await
    }

    async fn extend_path_with_match<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: Vec<u8>,
        candidates: Vec<Vec<u8>>,
    ) -> Result<Option<u32>> {
        accessor
            .with(|mut access| access.get().clone())
            ._extend_path_with_match(accessor, self_, path, candidates)
            .await
    }
}
