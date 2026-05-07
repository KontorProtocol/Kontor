use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{Keys, ViewStorage};

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
        path: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_list_u8<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<Vec<u8>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_keys<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(accessor, self_, path)
            .await
    }

    async fn exists<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(accessor, self_, path)
            .await
    }

    async fn extend_path_with_match<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
        variants: Vec<String>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._extend_path_with_match(accessor, self_, path, variants)
            .await
    }
}
