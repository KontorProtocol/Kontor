use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{Keys, ProcStorage, ViewStorage};

impl built_in::context::HostProcStorage for Runtime {}

impl built_in::context::HostProcStorageWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ProcStorage>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn get_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_list_u8<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<Vec<u8>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_keys<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(accessor, self_, path)
            .await
    }

    async fn exists<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(accessor, self_, path)
            .await
    }

    async fn extend_path_with_match<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        variants: Vec<String>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._extend_path_with_match(accessor, self_, path, variants)
            .await
    }

    async fn set_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        value: String,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        value: u64,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        value: i64,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        value: bool,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_list_u8<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        value: Vec<u8>,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_void<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, ())
            .await
    }

    async fn delete_matching_paths<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        base_path: String,
        variants: Vec<String>,
    ) -> Result<u64> {
        accessor
            .with(|mut access| access.get().clone())
            ._delete_matching_paths(
                accessor,
                self_,
                format!(r"^{}.({})(\..*|$)", base_path, variants.join("|")),
            )
            .await
    }

    async fn view_storage<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
    ) -> Result<Resource<ViewStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_view_storage(accessor, self_)
            .await
    }
}
