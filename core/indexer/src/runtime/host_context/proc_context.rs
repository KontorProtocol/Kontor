use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{ProcContext, ProcStorage, Signer, Transaction, ViewContext};

impl built_in::context::HostProcContext for Runtime {}

impl built_in::context::HostProcContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ProcContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_signer(accessor, self_)
            .await
    }

    async fn contract_signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_contract_signer(accessor, self_)
            .await
    }

    async fn transaction<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Transaction>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_transaction(accessor, self_)
            .await
    }

    async fn view_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ViewContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_view_context(accessor, self_)
            .await
    }

    async fn generate_id<T>(
        accessor: &Accessor<T, Self>,
        _self: Resource<ProcContext>,
    ) -> Result<String> {
        accessor
            .with(|mut access| access.get().clone())
            ._generate_id(accessor)
            .await
    }

    async fn storage<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ProcStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_storage(accessor, self_)
            .await
    }

    async fn block_height<T>(
        accessor: &Accessor<T, Self>,
        _self: Resource<ProcContext>,
    ) -> Result<u64> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Ok(runtime.storage.height as u64)
    }
}
