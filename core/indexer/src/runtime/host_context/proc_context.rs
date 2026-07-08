use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{
    Contract, Holder, ProcContext, ProcStorage, Signer, Transaction, ViewContext,
};

impl built_in::context::HostProcContext for Runtime {}

impl<T> built_in::context::HostProcContextWithStore<T> for Runtime {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<ProcContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn signer(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_signer(accessor, self_)
            .await
    }

    async fn payer(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Holder>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_payer(accessor, self_)
            .await
    }

    async fn contract_signer(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_contract_signer(accessor, self_)
            .await
    }

    async fn transaction(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Transaction>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_transaction(accessor, self_)
            .await
    }

    async fn view_context(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ViewContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_view_context(accessor, self_)
            .await
    }

    async fn generate_id(
        accessor: &Accessor<T, Self>,
        _self: Resource<ProcContext>,
    ) -> Result<String> {
        accessor
            .with(|mut access| access.get().clone())
            ._generate_id(accessor)
            .await
    }

    async fn storage(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ProcStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_storage(accessor, self_)
            .await
    }

    async fn block_height(
        accessor: &Accessor<T, Self>,
        _self: Resource<ProcContext>,
    ) -> Result<u64> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Ok(runtime.storage.height)
    }

    async fn network(
        accessor: &Accessor<T, Self>,
        _self: Resource<ProcContext>,
    ) -> Result<built_in::context::Network> {
        let runtime = accessor.with(|mut access| access.get().clone());
        // `bitcoin::Network` is `#[non_exhaustive]`; fold Testnet4 and any
        // future test network into `testnet`.
        Ok(match runtime.network {
            bitcoin::Network::Bitcoin => built_in::context::Network::Mainnet,
            bitcoin::Network::Signet => built_in::context::Network::Signet,
            bitcoin::Network::Regtest => built_in::context::Network::Regtest,
            _ => built_in::context::Network::Testnet,
        })
    }

    async fn contract(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Contract>> {
        accessor
            .with(|mut access| access.get().clone())
            ._contract(accessor, self_, Fuel::ProcContract)
            .await
    }
}
