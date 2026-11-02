use anyhow::Result;
use wasmtime::component::{Access, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::{
    Contract, Holder, ProcContext, ProcStorage, Signer, Transaction, ViewContext,
};

impl built_in::context::HostProcContext for Runtime {
    async fn drop(&mut self, rep: Resource<ProcContext>) -> Result<()> {
        self._drop(rep).await
    }
}

impl<T: Send> built_in::context::HostProcContextWithStore<T> for Runtime {
    async fn signer(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .get()
            .clone()
            ._proc_signer(&mut accessor, self_)
            .await
    }

    async fn payer(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Holder>> {
        accessor
            .get()
            .clone()
            ._proc_payer(&mut accessor, self_)
            .await
    }

    async fn contract_signer(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .get()
            .clone()
            ._proc_contract_signer(&mut accessor, self_)
            .await
    }

    async fn transaction(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Transaction>> {
        accessor
            .get()
            .clone()
            ._proc_transaction(&mut accessor, self_)
            .await
    }

    async fn view_context(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ViewContext>> {
        accessor
            .get()
            .clone()
            ._proc_view_context(&mut accessor, self_)
            .await
    }

    async fn generate_id(
        mut accessor: Access<'_, T, Self>,
        _self: Resource<ProcContext>,
    ) -> Result<String> {
        accessor.get().clone()._generate_id(&mut accessor).await
    }

    async fn storage(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ProcStorage>> {
        accessor
            .get()
            .clone()
            ._proc_storage(&mut accessor, self_)
            .await
    }

    async fn block_height(
        mut accessor: Access<'_, T, Self>,
        _self: Resource<ProcContext>,
    ) -> Result<u64> {
        Fuel::BlockHeight.consume(&mut accessor)?;
        Ok(accessor.get().storage.height)
    }

    async fn network(
        mut accessor: Access<'_, T, Self>,
        _self: Resource<ProcContext>,
    ) -> Result<built_in::context::Network> {
        Fuel::Network.consume(&mut accessor)?;
        let network = accessor.get().network;
        // `bitcoin::Network` is `#[non_exhaustive]`; fold Testnet4 and any
        // future test network into `testnet`.
        Ok(match network {
            bitcoin::Network::Bitcoin => built_in::context::Network::Mainnet,
            bitcoin::Network::Signet => built_in::context::Network::Signet,
            bitcoin::Network::Regtest => built_in::context::Network::Regtest,
            _ => built_in::context::Network::Testnet,
        })
    }

    async fn contract(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Contract>> {
        accessor
            .get()
            .clone()
            ._contract(&mut accessor, self_, Fuel::ProcContract)
            .await
    }
}
