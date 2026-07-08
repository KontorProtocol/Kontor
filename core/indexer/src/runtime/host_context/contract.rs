use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::ContractAddress;
use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::Contract;
use crate::runtime::wit::kontor::built_in;

impl built_in::context::HostContract for Runtime {}

impl<T> built_in::context::HostContractWithStore<T> for Runtime {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<Contract>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn address(
        accessor: &Accessor<T, Self>,
        self_: Resource<Contract>,
    ) -> Result<ContractAddress> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::ContractAddress
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        Ok(table.get(&self_)?.address.clone())
    }
}
