use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::Contract;
use crate::runtime::wit::kontor::built_in;

impl built_in::context::HostContract for Runtime {}

impl built_in::context::HostContractWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Contract>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn name<T>(accessor: &Accessor<T, Self>, self_: Resource<Contract>) -> Result<String> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::ContractName
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        Ok(table.get(&self_)?.address.name.clone())
    }

    async fn height<T>(accessor: &Accessor<T, Self>, self_: Resource<Contract>) -> Result<u64> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::ContractHeight
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        Ok(table.get(&self_)?.address.height)
    }

    async fn tx_index<T>(accessor: &Accessor<T, Self>, self_: Resource<Contract>) -> Result<u64> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::ContractTxIndex
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        Ok(table.get(&self_)?.address.tx_index)
    }
}
