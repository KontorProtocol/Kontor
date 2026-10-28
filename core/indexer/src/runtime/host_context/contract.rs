use anyhow::Result;
use wasmtime::component::{Access, Resource};

use crate::runtime::ContractAddress;
use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::Contract;
use crate::runtime::wit::kontor::built_in;

impl built_in::context::HostContract for Runtime {
    async fn drop(&mut self, rep: Resource<Contract>) -> Result<()> {
        self._drop(rep).await
    }
}

impl<T: Send> built_in::context::HostContractWithStore<T> for Runtime {
    async fn address(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<Contract>,
    ) -> Result<ContractAddress> {
        let runtime = accessor.get().clone();
        Fuel::ContractAddress.consume(&mut accessor)?;
        let table = runtime.table.lock().await;
        let address = &table.get(&self_)?.address;
        Fuel::ContractNameBytes(address.name.len() as u64).consume(&mut accessor)?;
        Ok(address.clone())
    }
}
