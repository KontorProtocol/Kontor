use anyhow::Result;
use futures_util::future::OptionFuture;
use indexer_types::deserialize;
use serde::{Deserialize, Serialize};
use wasmtime::AsContext;
use wasmtime::component::{Accessor, Resource};

use super::{
    Runtime,
    fuel::Fuel,
    wit::{HasContractId, Keys},
};

impl Runtime {
    pub(crate) async fn _get_primitive<S, T: HasContractId, R: for<'de> Deserialize<'de>>(
        &self,
        accessor: &Accessor<S, Self>,
        self_: Resource<T>,
        path: String,
    ) -> Result<Option<R>> {
        let fuel = accessor.with(|access| access.as_context().get_fuel())?;
        let table = self.table.lock().await;
        let contract_id = table.get(&self_)?.get_contract_id();
        OptionFuture::from(
            self.storage
                .get(fuel, contract_id, &path)
                .await?
                .map(async |bs| {
                    Fuel::Get(bs.len())
                        .consume(accessor, self.gauge.as_ref())
                        .await?;
                    deserialize(&bs)
                }),
        )
        .await
        .transpose()
    }

    pub(crate) async fn _get_keys<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: String,
    ) -> Result<Resource<Keys>> {
        let mut table = self.table.lock().await;
        let contract_id = table.get(&resource)?.get_contract_id();
        Fuel::GetKeys.consume(accessor, self.gauge.as_ref()).await?;
        let stream = Box::pin(self.storage.keys(contract_id, path.clone()).await?);
        Ok(table.push(Keys { stream })?)
    }

    pub(crate) async fn _exists<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: String,
    ) -> Result<bool> {
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        Fuel::Exists.consume(accessor, self.gauge.as_ref()).await?;
        self.storage.exists(_self.get_contract_id(), &path).await
    }

    pub(crate) async fn _extend_path_with_match<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: String,
        variants: Vec<String>,
    ) -> Result<Option<String>> {
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        Fuel::ExtendPathWithMatch(variants.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        self.storage
            .extend_path_with_match(
                _self.get_contract_id(),
                &path,
                &format!(r"^{}.({})(\..*|$)", path, variants.join("|")),
            )
            .await
    }

    pub(crate) async fn _delete_matching_paths<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        self_: Resource<T>,
        regexp: String,
    ) -> Result<u64> {
        Fuel::DeleteMatchingPaths(regexp.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let contract_id = self.table.lock().await.get(&self_)?.get_contract_id();
        self.storage
            .delete_matching_paths(contract_id, &regexp)
            .await
    }

    pub(crate) async fn _set_primitive<S, T: HasContractId, V: Serialize>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: String,
        value: V,
    ) -> Result<()> {
        let contract_id = self.table.lock().await.get(&resource)?.get_contract_id();
        Fuel::Path(path.clone())
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let bs = &indexer_types::serialize(&value)?;
        Fuel::Set(bs.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        self.storage.set(contract_id, &path, bs).await
    }
}
