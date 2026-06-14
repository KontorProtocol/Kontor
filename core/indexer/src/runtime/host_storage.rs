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
        let raw = self.storage.get(fuel, contract_id, path.as_bytes()).await?;
        if raw.is_none() {
            tracing::debug!(
                "storage read returned None: contract_id={contract_id} path={path} fuel={fuel} height={}",
                self.storage.height
            );
        }
        OptionFuture::from(raw.map(async |bs| {
            Fuel::Get(bs.len())
                .consume(accessor, self.gauge.as_ref())
                .await?;
            deserialize(&bs)
        }))
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
        let stream = Box::pin(self.storage.keys(contract_id, path.into_bytes()).await?);
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
        self.storage
            .exists(_self.get_contract_id(), path.as_bytes())
            .await
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
            .extend_path_with_match(_self.get_contract_id(), path.as_bytes(), &variants)
            .await
    }

    pub(crate) async fn _delete_matching_paths<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        self_: Resource<T>,
        base_path: String,
        variants: Vec<String>,
    ) -> Result<u64> {
        Fuel::DeleteMatchingPaths(variants.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let contract_id = self.table.lock().await.get(&self_)?.get_contract_id();
        self.storage
            .delete_matching_paths(contract_id, base_path.as_bytes(), &variants)
            .await
    }

    /// Tombstone a single path. Metered like a write (it appends a deleted
    /// version row). Returns true if a live value was removed.
    pub(crate) async fn _delete<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        self_: Resource<T>,
        path: String,
    ) -> Result<bool> {
        Fuel::Set(0).consume(accessor, self.gauge.as_ref()).await?;
        let contract_id = self.table.lock().await.get(&self_)?.get_contract_id();
        self.storage.delete(contract_id, path.as_bytes()).await
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
        self.storage.set(contract_id, path.as_bytes(), bs).await
    }
}
