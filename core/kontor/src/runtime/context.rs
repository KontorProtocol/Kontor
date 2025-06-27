use crate::runtime::{
    component_cache::ComponentCache,
    wit::{ContractImports, Foreign},
};

use super::{
    storage::Storage,
    wit::kontor::built_in::{foreign, storage},
};
use anyhow::{Context as AnyhowContext, Result};
use wasmtime::{
    Engine,
    component::{Resource, ResourceTable},
};

pub struct Context {
    pub engine: Engine,
    pub table: ResourceTable,
    pub component_cache: ComponentCache,
    pub storage: Storage,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            table: ResourceTable::new(),
            component_cache: self.component_cache.clone(),
            storage: self.storage.clone(),
        }
    }
}

impl Context {
    pub fn new(engine: Engine, storage: Storage) -> Self {
        Self {
            engine,
            table: ResourceTable::new(),
            component_cache: ComponentCache::new(),
            storage,
        }
    }
}

impl ContractImports for Context {
    async fn test(&mut self) -> Result<()> {
        Ok(())
    }
}

impl storage::Host for Context {
    async fn set(&mut self, key: String, value: Vec<u8>) -> Result<()> {
        self.storage.set(&key, &value).await
    }

    async fn get(&mut self, key: String) -> Result<Option<Vec<u8>>> {
        self.storage.get(&key).await
    }

    async fn delete(&mut self, key: String) -> Result<bool> {
        self.storage.delete(&key).await
    }
}

impl foreign::Host for Context {}

impl foreign::HostForeign for Context {
    async fn new(&mut self, address: String) -> Result<Resource<Foreign>> {
        let component_dir = "../../contracts/target/wasm32-unknown-unknown/debug/";
        let rep = Foreign::new(
            self.engine.clone(),
            self.component_cache.clone(),
            component_dir.to_string(),
            address,
        )
        .await?;
        Ok(self.table.push(rep)?)
    }

    async fn call(&mut self, handle: Resource<Foreign>, expr: String) -> Result<String> {
        let rep = self.table.get(&handle)?;
        let mut context = self.clone();
        context.storage.contract_id = rep.address.clone();
        rep.call(context, &expr)
            .await
            .context("Foreign call failed")
    }

    async fn drop(&mut self, handle: Resource<Foreign>) -> Result<()> {
        let _rep: Foreign = self.table.delete(handle)?;
        Ok(())
    }
}
