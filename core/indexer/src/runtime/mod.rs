mod component_cache;
mod dot_path_buf;
mod storage;
mod types;
mod wit;

pub use component_cache::ComponentCache;
pub use dot_path_buf::DotPathBuf;
pub use storage::Storage;
pub use types::default_val_for_type;
pub use wit::Contract;

use std::{fs::read, path::Path};

use wit::kontor::*;

use anyhow::{Result, anyhow};
use wasmtime::{
    Engine, Store,
    component::{
        Component, HasSelf, Linker, ResourceTable, wasm_wave::parser::Parser as WaveParser,
    },
};
use wit_component::ComponentEncoder;

pub struct Runtime {
    pub engine: Engine,
    pub table: ResourceTable,
    pub component_cache: ComponentCache,
    pub storage: Storage,
    pub contract_id: String,
}

impl Clone for Runtime {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            table: ResourceTable::new(),
            component_cache: self.component_cache.clone(),
            storage: self.storage.clone(),
            contract_id: self.contract_id.clone(),
        }
    }
}

impl Runtime {
    pub fn new(
        storage: Storage,
        component_cache: ComponentCache,
        contract_id: String,
    ) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.wasm_component_model(true);
        let engine = Engine::new(&config)?;
        let context = Self {
            engine,
            table: ResourceTable::new(),
            component_cache,
            storage,
            contract_id,
        };
        context.load_component()?;
        Ok(context)
    }

    pub fn with_contract_id(&self, contract_id: String) -> Result<Self> {
        let context = Self {
            engine: self.engine.clone(),
            table: ResourceTable::new(),
            component_cache: self.component_cache.clone(),
            storage: self.storage.clone(),
            contract_id,
        };
        context.load_component()?;
        Ok(context)
    }

    pub fn make_store(&self) -> Store<Self> {
        Store::new(&self.engine, self.clone())
    }

    pub fn make_linker(&self) -> Result<Linker<Self>> {
        let mut linker = Linker::new(&self.engine);
        Contract::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s)?;
        Ok(linker)
    }

    pub fn load_component(&self) -> Result<Component> {
        Ok(match self.component_cache.get(&self.contract_id) {
            Some(component) => component,
            None => {
                let path = Path::new(&format!(
                    "../../contracts/target/wasm32-unknown-unknown/debug/{}.wasm",
                    self.contract_id,
                ))
                .canonicalize()?;
                let module_bytes = read(path)?;
                let component_bytes = ComponentEncoder::default()
                    .module(&module_bytes)?
                    .validate(true)
                    .encode()?;

                let component = Component::from_binary(&self.engine, &component_bytes)?;
                self.component_cache
                    .put(self.contract_id.clone(), component.clone());
                component
            }
        })
    }

    pub async fn execute(self, expr: &str) -> Result<String> {
        let component = self.load_component()?;
        let linker = self.make_linker()?;
        let mut store = self.make_store();
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let call = WaveParser::new(expr).parse_raw_func_call()?;
        let func = instance
            .get_func(&mut store, call.name())
            .ok_or(anyhow!("Function not found"))?;
        let params = call.to_wasm_params(func.params(&store).iter().map(|(_, t)| t))?;
        let mut results = func
            .results(&store)
            .iter()
            .map(default_val_for_type)
            .collect::<Vec<_>>();
        func.call_async(&mut store, &params, &mut results).await?;
        if results.is_empty() {
            return Ok("()".to_string());
        }

        if results.len() == 1 {
            return results[0].to_wave();
        }

        Err(anyhow!(
            "Functions with multiple return values are not supported"
        ))
    }
}

impl built_in::storage::Host for Runtime {
    async fn set(&mut self, key: String, value: Vec<u8>) -> Result<()> {
        self.storage.set(&self.contract_id, &key, &value).await
    }

    async fn get(&mut self, key: String) -> Result<Option<Vec<u8>>> {
        self.storage.get(&self.contract_id, &key).await
    }

    async fn delete(&mut self, key: String) -> Result<bool> {
        self.storage.delete(&self.contract_id, &key).await
    }
}

impl built_in::foreign::Host for Runtime {
    async fn call(&mut self, contract_id: String, expr: String) -> Result<String> {
        let context = self.with_contract_id(contract_id)?;
        context.execute(&expr).await
    }
}
