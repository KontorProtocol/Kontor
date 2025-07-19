mod component_cache;
mod dot_path_buf;
mod storage;
mod types;
mod wit;

pub use component_cache::ComponentCache;
pub use dot_path_buf::DotPathBuf;
use serde::{Deserialize, Serialize};
pub use storage::Storage;
pub use types::default_val_for_type;
pub use wit::Contract;

use std::{
    fs::read,
    io::{Cursor, Read},
    path::Path,
};

use wit::kontor::*;

use anyhow::{Result, anyhow};
use wasmtime::{
    Engine, Store,
    component::{
        Component, HasSelf, Linker, Resource, ResourceTable,
        wasm_wave::parser::Parser as WaveParser,
    },
};
use wit_component::ComponentEncoder;

use crate::runtime::wit::{ProcContext, ProcStorage, ViewContext, ViewStorage};

#[derive(Clone, Copy, PartialEq)]
pub enum Context {
    View,
    Proc,
}

pub struct Runtime {
    pub engine: Engine,
    pub table: ResourceTable,
    pub component_cache: ComponentCache,
    pub storage: Storage,
    pub signer: String,
    pub contract_id: String,
}

impl Clone for Runtime {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            table: ResourceTable::new(),
            component_cache: self.component_cache.clone(),
            storage: self.storage.clone(),
            signer: self.signer.clone(),
            contract_id: self.contract_id.clone(),
        }
    }
}

impl Runtime {
    pub fn new(
        storage: Storage,
        component_cache: ComponentCache,
        signer: String,
        contract_id: String,
    ) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.wasm_component_model(true);
        let engine = Engine::new(&config)?;
        let runtime = Self {
            engine,
            table: ResourceTable::new(),
            component_cache,
            storage,
            signer,
            contract_id,
        };
        runtime.load_component()?;
        Ok(runtime)
    }

    pub fn with_contract_id(&self, contract_id: String) -> Result<Self> {
        let mut runtime = self.clone();
        runtime.contract_id = contract_id;
        runtime.load_component()?;
        Ok(runtime)
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
                    "../../contracts/target/wasm32-unknown-unknown/release/{}.wasm.br",
                    self.contract_id,
                ))
                .canonicalize()?;
                let compressed_bytes = read(path)?;
                let mut decompressor = brotli::Decompressor::new(&compressed_bytes[..], 4096);
                let mut module_bytes = Vec::new();
                decompressor.read_to_end(&mut module_bytes)?;

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

    pub async fn execute(mut self, ctx: Option<Context>, expr: &str) -> Result<String> {
        let component = self.load_component()?;
        let linker = self.make_linker()?;
        let mut store = self.make_store();
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let call = WaveParser::new(expr).parse_raw_func_call()?;
        let func = instance
            .get_func(&mut store, call.name())
            .ok_or(anyhow!("Function not found"))?;

        let func_params = func.params(&store);
        let func_param_types = func_params.iter().map(|(_, t)| t).collect::<Vec<_>>();
        let (func_ctx_param_type, func_param_types) = func_param_types
            .split_first()
            .ok_or(anyhow!("Context parameter not found"))?;
        let resource_type = match func_ctx_param_type {
            wasmtime::component::Type::Borrow(t) => Ok(t),
            _ => Err(anyhow!("Unsupported context type")),
        }?;
        let mut params = call.to_wasm_params(func_param_types.to_vec())?;
        let context_param = match resource_type {
            t if t.eq(&wasmtime::component::ResourceType::host::<ProcContext>())
                && ctx.is_none_or(|c| c == Context::Proc) =>
            {
                self.table
                    .push(ProcContext {})?
                    .try_into_resource_any(&mut store)
            }
            t if t.eq(&wasmtime::component::ResourceType::host::<ViewContext>())
                && ctx.is_none_or(|c| c == Context::View) =>
            {
                self.table
                    .push(ViewContext {})?
                    .try_into_resource_any(&mut store)
            }
            _ => Err(anyhow!("Unsupported context type")),
        }?;
        params.insert(0, wasmtime::component::Val::Resource(context_param));

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

impl built_in::foreign::Host for Runtime {
    async fn call_view(
        &mut self,
        contract_id: String,
        _: Resource<ViewContext>,
        expr: String,
    ) -> Result<String> {
        let runtime = self.with_contract_id(contract_id)?;
        runtime.execute(Some(Context::View), &expr).await
    }

    async fn call_proc(
        &mut self,
        contract_id: String,
        _: Resource<ProcContext>,
        expr: String,
    ) -> Result<String> {
        let runtime = self.with_contract_id(contract_id)?;
        runtime.execute(Some(Context::Proc), &expr).await
    }
}

impl built_in::storage::Host for Runtime {}

pub fn serialize_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::into_writer(value, &mut buffer)?;
    Ok(buffer)
}

pub fn deserialize_cbor<T: for<'a> Deserialize<'a>>(buffer: &[u8]) -> Result<T> {
    Ok(ciborium::from_reader(&mut Cursor::new(buffer))?)
}

impl built_in::storage::HostViewStorage for Runtime {
    async fn get_str(&mut self, _: Resource<ViewStorage>, path: String) -> Result<Option<String>> {
        let bs = self
            .storage
            .get(&self.contract_id, &path)
            .await?
            .ok_or(anyhow!("Key not found"))?;
        deserialize_cbor(&bs)
    }

    async fn get_u64(&mut self, _: Resource<ViewStorage>, path: String) -> Result<Option<u64>> {
        let bs = self
            .storage
            .get(&self.contract_id, &path)
            .await?
            .ok_or(anyhow!("Key not found"))?;
        deserialize_cbor(&bs)
    }

    async fn exists(&mut self, _: Resource<ViewStorage>, path: String) -> Result<bool> {
        self.storage.exists(&self.contract_id, &path).await
    }

    async fn drop(&mut self, rep: Resource<ViewStorage>) -> Result<()> {
        let _res = self.table.delete(rep)?;
        Ok(())
    }
}

impl built_in::storage::HostProcStorage for Runtime {
    async fn get_str(&mut self, _: Resource<ProcStorage>, path: String) -> Result<Option<String>> {
        let bs = self
            .storage
            .get(&self.contract_id, &path)
            .await?
            .ok_or(anyhow!("Key not found"))?;
        deserialize_cbor(&bs)
    }

    async fn set_str(
        &mut self,
        _: Resource<ProcStorage>,
        path: String,
        value: String,
    ) -> Result<()> {
        let bs = serialize_cbor(&value)?;
        self.storage.set(&self.contract_id, &path, &bs).await
    }

    async fn get_u64(&mut self, _: Resource<ProcStorage>, path: String) -> Result<Option<u64>> {
        let bs = self
            .storage
            .get(&self.contract_id, &path)
            .await?
            .ok_or(anyhow!("Key not found"))?;
        deserialize_cbor(&bs)
    }

    async fn set_u64(&mut self, _: Resource<ProcStorage>, path: String, value: u64) -> Result<()> {
        let bs = serialize_cbor(&value)?;
        self.storage.set(&self.contract_id, &path, &bs).await
    }

    async fn exists(&mut self, _: Resource<ProcStorage>, path: String) -> Result<bool> {
        self.storage.exists(&self.contract_id, &path).await
    }

    async fn drop(&mut self, rep: Resource<ProcStorage>) -> Result<()> {
        let _res = self.table.delete(rep)?;
        Ok(())
    }
}

impl built_in::context::Host for Runtime {}

impl built_in::context::HostViewContext for Runtime {
    async fn storage(&mut self, _: Resource<ViewContext>) -> Result<Resource<ViewStorage>> {
        Ok(self.table.push(ViewStorage {})?)
    }

    async fn drop(&mut self, rep: Resource<ViewContext>) -> Result<()> {
        let _res = self.table.delete(rep)?;
        Ok(())
    }
}

impl built_in::context::HostProcContext for Runtime {
    async fn storage(&mut self, _: Resource<ProcContext>) -> Result<Resource<ProcStorage>> {
        Ok(self.table.push(ProcStorage {})?)
    }

    async fn signer(&mut self, _: Resource<ProcContext>) -> Result<String> {
        Ok(self.signer.clone())
    }

    async fn view_context(&mut self, _: Resource<ProcContext>) -> Result<Resource<ViewContext>> {
        Ok(self.table.push(ViewContext {})?)
    }

    async fn drop(&mut self, rep: Resource<ProcContext>) -> Result<()> {
        let _res = self.table.delete(rep)?;
        Ok(())
    }
}
