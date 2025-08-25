mod component_cache;
mod native_contracts;
mod storage;
mod types;
mod wit;

pub use component_cache::ComponentCache;
use libsql::Connection;
pub use native_contracts::load_native_contracts;
use serde::{Deserialize, Serialize};
pub use storage::Storage;
use tokio::sync::Mutex;
pub use types::default_val_for_type;
pub use wit::Contract;

use std::{
    io::{Cursor, Read},
    sync::Arc,
};

use wit::kontor::*;

pub use wit::kontor::built_in::foreign::ContractAddress;

use anyhow::{Result, anyhow};
use wasmtime::{
    Engine, Store,
    component::{
        Component, HasSelf, Linker, Resource, ResourceTable,
        wasm_wave::{
            parser::Parser as WaveParser, to_string as to_wave_string, value::Value as WaveValue,
        },
    },
};
use wit_component::ComponentEncoder;

use crate::runtime::wit::{FallContext, HasContractId, ProcContext, Signer, ViewContext};

pub fn serialize_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::into_writer(value, &mut buffer)?;
    Ok(buffer)
}

pub fn deserialize_cbor<T: for<'a> Deserialize<'a>>(buffer: &[u8]) -> Result<T> {
    Ok(ciborium::from_reader(&mut Cursor::new(buffer))?)
}

#[derive(Clone)]
pub struct Runtime {
    pub engine: Engine,
    pub table: Arc<Mutex<ResourceTable>>,
    pub component_cache: ComponentCache,
    pub storage: Storage,
}

impl Runtime {
    pub async fn new(storage: Storage, component_cache: ComponentCache) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.wasm_component_model(true);
        // Ensure deterministic execution
        config.wasm_threads(false);
        config.wasm_relaxed_simd(false);
        config.cranelift_nan_canonicalization(true);
        let engine = Engine::new(&config)?;
        let runtime = Self {
            engine,
            table: Arc::new(Mutex::new(ResourceTable::new())),
            component_cache,
            storage,
        };
        Ok(runtime)
    }

    pub fn get_storage_conn(&self) -> Connection {
        self.storage.conn.clone()
    }

    pub fn make_store(&self) -> Store<Self> {
        Store::new(&self.engine, self.clone())
    }

    pub fn make_linker(&self) -> Result<Linker<Self>> {
        let mut linker = Linker::new(&self.engine);
        Contract::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s)?;
        Ok(linker)
    }

    pub async fn load_component(&self, contract_id: i64) -> Result<Component> {
        Ok(match self.component_cache.get(&contract_id) {
            Some(component) => component,
            None => {
                let compressed_bytes = self
                    .storage
                    .contract_bytes(contract_id)
                    .await?
                    .ok_or(anyhow!("Contract not found"))?;
                let mut decompressor = brotli::Decompressor::new(&compressed_bytes[..], 4096);
                let mut module_bytes = Vec::new();
                decompressor.read_to_end(&mut module_bytes)?;

                let component_bytes = ComponentEncoder::default()
                    .module(&module_bytes)?
                    .validate(true)
                    .encode()?;

                let component = Component::from_binary(&self.engine, &component_bytes)?;
                self.component_cache.put(contract_id, component.clone());
                component
            }
        })
    }

    pub async fn execute(
        &self,
        signer: Option<&str>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        let contract_id = self
            .storage
            .contract_id(contract_address)
            .await?
            .ok_or(anyhow!("Contract not found"))?;
        let component = self.load_component(contract_id).await?;
        let linker = self.make_linker()?;
        let mut store = self.make_store();
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let fallback_name = "fallback";
        let fallback_expr = format!(
            "{}({})",
            fallback_name,
            to_wave_string(&WaveValue::from(expr))?
        );

        let call = WaveParser::new(expr).parse_raw_func_call()?;
        let (call, func) = if let Some(func) = instance.get_func(&mut store, call.name()) {
            (call, func)
        } else if let Some(func) = instance.get_func(&mut store, fallback_name) {
            (WaveParser::new(&fallback_expr).parse_raw_func_call()?, func)
        } else {
            return Err(anyhow!("Expression does not refer to any known function"));
        };

        let func_params = func.params(&store);
        let func_param_types = func_params.iter().map(|(_, t)| t).collect::<Vec<_>>();
        let (func_ctx_param_type, func_param_types) = func_param_types
            .split_first()
            .ok_or(anyhow!("Context/signer parameter not found"))?;
        let mut params = call.to_wasm_params(func_param_types.to_vec())?;
        let resource_type = match func_ctx_param_type {
            wasmtime::component::Type::Borrow(t) => Ok(*t),
            _ => Err(anyhow!("Unsupported context type")),
        }?;
        {
            let mut table = self.table.lock().await;
            match (resource_type, signer) {
                (t, Some(signer))
                    if t.eq(&wasmtime::component::ResourceType::host::<ProcContext>()) =>
                {
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(ProcContext {
                                    signer: signer.to_string(),
                                    contract_id,
                                })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    )
                }
                (t, _) if t.eq(&wasmtime::component::ResourceType::host::<ViewContext>()) => params
                    .insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(ViewContext { contract_id })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    ),
                (t, signer) if t.eq(&wasmtime::component::ResourceType::host::<FallContext>()) => {
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(FallContext {
                                    signer: signer.map(|s| s.to_string()),
                                    contract_id,
                                })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    )
                }
                _ => return Err(anyhow!("Unsupported context/signer type")),
            }
        }

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
            let result = results.remove(0);
            return if call.name() == fallback_name {
                if let wasmtime::component::Val::String(return_expr) = result {
                    Ok(return_expr)
                } else {
                    Err(anyhow!("{fallback_name} did not return a string"))
                }
            } else {
                result.to_wave()
            };
        }

        Err(anyhow!(
            "Functions with multiple return values are not supported"
        ))
    }

    async fn _get_str<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<Option<String>> {
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        let bs = self.storage.get(_self.get_contract_id(), &path).await?;
        match bs {
            Some(bs) => deserialize_cbor(&bs),
            None => Ok(None),
        }
    }

    async fn _get_u64<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<Option<u64>> {
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        let bs = self.storage.get(_self.get_contract_id(), &path).await?;
        match bs {
            Some(bs) => deserialize_cbor(&bs),
            None => Ok(None),
        }
    }

    async fn _get_s64<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<Option<i64>> {
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        let bs = self.storage.get(_self.get_contract_id(), &path).await?;
        match bs {
            Some(bs) => deserialize_cbor(&bs),
            None => Ok(None),
        }
    }

    async fn _is_void<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<bool> {
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        let contract_id = _self.get_contract_id();
        let bs = self.storage.get(contract_id, &path).await?;
        Ok(if let Some(bs) = bs {
            bs.is_empty()
        } else if self.storage.exists(contract_id, &path).await? {
            false
        } else {
            panic!("Key not found in is_void check")
        })
    }

    async fn _exists<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<bool> {
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        self.storage.exists(_self.get_contract_id(), &path).await
    }

    async fn _matching_path<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        regexp: String,
    ) -> Result<Option<String>> {
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        self.storage
            .matching_path(_self.get_contract_id(), &regexp)
            .await
    }
}

impl built_in::foreign::Host for Runtime {
    async fn call(
        &mut self,
        contract_address: ContractAddress,
        signer: Option<Resource<Signer>>,
        expr: String,
    ) -> Result<String> {
        let signer = if let Some(resource) = signer {
            let table = self.table.lock().await;
            let _self = table.get(&resource)?;
            Some(_self.signer.clone())
        } else {
            None
        };
        self.execute(signer.as_deref(), &contract_address, &expr)
            .await
    }
}

impl built_in::context::Host for Runtime {}

impl built_in::context::HostViewContext for Runtime {
    async fn get_str(
        &mut self,
        resource: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<String>> {
        self._get_str(resource, path).await
    }

    async fn get_u64(
        &mut self,
        resource: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<u64>> {
        self._get_u64(resource, path).await
    }

    async fn get_s64(
        &mut self,
        resource: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<i64>> {
        self._get_s64(resource, path).await
    }

    async fn is_void(&mut self, resource: Resource<ViewContext>, path: String) -> Result<bool> {
        self._is_void(resource, path).await
    }

    async fn exists(&mut self, resource: Resource<ViewContext>, path: String) -> Result<bool> {
        self._exists(resource, path).await
    }

    async fn matching_path(
        &mut self,
        resource: Resource<ViewContext>,
        regexp: String,
    ) -> Result<Option<String>> {
        self._matching_path(resource, regexp).await
    }

    async fn drop(&mut self, resource: Resource<ViewContext>) -> Result<()> {
        let _res = self.table.lock().await.delete(resource)?;
        Ok(())
    }
}

impl built_in::context::HostSigner for Runtime {
    async fn to_string(&mut self, resource: Resource<Signer>) -> Result<String> {
        Ok(self.table.lock().await.get(&resource)?.signer.clone())
    }

    async fn drop(&mut self, resource: Resource<Signer>) -> Result<()> {
        let _res = self.table.lock().await.delete(resource)?;
        Ok(())
    }
}

impl built_in::context::HostProcContext for Runtime {
    async fn get_str(
        &mut self,
        resource: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<String>> {
        self._get_str(resource, path).await
    }

    async fn set_str(
        &mut self,
        resource: Resource<ProcContext>,
        path: String,
        value: String,
    ) -> Result<()> {
        let contract_id = self.table.lock().await.get(&resource)?.contract_id;
        let bs = serialize_cbor(&value)?;
        self.storage.set(contract_id, &path, &bs).await
    }

    async fn get_u64(
        &mut self,
        resource: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<u64>> {
        self._get_u64(resource, path).await
    }

    async fn set_u64(
        &mut self,
        resource: Resource<ProcContext>,
        path: String,
        value: u64,
    ) -> Result<()> {
        let bs = serialize_cbor(&value)?;
        let contract_id = self.table.lock().await.get(&resource)?.contract_id;
        self.storage.set(contract_id, &path, &bs).await
    }

    async fn get_s64(
        &mut self,
        resource: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<i64>> {
        self._get_s64(resource, path).await
    }

    async fn set_s64(
        &mut self,
        resource: Resource<ProcContext>,
        path: String,
        value: i64,
    ) -> Result<()> {
        let bs = serialize_cbor(&value)?;
        let contract_id = self.table.lock().await.get(&resource)?.contract_id;
        self.storage.set(contract_id, &path, &bs).await
    }

    async fn set_void(&mut self, resource: Resource<ProcContext>, path: String) -> Result<()> {
        let contract_id = self.table.lock().await.get(&resource)?.contract_id;
        self.storage.set(contract_id, &path, &[]).await
    }

    async fn is_void(&mut self, resource: Resource<ProcContext>, path: String) -> Result<bool> {
        self._is_void(resource, path).await
    }

    async fn exists(&mut self, resource: Resource<ProcContext>, path: String) -> Result<bool> {
        self._exists(resource, path).await
    }

    async fn matching_path(
        &mut self,
        resource: Resource<ProcContext>,
        regexp: String,
    ) -> Result<Option<String>> {
        self._matching_path(resource, regexp).await
    }

    async fn signer(&mut self, resource: Resource<ProcContext>) -> Result<Resource<Signer>> {
        let mut table = self.table.lock().await;
        let _self = table.get(&resource)?;
        let signer = _self.signer.clone();
        Ok(table.push(Signer { signer })?)
    }

    async fn view_context(
        &mut self,
        resource: Resource<ProcContext>,
    ) -> Result<Resource<ViewContext>> {
        let mut table = self.table.lock().await;
        let contract_id = table.get(&resource)?.contract_id;
        Ok(table.push(ViewContext { contract_id })?)
    }

    async fn drop(&mut self, rep: Resource<ProcContext>) -> Result<()> {
        let _res = self.table.lock().await.delete(rep)?;
        Ok(())
    }
}

impl built_in::context::HostFallContext for Runtime {
    async fn signer(
        &mut self,
        resource: Resource<FallContext>,
    ) -> Result<Option<Resource<Signer>>> {
        let mut table = self.table.lock().await;
        if let Some(signer) = table.get(&resource)?.signer.clone() {
            Ok(Some(table.push(Signer { signer })?))
        } else {
            Ok(None)
        }
    }

    async fn proc_context(
        &mut self,
        resource: Resource<FallContext>,
    ) -> Result<Option<Resource<ProcContext>>> {
        let mut table = self.table.lock().await;
        let _self = table.get(&resource)?;
        let contract_id = _self.contract_id;
        if let Some(signer) = _self.signer.clone() {
            Ok(Some(table.push(ProcContext {
                contract_id,
                signer,
            })?))
        } else {
            Ok(None)
        }
    }

    async fn view_context(
        &mut self,
        resource: Resource<FallContext>,
    ) -> Result<Resource<ViewContext>> {
        let mut table = self.table.lock().await;
        let contract_id = table.get(&resource)?.contract_id;
        Ok(table.push(ViewContext { contract_id })?)
    }

    async fn drop(&mut self, rep: Resource<FallContext>) -> Result<()> {
        let _res = self.table.lock().await.delete(rep)?;
        Ok(())
    }
}
