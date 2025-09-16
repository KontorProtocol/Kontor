mod component_cache;
mod contracts;
mod counter;
pub mod numerics;
mod stack;
mod storage;
mod types;
pub mod wit;

pub use component_cache::ComponentCache;
pub use contracts::{load_contracts, load_native_contracts};
use futures_util::StreamExt;
use libsql::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stdlib::impls;
pub use storage::Storage;
use tokio::sync::Mutex;
pub use types::default_val_for_type;
pub use wit::Contract;

use std::{
    io::{Cursor, Read},
    sync::Arc,
};

use wit::kontor::*;

pub use wit::kontor;
pub use wit::kontor::built_in::error::Error;
pub use wit::kontor::built_in::foreign::ContractAddress;
pub use wit::kontor::built_in::numbers::{
    Decimal, Integer, Ordering as NumericOrdering, Sign as NumericSign,
};

use anyhow::{Result, anyhow};
use wasmtime::{
    AsContext, AsContextMut, Engine, Store,
    component::{
        Accessor, Component, HasData, Linker, Resource, ResourceTable,
        wasm_wave::{
            parser::Parser as WaveParser, to_string as to_wave_string, value::Value as WaveValue,
        },
    },
};
use wit_component::ComponentEncoder;

use crate::runtime::{
    counter::Counter,
    stack::Stack,
    wit::{FallContext, HasContractId, Keys, ProcContext, Signer, ViewContext},
};

impls!(host = true);

pub fn serialize_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::into_writer(value, &mut buffer)?;
    Ok(buffer)
}

pub fn deserialize_cbor<T: for<'a> Deserialize<'a>>(buffer: &[u8]) -> Result<T> {
    Ok(ciborium::from_reader(&mut Cursor::new(buffer))?)
}

async fn load_component(
    engine: &Engine,
    component_cache: &ComponentCache,
    storage: &Storage,
    contract_id: i64,
) -> Result<Component> {
    Ok(match component_cache.get(&contract_id) {
        Some(component) => component,
        None => {
            let compressed_bytes = storage
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

            let component = Component::from_binary(engine, &component_bytes)?;
            component_cache.put(contract_id, component.clone());
            component
        }
    })
}

pub fn make_linker(engine: &Engine) -> Result<Linker<Runtime>> {
    let mut linker = Linker::new(engine);
    Contract::add_to_linker::<_, Runtime>(&mut linker, |s| s)?;
    Ok(linker)
}

pub fn make_store(engine: &Engine, runtime: &Runtime, fuel: u64) -> Result<Store<Runtime>> {
    let mut s = Store::new(engine, runtime.clone());
    s.set_fuel(fuel)?;
    Ok(s)
}

#[derive(Clone)]
pub struct Runtime {
    pub engine: Engine,
    pub table: Arc<Mutex<ResourceTable>>,
    pub component_cache: ComponentCache,
    pub storage: Storage,
    pub id_generation_counter: Counter,
    pub stack: Stack<i64>,
}

impl Runtime {
    pub async fn new(storage: Storage, component_cache: ComponentCache) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.wasm_component_model(true);
        config.consume_fuel(true);
        // Ensure deterministic execution
        config.wasm_threads(false);
        config.wasm_relaxed_simd(false);
        config.cranelift_nan_canonicalization(true);
        let engine = Engine::new(&config)?;

        Ok(Self {
            engine,
            table: Arc::new(Mutex::new(ResourceTable::new())),
            component_cache,
            storage,
            id_generation_counter: Counter::new(),
            stack: Stack::new(),
        })
    }

    pub fn get_storage_conn(&self) -> Connection {
        self.storage.conn.clone()
    }

    pub fn set_storage(&mut self, storage: Storage) {
        self.storage = storage;
    }

    pub fn make_store(&self) -> Result<Store<Self>> {
        let mut s = Store::new(&self.engine, self.clone());
        s.set_fuel(1000000)?;
        Ok(s)
    }

    pub fn make_linker(&self) -> Result<Linker<Self>> {
        let mut linker = Linker::new(&self.engine);
        Contract::add_to_linker::<_, Runtime>(&mut linker, |s| s)?;
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
        signer: Option<Signer>,
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
        let mut store = self.make_store()?;
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
            if let Some(Signer::ContractId(id)) = signer
                && self.stack.peek().await != Some(id)
            {
                return Err(anyhow!("Invalid contract id signer"));
            }
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
                                    signer,
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
                                    signer,
                                    contract_id,
                                })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    )
                }
                _ => return Err(anyhow!("Unsupported context/signer type")),
            }
        }

        self.stack.push(contract_id).await?;
        let mut results = func
            .results(&store)
            .iter()
            .map(default_val_for_type)
            .collect::<Vec<_>>();
        let call_result = func.call_async(&mut store, &params, &mut results).await;
        self.stack.pop().await;
        call_result?;
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

    async fn _get_primitive<T: HasContractId, R: for<'de> Deserialize<'de>>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<Option<R>> {
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        self.storage
            .get(1000000, _self.get_contract_id(), &path)
            .await?
            .map(|bs| deserialize_cbor(&bs))
            .transpose()
    }

    async fn _get_str<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<Option<String>> {
        self._get_primitive(resource, path).await
    }

    async fn _get_u64<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<Option<u64>> {
        self._get_primitive(resource, path).await
    }

    async fn _get_s64<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<Option<i64>> {
        self._get_primitive(resource, path).await
    }

    async fn _get_bool<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<Option<bool>> {
        self._get_primitive(resource, path).await
    }

    async fn _get_void<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<Option<()>> {
        self._get_primitive(resource, path).await
    }

    async fn _get_keys<T: HasContractId>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<Resource<Keys>> {
        let mut table = self.table.lock().await;
        let contract_id = table.get(&resource)?.get_contract_id();
        let stream = Box::pin(self.storage.keys(contract_id, path.clone()).await?);
        Ok(table.push(Keys { stream })?)
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

    async fn _set_primitive<T: Serialize>(
        &mut self,
        resource: Resource<ProcContext>,
        path: String,
        value: T,
    ) -> Result<()> {
        let contract_id = self.table.lock().await.get(&resource)?.contract_id;
        self.storage
            .set(contract_id, &path, &serialize_cbor(&value)?)
            .await
    }
}

impl HasData for Runtime {
    type Data<'a> = &'a mut Runtime;
}

impl built_in::error::Host for Runtime {
    async fn meta_force_generate_error(&mut self, _e: built_in::error::Error) -> Result<()> {
        unimplemented!()
    }
}

fn _hash(input: String) -> Result<(String, Vec<u8>)> {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let bs = hasher.finalize().to_vec();
    let s = hex::encode(&bs);
    Ok((s, bs))
}

impl built_in::crypto::Host for Runtime {}

impl built_in::crypto::HostWithStore for Runtime {
    async fn hash<T>(_: &Accessor<T, Self>, input: String) -> Result<(String, Vec<u8>)> {
        _hash(input)
    }

    async fn hash_with_salt<T>(
        _: &Accessor<T, Self>,
        input: String,
        salt: String,
    ) -> Result<(String, Vec<u8>)> {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hasher.update(salt.as_bytes());
        let bs = hasher.finalize().to_vec();
        let s = hex::encode(&bs);
        Ok((s, bs))
    }

    async fn generate_id<T>(accessor: &Accessor<T, Self>) -> Result<String> {
        let (height, tx_id, counter) = accessor.with(|mut access| {
            let _self = access.get();
            (
                _self.storage.height,
                _self.storage.tx_id,
                _self.id_generation_counter.clone(),
            )
        });
        let count = counter.get().await;
        counter.increment().await;
        let s = format!("{}-{}-{}", height, tx_id, count);
        _hash(s).map(|(s, _)| s)
    }
}

impl built_in::foreign::Host for Runtime {}

impl built_in::foreign::HostWithStore for Runtime {
    async fn call<T>(
        accessor: &Accessor<T, Self>,
        signer: Option<Resource<Signer>>,
        contract_address: ContractAddress,
        expr: String,
    ) -> Result<String> {
        let (runtime, engine, component_cache, storage, stack, resource_table) =
            accessor.with(|mut access| {
                let runtime = access.get();
                (
                    runtime.clone(),
                    runtime.engine.clone(),
                    runtime.component_cache.clone(),
                    runtime.storage.clone(),
                    runtime.stack.clone(),
                    runtime.table.clone(),
                )
            });

        let signer = if let Some(resource) = signer {
            let _self = resource_table.lock().await.get(&resource)?.clone();
            Some(_self)
        } else {
            None
        };

        let contract_id = storage
            .contract_id(&contract_address)
            .await?
            .ok_or(anyhow!("Contract not found"))?;
        let component = load_component(&engine, &component_cache, &storage, contract_id).await?;
        let linker = make_linker(&engine)?;
        let fuel = accessor.with(|access| access.as_context().get_fuel())?;
        let mut store = make_store(&engine, &runtime, fuel)?;
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let fallback_name = "fallback";
        let fallback_expr = format!(
            "{}({})",
            fallback_name,
            to_wave_string(&WaveValue::from(expr.clone()))?
        );

        let call = WaveParser::new(&expr).parse_raw_func_call()?;
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
            if let Some(Signer::ContractId(id)) = signer
                && stack.peek().await != Some(id)
            {
                return Err(anyhow!("Invalid contract id signer"));
            }
            let mut table = resource_table.lock().await;
            match (resource_type, signer) {
                (t, Some(signer))
                    if t.eq(&wasmtime::component::ResourceType::host::<ProcContext>()) =>
                {
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(ProcContext {
                                    signer,
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
                                    signer,
                                    contract_id,
                                })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    )
                }
                _ => return Err(anyhow!("Unsupported context/signer type")),
            }
        }

        stack.push(contract_id).await?;
        let mut results = func
            .results(&store)
            .iter()
            .map(default_val_for_type)
            .collect::<Vec<_>>();
        let (call_result, mut results, fuel_result) = tokio::spawn({
            let mut store = store; // Move store into the task
            async move {
                let call_result = func.call_async(&mut store, &params, &mut results).await;
                (call_result, results, store.get_fuel())
            }
        })
        .await?;
        stack.pop().await;
        let remaining_fuel = fuel_result?;
        accessor.with(|mut access| access.as_context_mut().set_fuel(remaining_fuel))?;
        call_result?;
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

    async fn get_bool(
        &mut self,
        resource: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<bool>> {
        self._get_bool(resource, path).await
    }

    async fn get_keys(
        &mut self,
        resource: Resource<ViewContext>,
        path: String,
    ) -> Result<Resource<Keys>> {
        self._get_keys(resource, path).await
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
        Ok(self.table.lock().await.get(&resource)?.to_string())
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
        self._set_primitive(resource, path, value).await
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
        self._set_primitive(resource, path, value).await
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
        self._set_primitive(resource, path, value).await
    }

    async fn get_bool(
        &mut self,
        resource: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<bool>> {
        self._get_bool(resource, path).await
    }

    async fn get_keys(
        &mut self,
        resource: Resource<ProcContext>,
        path: String,
    ) -> Result<Resource<Keys>> {
        self._get_keys(resource, path).await
    }

    async fn set_bool(
        &mut self,
        resource: Resource<ProcContext>,
        path: String,
        value: bool,
    ) -> Result<()> {
        self._set_primitive(resource, path, value).await
    }

    async fn set_void(&mut self, resource: Resource<ProcContext>, path: String) -> Result<()> {
        let contract_id = self.table.lock().await.get(&resource)?.contract_id;
        self.storage.set(contract_id, &path, &[]).await
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

    async fn delete_matching_paths(
        &mut self,
        resource: Resource<ProcContext>,
        regexp: String,
    ) -> Result<u64> {
        let table = self.table.lock().await;
        let contract_id = table.get(&resource)?.contract_id;
        self.storage
            .delete_matching_paths(contract_id, &regexp)
            .await
    }

    async fn signer(&mut self, resource: Resource<ProcContext>) -> Result<Resource<Signer>> {
        let mut table = self.table.lock().await;
        let _self = table.get(&resource)?;
        let signer = _self.signer.clone();
        Ok(table.push(signer)?)
    }

    async fn contract_signer(
        &mut self,
        resource: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        let mut table = self.table.lock().await;
        let _self = table.get(&resource)?;
        let signer = Signer::ContractId(_self.contract_id);
        Ok(table.push(signer)?)
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

impl built_in::context::HostKeys for Runtime {
    async fn next(&mut self, rep: Resource<Keys>) -> Result<Option<String>> {
        let mut table = self.table.lock().await;
        let keys = table.get_mut(&rep)?;
        Ok(keys.stream.next().await.transpose()?)
    }

    async fn drop(&mut self, rep: Resource<Keys>) -> Result<()> {
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
            Ok(Some(table.push(signer)?))
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

impl built_in::numbers::Host for Runtime {
    async fn u64_to_integer(&mut self, i: u64) -> Result<Integer> {
        Ok(numerics::u64_to_integer(i))
    }

    async fn s64_to_integer(&mut self, i: i64) -> Result<Integer> {
        Ok(numerics::s64_to_integer(i))
    }

    async fn string_to_integer(&mut self, s: String) -> Result<Result<Integer, Error>> {
        Ok(numerics::string_to_integer(&s))
    }

    async fn integer_to_string(&mut self, i: Integer) -> Result<String> {
        Ok(numerics::integer_to_string(i))
    }

    async fn eq_integer(&mut self, a: Integer, b: Integer) -> Result<bool> {
        Ok(numerics::eq_integer(a, b))
    }

    async fn cmp_integer(&mut self, a: Integer, b: Integer) -> Result<NumericOrdering> {
        Ok(numerics::cmp_integer(a, b))
    }

    async fn add_integer(&mut self, a: Integer, b: Integer) -> Result<Result<Integer, Error>> {
        Ok(numerics::add_integer(a, b))
    }

    async fn sub_integer(&mut self, a: Integer, b: Integer) -> Result<Result<Integer, Error>> {
        Ok(numerics::sub_integer(a, b))
    }

    async fn mul_integer(&mut self, a: Integer, b: Integer) -> Result<Result<Integer, Error>> {
        Ok(numerics::mul_integer(a, b))
    }

    async fn div_integer(&mut self, a: Integer, b: Integer) -> Result<Result<Integer, Error>> {
        Ok(numerics::div_integer(a, b))
    }

    async fn integer_to_decimal(&mut self, i: Integer) -> Result<Decimal> {
        Ok(numerics::integer_to_decimal(i))
    }

    async fn decimal_to_integer(&mut self, d: Decimal) -> Result<Integer> {
        Ok(numerics::decimal_to_integer(d))
    }

    async fn u64_to_decimal(&mut self, i: u64) -> Result<Decimal> {
        Ok(numerics::u64_to_decimal(i))
    }

    async fn s64_to_decimal(&mut self, i: i64) -> Result<Decimal> {
        Ok(numerics::s64_to_decimal(i))
    }

    async fn f64_to_decimal(&mut self, f: f64) -> Result<Decimal> {
        Ok(numerics::f64_to_decimal(f))
    }

    async fn string_to_decimal(&mut self, s: String) -> Result<Result<Decimal, Error>> {
        Ok(numerics::string_to_decimal(&s))
    }

    async fn decimal_to_string(&mut self, d: Decimal) -> Result<String> {
        Ok(numerics::decimal_to_string(d))
    }

    async fn eq_decimal(&mut self, a: Decimal, b: Decimal) -> Result<bool> {
        Ok(numerics::eq_decimal(a, b))
    }

    async fn cmp_decimal(&mut self, a: Decimal, b: Decimal) -> Result<NumericOrdering> {
        Ok(numerics::cmp_decimal(a, b))
    }

    async fn add_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Result<Decimal, Error>> {
        Ok(numerics::add_decimal(a, b))
    }

    async fn sub_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Result<Decimal, Error>> {
        Ok(numerics::sub_decimal(a, b))
    }

    async fn mul_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Result<Decimal, Error>> {
        Ok(numerics::mul_decimal(a, b))
    }

    async fn div_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Result<Decimal, Error>> {
        Ok(numerics::div_decimal(a, b))
    }

    async fn log10(&mut self, a: Decimal) -> Result<Decimal> {
        Ok(numerics::log10(a))
    }

    async fn meta_force_generate_integer(&mut self, _i: built_in::numbers::Integer) -> Result<()> {
        unimplemented!()
    }
    async fn meta_force_generate_decimal(&mut self, _d: built_in::numbers::Decimal) -> Result<()> {
        unimplemented!()
    }
}
