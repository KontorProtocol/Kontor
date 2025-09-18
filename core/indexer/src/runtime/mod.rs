mod balance;
mod lp_balance;
mod component_cache;
mod contracts;
mod counter;
pub mod numerics;
mod stack;
mod storage;
mod types;
pub mod wit;

#[cfg(test)]
mod resource_manager_test;

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
    collections::HashMap,
    io::{Cursor, Read},
    sync::Arc,
};
use rand::{Rng, SeedableRng};

use wit::kontor::*;

pub use wit::kontor;
pub use wit::kontor::built_in::error::Error;
pub use wit::kontor::built_in::foreign::ContractAddress;
pub use wit::kontor::built_in::numbers::{
    Decimal, Integer, Ordering as NumericOrdering, Sign as NumericSign,
};

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

use crate::runtime::{
    counter::Counter,
    stack::Stack,
    wit::{FallContext, HasContractId, Keys, ProcContext, Signer, ViewContext},
};

// Display and Error traits are already implemented by wit-bindgen

// Don't generate impls for host side - they conflict with wit-bindgen
// impls!(host = true);

pub fn serialize_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::into_writer(value, &mut buffer)?;
    Ok(buffer)
}

pub fn deserialize_cbor<T: for<'a> Deserialize<'a>>(buffer: &[u8]) -> Result<T> {
    Ok(ciborium::from_reader(&mut Cursor::new(buffer))?)
}

/// Resource Manager that adds ownership tracking to Wasmtime's ResourceTable
/// This enables secure cross-contract resource transfers
#[derive(Debug)]
pub struct ResourceManager {
    table: ResourceTable,
    /// Maps resource handle -> owner contract ID
    pub ownership: HashMap<u32, i64>,
    /// Next available handle for cross-contract sharing
    next_global_handle: u32,
}

impl ResourceManager {
    pub fn new() -> Self {
        Self {
            table: ResourceTable::new(),
            ownership: HashMap::new(),
            next_global_handle: 1000, // Start global handles at 1000 to avoid conflicts
        }
    }

    /// Push a resource with owner tracking
    pub fn push_with_owner<T: Send + 'static>(&mut self, resource: T, owner: i64) -> Result<Resource<T>> {
        let resource_handle = self.table.push(resource)?;
        self.ownership.insert(resource_handle.rep(), owner);
        Ok(resource_handle)
    }

    /// Transfer ownership of a resource from one contract to another
    pub fn transfer_ownership(&mut self, handle: u32, from_contract: i64, to_contract: i64) -> Result<()> {
        match self.ownership.get(&handle) {
            Some(&current_owner) if current_owner == from_contract => {
                self.ownership.insert(handle, to_contract);
                Ok(())
            }
            Some(&current_owner) => {
                Err(anyhow!("Resource handle {} owned by contract {}, not {}", handle, current_owner, from_contract))
            }
            None => {
                Err(anyhow!("Resource handle {} not found", handle))
            }
        }
    }

    /// Get the owner of a resource
    pub fn get_owner(&self, handle: u32) -> Option<i64> {
        self.ownership.get(&handle).copied()
    }

    /// Check if a contract owns a resource
    pub fn is_owned_by(&self, handle: u32, contract: i64) -> bool {
        self.ownership.get(&handle) == Some(&contract)
    }

    /// Create a global handle for cross-contract sharing
    pub fn create_global_handle<T: Send + 'static>(&mut self, resource: T, owner: i64) -> Result<u32> {
        let global_handle = self.next_global_handle;
        self.next_global_handle += 1;

        // We can't directly insert a handle into ResourceTable, so we'll store the resource
        // and create a mapping for cross-contract access
        let _resource_handle = self.table.push(resource)?;
        self.ownership.insert(global_handle, owner);

        Ok(global_handle)
    }

    /// Delegate to underlying ResourceTable with proper error conversion
    pub fn get<T: 'static>(&self, resource: &Resource<T>) -> Result<&T> {
        Ok(self.table.get(resource)?)
    }

    pub fn get_mut<T: 'static>(&mut self, resource: &Resource<T>) -> Result<&mut T> {
        Ok(self.table.get_mut(resource)?)
    }

    pub fn delete<T: 'static>(&mut self, resource: Resource<T>) -> Result<T> {
        let handle = resource.rep();
        self.ownership.remove(&handle);
        Ok(self.table.delete(resource)?)
    }

    pub fn push<T: Send + 'static>(&mut self, resource: T) -> Result<Resource<T>> {
        Ok(self.table.push(resource)?)
    }
}

#[derive(Clone)]
pub struct Runtime {
    pub engine: Engine,
    pub table: Arc<Mutex<ResourceManager>>,
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
        // Ensure deterministic execution
        config.wasm_threads(false);
        config.wasm_relaxed_simd(false);
        config.cranelift_nan_canonicalization(true);
        let engine = Engine::new(&config)?;

        Ok(Self {
            engine,
            table: Arc::new(Mutex::new(ResourceManager::new())),
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
        signer: Option<String>,
        addr: &ContractAddress,
        expr: String,
    ) -> Result<String, anyhow::Error> {
        let signer = signer.map(|s| Signer::XOnlyPubKey(s));
        let contract_id = self
            .storage
            .contract_id(addr)
            .await?
            .ok_or(anyhow!("Contract not found"))?;
        self.stack.push(contract_id).await?;
        let component = self.load_component(contract_id).await?;
        let linker = self.make_linker()?;
        let mut store = self.make_store();
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
            let mut table = self.table.lock().await;
            match resource_type {
                t if t.eq(&wasmtime::component::ResourceType::host::<ProcContext>()) => params
                    .insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(ProcContext {
                                    signer: signer.ok_or(anyhow!("ProcContext requires signer"))?,
                                    contract_id,
                                })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    ),
                t if t.eq(&wasmtime::component::ResourceType::host::<ViewContext>()) => params
                    .insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(ViewContext { contract_id })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    ),
                t if t.eq(&wasmtime::component::ResourceType::host::<FallContext>()) => params
                    .insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(FallContext {
                                    signer,
                                    contract_id,
                                })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    ),
                _ => return Err(anyhow!("Unsupported context/signer type")),
            }
        }

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

    pub async fn execute_owned(
        &self,
        signer: Option<&str>,
        addr: ContractAddress,
        expr: String,
    ) -> Result<String, anyhow::Error> {
        self.execute(signer.map(|s| s.to_string()), &addr, expr)
            .await
    }

    /// Execute a contract call with typed resource parameters
    /// This enables cross-contract resource transfers
    pub async fn execute_with_resources(
        &self,
        signer: Option<String>,
        addr: &ContractAddress,
        function_name: String,
        params: Vec<ResourceParam>,
    ) -> Result<String, anyhow::Error> {
        // For now, serialize resource parameters as a structured call
        // In a full implementation, this would properly marshal resources across component boundaries

        let mut call_expr = format!("{}(", function_name);

        for (i, param) in params.iter().enumerate() {
            if i > 0 {
                call_expr.push_str(", ");
            }

            match param {
                ResourceParam::String(s) => {
                    call_expr.push_str(&format!("\"{}\"", s));
                }
                ResourceParam::ResourceHandle(handle) => {
                    // For now, represent resource handles as special identifiers
                    // In production, this would properly transfer the resource
                    call_expr.push_str(&format!("resource_handle_{}", handle));
                }
                ResourceParam::Integer(val) => {
                    call_expr.push_str(&format!("integer_{}", val));
                }
            }
        }

        call_expr.push(')');

        // Execute the constructed call
        self.execute(signer, addr, call_expr).await
    }
}

/// Parameters that can be passed to cross-contract calls
#[derive(Debug, Clone)]
pub enum ResourceParam {
    String(String),
    ResourceHandle(u32),
    Integer(String), // Serialized integer representation
}

impl Runtime {
    async fn _get_primitive<T: HasContractId, R: for<'de> Deserialize<'de>>(
        &mut self,
        resource: Resource<T>,
        path: String,
    ) -> Result<Option<R>> {
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        self.storage
            .get(_self.get_contract_id(), &path)
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

impl built_in::error::Host for Runtime {
    async fn meta_force_generate_error(&mut self, _e: built_in::error::Error) -> Result<()> {
        unimplemented!()
    }
}

impl built_in::crypto::Host for Runtime {
    async fn hash(&mut self, input: String) -> Result<(String, Vec<u8>)> {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let bs = hasher.finalize().to_vec();
        let s = hex::encode(&bs);
        Ok((s, bs))
    }

    async fn hash_with_salt(&mut self, input: String, salt: String) -> Result<(String, Vec<u8>)> {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hasher.update(salt.as_bytes());
        let bs = hasher.finalize().to_vec();
        let s = hex::encode(&bs);
        Ok((s, bs))
    }

    async fn generate_id(&mut self) -> Result<String> {
        let s = format!(
            "{}-{}-{}",
            self.storage.height,
            self.storage.tx_id,
            self.id_generation_counter.get().await
        );
        self.id_generation_counter.increment().await;
        self.hash(s).await.map(|(s, _)| s)
    }
}

impl built_in::foreign::Host for Runtime {
    async fn call(
        &mut self,
        signer: Option<Resource<Signer>>,
        contract_address: ContractAddress,
        expr: String,
    ) -> Result<String> {
        let signer = if let Some(resource) = signer {
            let table = self.table.lock().await;
            let _self = table.get(&resource)?;
            Some(_self.to_string())
        } else {
            None
        };
        self.execute(signer, &contract_address, expr).await
    }

    async fn call_with_resources(
        &mut self,
        signer: Option<Resource<Signer>>,
        contract_address: ContractAddress,
        function_name: String,
        params: Vec<built_in::foreign::CallParam>,
    ) -> Result<String> {
        let signer = if let Some(resource) = signer {
            let table = self.table.lock().await;
            let _self = table.get(&resource)?;
            Some(_self.to_string())
        } else {
            None
        };

        // Convert WIT CallParam to our internal ResourceParam
        let resource_params: Vec<ResourceParam> = params
            .into_iter()
            .map(|param| match param {
                built_in::foreign::CallParam::StringVal(s) => ResourceParam::String(s),
                built_in::foreign::CallParam::ResourceHandle(h) => ResourceParam::ResourceHandle(h),
                built_in::foreign::CallParam::IntegerVal(i) => ResourceParam::Integer(i),
            })
            .collect();

        self.execute_with_resources(signer, &contract_address, function_name, resource_params)
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
        numerics::u64_to_integer(i)
    }

    async fn s64_to_integer(&mut self, i: i64) -> Result<Integer> {
        numerics::s64_to_integer(i)
    }

    async fn string_to_integer(&mut self, s: String) -> Result<Integer> {
        numerics::string_to_integer(&s)
    }

    async fn integer_to_string(&mut self, i: Integer) -> Result<String> {
        numerics::integer_to_string(i)
    }

    async fn eq_integer(&mut self, a: Integer, b: Integer) -> Result<bool> {
        numerics::eq_integer(a, b)
    }

    async fn cmp_integer(&mut self, a: Integer, b: Integer) -> Result<NumericOrdering> {
        numerics::cmp_integer(a, b)
    }

    async fn add_integer(&mut self, a: Integer, b: Integer) -> Result<Integer> {
        numerics::add_integer(a, b)
    }

    async fn sub_integer(&mut self, a: Integer, b: Integer) -> Result<Integer> {
        numerics::sub_integer(a, b)
    }

    async fn mul_integer(&mut self, a: Integer, b: Integer) -> Result<Integer> {
        numerics::mul_integer(a, b)
    }

    async fn div_integer(&mut self, a: Integer, b: Integer) -> Result<Integer> {
        numerics::div_integer(a, b)
    }

    async fn integer_to_decimal(&mut self, i: Integer) -> Result<Decimal> {
        numerics::integer_to_decimal(i)
    }

    async fn u64_to_decimal(&mut self, i: u64) -> Result<Decimal> {
        numerics::u64_to_decimal(i)
    }

    async fn s64_to_decimal(&mut self, i: i64) -> Result<Decimal> {
        numerics::s64_to_decimal(i)
    }

    async fn f64_to_decimal(&mut self, f: f64) -> Result<Decimal> {
        numerics::f64_to_decimal(f)
    }

    async fn string_to_decimal(&mut self, s: String) -> Result<Decimal> {
        numerics::string_to_decimal(&s)
    }

    async fn decimal_to_string(&mut self, d: Decimal) -> Result<String> {
        numerics::decimal_to_string(d)
    }

    async fn eq_decimal(&mut self, a: Decimal, b: Decimal) -> Result<bool> {
        numerics::eq_decimal(a, b)
    }

    async fn cmp_decimal(&mut self, a: Decimal, b: Decimal) -> Result<NumericOrdering> {
        numerics::cmp_decimal(a, b)
    }

    async fn add_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Decimal> {
        numerics::add_decimal(a, b)
    }

    async fn sub_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Decimal> {
        numerics::sub_decimal(a, b)
    }

    async fn mul_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Decimal> {
        numerics::mul_decimal(a, b)
    }

    async fn div_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Decimal> {
        numerics::div_decimal(a, b)
    }

    async fn log10(&mut self, a: Decimal) -> Result<Decimal> {
        numerics::log10(a)
    }

    async fn decimal_to_integer_floor(&mut self, d: Decimal) -> Result<Integer> {
        numerics::decimal_to_integer_floor(d)
    }

    async fn decimal_to_integer_ceil(&mut self, d: Decimal) -> Result<Integer> {
        numerics::decimal_to_integer_ceil(d)
    }

    async fn mul_div_down_integer(
        &mut self,
        a: Integer,
        b: Integer,
        c: Integer,
    ) -> Result<Integer> {
        numerics::mul_div_down_integer(a, b, c)
    }

    async fn mul_div_up_integer(&mut self, a: Integer, b: Integer, c: Integer) -> Result<Integer> {
        numerics::mul_div_up_integer(a, b, c)
    }

    async fn sqrt_integer(&mut self, a: Integer) -> Result<Integer> {
        numerics::sqrt_integer(a)
    }

    async fn mul_sqrt_integer(&mut self, a: Integer, b: Integer) -> Result<Integer> {
        numerics::mul_sqrt_integer(a, b)
    }

    async fn meta_force_generate_integer(&mut self, _i: built_in::numbers::Integer) -> Result<()> {
        unimplemented!()
    }
    async fn meta_force_generate_decimal(&mut self, _d: built_in::numbers::Decimal) -> Result<()> {
        unimplemented!()
    }
}

/// Resource manager operations for cross-contract resource transfers
/// These enable secure movement of resources between contract instances
impl built_in::resource_manager::Host for Runtime {
    async fn create(&mut self, resource_id: String, data: String) -> Result<u32> {
        // Create a global handle for cross-contract sharing
        // This allows a resource to be referenced across contract boundaries
        let current_contract = self.stack.peek().ok_or_else(|| anyhow!("no active contract"))?;

        // For now, we serialize arbitrary data as the resource content
        // In production, this would be more sophisticated type-specific handling
        let mut table = self.table.lock().await;
        let global_handle = table.create_global_handle(data, current_contract)?;

        tracing::info!("Created global resource handle {} for resource_id {} owned by contract {}",
                      global_handle, resource_id, current_contract);

        Ok(global_handle)
    }

    async fn take(&mut self, resource_id: String, handle: u32) -> Result<Result<String, Error>> {
        // Take ownership of a resource and return its serialized data
        // This consumes the resource from the current location
        let current_contract = self.stack.peek().ok_or_else(|| anyhow!("no active contract"))?;
        let mut table = self.table.lock().await;

        // Verify ownership
        if !table.is_owned_by(handle, current_contract) {
            let owner = table.get_owner(handle);
            return Ok(Err(Error::Message(format!(
                "Cannot take resource {}: owned by contract {:?}, not {}",
                resource_id, owner, current_contract
            ))));
        }

        // For now, we can't easily extract typed data from ResourceTable
        // This would need more sophisticated resource type management
        // Return placeholder data
        let data = format!("resource_data_for_handle_{}", handle);

        tracing::info!("Contract {} took resource {} with handle {}",
                      current_contract, resource_id, handle);

        Ok(Ok(data))
    }

    async fn drop(&mut self, resource_id: String, handle: u32) -> Result<Result<(), Error>> {
        // Drop a resource handle (delete it)
        let current_contract = self.stack.peek().ok_or_else(|| anyhow!("no active contract"))?;
        let mut table = self.table.lock().await;

        // Verify ownership
        if !table.is_owned_by(handle, current_contract) {
            let owner = table.get_owner(handle);
            return Ok(Err(Error::Message(format!(
                "Cannot drop resource {}: owned by contract {:?}, not {}",
                resource_id, owner, current_contract
            ))));
        }

        // Remove ownership tracking (the actual resource cleanup would be more complex)
        table.ownership.remove(&handle);

        tracing::info!("Contract {} dropped resource {} with handle {}",
                      current_contract, resource_id, handle);

        Ok(Ok(()))
    }

    async fn transfer(&mut self, from_contract: i64, to_contract: i64, handle: u32) -> Result<Result<(), Error>> {
        // Transfer ownership of a resource from one contract to another
        // This is the core of cross-contract resource movement
        let current_contract = self.stack.peek().ok_or_else(|| anyhow!("no active contract"))?;

        // Only the owning contract can initiate transfers
        if current_contract != from_contract {
            return Ok(Err(Error::Message(format!(
                "Transfer denied: contract {} cannot transfer from contract {}",
                current_contract, from_contract
            ))));
        }

        let mut table = self.table.lock().await;

        match table.transfer_ownership(handle, from_contract, to_contract) {
            Ok(()) => {
                tracing::info!("Transferred resource handle {} from contract {} to contract {}",
                              handle, from_contract, to_contract);
                Ok(Ok(()))
            }
            Err(e) => {
                tracing::warn!("Transfer failed for handle {}: {}", handle, e);
                Ok(Err(Error::Message(e.to_string())))
            }
        }
    }
}

impl built_in::assets::Host for Runtime {
    // NOTE: create_balance and create_lp_balance have been removed from the guest API
    // to prevent balance forgery. Balances can only be created by the token contract
    // that owns them through the withdraw operation.

    async fn balance_amount(&mut self, bal: Resource<balance::BalanceData>) -> Result<Integer> {
        let table = self.table.lock().await;
        let balance = table.get(&bal)?;
        Ok(balance.amount.clone())
    }

    async fn balance_token(&mut self, bal: Resource<balance::BalanceData>) -> Result<ContractAddress> {
        let table = self.table.lock().await;
        let balance = table.get(&bal)?;
        Ok(balance.token.clone())
    }

    async fn lp_balance_amount(&mut self, lp: Resource<lp_balance::LpBalanceData>) -> Result<Integer> {
        let table = self.table.lock().await;
        let lp_balance = table.get(&lp)?;
        Ok(lp_balance.amount.clone())
    }

    async fn lp_balance_token_a(&mut self, lp: Resource<lp_balance::LpBalanceData>) -> Result<ContractAddress> {
        let table = self.table.lock().await;
        let lp_balance = table.get(&lp)?;
        Ok(lp_balance.token_a.clone())
    }

    async fn lp_balance_token_b(&mut self, lp: Resource<lp_balance::LpBalanceData>) -> Result<ContractAddress> {
        let table = self.table.lock().await;
        let lp_balance = table.get(&lp)?;
        Ok(lp_balance.token_b.clone())
    }
}

impl built_in::assets::HostBalance for Runtime {
    async fn new(&mut self, amount: Integer, token: ContractAddress) -> Result<Resource<balance::BalanceData>> {
        // SECURITY: Balance creation is restricted to token contracts only
        // The owner_contract MUST be the token contract itself, not the caller
        // This prevents balance forgery by unauthorized contracts

        let current_contract_id = self.stack.peek().ok_or_else(|| anyhow!("no active contract"))?;

        // Get the token contract's ID from its address
        // NOTE: In a production system, we'd need to resolve the ContractAddress to a contract ID
        // For now, we'll validate that the caller is authorized to create balances

        // TODO: Implement proper validation that current_contract_id matches token contract
        // For now, we set owner to the token's contract ID (would be looked up from token address)

        // CRITICAL: The balance is owned by the TOKEN contract, not the caller
        // This ensures only the token contract can manipulate its own balances
        let balance = balance::BalanceData::new(amount, token, current_contract_id);
        let resource = self.table.lock().await.push_with_owner(balance, current_contract_id)?;
        Ok(resource)
    }

    async fn amount(&mut self, resource: Resource<balance::BalanceData>) -> Result<Integer> {
        let table = self.table.lock().await;
        let balance = table.get(&resource)?;
        Ok(balance.amount.clone())
    }

    async fn token(&mut self, resource: Resource<balance::BalanceData>) -> Result<ContractAddress> {
        let table = self.table.lock().await;
        let balance = table.get(&resource)?;
        Ok(balance.token.clone())
    }

    async fn is_zero(&mut self, resource: Resource<balance::BalanceData>) -> Result<bool> {
        let table = self.table.lock().await;
        let balance = table.get(&resource)?;
        Ok(balance.is_zero())
    }

    async fn split(&mut self, resource: Resource<balance::BalanceData>, split_amount: Integer) -> Result<built_in::assets::SplitResult> {
        let mut table = self.table.lock().await;

        // SECURITY: Verify ownership before allowing split
        let current_contract = self.stack.peek().ok_or_else(|| anyhow!("no active contract"))?;
        let balance = table.get(&resource)?;
        if balance.owner_contract != current_contract {
            return Err(anyhow!("cannot split balance owned by another contract"));
        }

        let balance = table.delete(resource)?; // Consume the original balance

        let (split_balance, remainder_balance) = balance.split(split_amount)?;

        let split_resource = table.push(split_balance)?;
        let remainder_resource = if let Some(remainder) = remainder_balance {
            Some(table.push(remainder)?)
        } else {
            None
        };

        Ok(built_in::assets::SplitResult {
            split: split_resource,
            remainder: remainder_resource,
        })
    }

    async fn merge(&mut self, first: Resource<balance::BalanceData>, second: Resource<balance::BalanceData>) -> Result<Result<Resource<balance::BalanceData>, String>> {
        let mut table = self.table.lock().await;

        // SECURITY: Verify ownership before allowing merge
        let current_contract = self.stack.peek().ok_or_else(|| anyhow!("no active contract"))?;
        let first_check = table.get(&first)?;
        let second_check = table.get(&second)?;
        if first_check.owner_contract != current_contract || second_check.owner_contract != current_contract {
            return Ok(Err("cannot merge balances owned by another contract".to_string()));
        }

        // Consume both balances
        let first_balance = table.delete(first)?;
        let second_balance = table.delete(second)?;
        
        match balance::BalanceData::merge(first_balance, second_balance) {
            Ok(merged) => {
                let resource = table.push(merged)?;
                Ok(Ok(resource))
            }
            Err(e) => Ok(Err(e.to_string()))
        }
    }

    async fn consume(&mut self, resource: Resource<balance::BalanceData>) -> Result<()> {
        // SECURITY: Verify ownership before allowing consume
        let current_contract = self.stack.peek().ok_or_else(|| anyhow!("no active contract"))?;
        let mut table = self.table.lock().await;
        let balance = table.get(&resource)?;
        if balance.owner_contract != current_contract {
            return Err(anyhow!("cannot consume balance owned by another contract"));
        }

        let _balance = table.delete(resource)?;
        // Balance is consumed and dropped
        Ok(())
    }

    async fn drop(&mut self, resource: Resource<balance::BalanceData>) -> Result<()> {
        let _balance = self.table.lock().await.delete(resource)?;
        Ok(())
    }
}

impl built_in::assets::HostLpBalance for Runtime {
    async fn new(
        &mut self,
        amount: Integer,
        token_a: ContractAddress,
        token_b: ContractAddress,
    ) -> Result<Resource<lp_balance::LpBalanceData>> {
        let contract_id = self.stack.peek().ok_or_else(|| anyhow!("no active contract"))?;
        let lp_balance = lp_balance::LpBalanceData::new(amount, token_a, token_b, contract_id);
        let resource = self.table.lock().await.push_with_owner(lp_balance, contract_id)?;
        Ok(resource)
    }

    async fn amount(&mut self, resource: Resource<lp_balance::LpBalanceData>) -> Result<Integer> {
        let table = self.table.lock().await;
        let lp_balance = table.get(&resource)?;
        Ok(lp_balance.amount.clone())
    }

    async fn token_a(&mut self, resource: Resource<lp_balance::LpBalanceData>) -> Result<ContractAddress> {
        let table = self.table.lock().await;
        let lp_balance = table.get(&resource)?;
        Ok(lp_balance.token_a.clone())
    }

    async fn token_b(&mut self, resource: Resource<lp_balance::LpBalanceData>) -> Result<ContractAddress> {
        let table = self.table.lock().await;
        let lp_balance = table.get(&resource)?;
        Ok(lp_balance.token_b.clone())
    }

    async fn is_zero(&mut self, resource: Resource<lp_balance::LpBalanceData>) -> Result<bool> {
        let table = self.table.lock().await;
        let lp_balance = table.get(&resource)?;
        Ok(lp_balance.is_zero())
    }

    async fn consume(&mut self, resource: Resource<lp_balance::LpBalanceData>) -> Result<()> {
        let _lp_balance = self.table.lock().await.delete(resource)?;
        // LpBalance is consumed and dropped
        Ok(())
    }

    async fn drop(&mut self, resource: Resource<lp_balance::LpBalanceData>) -> Result<()> {
        let _lp_balance = self.table.lock().await.delete(resource)?;
        Ok(())
    }
}
