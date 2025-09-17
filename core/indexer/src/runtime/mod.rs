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
pub use stdlib::CheckedArithmetics;
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
        Accessor, Component, Func, HasData, Linker, Resource, ResourceTable, Val,
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

async fn prepare_call(
    runtime: &Runtime,
    contract_address: &ContractAddress,
    signer: Option<Signer>,
    expr: &str,
    fuel: u64,
) -> Result<(Store<Runtime>, bool, Vec<Val>, Vec<Val>, Func)> {
    let contract_id = runtime
        .storage
        .contract_id(contract_address)
        .await?
        .ok_or(anyhow!("Contract not found"))?;
    let component = load_component(
        &runtime.engine,
        &runtime.component_cache,
        &runtime.storage,
        contract_id,
    )
    .await?;
    let linker = make_linker(&runtime.engine)?;
    let mut store = make_store(&runtime.engine, runtime, fuel)?;
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
            && runtime.stack.peek().await != Some(id)
        {
            return Err(anyhow!("Invalid contract id signer"));
        }
        let mut table = runtime.table.lock().await;
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

    runtime.stack.push(contract_id).await?;
    let results = func
        .results(&store)
        .iter()
        .map(default_val_for_type)
        .collect::<Vec<_>>();
    Ok((store, call.name() == fallback_name, params, results, func))
}

async fn handle_call(
    stack: &Stack<i64>,
    is_fallback: bool,
    call_result: Result<()>,
    mut results: Vec<Val>,
) -> Result<String> {
    stack.pop().await;
    call_result?;
    if results.is_empty() {
        return Ok("()".to_string());
    }

    if results.len() == 1 {
        let result = results.remove(0);
        return if is_fallback {
            if let wasmtime::component::Val::String(return_expr) = result {
                Ok(return_expr)
            } else {
                Err(anyhow!("fallback did not return a string"))
            }
        } else {
            result.to_wave()
        };
    }

    Err(anyhow!(
        "Functions with multiple return values are not supported"
    ))
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

    pub async fn execute(
        &self,
        signer: Option<Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        let (mut store, is_fallback, params, mut results, func) =
            prepare_call(self, contract_address, signer, expr, 1000000).await?;

        let call_result = func.call_async(&mut store, &params, &mut results).await;

        handle_call(&self.stack, is_fallback, call_result, results).await
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
        let runtime = accessor.with(|mut access| access.get().clone());
        let fuel = accessor.with(|access| access.as_context().get_fuel())?;

        let signer = if let Some(resource) = signer {
            let _self = runtime.table.lock().await.get(&resource)?.clone();
            Some(_self)
        } else {
            None
        };

        let (mut store, is_fallback, params, mut results, func) =
            prepare_call(&runtime, &contract_address, signer, &expr, fuel).await?;

        let (call_result, results, fuel_result) = tokio::spawn(async move {
            let call_result = func.call_async(&mut store, &params, &mut results).await;
            (call_result, results, store.get_fuel())
        })
        .await?;
        let remaining_fuel = fuel_result?;
        accessor.with(|mut access| access.as_context_mut().set_fuel(remaining_fuel))?;

        handle_call(&runtime.stack, is_fallback, call_result, results).await
    }
}

impl built_in::context::Host for Runtime {}

impl built_in::context::HostViewContext for Runtime {}

impl built_in::context::HostViewContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ViewContext>) -> Result<()> {
        let _res = accessor
            .with(|mut access| access.get().table.clone())
            .lock()
            .await
            .delete(rep)?;
        Ok(())
    }

    async fn get_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(self_, path)
            .await
    }

    async fn get_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(self_, path)
            .await
    }

    async fn get_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(self_, path)
            .await
    }

    async fn get_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(self_, path)
            .await
    }

    async fn get_keys<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(self_, path)
            .await
    }

    async fn exists<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(self_, path)
            .await
    }

    async fn matching_path<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        regexp: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._matching_path(self_, regexp)
            .await
    }
}

impl built_in::context::HostSigner for Runtime {}

impl built_in::context::HostSignerWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Signer>) -> Result<()> {
        let _res = accessor
            .with(|mut access| access.get().table.clone())
            .lock()
            .await
            .delete(rep)?;
        Ok(())
    }

    async fn to_string<T>(accessor: &Accessor<T, Self>, self_: Resource<Signer>) -> Result<String> {
        Ok(accessor
            .with(|mut access| access.get().table.clone())
            .lock()
            .await
            .get(&self_)?
            .to_string())
    }
}

impl built_in::context::HostProcContext for Runtime {}

impl built_in::context::HostProcContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ProcContext>) -> Result<()> {
        let _res = accessor
            .with(|mut access| access.get().table.clone())
            .lock()
            .await
            .delete(rep)?;
        Ok(())
    }

    async fn get_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(self_, path)
            .await
    }

    async fn get_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(self_, path)
            .await
    }

    async fn get_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(self_, path)
            .await
    }

    async fn get_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(self_, path)
            .await
    }

    async fn get_keys<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(self_, path)
            .await
    }

    async fn exists<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(self_, path)
            .await
    }

    async fn matching_path<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        regexp: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._matching_path(self_, regexp)
            .await
    }

    async fn set_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
        value: String,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(self_, path, value)
            .await
    }

    async fn set_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
        value: u64,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(self_, path, value)
            .await
    }

    async fn set_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
        value: i64,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(self_, path, value)
            .await
    }

    async fn set_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
        value: bool,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(self_, path, value)
            .await
    }

    async fn set_void<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(self_, path, ())
            .await
    }

    async fn delete_matching_paths<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        regexp: String,
    ) -> Result<u64> {
        let runtime = accessor.with(|mut access| access.get().clone());
        let contract_id = runtime.table.lock().await.get(&self_)?.contract_id;
        runtime
            .storage
            .delete_matching_paths(contract_id, &regexp)
            .await
    }

    async fn signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        let resource_table = accessor.with(|mut access| access.get().table.clone());
        let mut table = resource_table.lock().await;
        let signer = table.get(&self_)?.signer.clone();
        Ok(table.push(signer)?)
    }

    async fn contract_signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        let resource_table = accessor.with(|mut access| access.get().table.clone());
        let mut table = resource_table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(Signer::ContractId(contract_id))?)
    }

    async fn view_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ViewContext>> {
        let resource_table = accessor.with(|mut access| access.get().table.clone());
        let mut table = resource_table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ViewContext { contract_id })?)
    }
}

impl built_in::context::HostKeys for Runtime {}

impl built_in::context::HostKeysWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Keys>) -> Result<()> {
        let _res = accessor
            .with(|mut access| access.get().table.clone())
            .lock()
            .await
            .delete(rep)?;
        Ok(())
    }

    async fn next<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<Keys>,
    ) -> Result<Option<String>> {
        Ok(accessor
            .with(|mut access| access.get().table.clone())
            .lock()
            .await
            .get_mut(&self_)?
            .stream
            .next()
            .await
            .transpose()?)
    }
}

impl built_in::context::HostFallContext for Runtime {}

impl built_in::context::HostFallContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<FallContext>) -> Result<()> {
        let _res = accessor
            .with(|mut access| access.get().table.clone())
            .lock()
            .await
            .delete(rep)?;
        Ok(())
    }

    async fn signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<Signer>>> {
        let resource_table = accessor.with(|mut access| access.get().table.clone());
        let mut table = resource_table.lock().await;
        if let Some(signer) = table.get(&self_)?.signer.clone() {
            Ok(Some(table.push(signer)?))
        } else {
            Ok(None)
        }
    }

    async fn proc_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<ProcContext>>> {
        let resource_table = accessor.with(|mut access| access.get().table.clone());
        let mut table = resource_table.lock().await;
        let res = table.get(&self_)?;
        let contract_id = res.contract_id;
        if let Some(signer) = res.signer.clone() {
            Ok(Some(table.push(ProcContext {
                contract_id,
                signer,
            })?))
        } else {
            Ok(None)
        }
    }

    async fn view_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Resource<ViewContext>> {
        let resource_table = accessor.with(|mut access| access.get().table.clone());
        let mut table = resource_table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ViewContext { contract_id })?)
    }
}

impl built_in::numbers::Host for Runtime {}

impl built_in::numbers::HostWithStore for Runtime {
    async fn u64_to_integer<T>(_accessor: &Accessor<T, Self>, i: u64) -> Result<Integer> {
        Ok(numerics::u64_to_integer(i))
    }

    async fn s64_to_integer<T>(_accessor: &Accessor<T, Self>, i: i64) -> Result<Integer> {
        Ok(numerics::s64_to_integer(i))
    }

    async fn string_to_integer<T>(
        _accessor: &Accessor<T, Self>,
        s: String,
    ) -> Result<Result<Integer, Error>> {
        Ok(numerics::string_to_integer(&s))
    }

    async fn integer_to_string<T>(_accessor: &Accessor<T, Self>, i: Integer) -> Result<String> {
        Ok(numerics::integer_to_string(i))
    }

    async fn eq_integer<T>(_accessor: &Accessor<T, Self>, a: Integer, b: Integer) -> Result<bool> {
        Ok(numerics::eq_integer(a, b))
    }

    async fn cmp_integer<T>(
        _accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<NumericOrdering> {
        Ok(numerics::cmp_integer(a, b))
    }

    async fn add_integer<T>(
        _accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Ok(numerics::add_integer(a, b))
    }

    async fn sub_integer<T>(
        _accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Ok(numerics::sub_integer(a, b))
    }

    async fn mul_integer<T>(
        _accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Ok(numerics::mul_integer(a, b))
    }

    async fn div_integer<T>(
        _accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Ok(numerics::div_integer(a, b))
    }

    async fn integer_to_decimal<T>(_accessor: &Accessor<T, Self>, i: Integer) -> Result<Decimal> {
        Ok(numerics::integer_to_decimal(i))
    }

    async fn decimal_to_integer<T>(_accessor: &Accessor<T, Self>, d: Decimal) -> Result<Integer> {
        Ok(numerics::decimal_to_integer(d))
    }

    async fn u64_to_decimal<T>(_accessor: &Accessor<T, Self>, i: u64) -> Result<Decimal> {
        Ok(numerics::u64_to_decimal(i))
    }

    async fn s64_to_decimal<T>(_accessor: &Accessor<T, Self>, i: i64) -> Result<Decimal> {
        Ok(numerics::s64_to_decimal(i))
    }

    async fn f64_to_decimal<T>(_accessor: &Accessor<T, Self>, f: f64) -> Result<Decimal> {
        Ok(numerics::f64_to_decimal(f))
    }

    async fn string_to_decimal<T>(
        _accessor: &Accessor<T, Self>,
        s: String,
    ) -> Result<Result<Decimal, Error>> {
        Ok(numerics::string_to_decimal(&s))
    }

    async fn decimal_to_string<T>(_accessor: &Accessor<T, Self>, d: Decimal) -> Result<String> {
        Ok(numerics::decimal_to_string(d))
    }

    async fn eq_decimal<T>(_accessor: &Accessor<T, Self>, a: Decimal, b: Decimal) -> Result<bool> {
        Ok(numerics::eq_decimal(a, b))
    }

    async fn cmp_decimal<T>(
        _accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<NumericOrdering> {
        Ok(numerics::cmp_decimal(a, b))
    }

    async fn add_decimal<T>(
        _accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Ok(numerics::add_decimal(a, b))
    }

    async fn sub_decimal<T>(
        _accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Ok(numerics::sub_decimal(a, b))
    }

    async fn mul_decimal<T>(
        _accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Ok(numerics::mul_decimal(a, b))
    }

    async fn div_decimal<T>(
        _accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Ok(numerics::div_decimal(a, b))
    }

    async fn log10<T>(_accessor: &Accessor<T, Self>, a: Decimal) -> Result<Decimal> {
        Ok(numerics::log10(a))
    }

    async fn meta_force_generate_integer<T>(
        _accessor: &Accessor<T, Self>,
        _i: Integer,
    ) -> Result<()> {
        unimplemented!()
    }

    async fn meta_force_generate_decimal<T>(
        _accessor: &Accessor<T, Self>,
        _d: Decimal,
    ) -> Result<()> {
        unimplemented!()
    }
}
