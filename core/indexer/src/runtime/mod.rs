mod component_cache;
mod contracts;
pub mod counter;
pub mod fuel;
pub mod numerics;
mod stack;
mod storage;
mod types;
pub mod wit;

pub use component_cache::ComponentCache;
pub use contracts::load_contracts;
use futures_util::{StreamExt, future::OptionFuture};
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

use anyhow::{Context, Result, anyhow};
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

use crate::{
    database::Reader,
    runtime::{
        counter::Counter,
        fuel::{Fuel, FuelGauge},
        stack::Stack,
        wit::{FallContext, HasContractId, Keys, ProcContext, Signer, ViewContext},
    },
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

pub fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.into()
}

#[derive(Clone)]
pub struct Runtime {
    pub engine: Engine,
    pub table: Arc<Mutex<ResourceTable>>,
    pub component_cache: ComponentCache,
    pub storage: Storage,
    pub id_generation_counter: Counter,
    pub stack: Stack<i64>,
    pub gauge: Option<FuelGauge>,
    pub starting_fuel: u64,
    pub txid: Vec<u8>,
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
            gauge: Some(FuelGauge::new()),
            starting_fuel: 1000000,
            txid: Vec::new(),
        })
    }

    pub async fn new_read_only(reader: &Reader) -> Result<Self> {
        Runtime::new(
            Storage::builder()
                .conn(reader.connection().await?.clone())
                .build(),
            ComponentCache::new(),
        )
        .await
    }

    pub async fn set_context(
        &mut self,
        height: i64,
        tx_index: i64,
        input_index: i64,
        op_index: i64,
        txid: Vec<u8>,
    ) {
        self.storage.height = height;
        self.storage.tx_index = tx_index;
        self.storage.input_index = input_index;
        self.storage.op_index = op_index;
        self.id_generation_counter.reset().await;
        self.txid = txid;
    }

    pub fn get_storage_conn(&self) -> Connection {
        self.storage.conn.clone()
    }

    pub fn set_storage(&mut self, storage: Storage) {
        self.storage = storage;
    }

    pub fn set_starting_fuel(&mut self, starting_fuel: u64) {
        self.starting_fuel = starting_fuel
    }

    pub async fn publish(&self, signer: &Signer, name: &str, bytes: &[u8]) -> Result<String> {
        let id = self
            .storage
            .insert_contract(name, bytes)
            .await
            .expect("Failed to insert contract");
        let address = self
            .storage
            .contract_address(id)
            .await
            .expect("Failed to get contract address")
            .expect("Contract doesn't exist");
        self.execute(Some(signer), &address, "init()").await?;
        let value = wasm_wave::to_string(&wasm_wave::value::Value::from(address))
            .expect("Failed to convert address to string");
        self.storage
            .insert_contract_result(id, Some(value.clone()))
            .await
            .expect("Failed to insert contract result");
        Ok(value)
    }

    pub async fn execute(
        &self,
        signer: Option<&Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        OptionFuture::from(
            self.gauge
                .as_ref()
                .map(|g| g.set_starting_fuel(self.starting_fuel)),
        )
        .await;

        let (mut store, contract_id, is_fallback, params, mut results, func, is_proc) = self
            .prepare_call(contract_address, signer, expr, self.starting_fuel)
            .await?;
        let result = tokio::spawn(async move {
            let call_result = func.call_async(&mut store, &params, &mut results).await;
            (call_result, results, store)
        })
        .await
        .context("Failed to join execution");
        self.handle_call(
            is_fallback,
            is_proc,
            contract_id,
            result,
            |remaining_fuel| async move {
                OptionFuture::from(
                    self.gauge
                        .as_ref()
                        .map(|g| g.set_ending_fuel(remaining_fuel)),
                )
                .await;
                Ok(())
            },
        )
        .await
    }

    pub async fn get_component_bytes(&self, contract_id: i64) -> Result<Vec<u8>> {
        let compressed_bytes = self
            .storage
            .contract_bytes(contract_id)
            .await?
            .ok_or(anyhow!("Contract not found when trying to load component"))?;
        let mut decompressor = brotli::Decompressor::new(&compressed_bytes[..], 4096);
        let mut module_bytes = Vec::new();
        decompressor.read_to_end(&mut module_bytes)?;

        ComponentEncoder::default()
            .module(&module_bytes)?
            .validate(true)
            .encode()
    }

    pub async fn load_component(&self, contract_id: i64) -> Result<Component> {
        Ok(match self.component_cache.get(&contract_id) {
            Some(component) => component,
            None => {
                let component_bytes = self.get_component_bytes(contract_id).await?;
                let component = Component::from_binary(&self.engine, &component_bytes)?;
                self.component_cache.put(contract_id, component.clone());
                component
            }
        })
    }

    pub fn make_linker(&self) -> Result<Linker<Runtime>> {
        let mut linker = Linker::new(&self.engine);
        Contract::add_to_linker::<_, Runtime>(&mut linker, |s| s)?;
        Ok(linker)
    }

    pub fn make_store(&self, fuel: u64) -> Result<Store<Runtime>> {
        let mut s = Store::new(&self.engine, self.clone());
        s.set_fuel(fuel)?;
        Ok(s)
    }

    async fn prepare_call(
        &self,
        contract_address: &ContractAddress,
        signer: Option<&Signer>,
        expr: &str,
        fuel: u64,
    ) -> Result<(Store<Runtime>, i64, bool, Vec<Val>, Vec<Val>, Func, bool)> {
        let contract_id = self
            .storage
            .contract_id(contract_address)
            .await?
            .ok_or(anyhow!("Contract not found: {}", contract_address))?;
        let component = self.load_component(contract_id).await?;
        let linker = self.make_linker()?;
        let mut store = self.make_store(fuel)?;
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

        if let Some(Signer::ContractId { id, .. }) = signer
            && self.stack.peek().await != Some(*id)
        {
            return Err(anyhow!("Invalid contract id signer"));
        }

        let mut is_proc = false;

        {
            let mut table = self.table.lock().await;
            match (resource_type, signer) {
                (t, Some(signer))
                    if t.eq(&wasmtime::component::ResourceType::host::<ProcContext>()) =>
                {
                    is_proc = true;
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(ProcContext {
                                    signer: signer.clone(),
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
                    is_proc = signer.is_some();
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(FallContext {
                                    signer: signer.cloned(),
                                    contract_id,
                                })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    )
                }
                _ => return Err(anyhow!("Unsupported context/signer type")),
            }
        }

        let results = func
            .results(&store)
            .iter()
            .map(default_val_for_type)
            .collect::<Vec<_>>();

        self.stack.push(contract_id).await?;
        self.storage.savepoint().await?;

        Ok((
            store,
            contract_id,
            call.name() == fallback_name,
            params,
            results,
            func,
            is_proc,
        ))
    }

    async fn extract_wave_expr<F, Fut>(
        &self,
        is_fallback: bool,
        write_result: bool,
        contract_id: i64,
        result: Result<(Result<()>, Vec<Val>, Store<Runtime>)>,
        fuel_callback: F,
    ) -> Result<String>
    where
        F: FnOnce(u64) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let (call_result, mut results, mut store) = result?;

        let mut result = if let Err(e) = call_result {
            Err(e)
        } else if results.is_empty() {
            Ok("".to_string())
        } else if results.len() != 1 {
            Err(anyhow!(
                "Functions with multiple return values are not supported"
            ))
        } else {
            let val = results.remove(0);
            if is_fallback {
                if let wasmtime::component::Val::String(return_expr) = val {
                    Ok(return_expr)
                } else {
                    Err(anyhow!("fallback did not return a string"))
                }
            } else {
                val.to_wave()
            }
        };

        if write_result {
            let value = result.as_ref().map(|s| s.clone()).ok();
            if let Err(e) = Fuel::Result(value.as_ref().map_or(1, |v| v.len() as u64))
                .consume_with_store(self.gauge.as_ref(), &mut store)
                .await
            {
                result = Err(e);
            } else {
                self.storage
                    .insert_contract_result(contract_id, value)
                    .await
                    .expect("Failed to insert contract result");
            }
        }

        let remaining_fuel = store.get_fuel()?;
        fuel_callback(remaining_fuel).await?;

        result
    }

    async fn handle_call<F, Fut>(
        &self,
        is_fallback: bool,
        write_result: bool,
        contract_id: i64,
        result: Result<(Result<()>, Vec<Val>, Store<Runtime>)>,
        fuel_callback: F,
    ) -> Result<String>
    where
        F: FnOnce(u64) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        self.stack.pop().await;

        let result = self
            .extract_wave_expr(
                is_fallback,
                write_result,
                contract_id,
                result,
                fuel_callback,
            )
            .await;

        if result.is_err() {
            self.storage
                .rollback()
                .await
                .expect("Failed to rollback storage after failure to extract expression");
        }
        let expr = result?;

        if expr.starts_with("err(") {
            self.storage
                .rollback()
                .await
                .expect("Failed to rollback storage after Err returning call");
        } else {
            self.storage
                .commit()
                .await
                .expect("Failed to commit storage after successful call");
        }

        Ok(expr)
    }

    async fn _call<T>(
        &self,
        accessor: &Accessor<T, Self>,
        signer: Option<Resource<Signer>>,
        contract_address: ContractAddress,
        expr: String,
    ) -> Result<String> {
        let fuel = accessor.with(|access| access.as_context().get_fuel())?;

        let signer =
            OptionFuture::from(signer.map(async |s| self.table.lock().await.get(&s).cloned()))
                .await
                .transpose()?;

        let (mut store, contract_id, is_fallback, params, mut results, func, _is_proc) = self
            .prepare_call(&contract_address, signer.as_ref(), &expr, fuel)
            .await?;
        let result = tokio::spawn(async move {
            let call_result = func.call_async(&mut store, &params, &mut results).await;
            (call_result, results, store)
        })
        .await
        .context("Failed to join call");
        self.handle_call(
            is_fallback,
            false,
            contract_id,
            result,
            |remaining_fuel| async move {
                accessor.with(|mut access| access.as_context_mut().set_fuel(remaining_fuel))
            },
        )
        .await
    }

    async fn _get_primitive<S, T: HasContractId, R: for<'de> Deserialize<'de>>(
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
                    deserialize_cbor(&bs)
                }),
        )
        .await
        .transpose()
    }

    async fn _get_keys<S, T: HasContractId>(
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

    async fn _exists<S, T: HasContractId>(
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

    async fn _extend_path_with_match<S, T: HasContractId>(
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

    async fn _delete_matching_paths<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        regexp: String,
    ) -> Result<u64> {
        Fuel::DeleteMatchingPaths(regexp.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let contract_id = self.table.lock().await.get(&self_)?.contract_id;
        self.storage
            .delete_matching_paths(contract_id, &regexp)
            .await
    }

    async fn _set_primitive<S, T: Serialize>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<ProcContext>,
        path: String,
        value: T,
    ) -> Result<()> {
        let contract_id = self.table.lock().await.get(&resource)?.contract_id;
        Fuel::Path(path.clone())
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let bs = &serialize_cbor(&value)?;
        Fuel::Set(bs.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        self.storage.set(contract_id, &path, bs).await
    }

    async fn _hash<T>(
        &self,
        accessor: &Accessor<T, Runtime>,
        input: String,
    ) -> Result<(String, Vec<u8>)> {
        Fuel::CryptoHash(input.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let bs = hash_bytes(input.as_bytes());
        let s = hex::encode(bs);
        Ok((s, bs.to_vec()))
    }

    async fn _generate_id<T>(&self, accessor: &Accessor<T, Self>) -> Result<String> {
        Fuel::CryptoGenerateId
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let count = self.id_generation_counter.get().await;
        self.id_generation_counter.increment().await;
        Ok(hex::encode(
            &hash_bytes(&[self.txid.clone(), count.to_le_bytes().to_vec()].concat())[0..8],
        ))
    }

    async fn _signer_to_string<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<Signer>,
    ) -> Result<String> {
        Fuel::SignerToString
            .consume(accessor, self.gauge.as_ref())
            .await?;
        Ok(self.table.lock().await.get(&self_)?.to_string())
    }

    async fn _proc_signer<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        Fuel::ProcSigner
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let signer = table.get(&self_)?.signer.clone();
        Ok(table.push(signer)?)
    }

    async fn _proc_contract_signer<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        Fuel::ProcContractSigner
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(Signer::new_contract_id(contract_id))?)
    }

    async fn _proc_view_context<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ViewContext>> {
        Fuel::ProcViewContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ViewContext { contract_id })?)
    }

    async fn _next<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<Keys>,
    ) -> Result<Option<String>> {
        let k = self
            .table
            .lock()
            .await
            .get_mut(&self_)?
            .stream
            .next()
            .await
            .transpose()?;
        if let Some(k) = &k {
            Fuel::KeysNext(k.len() as u64)
                .consume(accessor, self.gauge.as_ref())
                .await?;
        }
        Ok(k)
    }

    async fn _fall_signer<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<Signer>>> {
        Fuel::FallSigner
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        Ok(table
            .get(&self_)?
            .signer
            .clone()
            .map(|s| table.push(s))
            .transpose()?)
    }

    async fn _fall_proc_context<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<ProcContext>>> {
        Fuel::FallProcContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let res = table.get(&self_)?;
        let contract_id = res.contract_id;
        Ok(res
            .signer
            .clone()
            .map(|signer| {
                table.push(ProcContext {
                    contract_id,
                    signer,
                })
            })
            .transpose()?)
    }

    async fn _fall_view_context<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Resource<ViewContext>> {
        Fuel::FallViewContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ViewContext { contract_id })?)
    }

    async fn _get_contract_address<T>(
        &self,
        accessor: &Accessor<T, Self>,
    ) -> Result<ContractAddress> {
        Fuel::ContractAddress
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let id = self.stack.peek().await.expect("Stack is empty");
        Ok(self
            .storage
            .contract_address(id)
            .await?
            .expect("Failed to get contract address"))
    }

    async fn _drop<T: 'static>(&self, rep: Resource<T>) -> Result<()> {
        self.table.lock().await.delete(rep)?;
        Ok(())
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

impl built_in::crypto::Host for Runtime {}

impl built_in::crypto::HostWithStore for Runtime {
    async fn hash<T>(accessor: &Accessor<T, Self>, input: String) -> Result<(String, Vec<u8>)> {
        accessor
            .with(|mut access| access.get().clone())
            ._hash(accessor, input)
            .await
    }

    async fn hash_with_salt<T>(
        accessor: &Accessor<T, Self>,
        input: String,
        salt: String,
    ) -> Result<(String, Vec<u8>)> {
        accessor
            .with(|mut access| access.get().clone())
            ._hash(accessor, input + &salt)
            .await
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
        accessor
            .with(|mut access| access.get().clone())
            ._call(accessor, signer, contract_address, expr)
            .await
    }

    async fn get_contract_address<T>(accessor: &Accessor<T, Self>) -> Result<ContractAddress> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_contract_address(accessor)
            .await
    }
}

impl built_in::context::Host for Runtime {}

impl built_in::context::HostViewContext for Runtime {}

impl built_in::context::HostViewContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ViewContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn get_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_keys<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(accessor, self_, path)
            .await
    }

    async fn exists<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(accessor, self_, path)
            .await
    }

    async fn extend_path_with_match<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
        path: String,
        variants: Vec<String>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._extend_path_with_match(accessor, self_, path, variants)
            .await
    }
}

impl built_in::context::HostSigner for Runtime {}

impl built_in::context::HostSignerWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Signer>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn to_string<T>(accessor: &Accessor<T, Self>, self_: Resource<Signer>) -> Result<String> {
        accessor
            .with(|mut access| access.get().clone())
            ._signer_to_string(accessor, self_)
            .await
    }
}

impl built_in::context::HostProcContext for Runtime {}

impl built_in::context::HostProcContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ProcContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn get_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_keys<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(accessor, self_, path)
            .await
    }

    async fn exists<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(accessor, self_, path)
            .await
    }

    async fn extend_path_with_match<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
        variants: Vec<String>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._extend_path_with_match(accessor, self_, path, variants)
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
            ._set_primitive(accessor, self_, path, value)
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
            ._set_primitive(accessor, self_, path, value)
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
            ._set_primitive(accessor, self_, path, value)
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
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_void<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        path: String,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, ())
            .await
    }

    async fn delete_matching_paths<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
        regexp: String,
    ) -> Result<u64> {
        accessor
            .with(|mut access| access.get().clone())
            ._delete_matching_paths(accessor, self_, regexp)
            .await
    }

    async fn signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_signer(accessor, self_)
            .await
    }

    async fn contract_signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_contract_signer(accessor, self_)
            .await
    }

    async fn view_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ViewContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_view_context(accessor, self_)
            .await
    }

    async fn generate_id<T>(
        accessor: &Accessor<T, Self>,
        _self: Resource<ProcContext>,
    ) -> Result<String> {
        accessor
            .with(|mut access| access.get().clone())
            ._generate_id(accessor)
            .await
    }
}

impl built_in::context::HostKeys for Runtime {}

impl built_in::context::HostKeysWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Keys>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn next<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<Keys>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._next(accessor, self_)
            .await
    }
}

impl built_in::context::HostFallContext for Runtime {}

impl built_in::context::HostFallContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<FallContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<Signer>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._fall_signer(accessor, self_)
            .await
    }

    async fn proc_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<ProcContext>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._fall_proc_context(accessor, self_)
            .await
    }

    async fn view_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Resource<ViewContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._fall_view_context(accessor, self_)
            .await
    }
}

impl built_in::numbers::Host for Runtime {}

impl built_in::numbers::HostWithStore for Runtime {
    async fn u64_to_integer<T>(accessor: &Accessor<T, Self>, i: u64) -> Result<Integer> {
        Fuel::NumbersU64ToInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::u64_to_integer(i))
    }

    async fn s64_to_integer<T>(accessor: &Accessor<T, Self>, i: i64) -> Result<Integer> {
        Fuel::NumbersS64ToInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::s64_to_integer(i))
    }

    async fn string_to_integer<T>(
        accessor: &Accessor<T, Self>,
        s: String,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersStringToInteger(s.len() as u64)
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::string_to_integer(&s))
    }

    async fn integer_to_string<T>(accessor: &Accessor<T, Self>, i: Integer) -> Result<String> {
        let s = numerics::integer_to_string(i);
        Fuel::NumbersIntegerToString(s.len() as u64)
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(s)
    }

    async fn eq_integer<T>(accessor: &Accessor<T, Self>, a: Integer, b: Integer) -> Result<bool> {
        Fuel::NumbersEqInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::eq_integer(a, b))
    }

    async fn cmp_integer<T>(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<NumericOrdering> {
        Fuel::NumbersCmpInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::cmp_integer(a, b))
    }

    async fn add_integer<T>(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersAddInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::add_integer(a, b))
    }

    async fn sub_integer<T>(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersSubInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::sub_integer(a, b))
    }

    async fn mul_integer<T>(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersMulInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::mul_integer(a, b))
    }

    async fn div_integer<T>(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersDivInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::div_integer(a, b))
    }

    async fn sqrt_integer<T>(
        accessor: &Accessor<T, Self>,
        i: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersSqrtInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::sqrt_integer(i))
    }

    async fn integer_to_decimal<T>(accessor: &Accessor<T, Self>, i: Integer) -> Result<Decimal> {
        Fuel::NumbersIntegerToDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::integer_to_decimal(i))
    }

    async fn decimal_to_integer<T>(accessor: &Accessor<T, Self>, d: Decimal) -> Result<Integer> {
        Fuel::NumbersDecimalToInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::decimal_to_integer(d))
    }

    async fn u64_to_decimal<T>(accessor: &Accessor<T, Self>, i: u64) -> Result<Decimal> {
        Fuel::NumbersU64ToDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::u64_to_decimal(i))
    }

    async fn s64_to_decimal<T>(accessor: &Accessor<T, Self>, i: i64) -> Result<Decimal> {
        Fuel::NumbersS64ToDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::s64_to_decimal(i))
    }

    async fn f64_to_decimal<T>(accessor: &Accessor<T, Self>, f: f64) -> Result<Decimal> {
        Fuel::NumbersF64ToDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::f64_to_decimal(f))
    }

    async fn string_to_decimal<T>(
        accessor: &Accessor<T, Self>,
        s: String,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersStringToDecimal(s.len() as u64)
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::string_to_decimal(&s))
    }

    async fn decimal_to_string<T>(accessor: &Accessor<T, Self>, d: Decimal) -> Result<String> {
        let s = numerics::decimal_to_string(d);
        Fuel::NumbersDecimalToString(s.len() as u64)
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(s)
    }

    async fn eq_decimal<T>(accessor: &Accessor<T, Self>, a: Decimal, b: Decimal) -> Result<bool> {
        Fuel::NumbersEqDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::eq_decimal(a, b))
    }

    async fn cmp_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<NumericOrdering> {
        Fuel::NumbersCmpDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::cmp_decimal(a, b))
    }

    async fn add_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersAddDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::add_decimal(a, b))
    }

    async fn sub_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersSubDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::sub_decimal(a, b))
    }

    async fn mul_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersMulDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::mul_decimal(a, b))
    }

    async fn div_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersDivDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::div_decimal(a, b))
    }

    async fn log10_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersLog10Decimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::log10_decimal(a))
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
