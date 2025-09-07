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
use fastnum::{D256, dec256, decimal};
use futures_util::StreamExt;
use libsql::Connection;
use num::bigint::BigInt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
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
pub use wit::kontor::built_in::numbers::{self, Decimal, Integer, Ordering as NumericOrdering};

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

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Message(msg) => write!(f, "Error: {}", msg),
            Error::Overflow(msg) => write!(f, "Overflow Error: {}", msg),
            Error::DivByZero(msg) => write!(f, "DivByZero Error: {}", msg),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl From<i64> for Integer {
    fn from(value_: i64) -> Self {
        Integer {
            value: value_.to_string(),
        }
    }
}

impl From<String> for Integer {
    fn from(value_: String) -> Self {
        let i = value_.parse::<BigInt>().expect("Must be valid integer");
        Integer {
            value: i.to_string(),
        }
    }
}

impl From<&str> for Integer {
    fn from(value_: &str) -> Self {
        let i = value_.parse::<BigInt>().expect("Must be valid integer");
        Integer {
            value: i.to_string(),
        }
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

const MIN_DECIMAL: D256 = dec256!(0.000_000_000_000_000_001);
const CTX: decimal::Context =
    decimal::Context::default().with_signal_traps(decimal::SignalsTraps::empty());

impl From<f64> for Decimal {
    fn from(value_: f64) -> Self {
        let dec: D256 = value_.into();
        let res = dec.with_ctx(CTX).quantize(MIN_DECIMAL);
        if res.is_op_invalid() {
            panic!("invalid decimal number");
        }
        Decimal {
            value: res.to_string(),
        }
    }
}

impl From<D256> for Decimal {
    fn from(dec: D256) -> Self {
        let res = dec.with_ctx(CTX).quantize(MIN_DECIMAL);
        if res.is_op_invalid() {
            panic!("invalid decimal number");
        }
        Decimal {
            value: res.to_string(),
        }
    }
}

impl From<String> for Decimal {
    fn from(value_: String) -> Self {
        let dec = value_
            .parse::<D256>()
            .expect("Must be valid decimal number");
        let res = dec.with_ctx(CTX).quantize(MIN_DECIMAL);
        if res.is_op_invalid() {
            panic!("invalid decimal number");
        }
        Decimal {
            value: res.to_string(),
        }
    }
}

impl From<&str> for Decimal {
    fn from(value_: &str) -> Self {
        let dec = value_
            .parse::<D256>()
            .expect("Must be valid decimal number");
        let res = dec.with_ctx(CTX).quantize(MIN_DECIMAL);
        if res.is_op_invalid() {
            panic!("invalid decimal number");
        }
        Decimal {
            value: res.to_string(),
        }
    }
}

impl fmt::Display for ContractAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}_{}", self.name, self.height, self.tx_index)
    }
}

impls!(host = true);

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
        signer: Option<Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        let contract_id = self
            .storage
            .contract_id(contract_address)
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
            Some(_self.clone())
        } else {
            None
        };
        self.execute(signer, &contract_address, &expr).await
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
    async fn eq_integer(&mut self, a: Integer, b: Integer) -> Result<bool> {
        numerics::eq_integer(&a, &b)
    }

    async fn cmp_integer(&mut self, a: Integer, b: Integer) -> Result<NumericOrdering> {
        numerics::cmp_integer(&a, &b)
    }

    async fn add_integer(&mut self, a: Integer, b: Integer) -> Result<Integer> {
        numerics::add_integer(&a, &b)
    }

    async fn sub_integer(&mut self, a: Integer, b: Integer) -> Result<Integer> {
        numerics::sub_integer(&a, &b)
    }

    async fn mul_integer(&mut self, a: Integer, b: Integer) -> Result<Integer> {
        numerics::mul_integer(&a, &b)
    }

    async fn div_integer(&mut self, a: Integer, b: Integer) -> Result<Integer> {
        numerics::div_integer(&a, &b)
    }

    async fn integer_to_decimal(&mut self, i: Integer) -> Result<Decimal> {
        numerics::integer_to_decimal(&i)
    }

    async fn eq_decimal(&mut self, a: Decimal, b: Decimal) -> Result<bool> {
        numerics::eq_decimal(&a, &b)
    }

    async fn cmp_decimal(&mut self, a: Decimal, b: Decimal) -> Result<NumericOrdering> {
        numerics::cmp_decimal(&a, &b)
    }

    async fn add_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Decimal> {
        numerics::add_decimal(&a, &b)
    }

    async fn sub_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Decimal> {
        numerics::sub_decimal(&a, &b)
    }

    async fn mul_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Decimal> {
        numerics::mul_decimal(&a, &b)
    }

    async fn div_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Decimal> {
        numerics::div_decimal(&a, &b)
    }

    async fn log10(&mut self, a: Decimal) -> Result<Decimal> {
        numerics::log10(&a)
    }

    async fn meta_force_generate_integer(&mut self, _i: built_in::numbers::Integer) -> Result<()> {
        unimplemented!()
    }
    async fn meta_force_generate_decimal(&mut self, _d: built_in::numbers::Decimal) -> Result<()> {
        unimplemented!()
    }
}
