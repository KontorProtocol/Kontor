mod component_cache;
mod contracts;
mod counter;
mod stack;
mod storage;
mod types;
pub mod wit;

pub use component_cache::ComponentCache;
pub use contracts::{load_contracts, load_native_contracts};
use libsql::Connection;
use num::bigint::BigInt;
use fastnum::{ D256, dec256 };
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{error::Error as StdError, fmt};
pub use storage::Storage;
use tokio::sync::Mutex;
pub use types::default_val_for_type;
pub use wit::Contract;

use std::{
    cmp::Ordering,
    io::{Cursor, Read},
    sync::Arc,
};

use wit::kontor::*;

pub use wit::kontor::built_in::error::Error;
pub use wit::kontor::built_in::foreign::ContractAddress;
pub use wit::kontor::built_in::numbers::{self, Integer, Decimal};

use anyhow::{Result, anyhow};
use wasm_wave::{self, wasm::WasmValue as _};
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
    wit::{FallContext, HasContractId, ProcContext, Signer, ViewContext},
};

impl Error {
    pub fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::variant([("message", Some(wasm_wave::value::Type::STRING))])
            .unwrap()
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Message(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl From<Error> for wasm_wave::value::Value {
    fn from(value_: Error) -> Self {
        (match value_ {
            Error::Message(operand) => wasm_wave::value::Value::make_variant(
                &Error::wave_type(),
                "message",
                Some(wasm_wave::value::Value::from(operand)),
            ),
        })
        .unwrap()
    }
}
impl From<wasm_wave::value::Value> for Error {
    fn from(value_: wasm_wave::value::Value) -> Self {
        let (key_, val_) = value_.unwrap_variant();
        match key_ {
            key_ if key_.eq("message") => {
                Error::Message(val_.unwrap().unwrap_string().into_owned())
            }
            key_ => panic!("Unknown tag {}", key_),
        }
    }
}

impl Integer {
    pub fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::record([
            ("value", wasm_wave::value::Type::STRING),
        ])
        .unwrap()
    }
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl From<Integer> for wasm_wave::value::Value {
    fn from(value_: Integer) -> Self {
        wasm_wave::value::Value::make_record(
            &Integer::wave_type(), [ ("value", wasm_wave::value::Value::from(value_.value)) ],
        )
        .unwrap()
    }
}

impl From<wasm_wave::value::Value> for Integer {
    fn from(value_: wasm_wave::value::Value) -> Self {
        let mut value = None;

        for (key_, val_) in value_.unwrap_record() {
            match key_.as_ref() {
                "value" => value = Some(val_.unwrap_string().into_owned()),
                key_ => panic!("Unknown field: {}", key_),
            }
        }

        Self {
            value: value.expect("Missing 'value' field"),
        }
    }
}

impl From<i64> for Integer {
    fn from(value_: i64) -> Self {
        Integer {
            value: value_.to_string(),
        }
    }
}

impl Decimal {
    pub fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::record([
            ("value", wasm_wave::value::Type::STRING),
        ])
        .unwrap()
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl From<Decimal> for wasm_wave::value::Value {
    fn from(value_: Decimal) -> Self {
        wasm_wave::value::Value::make_record(
            &Decimal::wave_type(), [ ("value", wasm_wave::value::Value::from(value_.value)) ],
        )
        .unwrap()
    }
}

impl From<wasm_wave::value::Value> for Decimal {
    fn from(value_: wasm_wave::value::Value) -> Self {
        let mut value = None;

        for (key_, val_) in value_.unwrap_record() {
            match key_.as_ref() {
                "value" => value = Some(val_.unwrap_string().into_owned()),
                key_ => panic!("Unknown field: {}", key_),
            }
        }

        Self {
            value: value.expect("Missing 'value' field"),
        }
    }
}

impl From<f64> for Decimal {
    fn from(value_: f64) -> Self {
        Decimal {
            value: value_.to_string(),
        }
    }
}

impl From<D256> for Decimal {
    fn from(value_: D256) -> Self {
        Decimal {
            value: value_.to_string(),
        }
    }
}

impl ContractAddress {
    pub fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::record([
            ("name", wasm_wave::value::Type::STRING),
            ("height", wasm_wave::value::Type::S64),
            ("tx-index", wasm_wave::value::Type::S64),
        ])
        .unwrap()
    }
}

impl fmt::Display for ContractAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}_{}", self.name, self.height, self.tx_index)
    }
}

impl From<ContractAddress> for wasm_wave::value::Value {
    fn from(value_: ContractAddress) -> Self {
        wasm_wave::value::Value::make_record(
            &ContractAddress::wave_type(),
            [
                ("name", wasm_wave::value::Value::from(value_.name)),
                ("height", wasm_wave::value::Value::from(value_.height)),
                ("tx-index", wasm_wave::value::Value::from(value_.tx_index)),
            ],
        )
        .unwrap()
    }
}

impl From<wasm_wave::value::Value> for ContractAddress {
    fn from(value_: wasm_wave::value::Value) -> Self {
        let mut name = None;
        let mut height = None;
        let mut tx_index = None;

        for (key_, val_) in value_.unwrap_record() {
            match key_.as_ref() {
                "name" => name = Some(val_.unwrap_string().into_owned()),
                "height" => height = Some(val_.unwrap_s64()),
                "tx-index" => tx_index = Some(val_.unwrap_s64()),
                key_ => panic!("Unknown field: {}", key_),
            }
        }

        Self {
            name: name.expect("Missing 'name' field"),
            height: height.expect("Missing 'height' field"),
            tx_index: tx_index.expect("Missing 'tx_index' field"),
        }
    }
}

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
        func.call_async(&mut store, &params, &mut results).await?;
        self.stack.pop().await;
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
    async fn eq(&mut self, a: Integer, b: Integer) -> Result<bool, anyhow::Error> {
        let big_a = a.value.parse::<BigInt>()?;
        let big_b = b.value.parse::<BigInt>()?;
        Ok(big_a == big_b)
    }

    async fn cmp(&mut self, a: Integer, b: Integer) -> Result<numbers::Ordering, anyhow::Error> {
        let big_a = a.value.parse::<BigInt>()?;
        let big_b = b.value.parse::<BigInt>()?;
        Ok(match big_a.cmp(&big_b) {
            Ordering::Less => numbers::Ordering::Less,
            Ordering::Equal => numbers::Ordering::Equal,
            Ordering::Greater => numbers::Ordering::Greater,
        })
    }

    async fn add(&mut self, a: Integer, b: Integer) -> Result<Integer, anyhow::Error> {
        let big_a = a.value.parse::<BigInt>()?;
        let big_b = b.value.parse::<BigInt>()?;
        Ok(Integer {
            value: (big_a + big_b).to_string(),
        })
    }

    async fn sub(&mut self, a: Integer, b: Integer) -> Result<Integer, anyhow::Error> {
        let big_a = a.value.parse::<BigInt>()?;
        let big_b = b.value.parse::<BigInt>()?;
        Ok(Integer {
            value: (big_a - big_b).to_string(),
        })
    }

    async fn integer_to_decimal(&mut self, i: Integer) -> Result<Decimal, anyhow::Error> {
        let dec = i.value.parse::<D256>()?;
        Ok(Decimal {
            value: dec.quantize(dec256!(0.000_000_000_000_000_001)).to_string(),
        })
    }

    async fn eq_decimal(&mut self, a: Decimal, b: Decimal) -> Result<bool, anyhow::Error> {
        let dec_a = a.value.parse::<D256>()?;
        let dec_b = b.value.parse::<D256>()?;
        Ok(dec_a == dec_b)
    }

    async fn cmp_decimal(&mut self, a: Decimal, b: Decimal) -> Result<numbers::Ordering, anyhow::Error> {
        let dec_a = a.value.parse::<D256>()?;
        let dec_b = b.value.parse::<D256>()?;
        Ok(match dec_a.cmp(&dec_b) {
            Ordering::Less => numbers::Ordering::Less,
            Ordering::Equal => numbers::Ordering::Equal,
            Ordering::Greater => numbers::Ordering::Greater,
        })
    }

    async fn add_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Decimal, anyhow::Error> {
        let dec_a = a.value.parse::<D256>()?;
        let dec_b = b.value.parse::<D256>()?;
        Ok(Decimal {
            value: (dec_a + dec_b).quantize(dec256!(0.000_000_000_000_000_001)).to_string(),
        })
    }

    async fn sub_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Decimal, anyhow::Error> {
        let dec_a = a.value.parse::<D256>()?;
        let dec_b = b.value.parse::<D256>()?;
        Ok(Decimal {
            value: (dec_a - dec_b).quantize(dec256!(0.000_000_000_000_000_001)).to_string(),
        })
    }

    async fn mul_decimal(&mut self, a: Decimal, b: Decimal) -> Result<Decimal, anyhow::Error> {
        let dec_a = a.value.parse::<D256>()?;
        let dec_b = b.value.parse::<D256>()?;
        Ok(Decimal {
            value: (dec_a * dec_b).quantize(dec256!(0.000_000_000_000_000_001)).to_string(),
        })
    }

    async fn log10 (&mut self, a: Decimal) -> Result<Decimal, anyhow::Error> {
        let dec_a = a.value.parse::<D256>()?;
        Ok(Decimal {
            value: (dec_a.log10()).quantize(dec256!(0.000_000_000_000_000_001)).to_string(),
        })
    }
}
