extern crate alloc;

mod component_cache;
pub mod counter;
pub mod file_ledger;
pub mod filestorage;
pub mod fuel;
pub mod numerics;
pub mod pool;
mod stack;
mod storage;
pub mod token;
mod types;
pub mod wit;

use bitcoin::{Txid, hashes::Hash};
pub use component_cache::ComponentCache;
pub use file_ledger::FileLedger;
use futures_util::{StreamExt, future::OptionFuture};
use libsql::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use stdlib::{
    CheckedArithmetics, FromWaveValue, WaveType, from_wave_expr, from_wave_value, to_wave_expr,
    wave_type,
};
use stdlib::{contract_address, impls};
pub use storage::Storage;
use tokio::sync::Mutex;
pub use types::default_val_for_type;
pub use wit::Root;

use std::sync::Arc;

use wit::kontor::*;

pub use wit::kontor;
pub use wit::kontor::built_in::error::Error;
pub use wit::kontor::built_in::file_ledger::RawFileDescriptor;
pub use wit::kontor::built_in::foreign::ContractAddress;
pub use wit::kontor::built_in::numbers::{
    Decimal, Integer, Ordering as NumericOrdering, Sign as NumericSign,
};

use anyhow::{Result, anyhow};
use indexer_types::{deserialize, serialize};
use wasmtime::{
    AsContext, AsContextMut, Engine, Store,
    component::{
        Accessor, Component, Func, HasData, Linker, Resource, ResourceTable, Val,
        wasm_wave::{
            parser::Parser as WaveParser, to_string as to_wave_string, value::Value as WaveValue,
        },
    },
};

use crate::database::native_contracts::{FILESTORAGE, TOKEN};
use crate::database::types::FileMetadataRow;
use crate::runtime::kontor::built_in::context::{OpReturnData, OutPoint};
use crate::runtime::wit::{CoreContext, FileDescriptor, Transaction};
use crate::{
    runtime::{
        counter::Counter,
        fuel::{Fuel, FuelGauge},
        stack::Stack,
        wit::{
            FallContext, HasContractId, Keys, ProcContext, ProcStorage, Signer, ViewContext,
            ViewStorage,
        },
    },
    test_utils::new_mock_transaction,
};

impls!(host = true);

pub fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.into()
}

impl RawFileDescriptor {
    fn to_file_metadata_row(raw: RawFileDescriptor, height: i64) -> Result<FileMetadataRow, Error> {
        let root = raw
            .root
            .try_into()
            .map_err(|_| Error::Validation("expected 32 bytes for root".to_string()))?;
        // Compute depth from padded_len (matches kontor_crypto::FileMetadata::depth())
        let depth = if raw.padded_len == 0 {
            0
        } else {
            raw.padded_len.trailing_zeros() as i64
        };
        Ok(FileMetadataRow::builder()
            .file_id(raw.file_id)
            .root(root)
            .depth(depth)
            .height(height)
            .build())
    }
}

#[derive(Clone)]
pub struct Runtime {
    pub engine: Engine,
    pub linker: Linker<Self>,
    pub table: Arc<Mutex<ResourceTable>>,
    pub component_cache: ComponentCache,
    pub storage: Storage,
    pub file_ledger: FileLedger,
    pub id_generation_counter: Counter,
    pub result_id_counter: Counter,
    pub stack: Stack<i64>,
    pub gauge: Option<FuelGauge>,
    pub gas_limit: Option<u64>,
    pub gas_limit_for_non_procs: u64,
    pub gas_to_fuel_multiplier: u64,
    pub gas_to_token_multiplier: Decimal,
    pub txid: Option<Txid>,
    pub previous_output: Option<bitcoin::OutPoint>,
    pub op_return_data: Option<OpReturnData>,
}

impl Runtime {
    pub fn new_engine() -> Result<Engine> {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.wasm_component_model(true);
        config.consume_fuel(true);
        // Ensure deterministic execution
        config.wasm_threads(false);
        config.wasm_relaxed_simd(false);
        config.cranelift_nan_canonicalization(true);
        Engine::new(&config)
    }

    pub fn new_linker(engine: &Engine) -> Result<Linker<Self>> {
        let mut linker = Linker::new(engine);
        Root::add_to_linker::<_, Self>(&mut linker, |s| s)?;
        Ok(linker)
    }

    pub async fn new(component_cache: ComponentCache, storage: Storage) -> Result<Self> {
        let engine = Self::new_engine()?;
        let linker = Self::new_linker(&engine)?;
        Self::new_with(engine, linker, component_cache, storage).await
    }

    pub async fn new_with(
        engine: Engine,
        linker: Linker<Self>,
        component_cache: ComponentCache,
        storage: Storage,
    ) -> Result<Self> {
        let file_ledger = FileLedger::rebuild_from_db(&storage).await?;
        Ok(Self {
            engine,
            linker,
            table: Arc::new(Mutex::new(ResourceTable::new())),
            component_cache,
            storage,
            file_ledger,
            id_generation_counter: Counter::new(),
            result_id_counter: Counter::new(),
            stack: Stack::new(),
            gauge: Some(FuelGauge::new()),
            gas_limit: None,
            gas_limit_for_non_procs: 100_000,
            gas_to_fuel_multiplier: 1_000,
            gas_to_token_multiplier: Decimal::from("1e-9"),
            txid: None,
            previous_output: None,
            op_return_data: None,
        })
    }

    pub async fn new_read_only(
        engine: Engine,
        linker: Linker<Self>,
        component_cache: ComponentCache,
        conn: Connection,
    ) -> Result<Self> {
        Runtime::new_with(
            engine,
            linker,
            component_cache,
            Storage::builder().conn(conn).build(),
        )
        .await
    }

    pub async fn set_context(
        &mut self,
        height: i64,
        tx_index: i64,
        input_index: i64,
        op_index: i64,
        txid: Txid,
        previous_output: Option<bitcoin::OutPoint>,
        op_return_data: Option<OpReturnData>,
    ) {
        self.storage.height = height;
        self.storage.tx_index = tx_index;
        self.storage.input_index = input_index;
        self.storage.op_index = op_index;
        self.id_generation_counter.reset().await;
        self.result_id_counter.reset().await;
        self.txid = Some(txid);
        self.previous_output = previous_output;
        self.op_return_data = op_return_data;
        if let Some(gauge) = self.gauge.as_ref() {
            gauge.reset().await;
        }
    }

    pub fn get_storage_conn(&self) -> Connection {
        self.storage.conn.clone()
    }

    pub fn set_storage(&mut self, storage: Storage) {
        self.storage = storage;
    }

    pub fn fuel_limit(&self) -> Option<u64> {
        self.gas_limit.map(|l| l * self.gas_to_fuel_multiplier)
    }

    pub fn fuel_limit_for_non_procs(&self) -> u64 {
        self.gas_limit_for_non_procs * self.gas_to_fuel_multiplier
    }

    pub fn set_gas_limit(&mut self, gas_limit: u64) {
        self.gas_limit = Some(gas_limit);
    }

    pub fn gas_consumed(&self, starting_fuel: u64, ending_fuel: u64) -> u64 {
        (starting_fuel - ending_fuel).div_ceil(self.gas_to_fuel_multiplier)
    }

    pub async fn publish_native_contracts(&mut self) -> Result<()> {
        self.set_context(0, 0, 0, 0, new_mock_transaction(0).txid, None, None)
            .await;
        self.set_gas_limit(self.gas_limit_for_non_procs);
        self.publish(&Signer::Core(Box::new(Signer::Nobody)), "token", TOKEN)
            .await?;
        self.publish(
            &Signer::Core(Box::new(Signer::Nobody)),
            "filestorage",
            FILESTORAGE,
        )
        .await?;
        Ok(())
    }

    pub async fn publish(&mut self, signer: &Signer, name: &str, bytes: &[u8]) -> Result<String> {
        let address = ContractAddress {
            name: name.to_string(),
            height: self.storage.height as u64,
            tx_index: self.storage.tx_index as u64,
        };
        if self
            .storage
            .contract_id(&address)
            .await
            .expect("Failed to perform contract existence check")
            .is_some()
        {
            return Ok("".to_string());
        }

        self.storage
            .savepoint()
            .await
            .expect("Failed to create savepoint");
        self.storage
            .insert_contract(name, bytes)
            .await
            .expect("Failed to insert contract");
        let result = self.execute(Some(signer), &address, "init()").await;
        if result.is_err() {
            self.storage.rollback().await.expect("Failed to rollback");
            result
        } else {
            self.storage.commit().await.expect("Failed to commit");
            Ok(to_wave_expr(address.clone()))
        }
    }

    pub async fn issuance(&mut self, signer: &Signer) -> Result<()> {
        token::api::issuance(self, &Signer::Core(Box::new(signer.clone())), 10.into())
            .await
            .expect("Failed to run issuance")
            .expect("Failed to issue tokens");
        Ok(())
    }

    pub async fn execute(
        &mut self,
        signer: Option<&Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        tracing::info!(
            "Executing contract {} with expr {} at input index {}",
            contract_address,
            expr,
            self.storage.input_index
        );
        let (
            mut store,
            contract_id,
            func_name,
            is_fallback,
            params,
            mut results,
            func,
            is_proc,
            starting_fuel,
        ) = self
            .prepare_call(contract_address, signer, expr, true, self.fuel_limit())
            .await?;
        OptionFuture::from(
            self.gauge
                .as_ref()
                .map(|g| g.set_starting_fuel(starting_fuel)),
        )
        .await;
        let (result, results, mut store) = tokio::spawn(async move {
            (
                func.call_async(&mut store, &params, &mut results).await,
                results,
                store,
            )
        })
        .await
        .expect("Failed to join execution");
        let mut result = self.handle_call(is_fallback, result, results).await;
        OptionFuture::from(
            self.gauge
                .as_ref()
                .map(|g| g.set_ending_fuel(store.get_fuel().unwrap())),
        )
        .await;
        if is_proc {
            let signer = signer.expect("Signer should be available in proc");
            result = self
                .handle_procedure(
                    signer,
                    contract_id,
                    contract_address,
                    &func_name,
                    true,
                    starting_fuel,
                    &mut store,
                    result,
                )
                .await;
        }
        result
    }

    pub async fn load_component(&self, contract_id: i64) -> Result<Component> {
        Ok(match self.component_cache.get(&contract_id).await {
            Some(component) => component,
            None => {
                let component_bytes = self.storage.component_bytes(contract_id).await?;
                let component = Component::from_binary(&self.engine, &component_bytes)?;
                self.component_cache
                    .put(contract_id, component.clone())
                    .await;
                component
            }
        })
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
        is_top_level: bool,
        fuel: Option<u64>,
    ) -> Result<(
        Store<Runtime>,
        i64,
        String,
        bool,
        Vec<Val>,
        Vec<Val>,
        Func,
        bool,
        u64,
    )> {
        let contract_id = self
            .storage
            .contract_id(contract_address)
            .await?
            .ok_or(anyhow!("Contract not found: {}", contract_address))?;
        let component = self.load_component(contract_id).await?;
        let mut fuel_limit = fuel.unwrap_or(self.fuel_limit_for_non_procs());
        let mut store = self.make_store(fuel_limit)?;
        let instance = self
            .linker
            .instantiate_async(&mut store, &component)
            .await?;
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

        let func_name = call.name();
        let component_func = func.ty(&store);
        let func_params = component_func.params();
        let func_param_types = func_params.map(|(_, t)| t).collect::<Vec<_>>();
        let (func_ctx_param_type, func_param_types) = func_param_types
            .split_first()
            .ok_or(anyhow!("Context/signer parameter not found"))?;
        let mut params = call.to_wasm_params(func_param_types)?;
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
                (t, Some(Signer::Core(signer)))
                    if t.eq(&wasmtime::component::ResourceType::host::<CoreContext>()) =>
                {
                    is_proc = true;
                    fuel_limit = self.fuel_limit_for_non_procs();
                    store
                        .set_fuel(fuel_limit)
                        .expect("Failed to set fuel for core context procedure");
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(CoreContext {
                                    signer: *signer.clone(),
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
                (t, signer) => {
                    return Err(anyhow!(
                        "Unsupported context/signer type: {:?} {:?}",
                        t,
                        signer
                    ));
                }
            }
        }

        if is_proc && fuel.is_none() {
            return Err(anyhow!("Missing fuel for procedure"));
        }

        let results = component_func
            .results()
            .map(default_val_for_type)
            .collect::<Vec<_>>();

        if is_proc
            && is_top_level
            && let Some(signer) = signer
            && !signer.is_core()
        {
            Box::pin({
                let mut runtime = self.clone();
                async move {
                    token::api::hold(
                        &mut runtime,
                        &Signer::Core(Box::new(signer.clone())),
                        Decimal::from(fuel_limit)
                            .div(Decimal::from(self.gas_to_fuel_multiplier))
                            .expect("Failed to convert fuel limit into gas limit")
                            .mul(self.gas_to_token_multiplier)
                            .expect("Failed to convert gas limit into token limit"),
                    )
                    .await
                }
            })
            .await
            .expect("Failed to escrow gas")
            .map_err(|e| {
                anyhow!(
                    "Signer {:?} does not have enough token to cover gas limit: {}",
                    signer,
                    e
                )
            })?;
        }

        self.stack.push(contract_id).await?;
        self.storage.savepoint().await?;
        self.file_ledger.clear_dirty().await;

        Ok((
            store,
            contract_id,
            func_name.to_string(),
            func_name == fallback_name,
            params,
            results,
            func,
            is_proc,
            fuel_limit,
        ))
    }

    async fn handle_call(
        &self,
        is_fallback: bool,
        result: Result<()>,
        mut results: Vec<Val>,
    ) -> Result<String> {
        self.stack.pop().await;

        let result = if let Err(e) = result {
            Err(anyhow!(format!("{}", e.root_cause())))
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

        if result.is_err() || result.as_ref().is_ok_and(|val| val.starts_with("err(")) {
            self.storage
                .rollback()
                .await
                .expect("Failed to rollback storage after failure to extract expression");
            self.file_ledger
                .resync_from_db(&self.storage)
                .await
                .expect("Failed to resync file ledger after rollback");
        } else {
            self.storage
                .commit()
                .await
                .expect("Failed to commit storage after successful call");
        }

        result
    }

    pub async fn handle_procedure(
        &mut self,
        signer: &Signer,
        contract_id: i64,
        contract_address: &ContractAddress,
        func_name: &str,
        is_op_result: bool,
        starting_fuel: u64,
        store: &mut Store<Runtime>,
        mut result: Result<String>,
    ) -> Result<String> {
        if let Ok(value) = &result
            && let Err(e) = Fuel::Result(value.len() as u64)
                .consume_with_store(self.gauge.as_ref(), store)
                .await
        {
            result = Err(e);
        }
        let gas = self
            .gas_consumed(
                starting_fuel,
                store.get_fuel().expect("Fuel should be available"),
            )
            .max(1);

        if is_op_result && !signer.is_core() {
            tracing::info!(
                "Gas consumed: {} {} {}",
                gas,
                starting_fuel,
                store.get_fuel().unwrap()
            );
            Box::pin({
                let mut runtime = self.clone();
                runtime.stack = Stack::new();
                let gas_to_token_multiplier = self.gas_to_token_multiplier;
                async move {
                    token::api::release(
                        &mut runtime,
                        &Signer::Core(Box::new(signer.clone())),
                        Decimal::from(gas)
                            .mul(gas_to_token_multiplier)
                            .expect("Failed to convert gas consumed to token amount"),
                    )
                    .await
                }
            })
            .await
            .expect("Failed to run burn and release gas")
            .expect("Failed to burn and release gas");
        }
        // don't write result for native token hold function
        if contract_address == &token::address() && func_name == "hold" {
            return result;
        }
        let value = result.as_ref().map(|v| v.clone()).ok();
        let result_index = self.result_id_counter.get().await as i64;
        self.storage
            .insert_contract_result(
                result_index,
                contract_id,
                func_name.to_string(),
                gas as i64,
                value,
            )
            .await
            .expect("Failed to insert contract result");
        self.result_id_counter.increment().await;
        result
    }

    async fn _call<T>(
        &mut self,
        accessor: &Accessor<T, Self>,
        signer: Option<Resource<Signer>>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        let starting_fuel = accessor.with(|access| access.as_context().get_fuel())?;

        let signer =
            OptionFuture::from(signer.map(async |s| self.table.lock().await.get(&s).cloned()))
                .await
                .transpose()
                .expect("Failed to lock table and get signer");

        let (
            mut store,
            contract_id,
            func_name,
            is_fallback,
            params,
            mut results,
            func,
            is_proc,
            _fuel,
        ) = self
            .prepare_call(
                contract_address,
                signer.as_ref(),
                expr,
                false,
                Some(starting_fuel),
            )
            .await?;
        let (result, results, mut store) = tokio::spawn(async move {
            (
                func.call_async(&mut store, &params, &mut results).await,
                results,
                store,
            )
        })
        .await
        .expect("Failed to join call");
        let mut result = self.handle_call(is_fallback, result, results).await;
        let fuel = store.get_fuel().unwrap();
        accessor
            .with(|mut access| access.as_context_mut().set_fuel(fuel))
            .expect("Failed to set remaining fuel on parent store");
        if is_proc {
            result = self
                .handle_procedure(
                    signer.as_ref().expect("Signer should be available in proc"),
                    contract_id,
                    contract_address,
                    &func_name,
                    false,
                    starting_fuel,
                    &mut store,
                    result,
                )
                .await;
        }
        result
    }

    async fn _add_file<T>(
        &self,
        accessor: &Accessor<T, Self>,
        file_descriptor: Resource<FileDescriptor>,
    ) -> Result<()> {
        Fuel::AddFile.consume(accessor, self.gauge.as_ref()).await?;
        let table = self.table.lock().await;
        let file_metadata_row = table.get(&file_descriptor)?.file_metadata_row.clone();
        self.file_ledger
            .add_file(&self.storage, &file_metadata_row)
            .await
    }

    async fn _file_id<T>(
        &self,
        accessor: &Accessor<T, Self>,
        rep: Resource<FileDescriptor>,
    ) -> Result<String> {
        Fuel::GetFileId
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let table = self.table.lock().await;
        let file_id = table.get(&rep)?.file_metadata_row.file_id.clone();

        Ok(file_id)
    }

    async fn _from_raw<T>(
        &self,
        accessor: &Accessor<T, Self>,
        raw: RawFileDescriptor,
    ) -> Result<Result<Resource<FileDescriptor>, Error>> {
        Fuel::FromRawFileDescriptor
            .consume(accessor, self.gauge.as_ref())
            .await?;

        let mut table = self.table.lock().await;

        Ok(
            match RawFileDescriptor::to_file_metadata_row(raw, self.storage.height) {
                Ok(file_metadata_row) => Ok(table.push(FileDescriptor { file_metadata_row })?),
                Err(error) => Err(error),
            },
        )
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
                    deserialize(&bs)
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

    async fn _delete_matching_paths<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        self_: Resource<T>,
        regexp: String,
    ) -> Result<u64> {
        Fuel::DeleteMatchingPaths(regexp.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let contract_id = self.table.lock().await.get(&self_)?.get_contract_id();
        self.storage
            .delete_matching_paths(contract_id, &regexp)
            .await
    }

    async fn _set_primitive<S, T: HasContractId, V: Serialize>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: String,
        value: V,
    ) -> Result<()> {
        let contract_id = self.table.lock().await.get(&resource)?.get_contract_id();
        Fuel::Path(path.clone())
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let bs = &serialize(&value)?;
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
            &hash_bytes(
                &[
                    self.txid
                        .expect("txid is not set")
                        .to_raw_hash()
                        .to_byte_array()
                        .to_vec(),
                    count.to_le_bytes().to_vec(),
                ]
                .concat(),
            )[0..8],
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

    async fn _proc_transaction<T>(
        &self,
        accessor: &Accessor<T, Self>,
        _: Resource<ProcContext>,
    ) -> Result<Resource<Transaction>> {
        Fuel::ProcTransaction
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        Ok(table.push(Transaction {})?)
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

    async fn _proc_view_storage<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
    ) -> Result<Resource<ViewStorage>> {
        Fuel::ProcViewContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ViewStorage { contract_id })?)
    }

    async fn _view_storage<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
    ) -> Result<Resource<ViewStorage>> {
        Fuel::ViewStorage
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ViewStorage { contract_id })?)
    }

    async fn _proc_storage<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ProcStorage>> {
        Fuel::ProcStorage
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ProcStorage { contract_id })?)
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

    async fn _core_proc_context<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        Fuel::CoreProcContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let res = table.get(&self_)?;
        let contract_id = res.contract_id;
        let signer = res.signer.clone();
        Ok(table.push(ProcContext {
            contract_id,
            signer: Signer::Core(Box::new(signer)),
        })?)
    }

    async fn _core_signer_proc_context<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        Fuel::CoreProcContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let res = table.get(&self_)?;
        let contract_id = res.contract_id;
        let signer = res.signer.clone();
        Ok(table.push(ProcContext {
            contract_id,
            signer,
        })?)
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

    async fn _verify_challenge_proof(
        &self,
        challenge_id: String,
        _proof: Vec<u8>,
    ) -> Result<Result<built_in::challenges::VerifyProofResult, Error>> {
        use crate::database::queries::get_challenge_by_id;
        use crate::database::types::ChallengeStatus;

        // Look up the challenge
        let challenge = match get_challenge_by_id(&self.storage.conn, &challenge_id).await? {
            Some(c) => c,
            None => {
                return Ok(Ok(built_in::challenges::VerifyProofResult {
                    verified: false,
                    error_message: Some(format!("Challenge not found: {}", challenge_id)),
                }));
            }
        };

        // Check if challenge is still pending
        if challenge.status != ChallengeStatus::Active {
            return Ok(Ok(built_in::challenges::VerifyProofResult {
                verified: false,
                error_message: Some("Challenge is not pending".to_string()),
            }));
        }

        // TODO: Implement actual proof verification using kontor-crypto
        // 1. Get the file metadata from the agreement (need to read from contract state)
        // 2. Reconstruct the kontor_crypto::Challenge from stored data
        // 3. Call PorSystem::verify(proof, &[challenge])
        // 4. Return result
        let _agreement_id = challenge.agreement_id.clone();
        let _file_id = challenge.file_id.clone();
        todo!("Implement proof verification with kontor-crypto PorSystem::verify");

        // When implemented, on success:
        // update_challenge_status(&self.storage.conn, &challenge_id, ChallengeStatus::Proven).await?;
        // Ok(Ok(built_in::challenges::VerifyProofResult { verified: true, error_message: None }))
    }
}

impl HasData for Runtime {
    type Data<'a> = &'a mut Runtime;
}

impl built_in::error::Host for Runtime {}

impl built_in::file_ledger::Host for Runtime {}

impl built_in::file_ledger::HostFileDescriptor for Runtime {}

impl built_in::file_ledger::HostWithStore for Runtime {
    async fn add_file<T>(
        accessor: &Accessor<T, Self>,
        file_descriptor: Resource<FileDescriptor>,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._add_file(accessor, file_descriptor)
            .await
    }
}

impl built_in::file_ledger::HostFileDescriptorWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<FileDescriptor>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn file_id<T>(
        accessor: &Accessor<T, Self>,
        rep: Resource<FileDescriptor>,
    ) -> Result<String> {
        accessor
            .with(|mut access| access.get().clone())
            ._file_id(accessor, rep)
            .await
    }

    async fn from_raw<T>(
        accessor: &Accessor<T, Self>,
        raw: built_in::file_ledger::RawFileDescriptor,
    ) -> Result<Result<Resource<FileDescriptor>, Error>> {
        accessor
            .with(|mut access| access.get().clone())
            ._from_raw(accessor, raw)
            .await
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
            ._hash(accessor, input + salt.as_str())
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
            ._call(accessor, signer, &contract_address, &expr)
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

impl built_in::context::HostViewStorage for Runtime {}

impl built_in::context::HostViewStorageWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ViewStorage>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn get_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_list_u8<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<Vec<u8>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_keys<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(accessor, self_, path)
            .await
    }

    async fn exists<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(accessor, self_, path)
            .await
    }

    async fn extend_path_with_match<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
        variants: Vec<String>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._extend_path_with_match(accessor, self_, path, variants)
            .await
    }
}

impl built_in::context::HostViewContext for Runtime {}

impl built_in::context::HostViewContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ViewContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn storage<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
    ) -> Result<Resource<ViewStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._view_storage(accessor, self_)
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

impl built_in::context::HostProcStorage for Runtime {}

impl built_in::context::HostProcStorageWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ProcStorage>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn get_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_list_u8<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<Vec<u8>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_keys<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(accessor, self_, path)
            .await
    }

    async fn exists<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(accessor, self_, path)
            .await
    }

    async fn extend_path_with_match<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
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
        self_: Resource<ProcStorage>,
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
        self_: Resource<ProcStorage>,
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
        self_: Resource<ProcStorage>,
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
        self_: Resource<ProcStorage>,
        path: String,
        value: bool,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_list_u8<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        value: Vec<u8>,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_void<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, ())
            .await
    }

    async fn delete_matching_paths<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        base_path: String,
        variants: Vec<String>,
    ) -> Result<u64> {
        accessor
            .with(|mut access| access.get().clone())
            ._delete_matching_paths(
                accessor,
                self_,
                format!(r"^{}.({})(\..*|$)", base_path, variants.join("|")),
            )
            .await
    }

    async fn view_storage<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
    ) -> Result<Resource<ViewStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_view_storage(accessor, self_)
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

    async fn transaction<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Transaction>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_transaction(accessor, self_)
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

    async fn storage<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ProcStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_storage(accessor, self_)
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

impl built_in::context::HostCoreContext for Runtime {}

impl built_in::context::HostCoreContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<CoreContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn proc_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._core_proc_context(accessor, self_)
            .await
    }

    async fn signer_proc_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._core_signer_proc_context(accessor, self_)
            .await
    }
}

impl built_in::context::HostTransaction for Runtime {}

impl built_in::context::HostTransactionWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Transaction>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn id<T>(accessor: &Accessor<T, Self>, _: Resource<Transaction>) -> Result<String> {
        Ok(accessor
            .with(|mut access| access.get().txid)
            .expect("transaction id called without txid present")
            .to_string())
    }

    async fn out_point<T>(
        accessor: &Accessor<T, Self>,
        _: Resource<Transaction>,
    ) -> Result<OutPoint> {
        Ok(accessor
            .with(|mut access| access.get().previous_output)
            .expect("utxo_id called without previous_output present")
            .into())
    }

    async fn op_return_data<T>(
        accessor: &Accessor<T, Self>,
        _: Resource<Transaction>,
    ) -> Result<Option<OpReturnData>> {
        Ok(accessor.with(|mut access| access.get().op_return_data.clone()))
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
}

impl built_in::challenges::Host for Runtime {}

impl built_in::challenges::HostWithStore for Runtime {
    async fn verify_challenge_proof<T>(
        accessor: &Accessor<T, Self>,
        challenge_id: String,
        proof: Vec<u8>,
    ) -> Result<Result<built_in::challenges::VerifyProofResult, Error>> {
        accessor
            .with(|mut access| access.get().clone())
            ._verify_challenge_proof(challenge_id, proof)
            .await
    }
}
