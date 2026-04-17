extern crate alloc;

mod component_cache;
pub mod counter;
pub mod file_ledger;
pub mod filestorage;
pub mod fuel;
pub mod numerics;
pub mod pool;
pub mod registry;
mod stack;
pub mod staking;
mod storage;
pub mod token;
mod types;
pub mod wit;

mod call;
mod host_context;
mod host_files;
mod host_numbers;
mod host_storage;

use bitcoin::XOnlyPublicKey;
pub use component_cache::ComponentCache;
pub use file_ledger::FileLedger;
use futures_util::future::OptionFuture;
use libsql::Connection;
use sha2::{Digest, Sha256};
pub use stdlib::{
    CheckedArithmetics, FromWaveValue, WaveType, from_wave_expr, from_wave_value, to_wave_expr,
    wave_type,
};
use stdlib::{contract_address, holder_ref, impls};
pub use storage::{Storage, TransactionContext};
use tokio::sync::Mutex;
pub use types::default_val_for_type;
pub use wit::Root;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

/// Distinguishes deterministic failures from non-deterministic failures
/// in the contract execution path.
#[derive(Debug)]
pub enum ExecutionError {
    /// Deterministic failure — all nodes see the same result for the same inputs.
    /// WASM traps, contract not found, bad arguments, etc.
    /// Caller should rollback and continue processing.
    Deterministic(anyhow::Error),
    /// Non-deterministic failure — DB/IO error, host panic, tokio task failure.
    /// Different nodes may see different results.
    /// Caller should propagate to reactor and shut down.
    NonDeterministic(anyhow::Error),
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionError::Deterministic(e) => write!(f, "deterministic error: {e:#}"),
            ExecutionError::NonDeterministic(e) => write!(f, "non-deterministic error: {e:#}"),
        }
    }
}

impl std::error::Error for ExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ExecutionError::Deterministic(e) | ExecutionError::NonDeterministic(e) => e.source(),
        }
    }
}

/// Convert an anyhow::Error to ExecutionError, preserving the classification
/// if the error already contains an ExecutionError (e.g. from a cross-contract
/// call through the WIT foreign::call boundary). Falls back to NonDeterministic
/// for errors without an ExecutionError inside.
impl From<anyhow::Error> for ExecutionError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast::<ExecutionError>() {
            Ok(ee) => ee,
            Err(e) => ExecutionError::NonDeterministic(e),
        }
    }
}

pub use wit::kontor;
pub use wit::kontor::built_in::error::Error;
pub use wit::kontor::built_in::file_registry::{ChallengeInput, RawFileDescriptor, VerifyResult};
pub use wit::kontor::built_in::foreign::ContractAddress;
pub use wit::kontor::built_in::numbers::{
    Decimal, Integer, Ordering as NumericOrdering, Sign as NumericSign,
};

use anyhow::{Result, anyhow};
use std::str::FromStr;
use wasmtime::{
    Engine, Store,
    component::{Component, HasData, Linker, ResourceTable},
};

use crate::bls::RegistrationProof;
use crate::database;
use crate::database::native_contracts::{FILESTORAGE, REGISTRY, STAKING, TOKEN};
use crate::runtime::kontor::built_in::context::OpReturnData;
use crate::runtime::{counter::Counter, fuel::FuelGauge, stack::Stack, wit::Signer};

#[derive(Clone, Debug)]
pub struct GenesisValidator {
    pub x_only_pubkey: String,
    pub stake: Decimal,
    pub ed25519_pubkey: Vec<u8>,
}

impl From<GenesisValidator> for staking::api::ActiveValidatorInfo {
    fn from(v: GenesisValidator) -> Self {
        Self {
            x_only_pubkey: v.x_only_pubkey,
            stake: v.stake,
            ed25519_pubkey: v.ed25519_pubkey,
        }
    }
}

impls!(host = true);

pub fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.into()
}

impl PartialEq for RawFileDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.file_id == other.file_id
            && self.object_id == other.object_id
            && self.nonce == other.nonce
            && self.root == other.root
            && self.padded_len == other.padded_len
            && self.original_size == other.original_size
            && self.filename == other.filename
    }
}

impl Eq for RawFileDescriptor {}

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
    pub previous_output: Option<bitcoin::OutPoint>,
    pub op_return_data: Option<OpReturnData>,
    pub node_label: String,
}

impl Runtime {
    pub fn new_engine() -> Result<Engine> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model_async(true);
        config.consume_fuel(true);
        // Ensure deterministic execution
        config.wasm_threads(false);
        config.wasm_relaxed_simd(false);
        config.cranelift_nan_canonicalization(true);
        Ok(Engine::new(&config)?)
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
        let file_ledger = FileLedger::rebuild_from_db(&storage.conn).await?;
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
            previous_output: None,
            op_return_data: None,
            node_label: String::new(),
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
        tx_context: Option<TransactionContext>,
        previous_output: Option<bitcoin::OutPoint>,
        op_return_data: Option<OpReturnData>,
    ) {
        self.storage.height = height;
        self.storage.tx_context = tx_context;
        self.id_generation_counter.reset().await;
        self.result_id_counter.reset().await;
        self.previous_output = previous_output;
        self.op_return_data = op_return_data;
        if self.storage.tx_context.is_some()
            && let Some(gauge) = self.gauge.as_ref()
        {
            gauge.reset().await;
        }
    }

    pub fn tx_context(&self) -> Option<&TransactionContext> {
        self.storage.tx_context.as_ref()
    }

    pub fn tx_context_mut(&mut self) -> Option<&mut TransactionContext> {
        self.storage.tx_context.as_mut()
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

    pub async fn publish_native_contracts(
        &mut self,
        genesis_validators: &[GenesisValidator],
    ) -> Result<()> {
        self.set_context(0, Some(TransactionContext::builder().build()), None, None)
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
        self.publish(&Signer::Core(Box::new(Signer::Nobody)), "staking", STAKING)
            .await?;
        self.publish(
            &Signer::Core(Box::new(Signer::Nobody)),
            "registry",
            REGISTRY,
        )
        .await?;
        if !genesis_validators.is_empty() {
            let validators = genesis_validators.iter().cloned().map(Into::into).collect();
            staking::api::set_genesis_set(
                self,
                &Signer::Core(Box::new(Signer::Nobody)),
                validators,
            )
            .await?;
        }
        Ok(())
    }

    pub async fn publish(
        &mut self,
        signer: &Signer,
        name: &str,
        bytes: &[u8],
    ) -> Result<String, ExecutionError> {
        let address = ContractAddress {
            name: name.to_string(),
            height: self.storage.height as u64,
            tx_index: self
                .tx_context()
                .expect("Transaction context must be set to public contracts")
                .tx_index as u64,
        };
        if self
            .storage
            .contract_id(&address)
            .await
            .map_err(ExecutionError::NonDeterministic)?
            .is_some()
        {
            return Ok("".to_string());
        }

        self.storage
            .savepoint()
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        self.storage
            .insert_contract(name, bytes)
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        let result = self.execute(Some(signer), &address, "init()").await;
        if result.is_err() {
            self.storage
                .rollback()
                .await
                .map_err(ExecutionError::NonDeterministic)?;
            result
        } else {
            self.storage
                .commit()
                .await
                .map_err(ExecutionError::NonDeterministic)?;
            Ok(to_wave_expr(address.clone()))
        }
    }

    pub async fn issuance(&mut self, signer: &Signer) -> Result<(), ExecutionError> {
        let result = token::api::issuance(
            self,
            &Signer::Core(Box::new(signer.clone())),
            10u64.try_into().expect("u64 to decimal"),
        )
        .await;
        result?.expect("issuance(10) should never fail");
        Ok(())
    }

    pub async fn get_or_create_identity(
        &self,
        x_only_pubkey: &str,
    ) -> Result<database::types::Identity, ExecutionError> {
        let conn = self.get_storage_conn();
        let height = self.storage.height;
        database::queries::get_or_create_identity(&conn, x_only_pubkey, height)
            .await
            .map_err(|e| ExecutionError::NonDeterministic(e.into()))
    }

    pub async fn register_bls_key(
        &mut self,
        signer: &Signer,
        bls_pubkey: &[u8],
        schnorr_sig: &[u8],
        bls_sig: &[u8],
    ) -> Result<(), ExecutionError> {
        let Signer::Id(identity) = signer else {
            return Err(ExecutionError::Deterministic(anyhow!(
                "RegisterBlsKey requires an Id signer"
            )));
        };

        let conn = self.get_storage_conn();
        let existing_bls = identity
            .bls_pubkey(&conn)
            .await
            .map_err(|e| ExecutionError::NonDeterministic(e.into()))?;
        if let Some(existing) = existing_bls {
            if existing == bls_pubkey {
                return Ok(());
            }
            return Err(ExecutionError::Deterministic(anyhow!(
                "BLS pubkey already registered for signer"
            )));
        }

        let x_only_pubkey = identity
            .x_only_pubkey(&conn)
            .await
            .map_err(|e| ExecutionError::NonDeterministic(e.into()))?;
        let x_only_pk = XOnlyPublicKey::from_str(&x_only_pubkey)
            .map_err(|e| ExecutionError::Deterministic(anyhow!("invalid x-only pubkey: {e}")))?;

        let bls_pubkey: [u8; 96] = bls_pubkey.try_into().map_err(|_| {
            ExecutionError::Deterministic(anyhow!(
                "RegisterBlsKey expected 96 bytes for bls_pubkey"
            ))
        })?;
        let schnorr_sig: [u8; 64] = schnorr_sig.try_into().map_err(|_| {
            ExecutionError::Deterministic(anyhow!(
                "RegisterBlsKey expected 64 bytes for schnorr_sig"
            ))
        })?;
        let bls_sig: [u8; 48] = bls_sig.try_into().map_err(|_| {
            ExecutionError::Deterministic(anyhow!("RegisterBlsKey expected 48 bytes for bls_sig"))
        })?;

        let proof = RegistrationProof {
            x_only_pubkey: x_only_pk.serialize(),
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        };
        proof.verify().map_err(ExecutionError::Deterministic)?;

        identity
            .register_bls_key(&conn, &proof.bls_pubkey, self.storage.height)
            .await
            .map_err(|e| ExecutionError::NonDeterministic(e.into()))?;

        Ok(())
    }

    pub async fn execute(
        &mut self,
        signer: Option<&Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String, ExecutionError> {
        tracing::info!(
            "Executing contract {} with expr {} with tx context {:?}",
            contract_address,
            expr,
            self.tx_context()
        );
        let (
            store,
            contract_id,
            func_name,
            is_fallback,
            params,
            results,
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
        let (mut result, mut store) = self
            .call_and_handle(store, func, params, results, is_fallback)
            .await?;
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
}

static SKIP_RESULT_RULES: LazyLock<HashMap<&str, HashSet<&str>>> =
    LazyLock::new(|| [("token", ["hold"].into())].into());

fn should_skip_result(contract_address: &ContractAddress, func_name: &str) -> bool {
    SKIP_RESULT_RULES
        .get(contract_address.name.as_str())
        .is_some_and(|methods| methods.contains(&func_name))
}

impl HasData for Runtime {
    type Data<'a> = &'a mut Runtime;
}
