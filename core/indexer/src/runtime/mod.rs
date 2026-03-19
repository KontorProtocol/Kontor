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
use stdlib::{contract_address, impls};
pub use storage::{Storage, TransactionContext};
use tokio::sync::Mutex;
pub use types::default_val_for_type;
pub use wit::Root;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

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
use crate::database::native_contracts::{FILESTORAGE, REGISTRY, STAKING, TOKEN};
use crate::runtime::kontor::built_in::context::OpReturnData;
use crate::runtime::{counter::Counter, fuel::FuelGauge, stack::Stack, wit::Signer};

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
}

impl Runtime {
    pub fn new_engine() -> Result<Engine> {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.wasm_component_model_async(true);
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

    pub async fn publish_native_contracts(&mut self) -> Result<()> {
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
        self.publish(
            &Signer::Core(Box::new(Signer::Nobody)),
            "registry",
            REGISTRY,
        )
        .await?;
        self.publish(&Signer::Core(Box::new(Signer::Nobody)), "staking", STAKING)
            .await?;
        Ok(())
    }

    pub async fn publish(&mut self, signer: &Signer, name: &str, bytes: &[u8]) -> Result<String> {
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

    pub async fn ensure_signer(&mut self, x_only_pubkey: &str) -> Result<u64> {
        self.set_gas_limit(self.gas_limit_for_non_procs);
        let entry = registry::api::ensure_signer(
            self,
            &Signer::Core(Box::new(Signer::Nobody)),
            x_only_pubkey,
        )
        .await?
        .map_err(|e| anyhow!("registry ensure-signer failed: {e:?}"))?;
        Ok(entry.signer_id)
    }

    pub async fn register_bls_key(
        &mut self,
        x_only_pubkey: &str,
        bls_pubkey: &[u8],
        schnorr_sig: &[u8],
        bls_sig: &[u8],
    ) -> Result<()> {
        self.set_gas_limit(self.gas_limit_for_non_procs);

        let x_only_pk = XOnlyPublicKey::from_str(x_only_pubkey)
            .map_err(|e| anyhow!("invalid x-only pubkey: {e}"))?;
        let signer_id = self.ensure_signer(&x_only_pk.to_string()).await?;
        let canonical_signer = Signer::SignerId {
            id: signer_id,
            id_str: format!("__sid__{}", signer_id),
        };

        if let Ok(Some(entry)) = registry::api::get_entry(self, &x_only_pk.to_string()).await
            && entry.bls_pubkey.as_deref() == Some(bls_pubkey)
        {
            return Ok(());
        }

        let bls_pubkey: [u8; 96] = bls_pubkey
            .try_into()
            .map_err(|_| anyhow!("RegisterBlsKey expected 96 bytes for bls_pubkey"))?;
        let schnorr_sig: [u8; 64] = schnorr_sig
            .try_into()
            .map_err(|_| anyhow!("RegisterBlsKey expected 64 bytes for schnorr_sig"))?;
        let bls_sig: [u8; 48] = bls_sig
            .try_into()
            .map_err(|_| anyhow!("RegisterBlsKey expected 48 bytes for bls_sig"))?;

        let proof = RegistrationProof {
            x_only_pubkey: x_only_pk.serialize(),
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        };
        proof.verify()?;

        registry::api::register_bls_key(
            self,
            &Signer::Core(Box::new(canonical_signer)),
            proof.bls_pubkey.to_vec(),
        )
        .await?
        .map(|_entry| ())
        .map_err(|e| anyhow!("registry register-bls-key failed: {e:?}"))
    }

    pub async fn execute(
        &mut self,
        signer: Option<&Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        tracing::info!(
            "Executing contract {} with expr {} with tx context {:?}",
            contract_address,
            expr,
            self.tx_context()
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
}

static SKIP_RESULT_RULES: LazyLock<HashMap<&str, HashSet<&str>>> = LazyLock::new(|| {
    [
        ("token", ["hold"].into()),
        (
            "registry",
            [
                "ensure-signer",
                "get-entry",
                "get-entry-by-id",
                "get-signer-id",
                "get-bls-pubkey",
            ]
            .into(),
        ),
    ]
    .into()
});

fn should_skip_result(contract_address: &ContractAddress, func_name: &str) -> bool {
    SKIP_RESULT_RULES
        .get(contract_address.name.as_str())
        .is_some_and(|methods| methods.contains(&func_name))
}

impl HasData for Runtime {
    type Data<'a> = &'a mut Runtime;
}
