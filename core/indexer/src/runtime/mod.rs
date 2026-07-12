extern crate alloc;

mod component_cache;
pub mod counter;
pub mod deposit;
pub mod filestorage;
pub mod fuel;
pub mod nft;
pub mod numerics;
pub mod pool;
mod stack;
pub mod staking;
mod storage;
pub mod system;
pub mod token;
mod types;
pub mod wit;

mod call;
mod host_context;
mod host_files;
mod host_numbers;
mod host_storage;
mod host_system;

use bitcoin::XOnlyPublicKey;
pub use component_cache::ComponentCache;
use futures_util::future::OptionFuture;
use libsql::Connection;
use sha2::{Digest, Sha256};
pub use stdlib::{
    CheckedArithmetics, FromWaveValue, WaveType, from_wave_expr, from_wave_value, to_wave_expr,
    wave_type,
};
use stdlib::{contract_address, holder_ref, impls};
use storage::print_component_wit;
pub use storage::{Storage, TransactionContext};
use tokio::sync::Mutex;
pub use types::default_val_for_type;

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
pub use wit::kontor::built_in::context::ContractAddress;
pub use wit::kontor::built_in::context::OutPoint;
pub use wit::kontor::built_in::error::Error;
pub use wit::kontor::built_in::file_registry_types::{
    ChallengeInput, RawFileDescriptor, VerifyResult,
};
pub use wit::kontor::built_in::numbers::{
    Decimal, Integer, Ordering as NumericOrdering, Sign as NumericSign,
};

use anyhow::{Result, anyhow};
use std::str::FromStr;
use wasmtime::{
    Engine, Store,
    component::{Component, HasData, Linker, ResourceTable},
};

use indexer_types::{BuildProvenance, CommitId, Forge, Payment, Platform, Source};
use wit_validator::Validator as WitValidator;

use crate::bls::RegistrationProof;
use crate::config::DEFAULT_VIEW_GAS_LIMIT;
use crate::database;
use crate::database::native_contracts::{NATIVE_CONTRACTS, is_native_contract_id};
use crate::database::types::CORE_SIGNER_ID;
use crate::runtime::{
    call::PreparedCall,
    counter::Counter,
    deposit::DepositMeter,
    fuel::FuelGauge,
    stack::{CallFrame, Stack},
    wit::Signer,
};

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

/// Provenance for the native/genesis contracts. `platform` + the pinned `image`
/// come from the committed native-contracts `build.json`; the source is the
/// Kontor repo at the node's build commit — which reproduces the committed
/// binaries (the reproducible-build gate proves that at every commit). A missing
/// git commit (e.g. a tarball build) → an all-zero "unknown" commit.
fn native_provenance() -> Result<BuildProvenance> {
    const BUILD_JSON: &str = include_str!("../../../../native-contracts/binaries/build.json");

    #[derive(serde::Deserialize)]
    struct BuildMeta {
        platform: String,
        image: String,
    }
    let meta: BuildMeta = serde_json::from_str(BUILD_JSON)?;

    let commit = crate::built_info::GIT_COMMIT_HASH
        .and_then(|h| {
            let mut bytes = [0u8; 20];
            hex::decode_to_slice(h, &mut bytes).ok().map(|_| bytes)
        })
        .map(CommitId::Sha1)
        .unwrap_or(CommitId::Sha1([0u8; 20]));

    let provenance = BuildProvenance {
        source: Source {
            forge: Forge::GitHub,
            owner: "KontorProtocol".to_string(),
            repo: "Kontor".to_string(),
            commit,
        },
        image: meta.image,
        platform: Platform::parse(&meta.platform)?,
    };
    provenance.validate()?;
    Ok(provenance)
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

/// The two host capability surfaces over a single `Runtime`. `user` registers
/// only the common built-ins; `native` additionally registers the privileged
/// interfaces (`file-registry`, `system`, `deposit`). Both share the same `Runtime`
/// host state — they differ only in which interfaces a component can import.
/// `prepare_call` selects one per contract by native contract id.
#[derive(Clone)]
pub struct Linkers {
    pub user: Linker<Runtime>,
    pub native: Linker<Runtime>,
}

#[derive(Clone)]
pub struct Runtime {
    pub engine: Engine,
    pub linkers: Linkers,
    pub table: Arc<Mutex<ResourceTable>>,
    pub component_cache: ComponentCache,
    pub storage: Storage,
    pub id_generation_counter: Counter,
    pub result_id_counter: Counter,
    pub stack: Stack<CallFrame>,
    pub gauge: Option<FuelGauge>,
    /// Transient per-op accumulator of the storage-deposit GAS reserved this op
    /// (the returned-at-settle slice that bounds growth). Reset at the top-level op
    /// start, drained at the settle boundary to compute the execution burn
    /// (`burn = gas - charge`).
    pub deposit: DepositMeter,
    /// Nominal gas limit stamped on system-issued `Payment`s (`core_payment`,
    /// `execute_api`). FIXED — never operator-configurable. Trusted core calls
    /// themselves run unmetered at `SYSTEM_FUEL_CEILING` (decided from the signer in
    /// `prepare_call`), so this is the Payment's nominal cap, not the core fuel
    /// budget; it still bounds a user-signed `execute_api` call (the test path).
    pub gas_limit_for_non_procs: u64,
    /// Fuel budget for read-only `/view` calls (the payment-`None` path) ONLY.
    /// Operator-configurable per node (set from `Config::view_gas_limit` on the
    /// read-only pool runtime; left at the default on the reactor's consensus runtime,
    /// where views don't run). DELIBERATELY SEPARATE from `gas_limit_for_non_procs` so
    /// an operator's view cap can NEVER starve consensus core calls.
    pub view_gas_limit: u64,
    pub gas_to_fuel_multiplier: u64,
    pub gas_to_token_multiplier: Decimal,
    pub previous_output: Option<bitcoin::OutPoint>,
    pub op_return_data: Option<Vec<u8>>,
    pub node_label: String,
    /// The chain's Bitcoin network — a genesis-fixed constant exposed to
    /// contracts via the `network()` built-in. Defaults to `Regtest` (tests /
    /// lite executor); production paths (reactor, runtime pool) set it from
    /// `config.network`.
    pub network: bitcoin::Network,
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

    /// Built-ins every contract gets (the user-land surface, plus the
    /// types-only `file-registry-types` for cross-contract ABIs).
    fn register_common(linker: &mut Linker<Self>) -> Result<()> {
        kontor::built_in::error::add_to_linker::<_, Self>(linker, |s| s)?;
        kontor::built_in::context::add_to_linker::<_, Self>(linker, |s| s)?;
        kontor::built_in::foreign::add_to_linker::<_, Self>(linker, |s| s)?;
        kontor::built_in::crypto::add_to_linker::<_, Self>(linker, |s| s)?;
        kontor::built_in::numbers::add_to_linker::<_, Self>(linker, |s| s)?;
        kontor::built_in::testing::add_to_linker::<_, Self>(linker, |s| s)?;
        kontor::built_in::file_registry_types::add_to_linker::<_, Self>(linker, |s| s)?;
        Ok(())
    }

    /// Privileged registries — registered only into the native linker, so a
    /// user contract that imports them fails to instantiate.
    fn register_native(linker: &mut Linker<Self>) -> Result<()> {
        kontor::built_in::file_registry::add_to_linker::<_, Self>(linker, |s| s)?;
        kontor::built_in::system::add_to_linker::<_, Self>(linker, |s| s)?;
        kontor::built_in::deposit::add_to_linker::<_, Self>(linker, |s| s)?;
        Ok(())
    }

    pub fn new_linkers(engine: &Engine) -> Result<Linkers> {
        let mut user = Linker::new(engine);
        Self::register_common(&mut user)?;
        let mut native = Linker::new(engine);
        Self::register_common(&mut native)?;
        Self::register_native(&mut native)?;
        Ok(Linkers { user, native })
    }

    pub async fn new(component_cache: ComponentCache, storage: Storage) -> Result<Self> {
        let engine = Self::new_engine()?;
        let linkers = Self::new_linkers(&engine)?;
        Self::new_with(engine, linkers, component_cache, storage).await
    }

    pub async fn new_with(
        engine: Engine,
        linkers: Linkers,
        component_cache: ComponentCache,
        storage: Storage,
    ) -> Result<Self> {
        Ok(Self {
            engine,
            linkers,
            table: Arc::new(Mutex::new(ResourceTable::new())),
            component_cache,
            storage,
            id_generation_counter: Counter::new(),
            result_id_counter: Counter::new(),
            stack: Stack::new(),
            gauge: Some(FuelGauge::new()),
            deposit: DepositMeter::new(),
            gas_limit_for_non_procs: 100_000,
            // The pool overrides this from node config on read-only runtimes; the
            // reactor's consensus runtime leaves it at the default (views never run
            // there). Independent of the system core-call budget.
            view_gas_limit: DEFAULT_VIEW_GAS_LIMIT,
            gas_to_fuel_multiplier: 1_000,
            gas_to_token_multiplier: Decimal::from("1e-9"),
            previous_output: None,
            op_return_data: None,
            node_label: String::new(),
            network: bitcoin::Network::Regtest,
        })
    }

    pub async fn new_read_only(
        engine: Engine,
        linkers: Linkers,
        component_cache: ComponentCache,
        conn: Connection,
    ) -> Result<Self> {
        // Make "read-only" a hard SQLite guarantee, not a convention: this runtime
        // wraps every call in a `BEGIN…COMMIT`, and on a shared WAL DB a view's
        // deferred read snapshot upgrading to a write at commit races the reactor's
        // single writer (SQLITE_BUSY_SNAPSHOT, which the reactor treats as fatal).
        // `query_only` makes the upgrade impossible — a stray write fails locally on
        // this connection instead of contending.
        conn.query("PRAGMA query_only = ON;", ()).await?;
        Runtime::new_with(
            engine,
            linkers,
            component_cache,
            Storage::builder().conn(conn).build(),
        )
        .await
    }

    pub async fn set_context(
        &mut self,
        height: u64,
        tx_context: Option<TransactionContext>,
        previous_output: Option<bitcoin::OutPoint>,
        op_return_data: Option<Vec<u8>>,
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

    pub fn fuel_limit_for_non_procs(&self) -> u64 {
        self.gas_limit_for_non_procs * self.gas_to_fuel_multiplier
    }

    /// Fuel budget for a read-only `/view` call (the operator-configurable cap),
    /// distinct from the fixed consensus core-call budget above.
    pub fn fuel_limit_for_view(&self) -> u64 {
        self.view_gas_limit * self.gas_to_fuel_multiplier
    }

    /// Build a Payment for system (Core-paid) operations.
    pub fn core_payment(&self) -> Payment {
        Payment {
            signer_id: CORE_SIGNER_ID,
            gas_limit: self.gas_limit_for_non_procs,
        }
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

        // Reserve the Core signer row before publishing any contracts. The
        // returned id is asserted equal to CORE_SIGNER_ID inside the query —
        // callers rely on the constant directly rather than reading it back.
        database::queries::create_core_signer(&self.get_storage_conn()).await?;

        // Publish order matches NATIVE_CONTRACTS and determines contract
        // IDs (1-indexed, assigned in iteration order). Adding a contract
        // = appending to the slice; no manual count to maintain.
        let core_signer = Signer::Core(Box::new(Signer::Nobody));
        let payment = self.core_payment();
        // Native contracts ARE reproducibly built — record their provenance from
        // the committed build.json (platform + pinned image) plus the source repo
        // at the node's build commit (CI gates that it reproduces these bytes).
        let provenance = native_provenance()?;
        for (name, bytes) in NATIVE_CONTRACTS {
            self.publish(&core_signer, payment.clone(), name, bytes, &provenance)
                .await?;
        }
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
        payment: Payment,
        name: &str,
        bytes: &[u8],
        // Required for every publish — user ops carry it on the wire; native
        // (core-signed) contracts derive it from the committed build.json.
        provenance: &BuildProvenance,
    ) -> Result<String, ExecutionError> {
        // Already enforced at decode (block::filter_map); re-checked here before
        // touching storage as defense-in-depth (Deterministic on every node).
        provenance
            .validate()
            .map_err(ExecutionError::Deterministic)?;
        // Contract names are embedded in the wire address format
        // `name_height_txindex` — `_` is the separator, so a name containing
        // it mints an ambiguously-parseable address, permanent once published
        // (#308). Enforce kebab-case (lowercase alphanumerics and hyphens)
        // deterministically on every node.
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(ExecutionError::Deterministic(anyhow!(
                "invalid contract name {name:?}: must be non-empty kebab-case ([a-z0-9-])"
            )));
        }
        let address = ContractAddress {
            name: name.to_string(),
            height: self.storage.height,
            tx_index: self
                .tx_context()
                .expect("Transaction context must be set to public contracts")
                .tx_index,
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

        // The op's signer is the publisher and becomes the provenance entry's
        // author — the UpdateProvenance authz anchor. Resolve it before opening
        // the savepoint so an unsupported signer can't leak an open savepoint.
        let author = match signer {
            Signer::Id(id) => id.signer_id(),
            Signer::Core(_) => CORE_SIGNER_ID,
            _ => {
                return Err(ExecutionError::Deterministic(anyhow!(
                    "publishing requires an Id or Core signer"
                )));
            }
        };

        self.storage
            .savepoint()
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        let contract_id = self
            .storage
            .insert_contract(name, bytes)
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        // Seed the append-only provenance log inside the savepoint, so it rolls
        // back with the contract if init fails.
        let encoded = postcard::to_allocvec(provenance)
            .map_err(|e| ExecutionError::NonDeterministic(e.into()))?;
        self.storage
            .insert_contract_provenance(contract_id, author, &encoded)
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        // Publish-time link validation: the contract must resolve all of its
        // imports against the built-in surface it will run under. A user
        // contract that imports a native-only interface (`file-registry` /
        // `system`) is rejected here — deterministically, before `init`
        // runs and before any state is committed. `instantiate_pre` is a pure
        // function of (component, linker), identical on every node, so its
        // failure is a Deterministic rejection (roll back and continue), never
        // a node shutdown. The linker itself is the allowlist, so there is no
        // separate interface list to keep in sync.
        let result = match self.validate_publishable(contract_id).await {
            Ok(()) => {
                self.execute(Some(signer), Some(payment), &address, "init()")
                    .await
            }
            Err(e) => Err(e),
        };
        if result.is_err() {
            self.storage
                .rollback()
                .await
                .map_err(ExecutionError::NonDeterministic)?;
            // The contract row is gone and SQLite may hand this id to a later
            // publish with different bytes. Drop the component we compiled and
            // cached during validation/init so `load_component` can't serve stale
            // WASM for whatever contract reuses the id.
            self.component_cache.invalidate(contract_id).await;
            result
        } else {
            self.storage
                .commit()
                .await
                .map_err(ExecutionError::NonDeterministic)?;
            Ok(to_wave_expr(address.clone()))
        }
    }

    /// Append a new claim to a contract's append-only provenance log. Authorized
    /// by the contract's publisher (`signer_id`). The gas charge + result row
    /// come from the `system.provenance-updated` call in the executor; this does
    /// the deterministic authz check and the host-side append. All checks are
    /// pure functions of the op + committed state, so they reject identically on
    /// every node (`Deterministic`).
    pub async fn update_provenance(
        &mut self,
        caller_signer_id: u64,
        contract: &ContractAddress,
        provenance: &BuildProvenance,
    ) -> Result<(), ExecutionError> {
        // Already enforced at decode (block::filter_map); re-checked as
        // defense-in-depth.
        provenance
            .validate()
            .map_err(ExecutionError::Deterministic)?;
        let contract_id = self
            .storage
            .contract_id(contract)
            .await
            .map_err(ExecutionError::NonDeterministic)?
            .ok_or_else(|| ExecutionError::Deterministic(anyhow!("contract not found")))?;
        // Authz: only the publisher (author of the first provenance entry) may
        // append. NOT contracts.signer_id, which is the contract's own signer.
        let publisher = self
            .storage
            .contract_provenance_publisher(contract_id)
            .await
            .map_err(ExecutionError::NonDeterministic)?
            .ok_or_else(|| {
                ExecutionError::Deterministic(anyhow!("contract has no provenance log"))
            })?;
        if publisher != caller_signer_id {
            return Err(ExecutionError::Deterministic(anyhow!(
                "only the contract's publisher can update its provenance"
            )));
        }
        let encoded = postcard::to_allocvec(provenance)
            .map_err(|e| ExecutionError::NonDeterministic(e.into()))?;
        self.storage
            .insert_contract_provenance(contract_id, caller_signer_id, &encoded)
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        Ok(())
    }

    /// Deterministic publish-time validation. All checks are pure functions of
    /// the contract bytes (and fixed code), so they reject identically on every
    /// node — `Deterministic`, never a shutdown.
    ///
    /// 1. **Link check** (all contracts): the component's imports must resolve
    ///    against the linker it will run under (native for ids
    ///    1..=NATIVE_CONTRACTS.len(), the restricted user linker otherwise).
    ///    Catches a user contract reaching for `file-registry`/`system`.
    /// 2. **WIT rule check** (user contracts only): the extracted WIT must
    ///    satisfy the Kontor rules the linker can't see — `init` exists with the
    ///    right shape, exports are `async`, valid context/return types, no
    ///    floats/flags/nested-lists/cycles, etc. Native contracts use the
    ///    privileged surface (core-context, file-registry) and are validated at
    ///    compile time, so the user-surface validator is skipped for them.
    async fn validate_publishable(&self, contract_id: u64) -> Result<(), ExecutionError> {
        // Compile + cache the component once here; `init` and every later call
        // reuse the cached artifact. We keep the encoded `bytes` so the WIT check
        // below decodes from them instead of recomputing them.
        let (bytes, component) = self
            .component_bytes_and_compiled(contract_id)
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        let linker = if is_native_contract_id(contract_id) {
            &self.linkers.native
        } else {
            &self.linkers.user
        };
        linker.instantiate_pre(&component).map_err(|e| {
            ExecutionError::Deterministic(anyhow!(
                "contract imports an interface it is not permitted to use: {e:#}"
            ))
        })?;

        if !is_native_contract_id(contract_id) {
            let wit = print_component_wit(&bytes).map_err(ExecutionError::NonDeterministic)?;
            Self::validate_user_wit(&wit)?;
        }
        Ok(())
    }

    /// Run the Kontor WIT rules over a user contract's extracted WIT (validated
    /// against the user-land built-in surface). A rule violation — missing
    /// `init`, sync export, bad context/return type, floats, etc. — is a
    /// Deterministic rejection. Pure function of the WIT string.
    fn validate_user_wit(wit: &str) -> Result<(), ExecutionError> {
        match WitValidator::validate_str(wit) {
            Ok((result, resolve)) if result.has_errors() => {
                let detail: Vec<String> =
                    result.errors.iter().map(|e| e.render(&resolve)).collect();
                Err(ExecutionError::Deterministic(anyhow!(
                    "contract WIT failed validation: {}",
                    detail.join("; ")
                )))
            }
            Ok(_) => Ok(()),
            Err(e) => Err(ExecutionError::Deterministic(anyhow!(
                "contract WIT could not be parsed: {}",
                e.message
            ))),
        }
    }

    pub async fn issuance(&mut self, signer: &Signer) -> Result<(), ExecutionError> {
        // `Issuance` is a gas-free faucet mint — a dev/test bootstrap
        // convenience. It must never mint on mainnet, where the only intended
        // mint path is protocol emissions; an ungated faucet falsifies the
        // supply schedule. Reject deterministically (same `network()` gate the
        // token's dev-mint uses), so every node agrees and no supply is created.
        if self.network == bitcoin::Network::Bitcoin {
            return Err(ExecutionError::Deterministic(anyhow!(
                "Issuance faucet is disabled on mainnet"
            )));
        }
        let result = token::api::issuance(
            self,
            &Signer::Core(Box::new(signer.clone())),
            10u64.try_into().expect("u64 to decimal"),
        )
        .await;
        result?.expect("issuance(10) should never fail");
        Ok(())
    }

    /// True when the *top* of the cross-contract call stack is a view
    /// frame — i.e. we're currently executing a `ViewContext` function
    /// (possibly nested under any number of outer proc / view frames).
    /// An empty stack means no contract is executing: a system caller
    /// (reactor, aggregate verifier, block-processing path) that's
    /// allowed to mutate state. So empty = NOT view.
    ///
    /// Host functions that have DB-mutating side effects gate on this:
    /// see `get_or_create_identity` below — inside a view frame it
    /// degrades to a lookup-only path and returns `Err` on miss
    /// rather than silently creating signer rows during a read-only
    /// API query.
    pub async fn is_in_view_context(&self) -> bool {
        match self.stack.peek().await {
            Some(frame) => !frame.is_proc,
            None => false,
        }
    }

    pub async fn get_or_create_identity(
        &self,
        x_only_pubkey: &str,
    ) -> Result<database::types::Identity, ExecutionError> {
        let conn = self.get_storage_conn();
        if self.is_in_view_context().await {
            return database::queries::get_identity(&conn, x_only_pubkey)
                .await
                .map_err(|e| ExecutionError::NonDeterministic(e.into()))?
                .ok_or_else(|| {
                    ExecutionError::Deterministic(anyhow!(
                        "signer not found for x-only-pubkey {x_only_pubkey} \
                         (view context — signer creation requires a proc context)"
                    ))
                });
        }
        let height = self.storage.height;
        database::queries::ensure_identity(&conn, x_only_pubkey, height)
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

    /// Host-side entry point used by macro-generated native-contract api
    /// wrappers (`token::api::*`, `system::api::*`, etc.). Derives a
    /// `Payment` from the caller's `signer` at the non-procs gas budget.
    ///
    /// For system-internal callers, `signer` is `Signer::Core(...)` and the
    /// `is_core()` bypass in `prepare_call` skips the hold regardless of
    /// `payment.signer_id`. For user-driven calls from tests, `signer` is the
    /// user and `payment.signer_id` resolves to their id so the hold charges
    /// the right account.
    pub async fn execute_api(
        &mut self,
        signer: Option<&Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String, ExecutionError> {
        let payment = signer.and_then(|s| s.signer_id()).map(|id| Payment {
            signer_id: id,
            gas_limit: self.gas_limit_for_non_procs,
        });
        self.execute(signer, payment, contract_address, expr).await
    }

    pub async fn execute(
        &mut self,
        signer: Option<&Signer>,
        payment: Option<Payment>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String, ExecutionError> {
        tracing::info!(
            "Executing contract {} with expr {} with tx context {:?}",
            contract_address,
            expr,
            self.tx_context()
        );
        let PreparedCall {
            store,
            contract_id,
            func_name,
            is_fallback,
            params,
            results,
            func,
            is_proc,
            fuel_limit: starting_fuel,
            ctx,
        } = self
            .prepare_call(contract_address, signer, payment.as_ref(), expr, None)
            .await?;
        OptionFuture::from(
            self.gauge
                .as_ref()
                .map(|g| g.set_starting_fuel(starting_fuel)),
        )
        .await;
        let (mut result, mut store) = self
            .call_and_handle(store, func, params, results, is_fallback, ctx)
            .await?;
        OptionFuture::from(
            self.gauge
                .as_ref()
                .map(|g| g.set_ending_fuel(store.get_fuel().unwrap())),
        )
        .await;
        if is_proc {
            let signer = signer.expect("Signer should be available in proc");
            let payment = payment.expect("Payment should be available in proc");
            result = self
                .handle_procedure(
                    signer,
                    Some(&payment),
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

    /// Fetch + JIT-compile the component and cache the compiled artifact,
    /// returning the encoded `bytes` too so a caller that also needs the embedded
    /// WIT pays the decompress/encode/compile exactly once. The bytes are not
    /// cached — only the compiled `Component`.
    async fn component_bytes_and_compiled(&self, contract_id: u64) -> Result<(Vec<u8>, Component)> {
        let bytes = self.storage.component_bytes(contract_id).await?;
        let component = Component::from_binary(&self.engine, &bytes)?;
        self.component_cache
            .put(contract_id, component.clone(), bytes.len())
            .await;
        Ok((bytes, component))
    }

    pub async fn load_component(&self, contract_id: u64) -> Result<Component> {
        Ok(match self.component_cache.get(&contract_id).await {
            Some(component) => component,
            None => self.component_bytes_and_compiled(contract_id).await?.1,
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

#[cfg(test)]
mod tests {
    use crate::database::queries::exists_contract_state;
    use crate::runtime::token;
    use crate::runtime::wit::resources::ViewContext;
    use crate::test_utils::{test_runtime, test_runtime_with_network};
    use stdlib::KeyElement;

    /// The `Issuance` faucet mint is a dev/test convenience — it must be
    /// rejected deterministically on mainnet, where the only intended mint is
    /// protocol emissions; an ungated faucet falsifies the supply schedule.
    #[tokio::test]
    async fn issuance_faucet_rejected_on_mainnet() {
        let (mut runtime, _dir, _name) = test_runtime_with_network(bitcoin::Network::Bitcoin)
            .await
            .expect("mainnet test runtime");
        let signer = super::Signer::Core(Box::new(super::Signer::Nobody));
        let err = runtime
            .issuance(&signer)
            .await
            .expect_err("issuance must be rejected on mainnet");
        assert!(
            matches!(err, super::ExecutionError::Deterministic(_)),
            "mainnet issuance must reject deterministically, got: {err:?}"
        );

        // Same call succeeds on a dev network (regtest) — the gate is
        // network-conditioned, not a blanket disable.
        let (mut dev, _dir2, _name2) = test_runtime().await.expect("regtest test runtime");
        dev.issuance(&signer)
            .await
            .expect("issuance must succeed on a dev network");
    }

    /// `_` is the ContractAddress wire separator — a name containing it mints
    /// an ambiguously-parseable address, permanent once published (#308). The
    /// gate must reject deterministically, before any storage is touched.
    #[tokio::test]
    async fn publish_rejects_non_kebab_contract_names() {
        let (mut runtime, _dir, _name) = test_runtime().await.expect("test runtime");
        runtime
            .set_context(
                1,
                Some(super::TransactionContext::builder().build()),
                None,
                None,
            )
            .await;
        let signer = super::Signer::Core(Box::new(super::Signer::Nobody));
        let payment = runtime.core_payment();
        let provenance = super::native_provenance().expect("provenance");
        for bad in ["counter_v2", "Counter", "has space", ""] {
            let err = runtime
                .publish(&signer, payment.clone(), bad, b"", &provenance)
                .await
                .expect_err("bad name must be rejected");
            assert!(
                matches!(err, super::ExecutionError::Deterministic(_)),
                "{bad:?} must reject deterministically, got: {err:?}"
            );
        }
        // The gate must not over-reject legitimate kebab names: this one only
        // fails later, at wasm decode — proving it passed the name check.
        let err = runtime
            .publish(&signer, payment, "valid-name-0", b"", &provenance)
            .await
            .expect_err("empty bytes cannot compile");
        assert!(
            !format!("{err:?}").contains("invalid contract name"),
            "kebab name must pass the gate: {err:?}"
        );
    }

    /// Context resources are drained from the shared `ResourceTable` when a
    /// call settles (#434): the table outlives the per-call stores, so a leak
    /// here accumulates for the runtime's whole life — and the reactor's
    /// runtime is never recycled. Freed table slots are reused, so probes
    /// pushed before and after a burst of calls must land on the same rep;
    /// before the drain, every call leaked one context entry and the second
    /// probe's rep grew by the call count.
    #[tokio::test]
    async fn call_context_resources_are_drained() {
        let (mut runtime, _dir, _name) = test_runtime().await.expect("test runtime");

        let probe = {
            let mut table = runtime.table.lock().await;
            let res = table.push(ViewContext { contract_id: 1 }).expect("push");
            let rep = res.rep();
            table.delete(res).expect("delete probe");
            rep
        };

        for _ in 0..5 {
            runtime
                .execute(None, None, &token::address(), "total-supply()")
                .await
                .expect("view call");
        }

        let probe_after = {
            let mut table = runtime.table.lock().await;
            let res = table.push(ViewContext { contract_id: 1 }).expect("push");
            let rep = res.rep();
            table.delete(res).expect("delete probe");
            rep
        };

        assert_eq!(
            probe_after, probe,
            "call context resources must be drained — a growing rep means the table leaks one entry per call"
        );
    }

    /// The structural security boundary: filestorage's component imports the
    /// native-only `file-registry` interface, so it links against the native
    /// linker but is *rejected* by the user linker. This is what stops a
    /// user-published contract from reaching the privileged registries.
    ///
    /// The rejection happens at `instantiate_pre` — import resolution, a pure
    /// function of (component, linker) and thus identical on every node. That is
    /// why `prepare_call` classifies it `ExecutionError::Deterministic` (reject
    /// the op and continue) rather than `NonDeterministic` (which shuts the node
    /// down). A misclassification here would let one publish tx halt the network.
    #[tokio::test]
    async fn user_linker_rejects_native_system_imports() {
        let (runtime, _dir, _name) = test_runtime().await.expect("test runtime");
        // filestorage = native contract id 2; its WIT imports `file-registry`.
        let component = runtime
            .load_component(2)
            .await
            .expect("load filestorage component");

        // Native linker resolves the file-registry imports.
        runtime
            .linkers
            .native
            .instantiate_pre(&component)
            .expect("native linker must satisfy file-registry imports");

        // User linker does NOT provide file-registry → fails at import
        // resolution (the deterministic phase), so prepare_call rejects the op
        // deterministically instead of crashing.
        assert!(
            runtime.linkers.user.instantiate_pre(&component).is_err(),
            "user linker must reject a component importing native-only file-registry"
        );

        // The token (native id 1) imports the native-only `deposit` interface (for
        // `storage-floor`), so it too is native-linker-only — a user contract cannot
        // reach `storage-floor` directly; it must call the token's `floor` view.
        let token = runtime
            .load_component(1)
            .await
            .expect("load token component");
        runtime
            .linkers
            .native
            .instantiate_pre(&token)
            .expect("native linker must satisfy the token's deposit import");
        assert!(
            runtime.linkers.user.instantiate_pre(&token).is_err(),
            "user linker must reject the token: it imports native-only `deposit`"
        );
    }

    /// Publish-time enforcement, end-to-end: a user-published contract (id past
    /// the native range) whose component imports a native-only interface is
    /// rejected DETERMINISTICALLY by `validate_publishable` — not stored,
    /// not a node shutdown. We reuse filestorage's bytes (which import
    /// `file-registry`) and insert them as a user contract.
    #[tokio::test]
    async fn publish_rejects_user_contract_importing_native_interface() {
        use crate::database::native_contracts::{FILESTORAGE, NATIVE_CONTRACTS};

        let (mut runtime, _dir, _name) = test_runtime().await.expect("test runtime");
        // Block 0 exists (genesis); the next contract id is past the native
        // range, so it resolves to the restricted user linker.
        runtime
            .set_context(
                0,
                Some(super::TransactionContext::builder().build()),
                None,
                None,
            )
            .await;
        let contract_id = runtime
            .storage
            .insert_contract("evil", FILESTORAGE)
            .await
            .expect("insert contract");
        assert!(
            contract_id > NATIVE_CONTRACTS.len() as u64,
            "expected a user-range id, got {contract_id}"
        );

        let err = runtime
            .validate_publishable(contract_id)
            .await
            .expect_err("user contract importing file-registry must be rejected");
        assert!(
            matches!(err, super::ExecutionError::Deterministic(_)),
            "rejection must be Deterministic (graceful reject), not NonDeterministic (shutdown): {err}"
        );
    }

    /// A user contract that *links* fine but violates a Kontor WIT rule (here,
    /// no `init`) must still be rejected at publish — and DETERMINISTICALLY. This
    /// exercises the WIT-rule branch of `validate_publishable`, which the link
    /// check alone can't catch. The WIT is in the printed-component shape the
    /// publish path actually validates.
    #[test]
    fn publish_wit_validation_rejects_rule_violation() {
        let wit = "package root:component;\n\
            world root {\n\
              include kontor:built-in/built-in;\n\
              use kontor:built-in/context.{view-context};\n\
              export get-value: async func(ctx: borrow<view-context>) -> string;\n\
            }\n";
        let err = super::Runtime::validate_user_wit(wit)
            .expect_err("a contract with no init must be rejected");
        assert!(
            matches!(err, super::ExecutionError::Deterministic(_)),
            "WIT rule violation must be Deterministic, got: {err}"
        );
        assert!(
            err.to_string().contains("init"),
            "error should point at the missing init: {err}"
        );
    }

    /// A failed publish must not leave its compiled component in the cache: the
    /// contract id is rolled back and SQLite can reuse it for a different
    /// contract, which would then be served stale WASM by `load_component`.
    #[tokio::test]
    async fn failed_publish_evicts_component_cache() {
        use crate::database::native_contracts::{FILESTORAGE, NATIVE_CONTRACTS};

        let (mut runtime, _dir, _name) = test_runtime().await.expect("test runtime");
        runtime
            .set_context(
                0,
                Some(super::TransactionContext::builder().build()),
                None,
                None,
            )
            .await;
        // The first user id — what this failed publish gets and then frees.
        let reused_id = NATIVE_CONTRACTS.len() as u64 + 1;

        // filestorage imports `file-registry`; published as a user contract it is
        // rejected at the link check and rolled back. (Signer is irrelevant — the
        // rejection is by contract id, before `init`.)
        let signer = super::Signer::Core(Box::new(super::Signer::Nobody));
        let payment = runtime.core_payment();
        let provenance = super::native_provenance().unwrap();
        let result = runtime
            .publish(&signer, payment, "evil", FILESTORAGE, &provenance)
            .await;
        assert!(
            result.is_err(),
            "publish of a file-registry-importing user contract must fail"
        );

        assert!(
            runtime.component_cache.get(&reused_id).await.is_none(),
            "failed publish must evict the cached component for its rolled-back id"
        );
    }

    /// `clear()` (used on reorg) must make subsequent `get`s miss, so reused ids
    /// recompile from fresh bytes. Guards the moka `invalidate_all` semantics.
    #[tokio::test]
    async fn cache_clear_drops_entries() {
        let (runtime, _dir, _name) = test_runtime().await.expect("test runtime");
        // token = native id 1; populate the cache.
        runtime.load_component(1).await.expect("load token");
        assert!(runtime.component_cache.get(&1).await.is_some());

        runtime.component_cache.clear();
        assert!(
            runtime.component_cache.get(&1).await.is_none(),
            "clear() must drop cached components"
        );
    }

    /// Golden on-disk format: after publishing the native contracts, a structural
    /// field name lands in `contract_state` as an INTERNED dict-ref, not its UTF-8
    /// string. `TokenStorage` declares `ledger` (id 0), `total_supply` (id 1),
    /// `dev_mint_enabled` (id 2); `init` writes `dev_mint_enabled`, so it must live
    /// at the single-element interned path `[TAG_DICT=0x06, id=0x02]` — and the
    /// pre-interning string-element path must be absent. Pins the format so an
    /// accidental encoding change (which would silently fork consensus across
    /// versions) trips here. token = native contract id 1.
    #[tokio::test]
    async fn golden_field_names_are_interned_in_contract_state() {
        let (runtime, _dir, _name) = test_runtime().await.expect("test runtime");
        let conn = &runtime.storage.conn;
        let token_id = 1;

        // The interned path: one dict-ref element, tag 0x06 + field id 0x02.
        let interned = [0x06u8, 0x02];
        assert!(
            exists_contract_state(conn, token_id, &interned)
                .await
                .unwrap(),
            "dev_mint_enabled must be stored at interned path [0x06, 0x02]"
        );

        // The pre-interning encoding — the field name as a string element — must
        // NOT appear, proving the macro emits a dict-ref rather than the string.
        let string_path = "dev_mint_enabled".to_string().encode();
        assert!(
            !exists_contract_state(conn, token_id, &string_path)
                .await
                .unwrap(),
            "a field-name string element must not appear in contract_state"
        );

        // It reads back as the value init wrote (regtest ⇒ dev mint enabled).
        let raw = runtime
            .storage
            .get(1_000_000, token_id, &interned)
            .await
            .unwrap()
            .expect("dev_mint_enabled value present");
        let val: bool = indexer_types::deserialize(&raw).unwrap();
        assert!(val, "dev_mint_enabled is true on regtest");
    }
}
