#[cfg(test)]
mod conversion_probe;
#[cfg(test)]
mod costs;
#[cfg(test)]
mod genesis_parity;
extern crate alloc;

mod component_cache;
mod component_policy;
pub mod counter;
pub mod deposit;
pub mod filestorage;
pub mod fuel;
pub mod nft;
pub mod numerics;
pub mod pool;
pub mod pricing;
#[cfg(test)]
mod resource_diagnostics;
#[cfg(test)]
mod sequential_tests;
pub(crate) mod stack;
pub mod staking;
mod storage;
mod storage_host;
pub mod system;
pub mod token;
mod types;
pub mod wit;
#[cfg(test)]
pub(crate) mod workload_telemetry;

mod call;
mod guest_memory;
mod host_context;
mod host_files;
mod host_numbers;
mod host_storage;
mod host_system;
mod invocation;
mod lowering;
pub mod ownership;
mod selected;

use crate::protocol::coordinator::selection::{ExecutionSelection, ExecutorVersion};
use bitcoin::XOnlyPublicKey;
pub(crate) use call::CallOutcome;
pub use component_cache::ComponentCache;
pub(crate) use component_cache::ComponentSource;
pub(crate) use guest_memory::GuestMemoryLimitExceeded;
use guest_memory::{GuestMemoryLimiter, GuestMemoryLimits};
use invocation::{InvocationBudget, InvocationLimitReached, InvocationStore, MAX_LIVE_INVOCATIONS};
#[cfg(test)]
use invocation::{ResourceProbePhase, ResourceProbeRole};
use libsql::Connection;
use lowering::Linker;
#[cfg(test)]
use ownership::AsyncGate;
use ownership::{ChildContext, OwnerService};
use sha2::{Digest, Sha256};
use staking::api::wave::{get_sigma_min_call_expr, get_sigma_min_parse_return_expr};
pub use stdlib::{
    CheckedArithmetics, FromWaveValue, WaveType, from_wave_expr, from_wave_value, to_wave_expr,
    wave_type,
};
#[cfg(test)]
pub(crate) use storage::BlockingGate;
use storage::{ComponentDecodeError, print_component_wit};
pub use storage::{Storage, TransactionContext};
use tokio::sync::Mutex;
#[cfg(test)]
use workload_telemetry::WorkloadTelemetry;

use std::sync::{Arc, Mutex as StdMutex, Weak};

pub use wit::kontor;
pub use wit::kontor::built_in::context_types::ContractAddress;
pub use wit::kontor::built_in::context_types::OutPoint;
pub use wit::kontor::built_in::error::Error;
pub use wit::kontor::built_in::file_registry_types::{
    ChallengeInput, RawFileDescriptor, VerifyResult,
};
pub use wit::kontor::built_in::numbers_types::{
    Decimal, Integer, Ordering as NumericOrdering, Sign as NumericSign,
};

use anyhow::{Result, anyhow};
use std::str::FromStr;
use wasmtime::{
    Engine, Store,
    component::{Component, HasData, ResourceTable},
};

use indexer_types::{BuildProvenance, Payment};
use wit_validator::Validator as WitValidator;

use crate::bls::RegistrationProof;
use crate::config::DEFAULT_VIEW_GAS_LIMIT;
use crate::database::types::{CORE_SIGNER_ID, Identity};
use crate::protocol::v1::engine;
pub use crate::protocol::v1::errors::ExecutionError;
pub(crate) use crate::protocol::v1::gas::MAX_UNTRUSTED_GAS_LIMIT;
use crate::protocol::v1::gas::{DEFAULT_NON_PROC_GAS_LIMIT, GAS_TO_FUEL_MULTIPLIER};
use crate::protocol::v1::native::{NATIVE_CONTRACTS, is_native_contract_id, native_provenance};
use crate::runtime::{
    counter::Counter,
    deposit::DepositMeter,
    fuel::{FuelGauge, UsageKind},
    pricing::Pricing,
    stack::{CallFrame, Stack},
    wit::Signer,
};

#[derive(Clone, Debug)]
pub struct GenesisParameters {
    pub sigma_min: Decimal,
    pub validators: Vec<GenesisValidator>,
}

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

pub fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.into()
}

// RawFileDescriptor's PartialEq/Eq moved to `built-in-types` (the crate that
// owns the type) — the exact relocation this consolidation exists for.

/// The two host capability surfaces over a single `Runtime`. `user` registers
/// only the common built-ins; `native` additionally registers the privileged
/// interfaces (`file-registry`, `system`, `deposit`). Both share the same `Runtime`
/// host state — they differ only in which interfaces a component can import.
/// `invoke` selects one per contract by native contract id. Share this immutable
/// pair through `Arc`: cloning a Wasmtime linker copies its definition registry.
///
/// New imports use the metered registration boundary without handler-side charges:
/// ```
/// use indexer::runtime::Runtime;
/// use std::sync::Arc;
/// # fn main() -> anyhow::Result<()> {
/// let engine = Runtime::new_engine()?;
/// let mut linkers = Runtime::new_linkers(&engine)?;
/// Arc::get_mut(&mut linkers).unwrap().user.root()
///     .func_wrap("extra-bytes", |_, (): ()| Ok((vec![0_u8; 8],)))?;
/// # Ok(())
/// # }
/// ```
/// An unpriced output shape fails registration at compile time:
/// ```compile_fail
/// use indexer::runtime::Runtime;
/// use std::sync::Arc;
/// # fn main() -> anyhow::Result<()> {
/// let engine = Runtime::new_engine()?;
/// let mut linkers = Runtime::new_linkers(&engine)?;
/// Arc::get_mut(&mut linkers).unwrap().user.root()
///     .func_wrap("unpriced-strings", |_, (): ()| Ok((vec![String::new()],)))?;
/// # Ok(())
/// # }
/// ```
/// Helpers requiring Wasmtime's raw mutable linker cannot bypass the boundary:
/// ```compile_fail
/// use indexer::runtime::Runtime;
/// use std::sync::Arc;
/// use wasmtime::component::Linker;
/// fn register_unmetered(_: &mut Linker<Runtime>) {}
/// # fn main() -> anyhow::Result<()> {
/// let engine = Runtime::new_engine()?;
/// let mut linkers = Runtime::new_linkers(&engine)?;
/// register_unmetered(&mut Arc::get_mut(&mut linkers).unwrap().user);
/// # Ok(())
/// # }
/// ```
pub struct Linkers {
    pub user: Linker<Runtime>,
    pub native: Linker<Runtime>,
}

type StoreTableOwners = Arc<StdMutex<Vec<Weak<Mutex<ResourceTable>>>>>;

#[derive(Clone)]
pub struct Runtime {
    pub(crate) engine: Engine,
    executor_version: ExecutorVersion,
    selected_context: Option<Arc<selected::SelectedContext>>,
    pub(crate) linkers: Arc<Linkers>,
    pub(crate) table: Arc<Mutex<ResourceTable>>,
    pub(crate) component_cache: ComponentCache,
    pub(crate) storage: Storage,
    pub(crate) id_generation_counter: Counter,
    pub(crate) result_id_counter: Counter,
    pub(crate) stack: Stack<CallFrame>,
    pub(crate) gauge: Option<FuelGauge>,
    guest_memory_limits: Option<GuestMemoryLimits>,
    guest_memory_limiter: Option<GuestMemoryLimiter>,
    invocation_budget: Option<Arc<InvocationBudget>>,
    store_table_owners: Option<StoreTableOwners>,
    invocation_depth: u32,
    ownership: Option<ChildContext>,
    #[cfg(test)]
    pub(crate) workload_telemetry: Option<Arc<WorkloadTelemetry>>,
    #[cfg(test)]
    resource_probe_phase: Option<ResourceProbePhase>,
    #[cfg(test)]
    conversion_probe: Option<conversion_probe::Probe>,
    #[cfg(test)]
    pub(crate) test_host_error_message: Option<Arc<str>>,
    #[cfg(test)]
    compile_gate: Option<Arc<BlockingGate>>,
    #[cfg(test)]
    init_host_gate: Option<(u64, Arc<AsyncGate>)>,
    pub(crate) usage_kind: UsageKind,
    pub(crate) fuel_checkpoint: u64,
    /// Transient per-op accumulator of the storage-deposit GAS reserved this op
    /// (the returned-at-settle slice that bounds growth). Reset at the top-level op
    /// start, drained at the settle boundary to compute the execution burn
    /// (`burn = gas - charge`).
    pub(crate) deposit: DepositMeter,
    /// Nominal gas limit stamped on system-issued `Payment`s (`core_payment`,
    /// `execute_api`). FIXED — never operator-configurable. Trusted core calls
    /// themselves run unmetered at `SYSTEM_FUEL_CEILING` (decided from the signer in
    /// `invoke`), so this is the Payment's nominal cap, not the core fuel
    /// budget; it still bounds a user-signed `execute_api` call (the test path).
    pub(crate) gas_limit_for_non_procs: u64,
    /// Requested gas budget for public read-only `/view` calls.
    /// Operator-configurable per node (set from `Config::view_gas_limit` on the
    /// read-only pool runtime). The effective budget cannot exceed
    /// `MAX_UNTRUSTED_GAS_LIMIT`; trusted consensus views use system fuel.
    pub(crate) view_gas_limit: u64,
    pub(crate) gas_to_fuel_multiplier: u64,
    pub(crate) pricing: Pricing,
    pub(crate) previous_output: Option<bitcoin::OutPoint>,
    // Host wrappers clone Runtime before their charge; copy payload bytes only
    // in the metered transaction accessor.
    pub(crate) op_return_data: Option<Arc<[u8]>>,
    pub(crate) node_label: String,
    /// The chain's Bitcoin network — a genesis-fixed constant exposed to
    /// contracts via the `network()` built-in. Defaults to `Regtest` (tests /
    /// lite executor); production paths (reactor, runtime pool) set it from
    /// `config.network`.
    pub(crate) network: bitcoin::Network,
    /// Simulation does not populate the shared compile cache. Keep speculative
    /// compilation from evicting canonical hot code; snapshot code identity also
    /// prevents a rolled-back row ID from resolving to a different cached module.
    pub(crate) simulating: bool,
}

impl Runtime {
    pub(crate) fn executor_version(&self) -> ExecutorVersion {
        self.executor_version
    }

    pub fn new_engine() -> Result<Engine> {
        engine::new_engine()
    }

    #[cfg(test)]
    pub(crate) fn new_resource_diagnostic_engine() -> Result<Engine> {
        engine::new_resource_diagnostic_engine()
    }

    #[cfg(test)]
    pub(crate) fn new_previous_memory_reservation_engine() -> Result<Engine> {
        engine::new_previous_memory_reservation_engine()
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

    pub fn new_linkers(engine: &Engine) -> Result<Arc<Linkers>> {
        let mut user = Linker::new(engine);
        Self::register_common(&mut user)?;
        let mut native = Linker::new(engine);
        Self::register_common(&mut native)?;
        Self::register_native(&mut native)?;
        Ok(Arc::new(Linkers { user, native }))
    }

    pub(crate) async fn new(component_cache: ComponentCache, storage: Storage) -> Result<Self> {
        let engine = Self::new_engine()?;
        let linkers = Self::new_linkers(&engine)?;
        Self::new_with(engine, linkers, component_cache, storage).await
    }

    pub(crate) async fn new_with(
        engine: Engine,
        linkers: Arc<Linkers>,
        component_cache: ComponentCache,
        storage: Storage,
    ) -> Result<Self> {
        Ok(Self {
            engine,
            executor_version: ExecutorVersion::LegacyP1,
            selected_context: None,
            linkers,
            table: Arc::new(Mutex::new(ResourceTable::new())),
            component_cache,
            storage,
            id_generation_counter: Counter::new(),
            result_id_counter: Counter::new(),
            stack: Stack::new(),
            // Diagnostic tracing is opt-in; fuel enforcement does not use the gauge.
            gauge: None,
            guest_memory_limits: Some(GuestMemoryLimits::default()),
            guest_memory_limiter: None,
            invocation_budget: None,
            store_table_owners: None,
            invocation_depth: 0,
            ownership: None,
            #[cfg(test)]
            workload_telemetry: None,
            #[cfg(test)]
            resource_probe_phase: None,
            #[cfg(test)]
            conversion_probe: None,
            #[cfg(test)]
            test_host_error_message: None,
            #[cfg(test)]
            compile_gate: None,
            #[cfg(test)]
            init_host_gate: None,
            deposit: DepositMeter::new(),
            usage_kind: UsageKind::System,
            fuel_checkpoint: 0,
            gas_limit_for_non_procs: DEFAULT_NON_PROC_GAS_LIMIT,
            // The pool overrides this from node config; trusted internal views
            // select the system budget independently.
            view_gas_limit: DEFAULT_VIEW_GAS_LIMIT,
            gas_to_fuel_multiplier: GAS_TO_FUEL_MULTIPLIER,
            pricing: Pricing::default(),
            previous_output: None,
            op_return_data: None,
            node_label: String::new(),
            network: bitcoin::Network::Regtest,
            simulating: false,
        })
    }

    pub(crate) async fn new_read_only(
        engine: Engine,
        linkers: Arc<Linkers>,
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

    pub(crate) async fn set_context(
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
        self.op_return_data = op_return_data.map(Arc::from);
    }

    pub(crate) fn tx_context(&self) -> Option<&TransactionContext> {
        self.storage.tx_context.as_ref()
    }

    pub(crate) fn tx_context_mut(&mut self) -> Option<&mut TransactionContext> {
        self.storage.tx_context.as_mut()
    }

    pub(crate) fn get_storage_conn(&self) -> Connection {
        self.storage.conn.clone()
    }

    pub fn fuel_limit_for_non_procs(&self) -> u64 {
        let gas = self.selected_gas_policy();
        gas.non_proc_allowance * gas.fuel_multiplier
    }

    /// Fuel budget for a read-only `/view` call.
    pub fn fuel_limit_for_view(&self) -> Result<u64, ExecutionError> {
        let gas = self.selected_gas_policy();
        gas.view_allowance
            .min(gas.untrusted_allowance)
            .checked_mul(gas.fuel_multiplier)
            .ok_or_else(|| {
                ExecutionError::Deterministic(anyhow!("View gas limit exceeds the fuel range"))
            })
    }

    /// Build a Payment for system (Core-paid) operations.
    pub fn core_payment(&self) -> Payment {
        Payment {
            signer_id: CORE_SIGNER_ID,
            gas_limit: self.selected_gas_policy().non_proc_allowance,
        }
    }

    pub fn gas_consumed(&self, starting_fuel: u64, ending_fuel: u64) -> u64 {
        (starting_fuel - ending_fuel).div_ceil(self.selected_gas_policy().fuel_multiplier)
    }

    pub(crate) async fn publish_native_contracts(
        &mut self,
        genesis: &GenesisParameters,
    ) -> Result<()> {
        self.publish_native_contracts_inner(genesis, None).await
    }

    pub(crate) async fn publish_native_contracts_owned(
        &mut self,
        genesis: &GenesisParameters,
        owner_service: &OwnerService,
    ) -> Result<()> {
        self.publish_native_contracts_inner(genesis, Some(owner_service))
            .await
    }

    async fn publish_native_contracts_inner(
        &mut self,
        genesis: &GenesisParameters,
        owner_service: Option<&OwnerService>,
    ) -> Result<()> {
        self.set_context(0, Some(TransactionContext::builder().build()), None, None)
            .await;
        let bootstrap = self.storage.native_bootstrap_progress().await?;
        self.result_id_counter
            .restore(bootstrap.next_result_index)
            .await;

        // Reserve the Core signer row before publishing any contracts. The
        // returned id is asserted equal to CORE_SIGNER_ID inside the query —
        // callers rely on the constant directly rather than reading it back.
        self.storage.create_core_signer().await?;

        // Publish order matches NATIVE_CONTRACTS and determines contract
        // IDs (1-indexed, assigned in iteration order). Adding a contract
        // = appending to the slice; no manual count to maintain.
        let core_signer = Signer::Core(Box::new(Signer::Nobody));
        let payment = self.core_payment();
        // Genesis provenance is part of the retained protocol, never the node build.
        let provenance = native_provenance()?;
        for (name, bytes) in NATIVE_CONTRACTS {
            let mut lease = if let Some(service) = owner_service {
                Some(service.begin_canonical(self, false).await?)
            } else {
                None
            };
            if lease.is_some() {
                self.storage.savepoint().await?;
            }
            let published = self
                .publish(&core_signer, payment.clone(), name, bytes, &provenance)
                .await;
            if let Some(lease) = lease.as_mut() {
                lease.drain(self).await?;
                if published.is_ok() {
                    self.storage.commit().await?;
                } else {
                    self.storage.rollback().await?;
                }
            }
            if let Some(lease) = lease {
                lease.complete(self).await?;
            }
            published?;
            // Existing genesis rows bypass publication. Validate their stored
            // artifacts before startup can proceed under this engine policy.
            let address = ContractAddress {
                name: name.to_string(),
                height: 0,
                tx_index: 0,
            };
            let contract_id = self
                .storage
                .contract_id(&address)
                .await?
                .ok_or_else(|| anyhow!("native contract missing after publication: {name}"))?;
            let component = self.load_component(contract_id).await?;
            self.linkers.native.instantiate_pre(&component)?;
        }
        // Zero is uninitialized, never a valid configured floor. This also
        // resumes an interrupted bootstrap after the contract was published.
        let mut lease = if let Some(service) = owner_service {
            Some(service.begin_canonical(self, false).await?)
        } else {
            None
        };
        if lease.is_some() {
            self.storage.savepoint().await?;
        }
        let result = self
            .execute_system_view(&staking::address(), &get_sigma_min_call_expr())
            .await;
        if let Some(lease) = lease.as_mut() {
            lease.drain(self).await?;
            self.storage.rollback().await?;
        }
        if let Some(lease) = lease {
            lease.complete(self).await?;
        }
        let result = result?;
        if get_sigma_min_parse_return_expr(&result) == Decimal::default() {
            let mut lease = if let Some(service) = owner_service {
                Some(service.begin_canonical(self, false).await?)
            } else {
                None
            };
            if lease.is_some() {
                self.storage.savepoint().await?;
            }
            let set_result =
                staking::api::set_sigma_min(self, &core_signer, genesis.sigma_min).await;
            if let Some(lease) = lease.as_mut() {
                lease.drain(self).await?;
                if set_result.as_ref().is_ok_and(|result| result.is_ok()) {
                    self.storage.commit().await?;
                } else {
                    self.storage.rollback().await?;
                }
            }
            if let Some(lease) = lease {
                lease.complete(self).await?;
            }
            set_result??;
        }
        if !genesis.validators.is_empty() && !bootstrap.validators_initialized {
            let validators = genesis.validators.iter().cloned().map(Into::into).collect();
            let mut lease = if let Some(service) = owner_service {
                Some(service.begin_canonical(self, false).await?)
            } else {
                None
            };
            if lease.is_some() {
                self.storage.savepoint().await?;
            }
            let set_result = staking::api::set_genesis_set(
                self,
                &Signer::Core(Box::new(Signer::Nobody)),
                validators,
            )
            .await;
            if let Some(lease) = lease.as_mut() {
                lease.drain(self).await?;
                if set_result.is_ok() {
                    self.storage.commit().await?;
                } else {
                    self.storage.rollback().await?;
                }
            }
            if let Some(lease) = lease {
                lease.complete(self).await?;
            }
            set_result?;
        }
        Ok(())
    }

    pub(crate) async fn publish(
        &mut self,
        signer: &Signer,
        payment: Payment,
        name: &str,
        bytes: &[u8],
        // Required for every publish — user ops carry it on the wire; native
        // (core-signed) contracts use the retained genesis provenance.
        provenance: &BuildProvenance,
    ) -> Result<String, ExecutionError> {
        // Already enforced at decode (block::filter_map); re-checked here before
        // touching storage as defense-in-depth (Deterministic on every node).
        provenance
            .validate()
            .map_err(ExecutionError::Deterministic)?;
        let fuel_limit = self.call_fuel_limit(Some(signer), Some(&payment), None)?;
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

        let outcome = if signer.is_core() {
            self.publish_unsettled(
                signer, &payment, &address, author, bytes, provenance, fuel_limit,
            )
            .await?
        } else {
            self.with_payment(&payment, fuel_limit, async |runtime| {
                runtime
                    .publish_unsettled(
                        signer, &payment, &address, author, bytes, provenance, fuel_limit,
                    )
                    .await
            })
            .await?
        };
        outcome.result
    }

    async fn publish_unsettled(
        &mut self,
        signer: &Signer,
        payment: &Payment,
        address: &ContractAddress,
        author: u64,
        bytes: &[u8],
        provenance: &BuildProvenance,
        fuel_limit: u64,
    ) -> Result<CallOutcome, ExecutionError> {
        self.storage
            .savepoint()
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        let mut inserted_id = None;
        let outcome = async {
            let contract_id = self
                .storage
                .insert_contract(&address.name, bytes)
                .await
                .map_err(ExecutionError::NonDeterministic)?;
            inserted_id = Some(contract_id);
            let encoded = postcard::to_allocvec(provenance)
                .map_err(|e| ExecutionError::NonDeterministic(e.into()))?;
            self.storage
                .insert_contract_provenance(contract_id, author, &encoded)
                .await
                .map_err(ExecutionError::NonDeterministic)?;
            if let Err(error) = self.validate_publishable(contract_id).await {
                return Ok(CallOutcome {
                    result: Err(error),
                    remaining_fuel: fuel_limit,
                });
            }
            self.invoke_unsettled(
                address,
                Some(signer),
                Some(payment),
                "init()",
                fuel_limit,
                false,
            )
            .await
        }
        .await;
        if outcome.as_ref().is_ok_and(|outcome| outcome.result.is_ok()) {
            self.storage
                .commit()
                .await
                .map_err(ExecutionError::NonDeterministic)?;
            outcome.map(|outcome| CallOutcome {
                result: Ok(to_wave_expr(address.clone())),
                ..outcome
            })
        } else {
            self.storage
                .rollback()
                .await
                .map_err(ExecutionError::NonDeterministic)?;
            // Rollback may free the id for a different component on the next publish.
            if let Some(contract_id) = inserted_id {
                self.component_cache.invalidate(contract_id).await;
            }
            outcome
        }
    }

    /// Append a new claim to a contract's append-only provenance log. Authorized
    /// by the contract's publisher (`signer_id`). The gas charge + result row
    /// come from the `system.provenance-updated` call in the executor; this does
    /// the deterministic authz check and the host-side append. All checks are
    /// pure functions of the op + committed state, so they reject identically on
    /// every node (`Deterministic`).
    pub(crate) async fn update_provenance(
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
    /// 1. **Component policy** (user contracts): reject stream/future types and
    ///    canonical operations, including inside nested components and types.
    /// 2. **Link check** (all contracts): the component's imports must resolve
    ///    against the linker it will run under (native for ids
    ///    1..=NATIVE_CONTRACTS.len(), the restricted user linker otherwise).
    ///    Catches a user contract reaching for `file-registry`/`system`.
    /// 3. **WIT rule check** (user contracts only): the extracted WIT must
    ///    satisfy the Kontor rules the linker can't see — `init` exists with the
    ///    right shape, exports are synchronous, valid context/return types, no
    ///    floats/flags/nested-lists/cycles, etc. Native contracts use the
    ///    privileged surface (core-context, file-registry) and are validated at
    ///    compile time, so the user-surface validator is skipped for them.
    async fn validate_publishable(&self, contract_id: u64) -> Result<(), ExecutionError> {
        // Compile + cache the component once here; `init` and every later call
        // reuse the cached artifact. We keep the encoded `bytes` so the WIT check
        // below decodes from them instead of recomputing them.
        // Content failures are DETERMINISTIC: decoding is a pure function of the
        // submitted bytes, so every node fails identically — and a NonDeterministic
        // error propagates out of `execute_block` rather than being recorded, which
        // means the whole network exits at the same height. `filter_map` does not
        // inspect Publish bytes, so that is reachable from any Bitcoin transaction.
        // Same reasoning as the `instantiate_pre` check just below.
        //
        // But only the CONTENT half. The read and the task join are this node's own
        // machinery; calling those deterministic would make one node reject a publish
        // its peers accept — the same divergence, silently and in the other direction.
        let stored = self
            .storage
            .stored_component_bytes(contract_id)
            .await
            .map_err(|e| match e {
                ComponentDecodeError::Content(e) => ExecutionError::Deterministic(e),
                ComponentDecodeError::Infrastructure(e) => ExecutionError::NonDeterministic(e),
            })?;
        let source = ComponentSource::new(contract_id, &stored);
        let bytes = self
            .storage
            .decode_stored_component_bytes(stored)
            .await
            .map_err(|e| match e {
                ComponentDecodeError::Content(e) => ExecutionError::Deterministic(
                    e.context("contract bytes are not a valid component"),
                ),
                ComponentDecodeError::Infrastructure(e) => ExecutionError::NonDeterministic(e),
            })?;
        component_policy::validate_no_starts(&bytes).map_err(ExecutionError::Deterministic)?;
        if !is_native_contract_id(contract_id) {
            component_policy::validate(&bytes)?;
        }
        let (bytes, component) =
            self.compile_component_bytes(bytes)
                .await
                .map_err(|e| match e {
                    ComponentDecodeError::Content(e) => ExecutionError::Deterministic(
                        e.context("contract is not a valid wasm component"),
                    ),
                    ComponentDecodeError::Infrastructure(e) => ExecutionError::NonDeterministic(e),
                })?;
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
            // Deterministic for the same reason: a pure function of bytes that already
            // decoded, so a failure here is a property of the contract, not this node.
            let wit = print_component_wit(&bytes).map_err(|e| {
                ExecutionError::Deterministic(e.context("contract WIT could not be read"))
            })?;
            Self::validate_user_wit(&wit)?;
        }
        // Publish can run inside a simulation under an id that rollback reuses.
        if !self.simulating {
            self.component_cache
                .put_selected(source, self.executor_version, component, bytes.len())
                .await
                .map_err(ExecutionError::NonDeterministic)?;
        }
        Ok(())
    }

    /// Run the Kontor WIT rules over a user contract's extracted WIT (validated
    /// against the user-land built-in surface). A rule violation (missing
    /// `init`, async export, bad context/return type, floats, etc.) is a
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

    pub(crate) async fn issuance(&mut self, signer: &Signer) -> Result<(), ExecutionError> {
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
    pub(crate) async fn is_in_view_context(&self) -> bool {
        match self.stack.peek().await {
            Some(frame) => !frame.is_proc,
            None => false,
        }
    }

    pub(crate) async fn get_or_create_identity(
        &self,
        x_only_pubkey: &str,
    ) -> Result<Identity, ExecutionError> {
        if self.is_in_view_context().await {
            return self
                .storage
                .lookup_identity(x_only_pubkey)
                .await
                .map_err(ExecutionError::NonDeterministic)?
                .map(Identity::new)
                .ok_or_else(|| {
                    ExecutionError::Deterministic(anyhow!(
                        "signer not found for x-only-pubkey {x_only_pubkey} \
                         (view context — signer creation requires a proc context)"
                    ))
                });
        }
        self.storage
            .ensure_identity(x_only_pubkey)
            .await
            .map(Identity::new)
            .map_err(|e| ExecutionError::NonDeterministic(e.into()))
    }

    pub(crate) async fn register_bls_key(
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

        let existing_bls = self
            .storage
            .identity_bls_key(identity.signer_id())
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        if let Some(existing) = existing_bls {
            if existing == bls_pubkey {
                return Ok(());
            }
            return Err(ExecutionError::Deterministic(anyhow!(
                "BLS pubkey already registered for signer"
            )));
        }

        let x_only_pubkey = self
            .storage
            .identity_pubkey(identity.signer_id())
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

        self.storage
            .write_identity_bls_key(identity.signer_id(), &proof.bls_pubkey)
            .await
            .map_err(ExecutionError::NonDeterministic)?;

        Ok(())
    }

    /// Host-side entry point used by macro-generated native-contract api
    /// wrappers (`token::api::*`, `system::api::*`, etc.). Derives a
    /// `Payment` from the caller's `signer` at the non-procs gas budget.
    ///
    /// For system-internal callers, `signer` is `Signer::Core(...)` and the
    /// `is_core()` bypass in `invoke` skips the hold regardless of
    /// `payment.signer_id`. For user-driven calls from tests, `signer` is the
    /// user and `payment.signer_id` resolves to their id so the hold charges
    /// the right account.
    pub(crate) async fn execute_api(
        &mut self,
        signer: Option<&Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String, ExecutionError> {
        let payment = signer.and_then(|s| s.signer_id()).map(|id| Payment {
            signer_id: id,
            gas_limit: self.selected_gas_policy().non_proc_allowance,
        });
        self.execute(signer, payment, contract_address, expr).await
    }

    pub(crate) async fn execute_selected_view(
        &mut self,
        selection: &ExecutionSelection,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String, ExecutionError> {
        selection
            .verify_view(&self.storage.conn, self.network, self.executor_version)
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        match selection.version() {
            ExecutorVersion::LegacyP1 => {
                self.bind_selection(selection)
                    .map_err(ExecutionError::NonDeterministic)?
                    .execute(None, None, contract_address, expr)
                    .await
            }
        }
    }

    pub(crate) async fn execute(
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
        self.invoke(contract_address, signer, payment.as_ref(), expr, None)
            .await?
            .result
    }

    /// Compile on a blocking thread: component translation has a deep native
    /// call chain that can exhaust the async execution thread's finite stack.
    async fn compile_component_bytes(
        &self,
        bytes: Vec<u8>,
    ) -> std::result::Result<(Vec<u8>, Component), ComponentDecodeError> {
        let engine = self.engine.clone();
        #[cfg(test)]
        let gate = self.compile_gate.clone();
        let compile = move || {
            #[cfg(test)]
            resource_diagnostics::record("compiler_entry");
            #[cfg(test)]
            if let Some(gate) = gate {
                gate.block();
            }
            let compiled = Component::from_binary(&engine, &bytes);
            #[cfg(test)]
            resource_diagnostics::record("compiler_exit");
            (bytes, compiled)
        };
        let (bytes, compiled) = match &self.ownership {
            Some(owner) => owner.run_blocking(compile).await,
            None => tokio::task::spawn_blocking(compile)
                .await
                .map_err(anyhow::Error::from),
        }
        .map_err(ComponentDecodeError::Infrastructure)?;
        Ok((
            bytes,
            compiled.map_err(|e| ComponentDecodeError::Content(e.into()))?,
        ))
    }

    /// Fetch + JIT-compile the component and cache the compiled artifact,
    /// returning the encoded `bytes` too so a caller that also needs the embedded
    /// WIT pays the decompress/encode/compile exactly once. The bytes are not
    /// cached — only the compiled `Component`.
    async fn component_bytes_and_compiled(
        &self,
        source: ComponentSource,
        stored: Vec<u8>,
    ) -> Result<(Vec<u8>, Component)> {
        let bytes = self
            .storage
            .decode_stored_component_bytes(stored)
            .await
            .map_err(|e| match e {
                ComponentDecodeError::Content(e) | ComponentDecodeError::Infrastructure(e) => e,
            })?;
        component_policy::validate_no_starts(&bytes)?;
        let (bytes, component) =
            self.compile_component_bytes(bytes)
                .await
                .map_err(|e| match e {
                    ComponentDecodeError::Content(e) | ComponentDecodeError::Infrastructure(e) => e,
                })?;
        // Match publication's policy: do not warm shared caches speculatively.
        if !self.simulating {
            self.component_cache
                .put_selected(
                    source,
                    self.executor_version,
                    component.clone(),
                    bytes.len(),
                )
                .await?;
        }
        Ok((bytes, component))
    }

    pub(crate) async fn load_component(&self, contract_id: u64) -> Result<Component> {
        // Resolve code from this root's snapshot before consulting a shared cache.
        // An old view can retain an ID whose newer canonical row contains new code.
        let stored = self
            .storage
            .stored_component_bytes(contract_id)
            .await
            .map_err(|e| match e {
                ComponentDecodeError::Content(e) | ComponentDecodeError::Infrastructure(e) => e,
            })?;
        let source = ComponentSource::new(contract_id, &stored);
        Ok(
            match self
                .component_cache
                .get_selected(source, self.executor_version, &self.engine)
                .await?
            {
                Some(component) => {
                    if !Engine::same(component.engine(), &self.engine) {
                        return Err(anyhow!(
                            "cached component belongs to a different execution engine"
                        ));
                    }
                    component
                }
                None => self.component_bytes_and_compiled(source, stored).await?.1,
            },
        )
    }

    #[cfg(test)]
    pub(crate) async fn cache_component_fixture(
        &self,
        contract_id: u64,
        component: Component,
        size: usize,
    ) -> Result<()> {
        let stored = self
            .storage
            .contract_bytes(contract_id)
            .await?
            .ok_or_else(|| anyhow!("fixture contract missing"))?;
        self.component_cache
            .put_selected(
                ComponentSource::new(contract_id, &stored),
                self.executor_version,
                component,
                size,
            )
            .await
    }

    pub(crate) fn make_store(&self, fuel: u64) -> Result<InvocationStore> {
        self.make_store_inner(
            fuel,
            #[cfg(test)]
            ResourceProbeRole::Unassigned,
        )
    }

    #[cfg(test)]
    fn make_store_for_call(&self, fuel: u64, address: &ContractAddress) -> Result<InvocationStore> {
        let role = self
            .resource_probe_phase
            .as_ref()
            .map_or(ResourceProbeRole::Unassigned, |phase| {
                phase.classify(address)
            });
        self.make_store_inner(fuel, role)
    }

    #[cfg(test)]
    fn record_resource_rejection(&self, address: &ContractAddress, kind: &str) {
        if let Some(budget) = &self.invocation_budget {
            let role = self
                .resource_probe_phase
                .as_ref()
                .map_or(ResourceProbeRole::Unassigned, |phase| {
                    phase.classify(address)
                });
            budget.record_rejection(role, kind);
        }
    }

    fn make_store_inner(
        &self,
        fuel: u64,
        #[cfg(test)] role: ResourceProbeRole,
    ) -> Result<InvocationStore> {
        self.verify_selected_runtime()?;
        let depth = self
            .invocation_depth
            .checked_add(1)
            .ok_or(InvocationLimitReached)?;
        if depth > MAX_LIVE_INVOCATIONS {
            return Err(InvocationLimitReached.into());
        }
        let budget = self
            .invocation_budget
            .clone()
            .unwrap_or_else(|| Arc::new(InvocationBudget::default()));
        #[cfg(test)]
        let lease = budget.reserve_for_role(role)?;
        #[cfg(not(test))]
        let lease = budget.reserve()?;
        // A child receives signer values and WAVE arguments, never parent handles.
        // Invocation ownership frees even resources abandoned by a guest trap.
        let mut runtime = self.clone();
        runtime.invocation_budget = Some(budget);
        runtime.invocation_depth = depth;
        let table = Arc::new(Mutex::new(ResourceTable::new()));
        if let Some(owners) = &self.store_table_owners {
            let mut owners = owners.lock().expect("store table tracker poisoned");
            owners.retain(|owner| owner.strong_count() != 0);
            owners.push(Arc::downgrade(&table));
        }
        runtime.table = table;
        runtime.guest_memory_limiter =
            match (&self.guest_memory_limiter, self.selected_memory_limits()) {
                (Some(parent), _) => Some(parent.new_child()),
                (None, Some(limits)) => Some(GuestMemoryLimiter::new_root(limits)),
                (None, None) => None,
            };
        let mut s = InvocationStore::new(Store::new(&self.engine, runtime), lease);
        if s.data().guest_memory_limiter.is_some() {
            s.limiter(|runtime| runtime.guest_memory_limiter.as_mut().unwrap());
        }
        if let Err(error) = s.set_fuel(fuel) {
            #[cfg(test)]
            s.record_initialization_failure();
            return Err(error.into());
        }
        if let Some(interval) = self
            .ownership
            .as_ref()
            .and_then(ChildContext::fuel_yield_interval)
            && let Err(error) = s.fuel_async_yield_interval(Some(interval))
        {
            #[cfg(test)]
            s.record_initialization_failure();
            return Err(error.into());
        }
        s.set_hostcall_fuel_enabled(false);
        s.data_mut().fuel_checkpoint = fuel;
        #[cfg(test)]
        if let Some(probe) = s.data().conversion_probe.clone() {
            probe.install(&mut s);
        }
        Ok(s)
    }
}

impl HasData for Runtime {
    type Data<'a> = &'a mut Runtime;
}

#[cfg(test)]
mod tests {
    use crate::database::native_contracts::FILESTORAGE;
    use crate::database::queries::exists_contract_state;
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

    /// The structural security boundary: filestorage's component imports the
    /// native-only `file-registry` interface, so it links against the native
    /// linker but is *rejected* by the user linker. This is what stops a
    /// user-published contract from reaching the privileged registries.
    ///
    /// The rejection happens at `instantiate_pre` — import resolution, a pure
    /// function of (component, linker) and thus identical on every node. That is
    /// why `invoke` classifies it `ExecutionError::Deterministic` (reject
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
        // resolution (the deterministic phase), so invocation preparation rejects the op
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

    /// Bytes that are not a decodable component must be rejected DETERMINISTICALLY.
    ///
    /// This one is a chain-halt guard, not a nicety. `filter_map` does not inspect
    /// Publish bytes, so a malformed payload reaches execution from an ordinary
    /// Bitcoin transaction — no API access needed. Classified NonDeterministic it
    /// propagates out of `execute_block` instead of being recorded as an op failure,
    /// and because the payload is deterministic content EVERY node reaches the same
    /// conclusion at the same height and exits together.
    #[tokio::test]
    async fn publish_rejects_undecodable_bytes_deterministically() {
        let (mut runtime, _dir, _name) = test_runtime().await.expect("test runtime");
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
            .insert_contract("garbage", &[0xFFu8; 64])
            .await
            .expect("insert contract");

        let err = runtime
            .validate_publishable(contract_id)
            .await
            .expect_err("undecodable bytes must be rejected");
        assert!(
            matches!(err, super::ExecutionError::Deterministic(_)),
            "rejection must be Deterministic (recorded op failure), not NonDeterministic \
             (every node exits at this height): {err}"
        );
    }

    /// The other half of the same classification: this node failing to READ the bytes
    /// is NOT the contract's fault, and must stay NonDeterministic. Recording it as a
    /// rejection would make one node refuse a publish its peers accept — the same
    /// divergence as the halt, silently and in the other direction.
    #[tokio::test]
    async fn publish_read_failure_stays_non_deterministic() {
        let (mut runtime, _dir, _name) = test_runtime().await.expect("test runtime");
        runtime
            .set_context(
                0,
                Some(super::TransactionContext::builder().build()),
                None,
                None,
            )
            .await;

        // No contract row at this id — stands in for any failure to obtain the bytes.
        let err = runtime
            .validate_publishable(9_999_999)
            .await
            .expect_err("a missing contract must not validate");
        assert!(
            matches!(err, super::ExecutionError::NonDeterministic(_)),
            "failing to read the bytes is this node's problem, so it must propagate \
             rather than be recorded as a deterministic rejection: {err}"
        );
    }

    /// The same guard through the door an ordinary Bitcoin transaction actually
    /// comes in by. The two tests above pin `validate_publishable` in isolation,
    /// which leaves the classification free to be re-wrapped anywhere between
    /// `publish` and it — and `publish` does not simply forward: it validates
    /// provenance and the name, inserts the contract row, and on failure rolls
    /// that row back and evicts the cache. Any of those could reclassify.
    ///
    /// `execute_op` records a `Deterministic` publish failure and continues, but
    /// returns `Err` for `NonDeterministic`, which propagates out of
    /// `execute_block` and exits the node. Since the payload is deterministic
    /// content every node reaches that point together, so the wrong class here is
    /// a whole-network halt costing one Bitcoin fee to trigger.
    #[tokio::test]
    async fn malformed_publish_is_recorded_not_fatal() {
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
        let provenance = super::native_provenance().expect("provenance");

        // Upstream's CVE-2026-111497 input exercises an invalid block switch.
        // Extra input also probes repeated buffering across the 4096-byte read.
        let invalid_block_switch =
            hex::decode("200010414141fcffff07002228f00b60f7f41f000000").expect("hex fixture");
        let mut padded_block_switch = invalid_block_switch.clone();
        padded_block_switch.resize(8192, 0x41);
        for payload in [vec![0xFF; 64], invalid_block_switch, padded_block_switch] {
            let payment = runtime.core_payment();
            let err = runtime
                .publish(&signer, payment, "halt-probe", &payload, &provenance)
                .await
                .expect_err("malformed bytes cannot publish");
            assert!(
                matches!(err, super::ExecutionError::Deterministic(_)),
                "a malformed publish must be a RECORDED op failure; NonDeterministic \
                 propagates out of execute_block and every node exits at this height: {err:?}"
            );
        }
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
              export get-value: func(ctx: borrow<view-context>) -> string;\n\
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

    /// Failed publication must release its speculative cache entry even though
    /// immutable code identity now prevents a reused row ID from aliasing it.
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

    /// Speculative code must not evict canonical hot entries. Cover both cache
    /// writers, loading and publication admission, rather than assuming they share
    /// a guard. This directly exercises runtime policy, not reactor simulation.
    #[tokio::test]
    async fn simulation_does_not_populate_the_component_cache() {
        let (mut runtime, _dir, _name) = test_runtime().await.expect("test runtime");
        runtime
            .set_context(
                0,
                Some(super::TransactionContext::builder().build()),
                None,
                None,
            )
            .await;

        // A fresh id — the natives are prewarmed into the cache, so reusing one of
        // theirs would make the first assertion pass without the guard.
        let contract_id = runtime
            .storage
            .insert_contract("cache-probe", FILESTORAGE)
            .await
            .expect("insert contract");

        runtime.simulating = true;
        runtime
            .load_component(contract_id)
            .await
            .expect("component still compiles while simulating");
        assert!(
            runtime.component_cache.get(&contract_id).await.is_none(),
            "a component compiled during simulation must not warm the shared cache"
        );

        // The publish path caches at its OWN site inside `validate_publishable`, so
        // it has to be asserted separately — a guard on the call path says nothing
        // about it. This publish fails (filestorage imports `file-registry`, which a
        // user contract may not), but only AFTER the component is compiled and would
        // have been cached, which is exactly the window under test.
        let publish_id = runtime
            .storage
            .insert_contract("publish-probe", FILESTORAGE)
            .await
            .expect("insert contract");
        let _ = runtime.validate_publishable(publish_id).await;
        assert!(
            runtime.component_cache.get(&publish_id).await.is_none(),
            "publication admission during simulation must not warm the shared cache"
        );

        // The guard must be scoped to simulation, not a blanket disable: caching is
        // what keeps every later call off the compiler.
        runtime.simulating = false;
        runtime
            .load_component(contract_id)
            .await
            .expect("component compiles normally");
        assert!(
            runtime.component_cache.get(&contract_id).await.is_some(),
            "outside simulation the cache must still be populated"
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
