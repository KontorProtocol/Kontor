use anyhow::{Result, anyhow};

use super::ExecutionError;
use futures_util::FutureExt;
use futures_util::future::OptionFuture;
use wasmtime::{
    AsContext, AsContextMut, Store,
    component::{
        Accessor, Func, Resource, Val,
        wasm_wave::{
            parser::Parser as WaveParser, to_string as to_wave_string, value::Value as WaveValue,
        },
    },
};

use indexer_types::{OpStatus, Payment};
use stdlib::CheckedArithmetics;

use crate::database::native_contracts::is_native_contract_id;
use crate::database::types::Identity;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;
use wasmtime::component::ResourceTable;

use super::{
    ContractAddress, Decimal, Runtime,
    fuel::Fuel,
    should_skip_result,
    stack::{CallFrame, Stack},
    token,
    types::default_val_for_type,
    wit::{Contract, CoreContext, FallContext, Holder, ProcContext, Signer, ViewContext},
};

/// Derive the payer's `Holder` for a top-level proc context. The payer's
/// signer_id comes from `Payment.signer_id` — the post-override value
/// `walker.materialize` recorded — falling back to the signer's own
/// signer_id when no Payment is supplied (non-proc paths). Returns a
/// Holder rather than a Signer so the contract cannot impersonate the
/// payer to authorize moves on their behalf.
fn payer_holder(signer: &Signer, payment: Option<&Payment>) -> Holder {
    let signer_id = payment
        .map(|p| p.signer_id)
        .or_else(|| signer.signer_id())
        .unwrap_or(0);
    Holder::for_signer_id(signer_id)
}

impl Runtime {
    pub(crate) async fn prepare_call(
        &self,
        contract_address: &ContractAddress,
        signer: Option<&Signer>,
        payment: Option<&Payment>,
        expr: &str,
        is_top_level: bool,
        fuel_override: Option<u64>,
    ) -> Result<
        (
            Store<Runtime>,
            u64,
            String,
            bool,
            Vec<Val>,
            Vec<Val>,
            Func,
            bool,
            u64,
        ),
        ExecutionError,
    > {
        let contract_id = self
            .storage
            .contract_id(contract_address)
            .await
            .map_err(ExecutionError::NonDeterministic)?
            .ok_or_else(|| {
                ExecutionError::Deterministic(anyhow!("Contract not found: {}", contract_address))
            })?;
        // Stamp the depositor for every write in this op = the top-level op's
        // payer (0 = none, i.e. no Payment). Only top-level sets it; nested
        // cross-contract calls inherit it via the shared `op_payer` (so a row
        // written deep in a nested call still attributes to the op's payer).
        // NOTE: Core/system ops pass a Payment with `CORE_SIGNER_ID`, so they're
        // stamped with that today — the step-4 exemption will map them to none.
        if is_top_level {
            self.op_payer
                .store(payment.map(|p| p.signer_id).unwrap_or(0), Ordering::Relaxed);
        }
        let component = self
            .load_component(contract_id)
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        let mut fuel_limit = match fuel_override {
            Some(f) => f,
            None => match payment {
                Some(p) => p.gas_limit * self.gas_to_fuel_multiplier,
                None => self.fuel_limit_for_non_procs(),
            },
        };
        let mut store = self
            .make_store(fuel_limit)
            .map_err(ExecutionError::NonDeterministic)?;
        // Native contracts get the privileged linker (file-registry, registry);
        // user contracts get the common-only linker, so importing a registry
        // interface fails to link.
        let linker = if is_native_contract_id(contract_id) {
            &self.linkers.native
        } else {
            &self.linkers.user
        };
        // Import resolution (`instantiate_pre`) is a pure function of the
        // component bytes and the linker — identical on every node — so a link
        // failure (e.g. a user contract importing a native-only interface) is
        // DETERMINISTIC: reject the op, don't shut the node down. Only the
        // actual instantiation step can fail for non-deterministic infra reasons.
        let instance_pre = linker
            .instantiate_pre(&component)
            .map_err(|e| ExecutionError::Deterministic(e.into()))?;
        let instance = instance_pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| ExecutionError::NonDeterministic(e.into()))?;
        let fallback_name = "fallback";
        let fallback_expr = format!(
            "{}({})",
            fallback_name,
            to_wave_string(&WaveValue::from(expr))
                .map_err(|e| ExecutionError::Deterministic(e.into()))?
        );

        let call = WaveParser::new(expr)
            .parse_raw_func_call()
            .map_err(|e| ExecutionError::Deterministic(e.into()))?;
        let (call, func) = if let Some(func) = instance.get_func(&mut store, call.name()) {
            (call, func)
        } else if let Some(func) = instance.get_func(&mut store, fallback_name) {
            (
                WaveParser::new(&fallback_expr)
                    .parse_raw_func_call()
                    .map_err(|e| ExecutionError::Deterministic(e.into()))?,
                func,
            )
        } else {
            return Err(ExecutionError::Deterministic(anyhow!(
                "Expression does not refer to any known function"
            )));
        };

        let func_name = call.name();
        let component_func = func.ty(&store);
        let func_params = component_func.params();
        let func_param_types = func_params.map(|(_, t)| t).collect::<Vec<_>>();
        let (func_ctx_param_type, func_param_types) =
            func_param_types.split_first().ok_or_else(|| {
                ExecutionError::Deterministic(anyhow!("Context/signer parameter not found"))
            })?;
        let mut params = call
            .to_wasm_params(func_param_types)
            .map_err(|e| ExecutionError::Deterministic(e.into()))?;
        let resource_type = match func_ctx_param_type {
            wasmtime::component::Type::Borrow(t) => Ok(*t),
            _ => Err(ExecutionError::Deterministic(anyhow!(
                "Unsupported context type"
            ))),
        }?;

        if let Some(Signer::Contract { id, .. }) = signer
            && self.stack.peek().await.map(|f| f.contract_id) != Some(*id)
        {
            return Err(ExecutionError::Deterministic(anyhow!(
                "Invalid contract id signer"
            )));
        }

        let mut is_proc = false;
        {
            let mut table = self.table.lock().await;
            match (resource_type, signer) {
                (t, Some(Signer::Core(signer)))
                    if t.eq(&wasmtime::component::ResourceType::host::<CoreContext>()) =>
                {
                    is_proc = true;
                    if self.stack.is_empty().await {
                        fuel_limit = self.fuel_limit_for_non_procs();
                        store
                            .set_fuel(fuel_limit)
                            .expect("Failed to set fuel for core context procedure");
                    } else {
                        fuel_limit = store.get_fuel().unwrap_or(0);
                    }
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(CoreContext {
                                    signer: *signer.clone(),
                                    contract_id,
                                })
                                .map_err(anyhow::Error::from)?
                                .try_into_resource_any(&mut store)
                                .map_err(anyhow::Error::from)?,
                        ),
                    )
                }
                (t, _) if t.eq(&wasmtime::component::ResourceType::host::<ViewContext>()) => params
                    .insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(ViewContext { contract_id })
                                .map_err(anyhow::Error::from)?
                                .try_into_resource_any(&mut store)
                                .map_err(anyhow::Error::from)?,
                        ),
                    ),
                (t, Some(signer))
                    if t.eq(&wasmtime::component::ResourceType::host::<ProcContext>()) =>
                {
                    is_proc = true;
                    // Payer is a Holder (not a Signer) by design — contracts
                    // can credit but not spend on the payer's behalf. The
                    // signer_id comes from the resolved Payment, which the
                    // reactor's `walker.materialize` already redirected per
                    // the override rules (cross-input Sponsor or aggregate-
                    // publisher).
                    let payer = payer_holder(signer, payment);
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(ProcContext {
                                    signer: signer.clone(),
                                    payer,
                                    contract_id,
                                })
                                .map_err(anyhow::Error::from)?
                                .try_into_resource_any(&mut store)
                                .map_err(anyhow::Error::from)?,
                        ),
                    )
                }

                (t, signer) if t.eq(&wasmtime::component::ResourceType::host::<FallContext>()) => {
                    is_proc = signer.is_some();
                    // FallContext has a payer iff it has a signer — a fall
                    // context with no acting signer has no payer either.
                    let payer = signer.map(|s| payer_holder(s, payment));
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(FallContext {
                                    signer: signer.cloned(),
                                    payer,
                                    contract_id,
                                })
                                .map_err(anyhow::Error::from)?
                                .try_into_resource_any(&mut store)
                                .map_err(anyhow::Error::from)?,
                        ),
                    )
                }
                (t, signer) => {
                    return Err(ExecutionError::Deterministic(anyhow!(
                        "Unsupported context/signer type: {:?} {:?}",
                        t,
                        signer
                    )));
                }
            }
        }

        if is_proc && payment.is_none() && fuel_override.is_none() {
            return Err(ExecutionError::Deterministic(anyhow!(
                "Missing fuel for procedure"
            )));
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
            let payment = payment.expect("payment is required for top-level proc calls");
            let payer = Signer::Id(Identity::new(payment.signer_id));
            let hold_amount = Decimal::try_from(fuel_limit)
                .expect("u64 to decimal")
                .div(
                    self.gas_to_fuel_multiplier
                        .try_into()
                        .expect("u64 to decimal"),
                )
                .expect("Failed to convert fuel limit into gas limit")
                .mul(self.gas_to_token_multiplier)
                .expect("Failed to convert gas limit into token limit");
            tracing::info!(
                node = %self.node_label,
                %hold_amount,
                signer = ?signer,
                payer = ?payer,
                "Gas hold"
            );
            Box::pin({
                let mut runtime = self.clone();
                async move {
                    token::api::hold(&mut runtime, &Signer::Core(Box::new(payer)), hold_amount)
                        .await
                }
            })
            .await
            .map_err(ExecutionError::NonDeterministic)?
            .map_err(|e| {
                ExecutionError::Deterministic(anyhow!(
                    "Payer {:?} does not have enough token to cover gas limit: {}",
                    payment.signer_id,
                    e
                ))
            })?;
            // Start this top-level op's deposit accumulator clean — after the
            // hold's own ledger writes, before any of the op's storage writes.
            // Gated to top-level so nested cross-contract calls don't reset it.
            self.deposit.reset().await;
        }

        self.stack
            .push(CallFrame {
                contract_id,
                is_proc,
            })
            .await
            .map_err(|e| ExecutionError::Deterministic(e.into()))?;
        self.storage.savepoint().await?;

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

    /// Spawn the WASM call, catch panics, and handle the result.
    /// Returns (call_result, store) — the store is always returned for gas accounting.
    pub(crate) async fn call_and_handle(
        &self,
        mut store: Store<Runtime>,
        func: Func,
        params: Vec<Val>,
        mut results: Vec<Val>,
        is_fallback: bool,
    ) -> Result<(Result<String, ExecutionError>, Store<Runtime>)> {
        let (result, results, mut store) = tokio::spawn(async move {
            match std::panic::AssertUnwindSafe(func.call_async(&mut store, &params, &mut results))
                .catch_unwind()
                .await
            {
                Ok(call_result) => (Ok(call_result), results, store),
                Err(panic_payload) => {
                    let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    (Err(msg), results, store)
                }
            }
        })
        .await
        .map_err(|e| anyhow::anyhow!("tokio task failed: {e}"))?;

        let call_result = self
            .handle_call(is_fallback, result, results, &mut store)
            .await;

        Ok((call_result, store))
    }

    /// Process the result of a WASM call: extract return value, rollback/commit,
    /// and classify errors as Contract (deterministic) or Infrastructure.
    ///
    /// The `result` parameter is either:
    /// - `Ok(wasmtime_result)` — normal return from func.call_async
    /// - `Err(panic_msg)` — host function panicked, caught by catch_unwind
    ///
    /// Error classification:
    /// - WASM traps (downcast to wasmtime::Trap) → Contract
    /// - Host Err returns (no Trap) or host panics → Infrastructure
    /// - Rollback/commit failures → Infrastructure
    pub(crate) async fn handle_call(
        &self,
        is_fallback: bool,
        result: std::result::Result<std::result::Result<(), wasmtime::Error>, String>,
        mut results: Vec<Val>,
        store: &mut Store<Runtime>,
    ) -> Result<String, ExecutionError> {
        self.stack.pop().await;

        // Classify before converting. An error is deterministic if:
        // - It's a WASM trap (wasmtime::Trap in the error chain)
        // - It originated from a deterministic ExecutionError in a cross-contract call
        // Host panics (caught by catch_unwind) are non-deterministic.
        //
        // wasmtime::Error is anyhow::Error, so downcast_ref looks through
        // context layers and finds types that dyn Error chain walking cannot.
        let is_deterministic = match &result {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                e.downcast_ref::<wasmtime::Trap>().is_some()
                    || e.downcast_ref::<ExecutionError>()
                        .is_some_and(|ee| matches!(ee, ExecutionError::Deterministic(_)))
            }
            Err(_) => false,
        };

        let result: Result<()> = match result {
            Ok(call_result) => call_result.map_err(Into::into),
            Err(panic_msg) => Err(anyhow!("host panic: {panic_msg}")),
        };

        let result = if let Err(e) = result {
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
                val_to_wave(val, store, &self.table).await
            }
        };

        let result = result.map_err(|e| {
            if is_deterministic {
                ExecutionError::Deterministic(e)
            } else {
                ExecutionError::NonDeterministic(e)
            }
        });

        if classify_result(&result) != OpStatus::Ok {
            self.storage
                .rollback()
                .await
                .map_err(|e| ExecutionError::NonDeterministic(e.context("rollback failed")))?;
        } else {
            self.storage
                .commit()
                .await
                .map_err(|e| ExecutionError::NonDeterministic(e.context("commit failed")))?;
        }

        result
    }

    pub async fn handle_procedure(
        &mut self,
        signer: &Signer,
        payment: Option<&Payment>,
        contract_id: u64,
        contract_address: &ContractAddress,
        func_name: &str,
        is_op_result: bool,
        starting_fuel: u64,
        store: &mut Store<Runtime>,
        mut result: Result<String, ExecutionError>,
    ) -> Result<String, ExecutionError> {
        if let Ok(value) = &result
            && let Err(e) = Fuel::Result(value.len() as u64)
                .consume_with_store(self.gauge.as_ref(), store)
                .await
        {
            result = Err(ExecutionError::Deterministic(e));
        }
        let gas = self
            .gas_consumed(
                starting_fuel,
                store.get_fuel().expect("Fuel should be available"),
            )
            .max(1);

        if is_op_result && !signer.is_core() {
            let payment = payment.expect("payment required for op-result release");
            let payer = Signer::Id(Identity::new(payment.signer_id));
            // Settle boundary: read the op's deposit accumulator before gas
            // release. Observation only for now — step 4 will hand (charge,
            // refunds) to the token `settle` to move the deposit into VAULT and
            // refund displaced setters. Batched per distinct setter.
            let (charge, refunds) = self.deposit.take().await;
            tracing::info!(
                node = %self.node_label,
                ?charge,
                refund_setters = refunds.len(),
                payer = ?payer,
                contract = %contract_address,
                func = func_name,
                "Deposit settlement observed"
            );
            let burn_amount = Decimal::try_from(gas)
                .expect("u64 to decimal")
                .mul(self.gas_to_token_multiplier)
                .expect("Failed to convert gas consumed to token amount");
            tracing::info!(
                node = %self.node_label,
                gas,
                starting_fuel,
                remaining_fuel = store.get_fuel().unwrap(),
                %burn_amount,
                call_succeeded = result.is_ok(),
                contract = %contract_address,
                func = func_name,
                signer = ?signer,
                payer = ?payer,
                "Gas release"
            );
            Box::pin({
                let mut runtime = self.clone();
                runtime.stack = Stack::new();
                async move {
                    token::api::release(&mut runtime, &Signer::Core(Box::new(payer)), burn_amount)
                        .await
                }
            })
            .await
            .map_err(ExecutionError::NonDeterministic)?
            .map_err(|e| ExecutionError::NonDeterministic(anyhow::anyhow!("{e:?}")))?;
        }
        if should_skip_result(contract_address, func_name) {
            return result;
        }
        let value = result.as_ref().map(|v| v.clone()).ok();
        let status = classify_result(&result);
        let result_index = self.result_id_counter.get().await as u32;
        let signer_id = signer
            .signer_id()
            .expect("signer_id must be set for result attribution");
        // Payer for this op — equals `signer_id` for self-pay, differs for
        // BLS-aggregate sponsored ops. `None` when there's no Payment (Core-
        // paid system calls that bypass hold/release).
        let payer_signer_id = payment.map(|p| p.signer_id);
        self.storage
            .insert_contract_result(
                result_index,
                contract_id,
                func_name.to_string(),
                gas,
                value,
                signer_id,
                payer_signer_id,
                status,
            )
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        self.result_id_counter.increment().await;
        result
    }

    pub(crate) async fn _call<T>(
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

        let (store, contract_id, func_name, is_fallback, params, results, func, is_proc, _fuel) =
            self.prepare_call(
                contract_address,
                signer.as_ref(),
                None,
                expr,
                false,
                Some(starting_fuel),
            )
            .await?;
        let (mut result, mut store) = self
            .call_and_handle(store, func, params, results, is_fallback)
            .await?;
        let fuel = store.get_fuel().unwrap();
        accessor
            .with(|mut access| access.as_context_mut().set_fuel(fuel))
            .expect("Failed to set remaining fuel on parent store");
        if is_proc {
            result = self
                .handle_procedure(
                    signer.as_ref().expect("Signer should be available in proc"),
                    None,
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
        result.map_err(Into::into)
    }
}

/// Serialize a contract function's return value to a WAVE string.
///
/// `wasm_wave::to_string` (via `val.to_wave()`) covers every record /
/// variant / primitive shape, but maps `Val::Resource` to
/// `WasmTypeKind::Unsupported` and panics in the writer. So before
/// delegating, special-case resources that the host knows how to
/// serialize against the resource table — currently just `Contract`,
/// which drains to its underlying `contract-address` record so the SDK
/// reads back the new address from a publish's result row the same way
/// any Call op surfaces its return.
///
/// Other resource types remain a deterministic error: a contract can't
/// return a `holder` / `signer` / `view-context` etc. across the
/// result-row boundary without an explicit serialization, and silently
/// trapping on the wasm-wave panic would mask the failure. Add new
/// types to this branch as they become legitimately returnable.
async fn val_to_wave(
    val: Val,
    store: &mut Store<Runtime>,
    table: &Arc<Mutex<ResourceTable>>,
) -> Result<String> {
    match val {
        Val::Resource(resource_any) => {
            let handle: Resource<Contract> = resource_any
                .try_into_resource::<Contract>(&mut *store)
                .map_err(|e| {
                    anyhow!("function returned a resource that is not a `contract`: {e}")
                })?;
            // Drain the resource: `delete` removes the entry from the
            // table and returns the owned `Contract`. `get` would only
            // borrow, leaving the entry in the `ResourceTable` for the
            // pooled runtime's lifetime — once per publish, accumulating.
            let mut table = table.lock().await;
            let contract = table.delete(handle)?;
            Ok(stdlib::to_wave_expr(contract.address))
        }
        other => other.to_wave().map_err(Into::into),
    }
}

/// Categorize the result of a wasm call into a persisted `OpStatus`.
///
/// - `Ok(s)` where `s` starts with `"err("` means the contract function
///   returned a `result<_, error>::Err` value. The call ran cleanly but
///   the semantic outcome was a failure; storage was rolled back. Treated
///   as `OpStatus::ContractErr`.
/// - `Ok(_)` otherwise is a successful call returning either a value or
///   nothing. `OpStatus::Ok`.
/// - `Err(ExecutionError::Deterministic(e))` is mapped by looking at the
///   underlying error for a `wasmtime::Trap` variant. `Trap::OutOfFuel`
///   becomes `OpStatus::OutOfFuel`; other trap variants become
///   `OpStatus::Trap`. If the error isn't a trap (host-side
///   `Fuel::consume` exhaustion produces an `anyhow!("Insufficient fuel")`
///   rather than a wasmtime trap, so check the message too), classify
///   as `OutOfFuel` or `Other`.
/// - `Err(NonDeterministic)` shouldn't normally produce a row — those
///   propagate as fatal infrastructure errors and the block won't
///   commit. Mapped to `Other` for completeness.
fn classify_result(result: &Result<String, ExecutionError>) -> OpStatus {
    match result {
        Ok(v) if v.starts_with("err(") => OpStatus::ContractErr,
        Ok(_) => OpStatus::Ok,
        Err(ExecutionError::Deterministic(e)) => {
            if let Some(trap) = e.downcast_ref::<wasmtime::Trap>() {
                match trap {
                    wasmtime::Trap::OutOfFuel => OpStatus::OutOfFuel,
                    _ => OpStatus::Trap,
                }
            } else if e.to_string().contains("Insufficient fuel") {
                OpStatus::OutOfFuel
            } else {
                OpStatus::Other
            }
        }
        Err(ExecutionError::NonDeterministic(_)) => OpStatus::Other,
    }
}
