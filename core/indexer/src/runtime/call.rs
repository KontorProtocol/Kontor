use anyhow::{Result, anyhow};

use super::ExecutionError;
#[cfg(test)]
use super::resource_diagnostics;
use futures_util::FutureExt;
use futures_util::future::OptionFuture;
use wasmtime::{
    AsContext, AsContextMut, GcHeapOutOfMemory, Store,
    component::{
        Access, Func, Resource, Type, Val,
        wasm_wave::{
            to_string as to_wave_string, untyped::UntypedFuncCall, value::Value as WaveValue,
        },
    },
};

use indexer_types::{OpStatus, Payment};

use crate::protocol::v1::errors::{classify_result, is_deterministic};
#[cfg(test)]
use crate::protocol::v1::gas::SYSTEM_FUEL_CEILING;
use crate::protocol::v1::native::{is_native_contract_id, records_result};

use super::{
    ContractAddress, Runtime,
    fuel::{Fuel, UsageKind, record_fuel},
    invocation::{
        InvocationCapacityExhausted, InvocationLimitReached, InvocationStore, MAX_LIVE_INVOCATIONS,
    },
    ownership::GuestCompletion,
    stack::CallFrame,
    wit::{CoreContext, FallContext, Holder, ProcContext, Signer, ViewContext},
};

mod input;
mod result;

#[cfg(test)]
mod tests;

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

struct PreparedCall {
    contract_id: u64,
    func_name: String,
    is_fallback: bool,
    params: Vec<Val>,
    results: Vec<Val>,
    func: Func,
    frame: CallFrame,
}

pub(crate) struct CallOutcome {
    pub result: Result<String, ExecutionError>,
    pub remaining_fuel: u64,
}

fn invocation_limit_outcome(fuel_limit: u64) -> CallOutcome {
    CallOutcome {
        result: Err(ExecutionError::Deterministic(InvocationLimitReached.into())),
        remaining_fuel: fuel_limit,
    }
}

impl Runtime {
    pub(crate) async fn execute_system_view(
        &mut self,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String, ExecutionError> {
        // A root call keeps system usage accounting, while no signer or payment
        // keeps the view context from gaining procedure authority.
        self.invoke_unsettled(
            contract_address,
            None,
            None,
            expr,
            self.selected_gas_policy().system_fuel,
            false,
        )
        .await?
        .result
    }

    fn guest_memory_backing_failure(&self) -> Option<ExecutionError> {
        self.guest_memory_limiter
            .as_ref()
            .filter(|limiter| limiter.backing_failed())
            .map(|_| ExecutionError::NonDeterministic(anyhow!("guest memory backing failure")))
    }

    fn classify_guest_memory_result<T>(
        &self,
        result: Result<T, ExecutionError>,
    ) -> Result<T, ExecutionError> {
        if let Some(error) = self.guest_memory_backing_failure() {
            return Err(error);
        }
        // Wasmtime can swallow a GC growth denial during retry. Once a backing
        // failure is ruled out, the resulting heap OOM is a deterministic limit.
        match result {
            Err(ExecutionError::NonDeterministic(error))
                if self.guest_memory_limiter.is_some()
                    && error
                        .chain()
                        .any(|cause| cause.is::<GcHeapOutOfMemory<()>>()) =>
            {
                Err(ExecutionError::Deterministic(error))
            }
            other => other,
        }
    }

    pub(super) async fn invoke(
        &self,
        contract_address: &ContractAddress,
        signer: Option<&Signer>,
        payment: Option<&Payment>,
        expr: &str,
        fuel_override: Option<u64>,
    ) -> Result<CallOutcome, ExecutionError> {
        self.verify_selected_runtime()
            .map_err(ExecutionError::NonDeterministic)?;
        let fuel_limit = self.call_fuel_limit(signer, payment, fuel_override)?;
        if fuel_override.is_none()
            && signer.is_some_and(|signer| !signer.is_core())
            && let Some(payment) = payment
        {
            let mut runtime = self.clone();
            runtime
                .with_payment(payment, fuel_limit, async |runtime| {
                    runtime
                        .invoke_unsettled(
                            contract_address,
                            signer,
                            Some(payment),
                            expr,
                            fuel_limit,
                            false,
                        )
                        .await
                })
                .await
        } else {
            self.invoke_unsettled(
                contract_address,
                signer,
                payment,
                expr,
                fuel_limit,
                fuel_override.is_some(),
            )
            .await
        }
    }

    pub(super) fn call_fuel_limit(
        &self,
        signer: Option<&Signer>,
        payment: Option<&Payment>,
        fuel_override: Option<u64>,
    ) -> Result<u64, ExecutionError> {
        let gas = self.selected_gas_policy();
        // The fuel budget is decided ONCE here, from the signer, so it can't drift
        // across the per-context arms below.
        Ok(match fuel_override {
            // Nested cross-contract call: inherit the remaining fuel the parent threaded.
            Some(f) => f,
            None => match (signer, payment) {
                // Trusted, system-paid, MUST-COMPLETE consensus work (per-block hooks,
                // issuance, native publishing) — effectively unmetered, regardless of
                // which context the procedure takes. Metering is a DoS/economic control
                // for UNTRUSTED user ops; a finite cap on must-complete system work
                // would eventually false-halt a healthy network on legitimate growth.
                // See `SYSTEM_FUEL_CEILING`.
                (Some(s), _) if s.is_core() => gas.system_fuel,
                // User op: metered by the payer's committed gas limit.
                (_, Some(p)) => {
                    if p.gas_limit > gas.untrusted_allowance {
                        let maximum = gas.untrusted_allowance;
                        return Err(ExecutionError::Deterministic(anyhow!(
                            "Gas limit exceeds the maximum of {maximum}"
                        )));
                    }
                    p.gas_limit
                        .checked_mul(gas.fuel_multiplier)
                        .ok_or_else(|| {
                            ExecutionError::Deterministic(anyhow!(
                                "Gas limit exceeds the fuel range"
                            ))
                        })?
                }
                // Read-only `/view`: the operator-configurable view cap.
                (_, None) => self.fuel_limit_for_view()?,
            },
        })
    }

    pub(super) async fn invoke_unsettled(
        &self,
        contract_address: &ContractAddress,
        signer: Option<&Signer>,
        payment: Option<&Payment>,
        expr: &str,
        fuel_limit: u64,
        nested: bool,
    ) -> Result<CallOutcome, ExecutionError> {
        if self.invocation_depth >= MAX_LIVE_INVOCATIONS {
            #[cfg(test)]
            self.record_resource_rejection(contract_address, "depth_gate_rejected");
            return Ok(invocation_limit_outcome(fuel_limit));
        }
        if self
            .invocation_budget
            .as_ref()
            .is_some_and(|budget| budget.live() >= MAX_LIVE_INVOCATIONS)
        {
            #[cfg(test)]
            self.record_resource_rejection(contract_address, "physical_capacity_rejected");
            return Err(ExecutionError::NonDeterministic(
                InvocationCapacityExhausted.into(),
            ));
        }
        #[cfg(test)]
        let store_result = self.make_store_for_call(fuel_limit, contract_address);
        #[cfg(not(test))]
        let store_result = self.make_store(fuel_limit);
        let mut store = match store_result {
            Ok(store) => store,
            Err(error) if error.is::<InvocationLimitReached>() => {
                return Ok(invocation_limit_outcome(fuel_limit));
            }
            Err(error) => return Err(error.into()),
        };
        if !nested {
            store.data_mut().usage_kind = match signer {
                Some(signer) if !signer.is_core() => UsageKind::User,
                _ => UsageKind::System,
            };
        }
        let mut runtime = store.data().clone();
        // The invocation driver never accesses this table; guest callbacks use
        // Store.data(). Keeping its table here would outlive Store on Err paths
        // and release the lease while the resource table is still alive.
        runtime.table = self.table.clone();
        let (result, mut store) = runtime
            .invoke_in_store(store, contract_address, signer, payment, expr, nested)
            .await?;
        drop(runtime);
        record_fuel(&mut store)?;
        Ok(CallOutcome {
            result,
            remaining_fuel: store.get_fuel().map_err(anyhow::Error::from)?,
        })
    }

    async fn invoke_in_store(
        &mut self,
        mut store: InvocationStore,
        contract_address: &ContractAddress,
        signer: Option<&Signer>,
        payment: Option<&Payment>,
        expr: &str,
        nested: bool,
    ) -> Result<(Result<String, ExecutionError>, InvocationStore), ExecutionError> {
        let starting_fuel = store.get_fuel().map_err(anyhow::Error::from)?;
        let prepared = self
            .prepare_in_store(&mut store, contract_address, signer, payment, expr, nested)
            .await;
        let prepared = match self.classify_guest_memory_result(prepared) {
            Ok(prepared) => prepared,
            // Keep the store even on failed initialization or argument resolution:
            // the parent still pays for work done before preparation failed.
            Err(error) => return Ok((Err(error), store)),
        };
        let PreparedCall {
            contract_id,
            func_name,
            is_fallback,
            params,
            results,
            func,
            frame,
        } = prepared;
        if let Err(error) = self.stack.push(frame).await {
            return Ok((Err(ExecutionError::Deterministic(error.into())), store));
        }
        if let Err(error) = self.storage.savepoint().await {
            self.stack.pop().await;
            return Err(error.into());
        }

        let execution = self
            .call_guest(store, func, params, results, is_fallback)
            .await
            .map(|(result, store)| (self.classify_guest_memory_result(result), store));
        self.stack.pop().await;
        let succeeded = execution
            .as_ref()
            .is_ok_and(|(result, _)| classify_result(result) == OpStatus::Ok);
        if succeeded {
            self.storage
                .commit()
                .await
                .map_err(|e| ExecutionError::NonDeterministic(e.context("commit failed")))?;
        } else {
            self.storage
                .rollback()
                .await
                .map_err(|e| ExecutionError::NonDeterministic(e.context("rollback failed")))?;
        }
        let (mut result, store) = execution?;
        if frame.is_proc
            || (!nested && payment.is_some() && signer.is_some_and(|signer| !signer.is_core()))
        {
            let gas = self
                .gas_consumed(
                    starting_fuel,
                    store.get_fuel().map_err(anyhow::Error::from)?,
                )
                .max(1);
            result = self
                .record_call(
                    signer.expect("recorded call requires a signer"),
                    payment,
                    contract_id,
                    &func_name,
                    gas,
                    result,
                )
                .await;
        }
        Ok((result, store))
    }

    async fn prepare_in_store(
        &self,
        mut store: &mut Store<Runtime>,
        contract_address: &ContractAddress,
        signer: Option<&Signer>,
        payment: Option<&Payment>,
        expr: &str,
        nested: bool,
    ) -> Result<PreparedCall, ExecutionError> {
        Fuel::WaveInputBytes(expr.len() as u64)
            .consume_with_store(store)
            .map_err(ExecutionError::Deterministic)?;
        Fuel::ContractNameBytes(contract_address.name.len() as u64)
            .consume_with_store(store)
            .map_err(ExecutionError::Deterministic)?;
        // Bound recursion before the WAVE parser can overflow the host stack.
        validate_expr(expr)?;
        let contract_id = self
            .storage
            .contract_id(contract_address)
            .await
            .map_err(ExecutionError::NonDeterministic)?
            .ok_or_else(|| {
                ExecutionError::Deterministic(anyhow!("Contract not found: {}", contract_address))
            })?;
        let component = self
            .load_component(contract_id)
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        let is_top_level = self.stack.is_empty().await;
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
        // DETERMINISTIC: reject the op, don't shut the node down. Instantiation
        // also executes Wasm initialization, so its runtime failures use the
        // same classification as exported calls.
        let instance_pre = linker
            .instantiate_pre(&component)
            .map_err(|e| ExecutionError::Deterministic(e.into()))?;
        let instance = instance_pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| {
                if is_deterministic(&e) {
                    ExecutionError::Deterministic(e.into())
                } else {
                    ExecutionError::NonDeterministic(e.into())
                }
            })?;
        let fallback_name = "fallback";
        let fallback_expr;

        let call =
            UntypedFuncCall::parse(expr).map_err(|e| ExecutionError::Deterministic(e.into()))?;
        let (call, func) = if let Some(func) = instance.get_func(&mut store, call.name()) {
            (call, func)
        } else if let Some(func) = instance.get_func(&mut store, fallback_name) {
            fallback_expr = format!(
                "{}({})",
                fallback_name,
                to_wave_string(&WaveValue::from(expr))
                    .map_err(|e| ExecutionError::Deterministic(e.into()))?
            );
            Fuel::WaveInputBytes(fallback_expr.len() as u64)
                .consume_with_store(store)
                .map_err(ExecutionError::Deterministic)?;
            // Escaping can expand the wrapped expression, so it too must clear
            // the parser's string/depth limits.
            validate_expr(&fallback_expr)?;
            (
                UntypedFuncCall::parse(&fallback_expr)
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
        let mut func_param_types = component_func.params().map(|(_, t)| t);
        let func_ctx_param_type = func_param_types.next().ok_or_else(|| {
            ExecutionError::Deterministic(anyhow!("Context/signer parameter not found"))
        })?;
        let mut params = {
            #[cfg(test)]
            let _conversion = resource_diagnostics::conversion_scope(
                "canonical_input_entry",
                "canonical_input_exit",
            );
            input::params(&call, func_param_types, store).map_err(ExecutionError::Deterministic)?
        };
        let resource_type = match func_ctx_param_type {
            Type::Borrow(t) => Ok(t),
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
            let table = store.data().table.clone();
            let mut table = table.lock().await;
            match (resource_type, signer) {
                (t, Some(Signer::Core(signer)))
                    if t.eq(&wasmtime::component::ResourceType::host::<CoreContext>()) =>
                {
                    // Fuel was already set above (SYSTEM_FUEL_CEILING for a top-level
                    // core call, inherited for a nested one) — this arm only wires up
                    // the trusted CoreContext resource.
                    is_proc = true;
                    let res = table
                        .push(CoreContext {
                            signer: *signer.clone(),
                            contract_id,
                        })
                        .map_err(anyhow::Error::from)?;
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            res.try_into_resource_any(&mut store)
                                .map_err(anyhow::Error::from)?,
                        ),
                    );
                }
                (t, _) if t.eq(&wasmtime::component::ResourceType::host::<ViewContext>()) => {
                    let res = table
                        .push(ViewContext { contract_id })
                        .map_err(anyhow::Error::from)?;
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            res.try_into_resource_any(&mut store)
                                .map_err(anyhow::Error::from)?,
                        ),
                    );
                }
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
                    let res = table
                        .push(ProcContext {
                            signer: signer.clone(),
                            payer,
                            contract_id,
                        })
                        .map_err(anyhow::Error::from)?;
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            res.try_into_resource_any(&mut store)
                                .map_err(anyhow::Error::from)?,
                        ),
                    );
                }

                (t, signer) if t.eq(&wasmtime::component::ResourceType::host::<FallContext>()) => {
                    is_proc = signer.is_some();
                    // FallContext has a payer iff it has a signer — a fall
                    // context with no acting signer has no payer either.
                    let payer = signer.map(|s| payer_holder(s, payment));
                    let res = table
                        .push(FallContext {
                            signer: signer.cloned(),
                            payer,
                            contract_id,
                        })
                        .map_err(anyhow::Error::from)?;
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            res.try_into_resource_any(&mut store)
                                .map_err(anyhow::Error::from)?,
                        ),
                    );
                }
                (t, signer) => {
                    return Err(ExecutionError::Deterministic(anyhow!(
                        "Unsupported context/signer type: {:?} {:?}",
                        t,
                        signer
                    )));
                }
            }
        };

        if is_proc && payment.is_none() && !nested {
            return Err(ExecutionError::Deterministic(anyhow!(
                "Missing fuel for procedure"
            )));
        }

        // Wasmtime checks the slot count and replaces each placeholder on return.
        let results = vec![Val::Bool(false); component_func.results().len()];

        // The outer paid-operation boundary owns the reservation. Nested writes
        // inherit its payer; core fee transfers never own user collateral.
        let depositor = if is_top_level {
            match signer {
                Some(s) if !s.is_core() => payment.map(|p| p.signer_id),
                _ => None,
            }
        } else {
            self.stack.peek().await.and_then(|f| f.depositor)
        };

        Ok(PreparedCall {
            contract_id,
            func_name: func_name.to_string(),
            is_fallback: func_name == fallback_name,
            params,
            results,
            func,
            frame: CallFrame {
                contract_id,
                is_proc,
                depositor,
            },
        })
    }

    /// Spawn the WASM call, catch panics, and handle the result.
    /// Returns (call_result, store) — the store is always returned for gas accounting.
    async fn call_guest(
        &self,
        mut store: InvocationStore,
        func: Func,
        params: Vec<Val>,
        mut results: Vec<Val>,
        is_fallback: bool,
    ) -> Result<(Result<String, ExecutionError>, InvocationStore)> {
        let execute = |mut store: InvocationStore| async move {
            match std::panic::AssertUnwindSafe(func.call_async(&mut store, &params, &mut results))
                .catch_unwind()
                .await
            {
                Ok(call_result) => GuestCompletion {
                    result: Ok(call_result),
                    results,
                    store,
                    host_panicked: false,
                },
                Err(panic_payload) => {
                    let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    GuestCompletion {
                        result: Err(msg),
                        results,
                        store,
                        host_panicked: true,
                    }
                }
            }
        };
        let GuestCompletion {
            result,
            results,
            mut store,
            host_panicked: _,
        } = if let Some(parent) = self.ownership.as_ref() {
            parent
                .run_guest(|child| {
                    store.data_mut().storage.ownership = Some(child.clone());
                    store.data_mut().ownership = Some(child);
                    execute(store)
                })
                .await?
        } else {
            tokio::spawn(execute(store))
                .await
                .map_err(|e| anyhow::anyhow!("tokio task failed: {e}"))?
        };

        let result = Self::decode_result(is_fallback, result, results, &mut store).await;
        Ok((result, store))
    }

    /// Process the result of a WASM call: extract its return value
    /// and classify errors as Contract (deterministic) or Infrastructure.
    ///
    /// The `result` parameter is either:
    /// - `Ok(wasmtime_result)` — normal return from func.call_async
    /// - `Err(panic_msg)` — host function panicked, caught by catch_unwind
    ///
    /// Error classification:
    /// - WASM traps and recognized guest conversion failures → Contract
    /// - Unknown host/engine errors or host panics → Infrastructure
    async fn decode_result(
        is_fallback: bool,
        result: std::result::Result<std::result::Result<(), wasmtime::Error>, String>,
        results: Vec<Val>,
        store: &mut Store<Runtime>,
    ) -> Result<String, ExecutionError> {
        // Classify before converting to anyhow, preserving Wasmtime's marker
        // distinguishing generated host errors from native conversion errors.
        let is_deterministic = match &result {
            Ok(Ok(())) => true,
            Ok(Err(e)) => is_deterministic(e),
            Err(_) => false,
        };

        let result: Result<()> = match result {
            Ok(call_result) => call_result.map_err(Into::into),
            Err(panic_msg) => Err(anyhow!("host panic: {panic_msg}")),
        };

        let result = if let Err(e) = result {
            Err(e)
        } else {
            #[cfg(test)]
            let _conversion = resource_diagnostics::conversion_scope(
                "canonical_output_entry",
                "canonical_output_exit",
            );
            result::encode(results, is_fallback, store).await
        };

        result.map_err(|e| {
            if is_deterministic {
                ExecutionError::Deterministic(e)
            } else {
                ExecutionError::NonDeterministic(e)
            }
        })
    }

    async fn record_call(
        &mut self,
        signer: &Signer,
        payment: Option<&Payment>,
        contract_id: u64,
        func_name: &str,
        gas: u64,
        result: Result<String, ExecutionError>,
    ) -> Result<String, ExecutionError> {
        // Infrastructure failures abort the transaction, so they cannot own
        // a committed contract-result row.
        if matches!(&result, Err(ExecutionError::NonDeterministic(_))) {
            return result;
        }
        // The highest result index is the API/SDK's canonical operation result.
        // Internal fee transfers must never masquerade as that outcome.
        if !records_result(contract_id, func_name) {
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
        accessor: &mut Access<'_, T, Self>,
        signer: Option<Resource<Signer>>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        let starting_fuel = {
            let remaining = accessor.as_context().get_fuel()?;
            accessor.get().record_fuel(remaining)?;
            remaining
        };

        let signer =
            OptionFuture::from(signer.map(async |s| self.table.lock().await.get(&s).cloned()))
                .await
                .transpose()
                .expect("Failed to lock table and get signer");

        let outcome = self
            .invoke(
                contract_address,
                signer.as_ref(),
                None,
                expr,
                Some(starting_fuel),
            )
            .await?;
        {
            accessor.as_context_mut().set_fuel(outcome.remaining_fuel)?;
            // The child already measured this fuel; only subsequent parent work counts.
            accessor.get().fuel_checkpoint = outcome.remaining_fuel;
        }
        outcome.result.map_err(Into::into)
    }
}

/// Max bytes for a single STRING LITERAL in a call expression. The WAVE parser
/// (`parse_raw_func_call`) recurses ~per character through a string literal,
/// overflowing the host stack (~32k chars on the default ~2MB thread stack —
/// measured). Bound well under that. This is NOT a cap on total expr size: a
/// long `list<u8>` (binary args, e.g. a filestorage proof) parses *iteratively*
/// and is safe at any size — only string literals recurse. Total size stays
/// bounded by the tx/witness limits at consensus.
///
/// CONSENSUS-LOAD-BEARING: this deterministically rejects ops, so changing it is a
/// consensus change — nodes on different values would disagree on op validity and
/// fork. Treat like the checkpoint format; only change behind a coordinated upgrade.
const MAX_STRING_LITERAL_BYTES: usize = 16 * 1024;

/// Max structural nesting (`(`/`[`/`{`) of a call expression. The other recursion
/// axis: a short but deeply nested expr recurses per level (bigger frames) and
/// overflows at a few thousand levels. 64 is far beyond any real call and far
/// below the overflow depth. CONSENSUS-LOAD-BEARING — see `MAX_STRING_LITERAL_BYTES`.
const MAX_EXPR_DEPTH: usize = 64;

/// Deterministically reject a call expression that would overflow the recursive
/// WAVE parser — along its two recursion axes: an over-long string literal, or
/// over-deep structural nesting. One O(n) non-recursive pass; bracket/quote bytes
/// inside a string literal are data, not structure. Deterministic (pure function
/// of the bytes) → a uniform failed op on every node, never a host-stack abort.
fn validate_expr(expr: &str) -> Result<(), ExecutionError> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut str_len = 0usize;
    for &b in expr.as_bytes() {
        if in_string {
            if escaped {
                escaped = false;
                str_len += 1;
            } else if b == b'\\' {
                escaped = true;
                str_len += 1;
            } else if b == b'"' {
                in_string = false; // closing quote
            } else {
                str_len += 1;
            }
            if in_string && str_len > MAX_STRING_LITERAL_BYTES {
                return Err(ExecutionError::Deterministic(anyhow!(
                    "call expression string literal too large (max {MAX_STRING_LITERAL_BYTES} bytes)"
                )));
            }
        } else {
            match b {
                b'"' => {
                    in_string = true;
                    str_len = 0;
                }
                b'(' | b'[' | b'{' => {
                    depth += 1;
                    if depth > MAX_EXPR_DEPTH {
                        return Err(ExecutionError::Deterministic(anyhow!(
                            "call expression nested too deeply (max {MAX_EXPR_DEPTH})"
                        )));
                    }
                }
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod expr_limit_tests {
    use super::{MAX_EXPR_DEPTH, MAX_STRING_LITERAL_BYTES, validate_expr};

    #[test]
    fn accepts_normal_expr() {
        assert!(validate_expr("transfer(signer-id(2), 100)").is_ok());
        assert!(validate_expr("noop()").is_ok());
    }

    #[test]
    fn accepts_long_list_arg() {
        // A big binary arg (e.g. a filestorage proof) is a `list<u8>` — parsed
        // iteratively, safe at any size. Must NOT be rejected.
        let elems = (0..60_000).map(|_| "1").collect::<Vec<_>>().join(", ");
        assert!(validate_expr(&format!("f([{elems}])")).is_ok());
    }

    #[test]
    fn rejects_oversized_string_arg() {
        // The exact shape that overflows the parser today.
        let big = format!("f(\"{}\")", "a".repeat(MAX_STRING_LITERAL_BYTES + 1));
        assert!(validate_expr(&big).is_err());
    }

    #[test]
    fn rejects_deep_nesting() {
        let deep = format!(
            "f({}{})",
            "[".repeat(MAX_EXPR_DEPTH + 1),
            "]".repeat(MAX_EXPR_DEPTH + 1)
        );
        assert!(validate_expr(&deep).is_err());
    }

    #[test]
    fn brackets_inside_strings_are_data_not_depth() {
        // A string packed with brackets is content, not structure — must pass.
        let s = format!("f(\"{}\")", "[".repeat(1000));
        assert!(validate_expr(&s).is_ok());
    }

    #[test]
    fn escaped_quote_does_not_end_string() {
        // The escaped quote must not be read as the closer (else the trailing
        // brackets would be miscounted as real nesting).
        let s = format!("f(\"a\\\"{}\")", "[".repeat(1000));
        assert!(validate_expr(&s).is_ok());
    }
}
