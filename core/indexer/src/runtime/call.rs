use anyhow::{Result, anyhow};

use super::ExecutionError;
use futures_util::FutureExt;
use futures_util::future::OptionFuture;
use wasmtime::{
    AsContext, AsContextMut, Store, Trap,
    component::{
        Accessor, Func, Resource, Val,
        wasm_wave::{
            to_string as to_wave_string, untyped::UntypedFuncCall, value::Value as WaveValue,
        },
    },
};

use indexer_types::{OpStatus, Payment};

use crate::database::native_contracts::is_native_contract_id;
use crate::database::types::Identity;

use super::{
    ContractAddress, Runtime,
    fuel::{UsageKind, record_fuel},
    should_skip_result,
    stack::{CallFrame, Stack},
    token,
    wit::{CoreContext, FallContext, Holder, ProcContext, Signer, ViewContext},
};

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

/// The paying account as a `Signer::Id`. Gas hold/release move tokens on its
/// behalf, wrapping it in a `Signer::Core` at the call site so the move is
/// system-authorized rather than the payer acting for themselves.
fn payer_signer(payment: &Payment) -> Signer {
    Signer::Id(Identity::new(payment.signer_id))
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

pub(super) struct CallOutcome {
    pub result: Result<String, ExecutionError>,
    pub remaining_fuel: u64,
}

impl Runtime {
    pub(super) async fn invoke(
        &self,
        contract_address: &ContractAddress,
        signer: Option<&Signer>,
        payment: Option<&Payment>,
        expr: &str,
        fuel_override: Option<u64>,
    ) -> Result<CallOutcome, ExecutionError> {
        // The fuel budget is decided ONCE here, from the signer, so it can't drift
        // across the per-context arms below.
        let fuel_limit = match fuel_override {
            // Nested cross-contract call: inherit the remaining fuel the parent threaded.
            Some(f) => f,
            None => match (signer, payment) {
                // Trusted, system-paid, MUST-COMPLETE consensus work (per-block hooks,
                // issuance, native publishing) — effectively unmetered, regardless of
                // which context the procedure takes. Metering is a DoS/economic control
                // for UNTRUSTED user ops; a finite cap on must-complete system work
                // would eventually false-halt a healthy network on legitimate growth.
                // See `SYSTEM_FUEL_CEILING`.
                (Some(s), _) if s.is_core() => SYSTEM_FUEL_CEILING,
                // User op: metered by the payer's committed gas limit.
                (_, Some(p)) => p.gas_limit * self.gas_to_fuel_multiplier,
                // Read-only `/view`: the operator-configurable view cap.
                (_, None) => self.fuel_limit_for_view(),
            },
        };
        let mut store = self.make_store(fuel_limit)?;
        if fuel_override.is_none() {
            store.data_mut().usage_kind = match signer {
                Some(signer) if !signer.is_core() => UsageKind::User,
                _ => UsageKind::System,
            };
        }
        let mut runtime = store.data().clone();
        let (result, mut store) = runtime
            .invoke_in_store(
                store,
                contract_address,
                signer,
                payment,
                expr,
                fuel_override.is_some(),
            )
            .await?;
        record_fuel(&mut store)?;
        Ok(CallOutcome {
            result,
            remaining_fuel: store.get_fuel().map_err(anyhow::Error::from)?,
        })
    }

    async fn invoke_in_store(
        &mut self,
        mut store: Store<Runtime>,
        contract_address: &ContractAddress,
        signer: Option<&Signer>,
        payment: Option<&Payment>,
        expr: &str,
        nested: bool,
    ) -> Result<(Result<String, ExecutionError>, Store<Runtime>), ExecutionError> {
        let starting_fuel = store.get_fuel().map_err(anyhow::Error::from)?;
        let prepared = match self
            .prepare_in_store(&mut store, contract_address, signer, payment, expr, nested)
            .await
        {
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
            .await;
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
        if frame.is_proc {
            let gas = self
                .gas_consumed(
                    starting_fuel,
                    store.get_fuel().map_err(anyhow::Error::from)?,
                )
                .max(1);
            result = self
                .settle_procedure(
                    signer.expect("procedure requires a signer"),
                    payment,
                    contract_id,
                    contract_address,
                    &func_name,
                    !nested,
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
        // also executes Wasm initialization, whose traps are deterministic;
        // non-trap instantiation failures remain infrastructure errors.
        let instance_pre = linker
            .instantiate_pre(&component)
            .map_err(|e| ExecutionError::Deterministic(e.into()))?;
        let instance = instance_pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| {
                if e.downcast_ref::<Trap>().is_some() {
                    ExecutionError::Deterministic(e.into())
                } else {
                    ExecutionError::NonDeterministic(e.into())
                }
            })?;
        let fallback_name = "fallback";
        let fallback_expr = format!(
            "{}({})",
            fallback_name,
            to_wave_string(&WaveValue::from(expr))
                .map_err(|e| ExecutionError::Deterministic(e.into()))?
        );

        let call =
            UntypedFuncCall::parse(expr).map_err(|e| ExecutionError::Deterministic(e.into()))?;
        let (call, func) = if let Some(func) = instance.get_func(&mut store, call.name()) {
            (call, func)
        } else if let Some(func) = instance.get_func(&mut store, fallback_name) {
            // The fallback wraps the whole expr as one string arg (~2× after
            // escaping), so it too must clear the limit before being parsed.
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

        if is_proc
            && is_top_level
            && let Some(signer) = signer
            && !signer.is_core()
        {
            let payment = payment.expect("payment is required for top-level proc calls");
            let payer = payer_signer(payment);
            let hold_amount = self.pricing.gas_hold(payment.gas_limit)?;
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

        // The depositor stamped on this frame's storage writes = the op's payer,
        // but ONLY when the op will actually floor-check at settle: a top-level op
        // with a NON-core signer (the SAME gate `hold`/`settle` use). A core-signed
        // op bypasses the floor check, so a depositor there would count toward a
        // floor nobody enforces (the stamp gate and the settle gate must agree).
        // `None` = no depositor. Nested frames INHERIT the op's payer from their
        // parent, so a row written deep in a nested call still attributes to it.
        // Because this rides the frame (not a shared atomic), the hold/settle
        // sub-ops can't clobber it — they carry their own (`None`) and pop away.
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
    /// - WASM traps (downcast to wasmtime::Trap) → Contract
    /// - Host Err returns (no Trap) or host panics → Infrastructure
    async fn decode_result(
        is_fallback: bool,
        result: std::result::Result<std::result::Result<(), wasmtime::Error>, String>,
        results: Vec<Val>,
        store: &mut Store<Runtime>,
    ) -> Result<String, ExecutionError> {
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
        } else {
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

    async fn settle_procedure(
        &mut self,
        signer: &Signer,
        payment: Option<&Payment>,
        contract_id: u64,
        contract_address: &ContractAddress,
        func_name: &str,
        is_op_result: bool,
        gas: u64,
        result: Result<String, ExecutionError>,
    ) -> Result<String, ExecutionError> {
        // A top-level non-core op pays its gas here: burn the execution slice and
        // refund the rest of the escrow (incl. the RETURNED storage-deposit
        // reservation) to the payer. The storage-deposit FLOOR is enforced up front
        // on every token debit (`token::transfer`/`hold`/`burn` reject a debit that
        // would leave the balance below `footprint x D`), so there is no settle-time
        // floor check and no op-revert to coordinate — the invocation already
        // committed/rolled back this op's savepoint.
        if is_op_result && !signer.is_core() {
            let payment = payment.expect("payment required for op-result release");
            let payer = payer_signer(payment);
            // The deposit gas reserved this op is RETURNED, not burned (it only
            // capped growth); burn = the execution slice = gas - charge.
            let charge_gas = self.deposit.take().await;
            let burn_amount = self.pricing.execution_fee(gas.saturating_sub(charge_gas))?;
            tracing::info!(
                node = %self.node_label,
                gas,
                charge_gas,
                %burn_amount,
                call_succeeded = result.is_ok(),
                contract = %contract_address,
                func = func_name,
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
        let starting_fuel = accessor.with(|mut access| {
            let remaining = access.as_context().get_fuel()?;
            access.get().record_fuel(remaining)?;
            Ok::<_, anyhow::Error>(remaining)
        })?;

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
        accessor.with(|mut access| {
            access.as_context_mut().set_fuel(outcome.remaining_fuel)?;
            // The child already measured this fuel; only subsequent parent work counts.
            access.get().fuel_checkpoint = outcome.remaining_fuel;
            Ok::<_, anyhow::Error>(())
        })?;
        outcome.result.map_err(Into::into)
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
///   `OpStatus::Trap`. Non-trap errors become `OpStatus::Other`.
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
            } else {
                OpStatus::Other
            }
        }
        Err(ExecutionError::NonDeterministic(_)) => OpStatus::Other,
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

/// Fuel budget for trusted, system-paid, MUST-COMPLETE core calls (per-block hooks,
/// issuance, native publishing) — effectively unmetered. Decided from the signer in
/// `invoke`.
///
/// `i64::MAX as u64`, NOT `u64::MAX`: the remaining fuel is bound into the storage
/// read path as a SQL i64 size-budget (`CASE WHEN size <= :fuel`, contract_state.rs),
/// so it must fit in i64 (`u64::MAX as i64 == -1` would make every core read fail).
/// i64::MAX is the largest i64-safe budget.
///
/// Fork-safe: core fuel never enters the checkpoint hash and the call runs inside the
/// block savepoint, so an over-budget hang can only stall a node a height behind —
/// never fork committed state. `gas_consumed` is a start−end difference, so true usage
/// still records. (The cap does not bound wall-clock work; per-block core work is
/// bounded by design — see the block-lifecycle hooks.)
///
/// CONSENSUS-LOAD-BEARING: all nodes must share this value — a node with a lower budget
/// would stall on a block the others commit. Change only behind a coordinated upgrade.
const SYSTEM_FUEL_CEILING: u64 = i64::MAX as u64;

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
