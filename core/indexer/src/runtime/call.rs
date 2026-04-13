use anyhow::{Context, Result, anyhow};
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

use stdlib::CheckedArithmetics;

use super::{
    ContractAddress, Decimal, Runtime,
    fuel::Fuel,
    should_skip_result,
    stack::Stack,
    token,
    types::default_val_for_type,
    wit::{CoreContext, FallContext, ProcContext, Signer, ViewContext},
};

impl Runtime {
    pub(crate) async fn prepare_call(
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
            let hold_amount = Decimal::from(fuel_limit)
                .div(Decimal::from(self.gas_to_fuel_multiplier))
                .expect("Failed to convert fuel limit into gas limit")
                .mul(self.gas_to_token_multiplier)
                .expect("Failed to convert gas limit into token limit");
            tracing::info!(
                node = %self.node_label,
                %hold_amount,
                signer = ?signer,
                "Gas hold"
            );
            Box::pin({
                let mut runtime = self.clone();
                async move {
                    token::api::hold(
                        &mut runtime,
                        &Signer::Core(Box::new(signer.clone())),
                        hold_amount,
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

    /// Spawn the WASM call, catch panics, and handle the result.
    /// Returns (call_result, store) — the store is always returned for gas accounting.
    pub(crate) async fn call_and_handle(
        &self,
        mut store: Store<Runtime>,
        func: Func,
        params: Vec<Val>,
        mut results: Vec<Val>,
        is_fallback: bool,
    ) -> Result<(Result<String>, Store<Runtime>)> {
        let (result, results, store) = tokio::spawn(async move {
            match std::panic::AssertUnwindSafe(
                func.call_async(&mut store, &params, &mut results),
            )
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

        let wasm_result = match result {
            Ok(call_result) => call_result.map_err(Into::into),
            Err(panic_msg) => Err(anyhow::anyhow!("host panic: {panic_msg}")),
        };
        let call_result = self.handle_call(is_fallback, wasm_result, results).await;

        Ok((call_result, store))
    }

    pub(crate) async fn handle_call(
        &self,
        is_fallback: bool,
        result: Result<()>,
        mut results: Vec<Val>,
    ) -> Result<String> {
        self.stack.pop().await;

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
                val.to_wave().map_err(Into::into)
            }
        };

        if result.is_err() || result.as_ref().is_ok_and(|val| val.starts_with("err(")) {
            self.storage
                .rollback()
                .await
                .context("Failed to rollback storage after call failure")?;
            self.file_ledger
                .resync_from_db(&self.storage.conn)
                .await
                .context("Failed to resync file ledger after rollback")?;
        } else {
            self.storage
                .commit()
                .await
                .context("Failed to commit storage after successful call")?;
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
            let burn_amount = Decimal::from(gas)
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
                "Gas release"
            );
            Box::pin({
                let mut runtime = self.clone();
                runtime.stack = Stack::new();
                async move {
                    token::api::release(
                        &mut runtime,
                        &Signer::Core(Box::new(signer.clone())),
                        burn_amount,
                    )
                    .await
                }
            })
            .await
            .expect("Failed to run burn and release gas")
            .expect("Failed to burn and release gas");
        }
        if should_skip_result(contract_address, func_name) {
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

        let (
            store,
            contract_id,
            func_name,
            is_fallback,
            params,
            results,
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
}
