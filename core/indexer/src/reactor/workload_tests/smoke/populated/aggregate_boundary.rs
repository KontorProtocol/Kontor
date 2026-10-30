use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::{Result, ensure};
use indexer_types::{ContractAddress, Inst, InstKind, OpStatus, ResultRow};
use serde_json::Value;

use super::mixed::MixedLayout;
use super::pagination;
use super::views::{self, CounterProgress, ViewConfig};
use super::{ANCHOR_HEIGHT, GAS_LIMIT, state, test_provenance};
use crate::bls::MAX_BLS_BULK_OPS;
use crate::runtime::wit::Signer;
use crate::runtime::workload_telemetry::WorkloadTelemetry;
use crate::runtime::{MAX_UNTRUSTED_GAS_LIMIT, Runtime, TransactionContext, from_wave_expr};

const VIEW_KEYS: usize = 257;

pub(super) struct CounterBoundary {
    contract: ContractAddress,
    fuel_target: Option<ContractAddress>,
}

impl CounterBoundary {
    pub(super) async fn prepare(
        runtime: &mut Runtime,
        fuel_target: Option<ContractAddress>,
    ) -> Result<Self> {
        ensure!(MAX_BLS_BULK_OPS == 10_000);
        ensure!(GAS_LIMIT == MAX_UNTRUSTED_GAS_LIMIT);
        if let Some(target) = &fuel_target {
            ensure!(state(runtime, target).await? == [0, 0, 0, 0]);
        }
        let contract = ContractAddress {
            name: "c".into(),
            height: ANCHOR_HEIGHT,
            tx_index: 7,
        };
        runtime
            .set_context(
                ANCHOR_HEIGHT,
                Some(TransactionContext::builder().tx_index(7).build()),
                None,
                None,
            )
            .await;
        runtime
            .publish(
                &Signer::Core(Box::new(Signer::Nobody)),
                runtime.core_payment(),
                &contract.name,
                include_bytes!("../../../../../../../test-contracts/binaries/counter.wasm.br"),
                &test_provenance()?,
            )
            .await?;
        ensure!(
            from_wave_expr::<u64>(&runtime.execute_system_view(&contract, "get()").await?) == 0
        );
        pagination::prepare(runtime, VIEW_KEYS).await?;
        Ok(Self {
            contract,
            fuel_target,
        })
    }

    pub(super) fn instructions(&self) -> Vec<Inst> {
        // Compact calls reach the operation cap without exceeding compose's
        // independent script-data cap. The mixed recipe tests different work.
        vec![self.instruction(); MAX_BLS_BULK_OPS]
    }

    pub(super) fn instruction(&self) -> Inst {
        Inst {
            gas_limit: GAS_LIMIT,
            kind: InstKind::Call {
                contract: self.fuel_target.as_ref().unwrap_or(&self.contract).clone(),
                expr: if self.fuel_target.is_some() {
                    "trap-out-of-fuel()"
                } else {
                    "increment()"
                }
                .into(),
            },
        }
    }

    pub(super) async fn run_with_views<T>(
        &self,
        directory: &Path,
        restore: &str,
        before: &Value,
        operations: usize,
        telemetry: Option<Arc<WorkloadTelemetry>>,
        work: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        ensure!(operations > 0);
        let maximum = if self.fuel_target.is_some() {
            0
        } else {
            u64::try_from(operations)?
        };
        views::run_target(
            directory,
            restore,
            ViewConfig {
                live_keys: VIEW_KEYS,
                historical_rows: 0,
            },
            before,
            self.contract.clone(),
            CounterProgress {
                maximum,
                completed: Arc::new(AtomicU64::new(maximum)),
                telemetry,
            },
            work,
        )
        .await
    }

    pub(super) async fn check(
        &self,
        runtime: &mut Runtime,
        roots: &[&ResultRow],
        layout: MixedLayout,
        height: u64,
        operations: usize,
    ) -> Result<()> {
        ensure!(operations > 0 && roots.len() == operations);
        let target = self
            .fuel_target
            .as_ref()
            .unwrap_or(&self.contract)
            .to_string();
        let function = if self.fuel_target.is_some() {
            "trap-out-of-fuel"
        } else {
            "increment"
        };
        for (index, row) in roots.iter().enumerate() {
            let (tx, input, op) = layout.position(index)?;
            ensure!(
                row.height == height
                    && row.tx_index == Some(tx)
                    && row.input_index == Some(input)
                    && row.op_index == Some(op)
                    && row.result_index == 0
                    && row.contract == target
                    && row.func == function
                    && row.signer_id == layout.signer(index)
                    && row.payer_signer_id == Some(layout.payer())
                    && if self.fuel_target.is_some() {
                        row.status == OpStatus::OutOfFuel
                            && row.value.is_none()
                            && row.gas == GAS_LIMIT
                    } else {
                        row.status == OpStatus::Ok
                            && row.value.as_deref() == Some("")
                            && row.gas > 0
                            && row.gas <= GAS_LIMIT
                    },
                "boundary receipt {index} differs"
            );
        }
        ensure!(
            from_wave_expr::<u64>(&runtime.execute_system_view(&self.contract, "get()").await?)
                == if self.fuel_target.is_some() {
                    0
                } else {
                    u64::try_from(operations)?
                }
        );
        if let Some(target) = &self.fuel_target {
            ensure!(state(runtime, target).await? == [0, 0, 0, 0]);
        }
        Ok(())
    }
}
