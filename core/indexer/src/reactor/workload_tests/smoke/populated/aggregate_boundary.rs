use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::{Context, Result, ensure};
use indexer_types::{ContractAddress, Inst, InstKind, OpStatus, ResultRow};
use serde_json::Value;

use super::mixed::MixedLayout;
use super::pagination;
use super::views::{self, CounterProgress, ViewConfig};
use super::{ANCHOR_HEIGHT, GAS_LIMIT, state, test_provenance};
use crate::bls::MAX_BLS_BULK_OPS;
use crate::database::queries::get_contract_provenance_log;
use crate::runtime::wit::Signer;
use crate::runtime::workload_telemetry::WorkloadTelemetry;
use crate::runtime::{
    MAX_UNTRUSTED_GAS_LIMIT, Runtime, TransactionContext, from_wave_expr, to_wave_expr,
};

const VIEW_KEYS: usize = 257;

pub(super) enum BoundaryOperation {
    Increment,
    ExhaustFuel(ContractAddress),
    Publish,
}

pub(super) struct BoundaryWorkload {
    contract: ContractAddress,
    operation: BoundaryOperation,
    instruction: Inst,
}

impl BoundaryWorkload {
    pub(super) async fn prepare(
        runtime: &mut Runtime,
        operation: BoundaryOperation,
    ) -> Result<Self> {
        ensure!(MAX_BLS_BULK_OPS == 10_000);
        ensure!(GAS_LIMIT == MAX_UNTRUSTED_GAS_LIMIT);
        if let BoundaryOperation::ExhaustFuel(target) = &operation {
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
        let kind = match &operation {
            BoundaryOperation::Increment => InstKind::Call {
                contract: contract.clone(),
                expr: "increment()".into(),
            },
            BoundaryOperation::ExhaustFuel(target) => InstKind::Call {
                contract: target.clone(),
                expr: "trap-out-of-fuel()".into(),
            },
            BoundaryOperation::Publish => InstKind::Publish {
                name: "published-counter".into(),
                bytes: include_bytes!(
                    "../../../../../../../test-contracts/binaries/counter.wasm.br"
                )
                .to_vec(),
                provenance: test_provenance()?,
            },
        };
        Ok(Self {
            contract,
            operation,
            instruction: Inst {
                gas_limit: GAS_LIMIT,
                kind,
            },
        })
    }

    pub(super) fn instructions(&self) -> Vec<Inst> {
        // Compact calls reach the operation cap without exceeding compose's
        // independent script-data cap. The mixed recipe tests different work.
        vec![self.instruction(); MAX_BLS_BULK_OPS]
    }

    pub(super) fn instruction(&self) -> Inst {
        self.instruction.clone()
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
        let maximum = if !matches!(self.operation, BoundaryOperation::Increment) {
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
        if matches!(self.operation, BoundaryOperation::Publish) {
            return self
                .check_publications(runtime, roots, layout, height)
                .await;
        }
        let fuel_target = match &self.operation {
            BoundaryOperation::ExhaustFuel(target) => Some(target),
            _ => None,
        };
        let target = fuel_target.unwrap_or(&self.contract).to_string();
        let function = if fuel_target.is_some() {
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
                    && if fuel_target.is_some() {
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
                == if fuel_target.is_some() {
                    0
                } else {
                    u64::try_from(operations)?
                }
        );
        if let Some(target) = fuel_target {
            ensure!(state(runtime, target).await? == [0, 0, 0, 0]);
        }
        Ok(())
    }

    async fn check_publications(
        &self,
        runtime: &mut Runtime,
        roots: &[&ResultRow],
        layout: MixedLayout,
        height: u64,
    ) -> Result<()> {
        let InstKind::Publish {
            name,
            bytes,
            provenance,
        } = &self.instruction.kind
        else {
            anyhow::bail!("publication workload has a non-publication instruction");
        };
        let encoded_provenance = postcard::to_allocvec(provenance)?;
        for (index, row) in roots.iter().enumerate() {
            let (tx, input, op) = layout.position(index)?;
            // Receipts project the Kontor transaction ordinal, while publication
            // addresses/provenance retain the raw Bitcoin position (commit + reveal).
            let raw_index = u32::try_from(index)?
                .checked_mul(2)
                .and_then(|value| value.checked_add(2))
                .context("publication position overflow")?;
            let address = ContractAddress {
                name: name.clone(),
                height,
                tx_index: raw_index,
            };
            ensure!(
                row.height == height
                    && row.tx_index == Some(tx)
                    && row.input_index == Some(input)
                    && row.op_index == Some(op)
                    && row.result_index == 0
                    && row.contract == address.to_string()
                    && row.func == "init"
                    && row.status == OpStatus::Ok
                    && row.value.as_deref() == Some(to_wave_expr(address.clone()).as_str())
                    && row.signer_id == layout.signer(index)
                    && row.payer_signer_id == Some(layout.payer())
                    && row.gas > 0
                    && row.gas <= GAS_LIMIT,
                "publication receipt {index} differs"
            );
            let id = runtime
                .storage
                .contract_id(&address)
                .await?
                .context("published contract missing")?;
            ensure!(runtime.storage.contract_bytes(id).await?.as_ref() == Some(bytes));
            let log = get_contract_provenance_log(&runtime.get_storage_conn(), id).await?;
            ensure!(
                log.len() == 1
                    && log[0].contract_id == id
                    && log[0].author_signer_id == layout.signer(index)
                    && log[0].height == height
                    && log[0].tx_index == raw_index
                    && log[0].provenance == encoded_provenance,
                "publication provenance {index} differs"
            );
            ensure!(
                from_wave_expr::<u64>(&runtime.execute_system_view(&address, "get()").await?) == 0
            );
        }
        ensure!(
            from_wave_expr::<u64>(&runtime.execute_system_view(&self.contract, "get()").await?)
                == 0
        );
        Ok(())
    }
}
