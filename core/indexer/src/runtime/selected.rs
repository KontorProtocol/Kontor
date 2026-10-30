use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::{Result, ensure};

use super::{Runtime, pricing::Pricing};
use crate::protocol::coordinator::selection::{ExecutionSelection, ExecutorVersion};
use crate::protocol::v1::gas::{
    DEFAULT_NON_PROC_GAS_LIMIT, GAS_TO_FUEL_MULTIPLIER, MAX_UNTRUSTED_GAS_LIMIT,
    SYSTEM_FUEL_CEILING,
};

#[derive(Clone, Copy)]
pub(super) struct SelectedGasPolicy {
    pub non_proc_allowance: u64,
    pub untrusted_allowance: u64,
    pub fuel_multiplier: u64,
    pub system_fuel: u64,
    pub view_allowance: u64,
}

impl SelectedGasPolicy {
    fn resolve(version: ExecutorVersion, public_view_allowance: Option<u64>) -> Self {
        match version {
            ExecutorVersion::LegacyP1 => Self {
                non_proc_allowance: DEFAULT_NON_PROC_GAS_LIMIT,
                untrusted_allowance: MAX_UNTRUSTED_GAS_LIMIT,
                fuel_multiplier: GAS_TO_FUEL_MULTIPLIER,
                system_fuel: SYSTEM_FUEL_CEILING,
                view_allowance: public_view_allowance.unwrap_or(MAX_UNTRUSTED_GAS_LIMIT),
            },
        }
    }
}

pub(super) struct SelectedContext {
    selection: ExecutionSelection,
    gas: SelectedGasPolicy,
    pricing: Pricing,
}

// This guard restores only semantic context. Storage authority, child joining
// and cancellation remain with the existing owner service. Child Runtime clones
// retain the same immutable context even when the caller's future is dropped.
pub(crate) struct SelectedRuntime<'a> {
    runtime: &'a mut Runtime,
    previous: Option<Arc<SelectedContext>>,
}

impl Deref for SelectedRuntime<'_> {
    type Target = Runtime;

    fn deref(&self) -> &Self::Target {
        self.runtime
    }
}

impl DerefMut for SelectedRuntime<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.runtime
    }
}

impl Drop for SelectedRuntime<'_> {
    fn drop(&mut self) {
        self.runtime.selected_context = self.previous.take();
    }
}

impl Runtime {
    pub(crate) fn bind_selection(
        &mut self,
        selection: &ExecutionSelection,
    ) -> Result<SelectedRuntime<'_>> {
        selection.ensure_runtime(self.network, self.executor_version())?;
        let context = match &self.selected_context {
            Some(context) => {
                ensure!(
                    context.selection == *selection,
                    "nested execution cannot replace its root selection"
                );
                context.clone()
            }
            None => Arc::new(SelectedContext {
                selection: selection.clone(),
                gas: SelectedGasPolicy::resolve(
                    selection.version(),
                    selection.is_public_view().then_some(self.view_gas_limit),
                ),
                pricing: match selection.version() {
                    ExecutorVersion::LegacyP1 => Pricing::default(),
                },
            }),
        };
        let previous = self.selected_context.replace(context);
        Ok(SelectedRuntime {
            runtime: self,
            previous,
        })
    }

    pub(super) fn verify_selected_runtime(&self) -> Result<()> {
        if let Some(context) = &self.selected_context {
            context
                .selection
                .ensure_runtime(self.network, self.executor_version())?;
        }
        Ok(())
    }

    pub(super) fn selected_gas_policy(&self) -> SelectedGasPolicy {
        self.selected_context
            .as_ref()
            .map(|context| context.gas)
            .unwrap_or(SelectedGasPolicy {
                non_proc_allowance: self.gas_limit_for_non_procs,
                untrusted_allowance: MAX_UNTRUSTED_GAS_LIMIT,
                fuel_multiplier: self.gas_to_fuel_multiplier,
                system_fuel: SYSTEM_FUEL_CEILING,
                view_allowance: self.view_gas_limit,
            })
    }

    pub(super) fn selected_pricing(&self) -> Pricing {
        self.selected_context
            .as_ref()
            .map_or(self.pricing, |context| context.pricing)
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;

    use bitcoin::Network;
    use futures_util::FutureExt;
    use indexer_types::Payment;

    use super::*;
    use crate::database::types::Identity;
    use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
    use crate::runtime::Decimal;
    use crate::runtime::wit::Signer;
    use crate::test_utils::test_runtime;

    #[tokio::test]
    async fn selected_policy_is_immutable_and_inherited_by_guest_stores() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        runtime.view_gas_limit = 17;
        let selection = select_legacy_p1(
            &runtime.get_storage_conn(),
            runtime.network,
            ApplicationPosition::View,
        )
        .await?;
        let mut child = {
            let mut selected = runtime.bind_selection(&selection)?;
            selected.gas_to_fuel_multiplier = 1;
            selected.gas_limit_for_non_procs = 1;
            selected.view_gas_limit = 1;
            selected.pricing = Pricing::new(Decimal::default(), 9)?;
            let child = selected.make_store(7)?;
            ensure!(Arc::ptr_eq(
                selected.selected_context.as_ref().unwrap(),
                child.data().selected_context.as_ref().unwrap()
            ));
            ensure!(selected.fuel_limit_for_view()? == 17 * GAS_TO_FUEL_MULTIPLIER);
            ensure!(selected.core_payment().gas_limit == DEFAULT_NON_PROC_GAS_LIMIT);
            ensure!(selected.selected_pricing().storage_deposit_gas(1) == Some(1));
            ensure!(
                selected.selected_pricing().execution_fee(1)?
                    == Pricing::default().execution_fee(1)?
            );
            child
        };
        ensure!(runtime.selected_context.is_none());
        ensure!(child.data().fuel_limit_for_view()? == 17 * GAS_TO_FUEL_MULTIPLIER);
        let signer = Signer::Id(Identity::new(1));
        let payment = Payment {
            signer_id: 1,
            gas_limit: MAX_UNTRUSTED_GAS_LIMIT,
        };
        ensure!(
            child
                .data()
                .call_fuel_limit(Some(&signer), Some(&payment), None)?
                == MAX_UNTRUSTED_GAS_LIMIT * GAS_TO_FUEL_MULTIPLIER
        );
        ensure!(
            child
                .data()
                .call_fuel_limit(Some(&signer), Some(&payment), Some(7))?
                == 7
        );
        child.data_mut().network = Network::Bitcoin;
        ensure!(child.data().make_store(7).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_scope_restores_context_and_nested_reselection_is_rejected() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let selection = select_legacy_p1(
            &runtime.get_storage_conn(),
            runtime.network,
            ApplicationPosition::View,
        )
        .await?;
        let other = select_legacy_p1(
            &runtime.get_storage_conn(),
            runtime.network,
            ApplicationPosition::Committee,
        )
        .await?;
        let future = async {
            let mut selected = runtime.bind_selection(&selection)?;
            ensure!(selected.bind_selection(&other).is_err());
            {
                let nested = selected.bind_selection(&selection)?;
                ensure!(nested.selected_context.is_some());
            }
            ensure!(selected.selected_context.is_some());
            pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        };
        ensure!(future.now_or_never().is_none());
        ensure!(runtime.selected_context.is_none());
        runtime.view_gas_limit = 0;
        let selected = runtime.bind_selection(&other)?;
        ensure!(
            selected.fuel_limit_for_view()? == MAX_UNTRUSTED_GAS_LIMIT * GAS_TO_FUEL_MULTIPLIER
        );
        Ok(())
    }
}
