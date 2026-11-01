use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::{Result, ensure};

use super::{Runtime, pricing::Pricing};
use crate::protocol::execution::{ExecutorVersion, SelectionEnvelope};
use crate::protocol::v1::gas::{
    DEFAULT_NON_PROC_GAS_LIMIT, GAS_TO_FUEL_MULTIPLIER, MAX_UNTRUSTED_GAS_LIMIT,
    SYSTEM_FUEL_CEILING,
};
use crate::protocol::v1::resources::GuestMemoryLimits;

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
    selection: SelectionEnvelope,
    gas: SelectedGasPolicy,
    pricing: Pricing,
    memory: GuestMemoryLimits,
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
    fn verify_selection_envelope(&self, selection: &SelectionEnvelope) -> Result<()> {
        ensure!(
            selection.1 == self.network.magic().to_bytes(),
            "executor selection network mismatch"
        );
        ensure!(
            selection.0 == self.executor_version().tag(),
            "runtime does not match selected executor"
        );
        let valid_position = matches!(
            selection.3,
            (0 | 1, 0, None, 0)
                | (2, _, _, 0)
                | (5, _, None, 0)
                | (3 | 4, _, Some(_), _)
                | (6, _, None, 1)
                | (6, 0, None, 0)
                | (7, 0, None, _)
        );
        ensure!(
            valid_position,
            "invalid executor selection position envelope"
        );
        Ok(())
    }

    fn resolve_selection(&self, selection: &SelectionEnvelope) -> Result<Arc<SelectedContext>> {
        self.verify_selection_envelope(selection)?;
        Ok(match &self.selected_context {
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
                    self.executor_version(),
                    (selection.3.0 == 0).then_some(self.view_gas_limit),
                ),
                memory: match self.executor_version() {
                    ExecutorVersion::LegacyP1 => GuestMemoryLimits::default(),
                },
                pricing: match self.executor_version() {
                    ExecutorVersion::LegacyP1 => Pricing::default(),
                },
            }),
        })
    }

    pub(super) fn install_root_selection(&mut self, selection: &SelectionEnvelope) -> Result<()> {
        ensure!(
            self.selected_context.is_none(),
            "executor root already has a selection"
        );
        self.selected_context = Some(self.resolve_selection(selection)?);
        Ok(())
    }

    pub(crate) fn bind_selection(
        &mut self,
        selection: &SelectionEnvelope,
    ) -> Result<SelectedRuntime<'_>> {
        let context = self.resolve_selection(selection)?;
        let previous = self.selected_context.replace(context);
        Ok(SelectedRuntime {
            runtime: self,
            previous,
        })
    }

    pub(super) fn verify_selected_runtime(&self) -> Result<()> {
        if let Some(context) = &self.selected_context {
            self.verify_selection_envelope(&context.selection)?;
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

    pub(super) fn selected_memory_limits(&self) -> Option<GuestMemoryLimits> {
        self.selected_context
            .as_ref()
            .map(|context| context.memory)
            .or(self.guest_memory_limits)
    }

    pub(crate) fn selected_pricing(&self) -> Pricing {
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
    use wasmtime::{Memory, MemoryType};

    use super::*;
    use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
    use crate::protocol::v1::types::Identity;
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
            let mut selected = runtime.bind_selection(&selection.envelope())?;
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
    async fn selected_memory_policy_survives_mutation_and_shares_nested_usage() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        runtime.guest_memory_limits = Some(GuestMemoryLimits {
            per_root: 0,
            ..GuestMemoryLimits::default()
        });
        let selection = select_legacy_p1(
            &runtime.get_storage_conn(),
            runtime.network,
            ApplicationPosition::View,
        )
        .await?;
        let mut root = {
            let mut selected = runtime.bind_selection(&selection.envelope())?;
            selected.guest_memory_limits = None;
            selected.make_store(100)?
        };
        let _memory = Memory::new(&mut root, MemoryType::new(1, Some(1))?)?;
        root.data_mut().guest_memory_limits = None;
        let mut child = root.data().make_store(100)?;
        let _child_memory = Memory::new(&mut child, MemoryType::new(1, Some(1))?)?;
        let limiter = root.data().guest_memory_limiter.as_ref().unwrap();
        ensure!(limiter.admitted() == 2 * 65_536);
        ensure!(child.data().selected_memory_limits().unwrap().per_root == 512 * 1024 * 1024);
        drop(child);
        ensure!(
            root.data()
                .guest_memory_limiter
                .as_ref()
                .unwrap()
                .admitted()
                == 65_536
        );
        Ok(())
    }

    #[tokio::test]
    async fn selection_envelope_rejects_foreign_or_ambiguous_context() -> Result<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let envelope = select_legacy_p1(
            &runtime.get_storage_conn(),
            runtime.network,
            ApplicationPosition::View,
        )
        .await?
        .envelope();
        let mut foreign = envelope.clone();
        foreign.0 = u32::MAX;
        ensure!(runtime.bind_selection(&foreign).is_err());
        foreign = envelope.clone();
        foreign.1 = Network::Bitcoin.magic().to_bytes();
        ensure!(runtime.bind_selection(&foreign).is_err());
        for position in [
            (0, 1, None, 0),
            (1, 0, Some([0; 32]), 0),
            (2, 0, None, 1),
            (3, 1, None, 1),
            (4, 1, None, 1),
            (5, 1, Some([0; 32]), 0),
            (u8::MAX, 0, None, 0),
        ] {
            let mut malformed = envelope.clone();
            malformed.3 = position;
            ensure!(runtime.bind_selection(&malformed).is_err());
        }
        let mut selected = runtime.bind_selection(&envelope)?;
        for field in 0..7 {
            let mut changed = envelope.clone();
            match field {
                0 => changed.2.0.push('x'),
                1 => changed.2.1 += 1,
                2 => changed.2.2 = Some(u64::MAX),
                3 => changed.2.3 = Some("different block".into()),
                4 => changed.2.4 += 1,
                5 => changed.2.5 = Some(u64::MAX),
                6 => changed.2.6 = Some("different checkpoint".into()),
                _ => unreachable!(),
            }
            ensure!(selected.bind_selection(&changed).is_err());
        }
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
            let mut selected = runtime.bind_selection(&selection.envelope())?;
            ensure!(selected.bind_selection(&other.envelope()).is_err());
            {
                let nested = selected.bind_selection(&selection.envelope())?;
                ensure!(nested.selected_context.is_some());
            }
            ensure!(selected.selected_context.is_some());
            pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        };
        ensure!(future.now_or_never().is_none());
        ensure!(runtime.selected_context.is_none());
        runtime.view_gas_limit = 0;
        let selected = runtime.bind_selection(&other.envelope())?;
        ensure!(
            selected.fuel_limit_for_view()? == MAX_UNTRUSTED_GAS_LIMIT * GAS_TO_FUEL_MULTIPLIER
        );
        Ok(())
    }
}
