use std::sync::Arc;

use anyhow::{Result, ensure};

use super::bundle_ownership::HostError;
use super::bundle_session::{BundleSession, infrastructure};
use super::{ContractAddress, ExecutionError, Runtime};
use crate::protocol::execution::SelectionEnvelope;
use crate::protocol::operations::{
    BeginUnitCall, CommitteeCall, ContractWitCall, LifecycleCall, SessionOwner, ViewCall,
};
use crate::protocol::v1::committee::derive_committee;
use crate::protocol::v1::lifecycle::run_block_lifecycle;

impl BundleSession {
    pub(crate) fn lifecycle(self: &Arc<Self>) -> LifecycleCall {
        let expected = self.clone();
        Arc::new(move |opaque, selection| {
            let session = expected.clone();
            Box::pin(async move {
                session.verify_operation_owner(opaque)?;
                let mut runtime = session.runtime.lock().await;
                runtime
                    .verify_bundle_operation(&selection, 3)
                    .map_err(infrastructure)?;
                let mut runtime = runtime.bind_selection(&selection).map_err(infrastructure)?;
                let (_, height, Some(hash), _) = selection.3 else {
                    return Err((2, "lifecycle requires a selected block hash".into()));
                };
                if runtime.storage.savepoint_stack.is_empty().await {
                    return Err((2, "lifecycle requires an open canonical unit".into()));
                }
                let previous = runtime.start_usage();
                let result = run_block_lifecycle(&mut runtime, height, hash).await;
                let usage = runtime.finish_usage(previous);
                // Preserve execution-error precedence while restoring accounting
                // even when the lifecycle itself fails.
                result.map_err(infrastructure)?;
                let usage = usage.map_err(infrastructure)?;
                Ok((usage.user_fuel, usage.system_fuel, usage.deposit_fuel))
            })
        })
    }

    pub(crate) fn begin_unit(self: &Arc<Self>) -> BeginUnitCall {
        let expected = self.clone();
        Arc::new(move |opaque, selection| {
            let session = expected.clone();
            Box::pin(async move {
                session.verify_operation_owner(opaque)?;
                let mut runtime = session.runtime.lock().await;
                runtime
                    .verify_bundle_operation(&selection, selection.3.0)
                    .map_err(infrastructure)?;
                if !matches!(selection.3.0, 1 | 3 | 4 | 5) {
                    return Err((2, "executor unit requires a canonical selection".into()));
                }
                let runtime = runtime.bind_selection(&selection).map_err(infrastructure)?;
                if !runtime.storage.savepoint_stack.is_empty().await {
                    return Err((2, "executor unit transaction is already open".into()));
                }
                runtime.storage.savepoint().await.map_err(infrastructure)
            })
        })
    }

    pub(crate) fn contract_wit(self: &Arc<Self>) -> ContractWitCall {
        let expected = self.clone();
        Arc::new(move |opaque, selection, address| {
            let session = expected.clone();
            Box::pin(async move {
                session.verify_operation_owner(opaque)?;
                let mut runtime = session.runtime.lock().await;
                runtime
                    .verify_bundle_operation(&selection, 0)
                    .map_err(infrastructure)?;
                let runtime = runtime.bind_selection(&selection).map_err(infrastructure)?;
                let address = ContractAddress {
                    name: address.0,
                    height: address.1,
                    tx_index: address.2,
                };
                match runtime
                    .storage
                    .contract_id(&address)
                    .await
                    .map_err(infrastructure)?
                {
                    Some(id) => runtime
                        .storage
                        .component_wit(id)
                        .await
                        .map(Some)
                        .map_err(infrastructure),
                    None => Ok(None),
                }
            })
        })
    }

    pub(crate) fn view(self: &Arc<Self>) -> ViewCall {
        let expected = self.clone();
        Arc::new(move |opaque, selection, address, expression| {
            let session = expected.clone();
            Box::pin(async move {
                session.verify_operation_owner(opaque)?;
                let mut runtime = session.runtime.lock().await;
                runtime
                    .verify_bundle_operation(&selection, 0)
                    .map_err(infrastructure)?;
                let mut runtime = runtime.bind_selection(&selection).map_err(infrastructure)?;
                let address = ContractAddress {
                    name: address.0,
                    height: address.1,
                    tx_index: address.2,
                };
                Ok(runtime
                    .execute(None, None, &address, &expression)
                    .await
                    .map_err(|error| {
                        (
                            matches!(&error, ExecutionError::Deterministic(_)),
                            format!("{error:?}"),
                        )
                    }))
            })
        })
    }

    pub(crate) fn committee(self: &Arc<Self>) -> CommitteeCall {
        let expected = self.clone();
        Arc::new(move |opaque, selection| {
            let session = expected.clone();
            Box::pin(async move {
                session.verify_operation_owner(opaque)?;
                let mut runtime = session.runtime.lock().await;
                runtime
                    .verify_bundle_operation(&selection, 1)
                    .map_err(infrastructure)?;
                let mut runtime = runtime.bind_selection(&selection).map_err(infrastructure)?;
                derive_committee(&mut runtime).await.map_err(infrastructure)
            })
        })
    }

    pub(super) fn verify_operation_owner(
        self: &Arc<Self>,
        opaque: SessionOwner,
    ) -> Result<(), HostError> {
        let supplied = opaque
            .downcast::<Self>()
            .map_err(|_| (2, "executor session has the wrong type".into()))?;
        if !Arc::ptr_eq(&supplied, self) {
            return Err((2, "executor session has the wrong identity".into()));
        }
        Ok(())
    }
}

impl Runtime {
    pub(super) fn verify_bundle_operation(
        &self,
        selection: &SelectionEnvelope,
        purpose: u8,
    ) -> Result<()> {
        ensure!(
            self.bundle_owner.is_some() && self.selected_context.is_some(),
            "executor operation requires an admitted selected root"
        );
        ensure!(
            selection.3.0 == purpose,
            "executor operation selection purpose mismatch"
        );
        Ok(())
    }
}
