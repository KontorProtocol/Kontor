use anyhow::Result;
use wasmtime::component::Accessor;

use super::{Runtime, fuel::Fuel, wit::kontor::built_in};

impl Runtime {
    async fn _register_bls_key<T>(&self, accessor: &Accessor<T, Self>) -> Result<()> {
        Fuel::RegisterBlsKey
            .consume(accessor, self.gauge.as_ref())
            .await?;
        Ok(())
    }

    async fn _update_provenance<T>(&self, accessor: &Accessor<T, Self>) -> Result<()> {
        Fuel::UpdateProvenance
            .consume(accessor, self.gauge.as_ref())
            .await?;
        Ok(())
    }
}

impl built_in::system::Host for Runtime {}

impl<T> built_in::system::HostWithStore<T> for Runtime {
    /// Consume fuel for a RegisterBlsKey operation. The reactor performs
    /// the actual signature verification and DB write in
    /// `Runtime::register_bls_key` outside the contract boundary; this
    /// host call exists so the contract's fuel accounting reflects the
    /// real cost of the op. Insufficient fuel traps the caller.
    async fn register_bls_key(accessor: &Accessor<T, Self>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._register_bls_key(accessor)
            .await
    }

    /// Consume fuel for an UpdateProvenance operation. The reactor performs
    /// the owner authz check and the provenance-log append in
    /// `Runtime::update_provenance` outside the contract boundary; this host
    /// call exists so the contract's fuel accounting reflects the op's cost.
    /// Insufficient fuel traps the caller.
    async fn update_provenance(accessor: &Accessor<T, Self>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._update_provenance(accessor)
            .await
    }
}
