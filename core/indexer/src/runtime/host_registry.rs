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
}

impl built_in::registry::Host for Runtime {}

impl built_in::registry::HostWithStore for Runtime {
    /// Consume fuel for a RegisterBlsKey operation. The reactor performs
    /// the actual signature verification and DB write in
    /// `Runtime::register_bls_key` outside the contract boundary; this
    /// host call exists so the contract's fuel accounting reflects the
    /// real cost of the op. Insufficient fuel traps the caller.
    async fn register_bls_key<T>(accessor: &Accessor<T, Self>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._register_bls_key(accessor)
            .await
    }
}
