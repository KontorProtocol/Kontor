use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use wasmtime::AsContextMut;

use super::Runtime;

#[cfg(test)]
mod tests;

/// Fuel consumed by execution, before gas rounding or minimum billing. Storage
/// reservations are reported separately, even when their writes were reverted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutionUsage {
    pub user_fuel: u64,
    pub system_fuel: u64,
    pub deposit_fuel: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum UsageKind {
    User,
    System,
}

#[derive(Clone, Default)]
pub(crate) struct UsageMeter(Arc<Mutex<ExecutionUsage>>);

impl UsageMeter {
    pub fn record(&self, kind: UsageKind, fuel: u64) -> Result<()> {
        let mut usage = self.0.lock().map_err(|_| anyhow!("usage meter poisoned"))?;
        let total = match kind {
            UsageKind::User => &mut usage.user_fuel,
            UsageKind::System => &mut usage.system_fuel,
        };
        *total = total
            .checked_add(fuel)
            .ok_or_else(|| anyhow!("execution usage overflow"))?;
        Ok(())
    }

    pub fn record_deposit(&self, fuel: u64) -> Result<()> {
        let mut usage = self.0.lock().map_err(|_| anyhow!("usage meter poisoned"))?;
        usage.deposit_fuel = usage
            .deposit_fuel
            .checked_add(fuel)
            .ok_or_else(|| anyhow!("deposit usage overflow"))?;
        Ok(())
    }

    pub fn snapshot(&self) -> Result<ExecutionUsage> {
        let mut usage = *self.0.lock().map_err(|_| anyhow!("usage meter poisoned"))?;
        usage.user_fuel = usage
            .user_fuel
            .checked_sub(usage.deposit_fuel)
            .ok_or_else(|| anyhow!("deposit fuel exceeds measured user fuel"))?;
        Ok(usage)
    }
}

// Sample only at store boundaries, not every host import. Before handing fuel
// to a child, sample the parent; after the handoff, advance its checkpoint past
// the child's work. This also captures child preparation failures whose fuel
// the existing billing path does not forward to the parent.
pub(crate) fn record_fuel(mut store: impl AsContextMut<Data = Runtime>) -> Result<()> {
    let mut store = store.as_context_mut();
    let remaining = store.get_fuel()?;
    store.data_mut().record_fuel(remaining)
}

impl Runtime {
    pub(crate) fn record_fuel(&mut self, remaining: u64) -> Result<()> {
        if let Some(usage) = &self.usage {
            let consumed = self
                .fuel_checkpoint
                .checked_sub(remaining)
                .ok_or_else(|| anyhow!("fuel increased between usage checkpoints"))?;
            usage.record(self.usage_kind, consumed)?;
        }
        self.fuel_checkpoint = remaining;
        Ok(())
    }

    /// Starts an independent measurement scope. Views on other runtimes and
    /// previous operations cannot leak into its totals. Restoring the previous
    /// meter also keeps host-initiated measurement scopes independent.
    pub(crate) fn start_usage(&mut self) -> Option<UsageMeter> {
        self.usage.replace(UsageMeter::default())
    }

    pub(crate) fn finish_usage(&mut self, previous: Option<UsageMeter>) -> Result<ExecutionUsage> {
        let meter = std::mem::replace(&mut self.usage, previous)
            .ok_or_else(|| anyhow!("no execution usage scope"))?;
        meter.snapshot()
    }
}
