use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use indexmap::IndexMap;
use wasmtime::AsContextMut;

use super::{Fuel, FuelDiscriminants};
use crate::runtime::Runtime;

#[cfg(test)]
mod tests;

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

#[derive(Default)]
struct RawUsage {
    gross_user_fuel: u64,
    system_fuel: u64,
    deposit_fuel: u64,
}

impl RawUsage {
    fn snapshot(&self) -> Result<ExecutionUsage> {
        Ok(ExecutionUsage {
            user_fuel: self
                .gross_user_fuel
                .checked_sub(self.deposit_fuel)
                .ok_or_else(|| anyhow!("deposit fuel exceeds measured user fuel"))?,
            system_fuel: self.system_fuel,
            deposit_fuel: self.deposit_fuel,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct FuelStats {
    pub consumed_count: u64,
    pub consumed_fuel: u64,
    pub rejected_count: u64,
    pub rejected_fuel: u64,
}

#[derive(Clone, Debug)]
pub struct FuelCharge {
    pub operation: FuelDiscriminants,
    pub fuel: u64,
    pub consumed: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FuelProfile {
    // Includes successfully reserved deposits; use the event/type breakdown to
    // separate these from host work, just as ExecutionUsage does for total fuel.
    pub consumed_host_fuel: u64,
    pub per_type: IndexMap<FuelDiscriminants, FuelStats>,
    pub history: Vec<FuelCharge>,
}

#[derive(Clone, Debug)]
pub struct FuelReport {
    pub usage: ExecutionUsage,
    pub profile: Option<FuelProfile>,
}

struct GaugeState {
    usage: RawUsage,
    profile: Option<Box<FuelProfile>>,
}

#[derive(Clone)]
pub struct FuelGauge {
    state: Arc<Mutex<GaugeState>>,
    // Immutable: ordinary charges can skip the mutex entirely when only the
    // boundary totals are enabled. Detailed storage is allocated only on request.
    profiling: bool,
}

impl Default for FuelGauge {
    fn default() -> Self {
        Self::new()
    }
}

impl FuelGauge {
    pub fn new() -> Self {
        Self::create(false)
    }

    pub fn with_profiling() -> Self {
        Self::create(true)
    }

    fn create(profiling: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(GaugeState {
                usage: RawUsage::default(),
                profile: profiling.then(Box::default),
            })),
            profiling,
        }
    }

    pub(crate) fn track(&self, fuel: &Fuel, consumed: bool) -> Result<()> {
        if !self.profiling {
            return Ok(());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("fuel gauge poisoned"))?;
        let profile = state
            .profile
            .as_deref_mut()
            .ok_or_else(|| anyhow!("missing fuel profile"))?;
        let cost = fuel.cost();
        let operation = fuel.into();
        let stats = profile.per_type.entry(operation).or_default();
        if consumed {
            add(&mut stats.consumed_count, 1)?;
            add(&mut stats.consumed_fuel, cost)?;
            add(&mut profile.consumed_host_fuel, cost)?;
        } else {
            add(&mut stats.rejected_count, 1)?;
            add(&mut stats.rejected_fuel, cost)?;
        }
        profile.history.push(FuelCharge {
            operation,
            fuel: cost,
            consumed,
        });
        Ok(())
    }

    pub(crate) fn record(&self, kind: UsageKind, fuel: u64) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("fuel gauge poisoned"))?;
        let total = match kind {
            UsageKind::User => &mut state.usage.gross_user_fuel,
            UsageKind::System => &mut state.usage.system_fuel,
        };
        add(total, fuel)
    }

    pub(crate) fn record_deposit(&self, fuel: u64) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("fuel gauge poisoned"))?;
        add(&mut state.usage.deposit_fuel, fuel)
    }

    pub fn report(&self) -> Result<FuelReport> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("fuel gauge poisoned"))?;
        Ok(FuelReport {
            usage: state.usage.snapshot()?,
            profile: state.profile.as_deref().cloned(),
        })
    }
}

fn add(total: &mut u64, fuel: u64) -> Result<()> {
    *total = total
        .checked_add(fuel)
        .ok_or_else(|| anyhow!("fuel accounting overflow"))?;
    Ok(())
}

// Sample before handing fuel to a child, then advance the parent's checkpoint
// past the returned fuel. Each child accounts for its own work, including failed
// preparation and result charging that billing does not forward to the parent.
pub(crate) fn record_fuel(mut store: impl AsContextMut<Data = Runtime>) -> Result<()> {
    let mut store = store.as_context_mut();
    let remaining = store.get_fuel()?;
    store.data_mut().record_fuel(remaining)
}

impl Runtime {
    pub(crate) fn record_fuel(&mut self, remaining: u64) -> Result<()> {
        if let Some(gauge) = &self.gauge {
            let consumed = self
                .fuel_checkpoint
                .checked_sub(remaining)
                .ok_or_else(|| anyhow!("fuel increased between usage checkpoints"))?;
            gauge.record(self.usage_kind, consumed)?;
        }
        self.fuel_checkpoint = remaining;
        Ok(())
    }

    pub(crate) fn start_usage(&mut self) -> Option<FuelGauge> {
        self.gauge.replace(FuelGauge::new())
    }

    pub(crate) fn finish_usage(&mut self, previous: Option<FuelGauge>) -> Result<ExecutionUsage> {
        let gauge = std::mem::replace(&mut self.gauge, previous)
            .ok_or_else(|| anyhow!("no fuel accounting scope"))?;
        Ok(gauge.report()?.usage)
    }
}
