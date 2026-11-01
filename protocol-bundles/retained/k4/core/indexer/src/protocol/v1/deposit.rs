use std::sync::Arc;

use tokio::sync::Mutex;

/// Per-op accumulator of the storage-deposit GAS reserved this op — the sum of
/// every `Fuel::Deposit(bytes x D)` charged by `_set_primitive`.
///
/// In the FLOOR model the deposit is a *reservation*, not a cost: it caps how much
/// storage one op can grow (an unaffordable write trips the out-of-gas path during
/// execution) but is REFUNDED at settle — only the execution slice burns. So this
/// is a plain running total: `burn_gas = gas_consumed - charge_gas`, and the
/// `charge_gas` is returned to the payer with the rest of the escrow.
///
/// It needs no savepoint frames: deposit gas is consumed monotonically from the
/// wasm store (a rolled-back nested call's fuel is not restored), and a reverted
/// write's reservation is returned just like a committed one's — so the total to
/// EXCLUDE from the burn is simply all deposit gas consumed this op, with nothing
/// to discard on rollback. Reset per top-level op, drained at settle.
#[derive(Debug, Clone, Default)]
pub struct DepositMeter {
    charge_gas: Arc<Mutex<u64>>,
}

impl DepositMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Zero the accumulator at the start of a top-level op.
    pub async fn reset(&self) {
        *self.charge_gas.lock().await = 0;
    }

    /// Add the deposit gas reserved for one written row.
    pub async fn record_charge(&self, gas: u64) {
        let mut c = self.charge_gas.lock().await;
        *c = c.saturating_add(gas);
    }

    /// Drain the op's reserved deposit gas at the settle boundary, leaving it zero.
    pub async fn take(&self) -> u64 {
        let mut c = self.charge_gas.lock().await;
        std::mem::take(&mut *c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accumulates_and_drains() {
        let m = DepositMeter::new();
        m.record_charge(10).await;
        m.record_charge(5).await;
        assert_eq!(m.take().await, 15);
        // `take` left it zero.
        assert_eq!(m.take().await, 0);
    }

    #[tokio::test]
    async fn reset_zeroes() {
        let m = DepositMeter::new();
        m.record_charge(10).await;
        m.reset().await;
        assert_eq!(m.take().await, 0);
    }
}
