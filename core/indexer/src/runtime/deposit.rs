use std::collections::HashMap;
use std::sync::Arc;

use stdlib::CheckedArithmetics;
use tokio::sync::Mutex;

use crate::runtime::Decimal;

/// Per-op storage-deposit accumulator (replaces the observation-only net-i64
/// footprint gauge). During an op it builds the two settlement quantities the
/// vault needs: the gross CHARGE the op payer owes for the rows it writes, and
/// the per-setter REFUNDS owed for rows this op freed or displaced (delete,
/// overwrite, variant-cleanup). Read at the settle boundary.
///
/// Refund-to-setter is gross-with-attribution, NOT net: an overwrite charges the
/// new payer the full new deposit AND refunds the displaced setter their old
/// deposit. Refunds are batched per distinct setter (the map). Because it holds a
/// map it needs a `Mutex` (like `FuelGauge`), not an atomic like the old gauge.
///
/// Observation-only until step 4 wires it into the token `settle` (which moves
/// the tokens). Reset at the top-level op start; `take`n at the settle boundary.
#[derive(Debug, Default)]
struct DepositState {
    /// Total deposit the op payer owes for rows written this op. `None` = zero
    /// (saves needing a `Decimal` zero constant).
    charge: Option<Decimal>,
    /// Per-setter refunds (summed) owed for rows freed/displaced this op.
    refunds: HashMap<u64, Decimal>,
}

#[derive(Debug, Clone, Default)]
pub struct DepositMeter {
    inner: Arc<Mutex<DepositState>>,
}

impl DepositMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the deposit a newly-written row owes its payer — gross (every new
    /// row adds, overwrites included; the displaced row is refunded separately).
    pub async fn record_charge(&self, amount: Decimal) -> anyhow::Result<()> {
        let mut s = self.inner.lock().await;
        s.charge = Some(match s.charge.take() {
            Some(c) => c.add(amount)?,
            None => amount,
        });
        Ok(())
    }

    /// Record a refund owed to `setter` for a row this op freed/displaced.
    pub async fn record_refund(&self, setter: u64, amount: Decimal) -> anyhow::Result<()> {
        let mut s = self.inner.lock().await;
        let sum = match s.refunds.remove(&setter) {
            Some(prev) => prev.add(amount)?,
            None => amount,
        };
        s.refunds.insert(setter, sum);
        Ok(())
    }

    /// Reset at the start of a top-level op so the accumulator reflects only that
    /// op's writes (across all contracts it touches).
    pub async fn reset(&self) {
        let mut s = self.inner.lock().await;
        s.charge = None;
        s.refunds.clear();
    }

    /// Take the accumulated `(charge, refunds)` at the settle boundary, leaving it
    /// reset. `charge` is `None` when the op wrote nothing chargeable.
    pub async fn take(&self) -> (Option<Decimal>, HashMap<u64, Decimal>) {
        let mut s = self.inner.lock().await;
        (s.charge.take(), std::mem::take(&mut s.refunds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(n: u64) -> Decimal {
        Decimal::try_from(n).unwrap()
    }

    #[tokio::test]
    async fn charge_sums_and_refunds_batch_per_setter() {
        let m = DepositMeter::new();
        m.record_charge(dec(10)).await.unwrap();
        m.record_charge(dec(5)).await.unwrap();
        m.record_refund(7, dec(3)).await.unwrap();
        m.record_refund(7, dec(4)).await.unwrap(); // same setter → batched
        m.record_refund(9, dec(2)).await.unwrap();

        let (charge, refunds) = m.take().await;
        assert_eq!(charge, Some(dec(15)));
        assert_eq!(refunds.len(), 2);
        assert_eq!(refunds.get(&7), Some(&dec(7)));
        assert_eq!(refunds.get(&9), Some(&dec(2)));

        // `take` left it reset.
        let (charge2, refunds2) = m.take().await;
        assert_eq!(charge2, None);
        assert!(refunds2.is_empty());
    }

    #[tokio::test]
    async fn reset_clears() {
        let m = DepositMeter::new();
        m.record_charge(dec(10)).await.unwrap();
        m.record_refund(1, dec(1)).await.unwrap();
        m.reset().await;
        let (charge, refunds) = m.take().await;
        assert_eq!(charge, None);
        assert!(refunds.is_empty());
    }
}
