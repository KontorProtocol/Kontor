use std::collections::HashMap;
use std::sync::Arc;

use stdlib::CheckedArithmetics;
use tokio::sync::Mutex;

use crate::runtime::Decimal;

/// One call-frame's worth of deposit settlement, mirroring a storage savepoint.
/// `charge_gas` is the GROSS new deposit this frame owes the op payer, denominated
/// in GAS (a slice of the op's fuel budget — see `_set_primitive`). `refunds` are
/// the per-setter token amounts owed for rows this frame freed or displaced
/// (delete, overwrite). Refunds are token, not gas: they are the verbatim
/// `deposited_amount` recorded on each freed row, refunded exactly.
#[derive(Debug, Default)]
struct Frame {
    charge_gas: u64,
    refunds: HashMap<u64, Decimal>,
}

impl Frame {
    /// Fold a child frame into this one on commit (charges add, refunds sum per
    /// setter).
    fn absorb(&mut self, child: Frame) -> anyhow::Result<()> {
        self.charge_gas = self.charge_gas.saturating_add(child.charge_gas);
        for (setter, amount) in child.refunds {
            let sum = match self.refunds.remove(&setter) {
                Some(prev) => prev.add(amount)?,
                None => amount,
            };
            self.refunds.insert(setter, sum);
        }
        Ok(())
    }
}

/// Per-op storage-deposit accumulator, scoped to the storage savepoint stack so a
/// caught-and-continued nested call that ROLLED BACK its writes also drops its
/// charges (its frame is discarded, not merged). The frame stack is driven by the
/// `CallFrame` push/pop (`prepare_call` / `handle_call`) — the same op-execution
/// nesting the storage savepoints follow. When the last frame commits its totals
/// land in `finalized`, which `take` drains at the settle boundary.
///
/// Refund-to-setter is gross-with-attribution, NOT net: an overwrite charges the
/// new payer the full new deposit AND refunds the displaced setter their old
/// deposit. Because it holds a stack + map it needs a `Mutex`, not an atomic.
#[derive(Debug, Default)]
struct DepositState {
    frames: Vec<Frame>,
    /// Committed op total, accumulated as frames unwind to empty. Drained by
    /// `take` at settle.
    finalized: Frame,
}

#[derive(Debug, Clone, Default)]
pub struct DepositMeter {
    inner: Arc<Mutex<DepositState>>,
}

impl DepositMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a frame when a call frame is pushed (mirrors a storage savepoint).
    pub async fn push_frame(&self) {
        self.inner.lock().await.frames.push(Frame::default());
    }

    /// Commit the top frame into its parent (or into `finalized` when it was the
    /// outermost). Mirrors a storage savepoint RELEASE/COMMIT.
    pub async fn commit_frame(&self) -> anyhow::Result<()> {
        let mut s = self.inner.lock().await;
        if let Some(child) = s.frames.pop() {
            match s.frames.last_mut() {
                Some(parent) => parent.absorb(child)?,
                None => s.finalized.absorb(child)?,
            }
        }
        Ok(())
    }

    /// Discard the top frame and everything it accumulated. Mirrors a storage
    /// ROLLBACK — the matching writes are gone, so their charges/refunds must go
    /// too.
    pub async fn discard_frame(&self) {
        self.inner.lock().await.frames.pop();
    }

    /// Record the deposit (in GAS) a newly-written row owes its payer — gross
    /// (overwrites included; the displaced row is refunded separately).
    pub async fn record_charge(&self, gas: u64) {
        let mut s = self.inner.lock().await;
        if let Some(frame) = s.frames.last_mut() {
            frame.charge_gas = frame.charge_gas.saturating_add(gas);
        } else {
            debug_assert!(false, "record_charge with no open deposit frame");
        }
    }

    /// Record a token refund owed to `setter` for a row this op freed/displaced.
    pub async fn record_refund(&self, setter: u64, amount: Decimal) -> anyhow::Result<()> {
        let mut s = self.inner.lock().await;
        let Some(frame) = s.frames.last_mut() else {
            debug_assert!(false, "record_refund with no open deposit frame");
            return Ok(());
        };
        let sum = match frame.refunds.remove(&setter) {
            Some(prev) => prev.add(amount)?,
            None => amount,
        };
        frame.refunds.insert(setter, sum);
        Ok(())
    }

    /// Reset at the start of a top-level op so the accumulator reflects only that
    /// op's writes (across all contracts it touches).
    pub async fn reset(&self) {
        let mut s = self.inner.lock().await;
        s.frames.clear();
        s.finalized = Frame::default();
    }

    /// Take the finalized `(charge_gas, refunds)` at the settle boundary, leaving
    /// the meter reset. `charge_gas` is 0 when the op committed nothing chargeable
    /// (or was rolled back — its frame was discarded).
    pub async fn take(&self) -> (u64, HashMap<u64, Decimal>) {
        let mut s = self.inner.lock().await;
        s.frames.clear();
        let f = std::mem::take(&mut s.finalized);
        (f.charge_gas, f.refunds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(n: u64) -> Decimal {
        Decimal::try_from(n).unwrap()
    }

    #[tokio::test]
    async fn committed_frames_fold_into_finalized() {
        let m = DepositMeter::new();
        m.push_frame().await; // op frame
        m.record_charge(10).await;
        m.record_refund(7, dec(3)).await.unwrap();

        m.push_frame().await; // nested call
        m.record_charge(5).await;
        m.record_refund(7, dec(4)).await.unwrap(); // same setter → batched on merge
        m.record_refund(9, dec(2)).await.unwrap();
        m.commit_frame().await.unwrap(); // nested commits into op frame

        m.commit_frame().await.unwrap(); // op frame commits into finalized

        let (charge_gas, refunds) = m.take().await;
        assert_eq!(charge_gas, 15);
        assert_eq!(refunds.len(), 2);
        assert_eq!(refunds.get(&7), Some(&dec(7)));
        assert_eq!(refunds.get(&9), Some(&dec(2)));

        // `take` left it reset.
        let (charge2, refunds2) = m.take().await;
        assert_eq!(charge2, 0);
        assert!(refunds2.is_empty());
    }

    #[tokio::test]
    async fn discarded_frame_drops_its_charges() {
        let m = DepositMeter::new();
        m.push_frame().await; // op frame
        m.record_charge(10).await;

        m.push_frame().await; // nested call that will roll back
        m.record_charge(99).await;
        m.record_refund(1, dec(50)).await.unwrap();
        m.discard_frame().await; // rolled back → its charges vanish

        m.commit_frame().await.unwrap(); // op frame commits

        let (charge_gas, refunds) = m.take().await;
        assert_eq!(charge_gas, 10);
        assert!(refunds.is_empty());
    }

    #[tokio::test]
    async fn reset_clears() {
        let m = DepositMeter::new();
        m.push_frame().await;
        m.record_charge(10).await;
        m.reset().await;
        let (charge_gas, refunds) = m.take().await;
        assert_eq!(charge_gas, 0);
        assert!(refunds.is_empty());
    }
}
