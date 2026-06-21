use std::sync::Arc;

use tokio::sync::Mutex;

/// Transient, per-op accumulator of the net storage byte-delta attributed to an
/// op's payer. The host tallies the bytes a top-level op writes so a later
/// settle step can fold the delta into the payer's footprint (the storage
/// deposit floor `balance ≥ footprint × D`).
///
/// Phase 0 is OBSERVATION ONLY: nothing here enforces a floor or moves tokens —
/// the net is reset at the top-level op start and read (logged) at the settle
/// boundary. The net is a true delta: a write adds `path + value` on first
/// create and the value delta on overwrite, a delete subtracts the freed bytes.
/// One narrow case is not yet netted — `delete_matching_paths` (intra-block
/// enum/option variant cleanup) doesn't materialize row sizes, so a variant
/// switch slightly OVER-counts footprint until the enforcement phase. Exemption
/// of Core/system + core-ledger writes is also deferred to enforcement (the
/// observation phase counts all contracts uniformly).
///
/// Shared across `Runtime` clones via `Arc` — the store holds a clone (see
/// `make_store`) and host writes run against it, exactly like `FuelGauge`.
#[derive(Debug, Clone, Default)]
pub struct FootprintMeter {
    net_bytes: Arc<Mutex<i64>>,
}

impl FootprintMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a signed byte delta to the op's net: positive for bytes a write
    /// adds (path + value on create, value delta on overwrite), negative for
    /// bytes a delete frees. The caller computes the delta; the meter just sums.
    pub async fn record_delta(&self, delta: i64) {
        *self.net_bytes.lock().await += delta;
    }

    pub async fn net(&self) -> i64 {
        *self.net_bytes.lock().await
    }

    /// Reset the accumulator at the start of a top-level op so the net reflects
    /// only that op's writes (across all contracts it touches).
    pub async fn reset(&self) {
        *self.net_bytes.lock().await = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_delta_sums_signed() {
        let m = FootprintMeter::new();
        assert_eq!(m.net().await, 0);
        m.record_delta(14).await; // create: path + value
        m.record_delta(6).await; // overwrite grows value by 6
        m.record_delta(-20).await; // delete frees the row
        assert_eq!(m.net().await, 0);
    }

    #[tokio::test]
    async fn reset_zeroes_and_clones_share_inner() {
        let m = FootprintMeter::new();
        m.record_delta(10).await;
        // A clone shares the Arc-backed counter, like the store's Runtime clone.
        let cloned = m.clone();
        cloned.record_delta(10).await;
        assert_eq!(m.net().await, 20);
        m.reset().await;
        assert_eq!(cloned.net().await, 0);
    }
}
