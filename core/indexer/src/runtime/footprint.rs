use std::sync::Arc;

use tokio::sync::Mutex;

/// Transient, per-op accumulator of the net storage byte-delta attributed to an
/// op's payer. The host tallies the bytes a top-level op writes so a later
/// settle step can fold the delta into the payer's footprint (the storage
/// deposit floor `balance ≥ footprint × D`).
///
/// Phase 0 is OBSERVATION ONLY: nothing here enforces a floor or moves tokens —
/// the net is reset at the top-level op start and read (logged) at the settle
/// boundary. Two follow-ups the net deliberately does not yet capture: the OLD
/// live size on an overwrite/delete (needed to make the delta truly net, not
/// gross-on-write), and exemption of Core/system + core-ledger writes.
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

    /// Add the bytes a write occupies: path (key) bytes + serialized value
    /// bytes. Counting the path matters — keycodec paths can be sizable and the
    /// row's footprint is path + value, not value alone.
    pub async fn record_write(&self, path_len: usize, value_len: usize) {
        *self.net_bytes.lock().await += (path_len + value_len) as i64;
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
    async fn record_write_accumulates_path_plus_value() {
        let m = FootprintMeter::new();
        assert_eq!(m.net().await, 0);
        m.record_write(4, 10).await;
        m.record_write(2, 6).await;
        assert_eq!(m.net().await, 22);
    }

    #[tokio::test]
    async fn reset_zeroes_and_clones_share_inner() {
        let m = FootprintMeter::new();
        m.record_write(3, 7).await;
        // A clone shares the Arc-backed counter, like the store's Runtime clone.
        let cloned = m.clone();
        cloned.record_write(1, 9).await;
        assert_eq!(m.net().await, 20);
        m.reset().await;
        assert_eq!(cloned.net().await, 0);
    }
}
