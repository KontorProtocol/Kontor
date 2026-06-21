use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

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
/// Backed by a single `AtomicI64` (the meter guards one scalar — unlike
/// `FuelGauge`, which needs a `Mutex` for its history/per-type stats). Shared
/// across `Runtime` clones via `Arc` — the store holds a clone (see
/// `make_store`) and host writes run against it. `Relaxed` ordering is correct:
/// the counter gates no other shared memory, and the read at the settle boundary
/// is sequenced after every write by the op-boundary task joins (the wasm call's
/// `tokio::spawn(..).await`), which supply the happens-before.
#[derive(Debug, Clone, Default)]
pub struct FootprintGauge {
    net_bytes: Arc<AtomicI64>,
}

impl FootprintGauge {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a signed byte delta to the op's net: positive for bytes a write
    /// adds (path + value on create, value delta on overwrite), negative for
    /// bytes a delete frees. The caller computes the delta; the gauge just sums.
    pub fn record_delta(&self, delta: i64) {
        self.net_bytes.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn net(&self) -> i64 {
        self.net_bytes.load(Ordering::Relaxed)
    }

    /// Reset the accumulator at the start of a top-level op so the net reflects
    /// only that op's writes (across all contracts it touches).
    pub fn reset(&self) {
        self.net_bytes.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_delta_sums_signed() {
        let g = FootprintGauge::new();
        assert_eq!(g.net(), 0);
        g.record_delta(14); // create: path + value
        g.record_delta(6); // overwrite grows value by 6
        g.record_delta(-20); // delete frees the row
        assert_eq!(g.net(), 0);
    }

    #[test]
    fn reset_zeroes_and_clones_share_inner() {
        let g = FootprintGauge::new();
        g.record_delta(10);
        // A clone shares the Arc-backed counter, like the store's Runtime clone.
        let cloned = g.clone();
        cloned.record_delta(10);
        assert_eq!(g.net(), 20);
        g.reset();
        assert_eq!(cloned.net(), 0);
    }
}
