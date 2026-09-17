use crate::runtime::kontor::built_in::context::OutPoint;

/// `bitcoin::OutPoint` → wit shape (a free fn: both types are foreign here now
/// that `OutPoint` comes from the shared `built-in-types`).
pub fn outpoint_from_bitcoin(value: bitcoin::OutPoint) -> OutPoint {
    OutPoint {
        txid: value.txid.to_string(),
        vout: value.vout,
    }
}
