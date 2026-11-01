use std::sync::Arc;

use super::storage_rows::HostFuture;

// Structural envelopes keep separately compiled copies type-compatible. Signed
// database fields remain signed until the retained executor validates them.
pub(crate) type BootstrapReceipt = (
    i64,
    String,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    i64,
    i64,
    Option<i64>,
    String,
);
pub(crate) type BootstrapSnapshot = (u64, Vec<BootstrapReceipt>, Option<Vec<u8>>, Option<Vec<u8>>);

pub(crate) type BootstrapRead =
    Arc<dyn Fn(u64, Vec<u8>, Vec<u8>) -> HostFuture<BootstrapSnapshot> + Send + Sync>;
