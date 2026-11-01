#[path = "../../core/indexer/src/bls/mod.rs"]
mod bls;
#[path = "../../core/indexer/src/protocol/mod.rs"]
mod protocol;
#[path = "../../core/indexer/src/runtime/mod.rs"]
mod runtime;

mod testlib_exports {
    pub use crate::runtime::{
        CheckedArithmetics, FromWaveValue, WaveType, from_wave_expr, from_wave_value,
        numerics as numbers, to_wave_expr, wave_type,
        wit::{
            Signer,
            kontor::built_in::{
                context::{ContractAddress, HolderRef, OutPoint},
                error::Error,
                file_registry::RawFileDescriptor,
                numbers::{Decimal, Integer},
            },
        },
    };
    pub use anyhow::{Error as AnyhowError, Result, anyhow, bail};
    pub use macros::import_test as import;
}

use bitcoin::{Network, p2p::Magic};
use protocol::session::{HostError, HostFuture, SessionExports};
use protocol::storage_callbacks::StorageCallbacks;
use runtime::bundle_session::BundleSession;
use runtime::{ComponentCache, Runtime, Storage};
use std::sync::Arc;

pub type Factory =
    Arc<dyn Fn(StorageCallbacks, [u8; 4], Option<u64>) -> HostFuture<SessionExports> + Send + Sync>;

pub fn factory() -> Result<Factory, HostError> {
    let engine = Runtime::new_engine().map_err(|e| (0, format!("{e:#}")))?;
    let linkers = Runtime::new_linkers(&engine).map_err(|e| (0, format!("{e:#}")))?;
    let cache = ComponentCache::new();
    Ok(Arc::new(move |callbacks, network, view_limit| {
        let engine = engine.clone();
        let linkers = linkers.clone();
        let cache = cache.clone();
        Box::pin(async move {
            let network = Network::from_magic(Magic::from_bytes(network))
                .ok_or_else(|| (2, "invalid executor network".into()))?;
            let storage = Storage::builder()
                .host(callbacks.into())
                .height(if view_limit.is_some() { 1 } else { 0 })
                .build();
            let mut runtime = Runtime::new_with(engine, linkers, cache, storage)
                .await
                .map_err(|e| (0, format!("{e:#}")))?;
            runtime.network = network;
            if let Some(limit) = view_limit {
                runtime.view_gas_limit = limit;
            }
            Ok(BundleSession::export(runtime))
        })
    }))
}
