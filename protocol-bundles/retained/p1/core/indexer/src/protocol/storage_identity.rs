use std::sync::Arc;

use super::storage_rows::{CursorOwner, HostFuture};

pub(crate) type LookupIdentity = Arc<dyn Fn(String) -> HostFuture<Option<u64>> + Send + Sync>;
pub(crate) type CreateSigner = Arc<dyn Fn(u64) -> HostFuture<u64> + Send + Sync>;
pub(crate) type WritePubkey = Arc<dyn Fn(u64, String, u64) -> HostFuture<()> + Send + Sync>;
pub(crate) type InitializeNonce = Arc<dyn Fn(u64, u64) -> HostFuture<()> + Send + Sync>;
pub(crate) type ReadPubkey = Arc<dyn Fn(u64) -> HostFuture<Option<String>> + Send + Sync>;
pub(crate) type ReadBls = Arc<dyn Fn(u64) -> HostFuture<Option<Vec<u8>>> + Send + Sync>;
pub(crate) type WriteBls = Arc<dyn Fn(u64, Vec<u8>, u64) -> HostFuture<()> + Send + Sync>;
pub(crate) type ContractSigner = Arc<dyn Fn(u64) -> HostFuture<Option<u64>> + Send + Sync>;
pub(crate) type SignerRecord = (u64, Option<String>, Option<Vec<u8>>, Option<u64>);
pub(crate) type ReadSigner = Arc<dyn Fn(u64) -> HostFuture<Option<SignerRecord>> + Send + Sync>;
pub(crate) type IdentityCallbacks = (
    LookupIdentity,
    CreateSigner,
    WritePubkey,
    InitializeNonce,
    ReadPubkey,
    ReadBls,
    WriteBls,
    ContractSigner,
    ReadSigner,
);
pub(crate) type FirstSigner = Arc<dyn Fn() -> HostFuture<Option<u64>> + Send + Sync>;
pub(crate) type CreateCore = Arc<dyn Fn() -> HostFuture<u64> + Send + Sync>;
pub(crate) type CoreCallbacks = (FirstSigner, CreateCore);
pub(crate) type ReadNonce =
    Arc<dyn Fn(u64) -> HostFuture<(CursorOwner, Option<u64>)> + Send + Sync>;
pub(crate) type WriteNonce = Arc<dyn Fn(CursorOwner, u64, u64) -> HostFuture<()> + Send + Sync>;
pub(crate) type NonceCallbacks = (ReadNonce, WriteNonce);
