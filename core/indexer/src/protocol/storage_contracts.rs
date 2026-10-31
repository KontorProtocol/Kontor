use std::sync::Arc;

use super::storage_rows::HostFuture;

pub(crate) type Address = (String, u64, u32);
pub(crate) type ContractWrite = (String, u64, u32, u64, Vec<u8>, Option<u64>);
pub(crate) type ProvenanceWrite = (u64, u64, u64, u32, Vec<u8>);
pub(crate) type ResultWrite = (
    u64,
    u64,
    String,
    u64,
    Option<u64>,
    Option<u32>,
    Option<u32>,
    u32,
    u64,
    Option<String>,
    u64,
    Option<u64>,
    String,
);
pub(crate) type CreateSigner = Arc<dyn Fn(u64) -> HostFuture<u64> + Send + Sync>;
pub(crate) type InsertContract = Arc<dyn Fn(ContractWrite) -> HostFuture<u64> + Send + Sync>;
pub(crate) type FindContract = Arc<dyn Fn(Address) -> HostFuture<Option<u64>> + Send + Sync>;
pub(crate) type ReadAddress = Arc<dyn Fn(u64) -> HostFuture<Option<Address>> + Send + Sync>;
pub(crate) type ReadBytes = Arc<dyn Fn(u64) -> HostFuture<Option<Vec<u8>>> + Send + Sync>;
pub(crate) type InsertProvenance = Arc<dyn Fn(ProvenanceWrite) -> HostFuture<u64> + Send + Sync>;
pub(crate) type ReadPublisher = Arc<dyn Fn(u64) -> HostFuture<Option<u64>> + Send + Sync>;
pub(crate) type InsertResult = Arc<dyn Fn(ResultWrite) -> HostFuture<u64> + Send + Sync>;
pub(crate) type ContractCallbacks = (
    CreateSigner,
    InsertContract,
    FindContract,
    ReadAddress,
    ReadBytes,
    InsertProvenance,
    ReadPublisher,
    InsertResult,
);
