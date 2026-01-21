use std::pin::Pin;

use futures_util::Stream;
pub use indexer_types::Signer;

use crate::database::types::{FileMetadataRow, bytes_to_field_element};
use crate::runtime::kontor::built_in::{error::Error, file_registry::RawFileDescriptor};
use kontor_crypto::Proof as CryptoProof;
use kontor_crypto::api::{Challenge, FileMetadata as CryptoFileMetadata};

pub trait HasContractId: 'static {
    fn get_contract_id(&self) -> i64;
}

pub struct ViewContext {
    pub contract_id: i64,
}

impl HasContractId for ViewContext {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct ViewStorage {
    pub contract_id: i64,
}

impl HasContractId for ViewStorage {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct ProcStorage {
    pub contract_id: i64,
}

impl HasContractId for ProcStorage {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct ProcContext {
    pub contract_id: i64,
    pub signer: Signer,
}

impl HasContractId for ProcContext {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct FallContext {
    pub contract_id: i64,
    pub signer: Option<Signer>,
}

impl HasContractId for FallContext {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct Keys {
    pub stream: Pin<Box<dyn Stream<Item = Result<String, libsql::Error>> + Send>>,
}

pub struct CoreContext {
    pub contract_id: i64,
    pub signer: Signer,
}

impl HasContractId for CoreContext {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct Transaction {}

pub struct FileDescriptor {
    pub file_metadata_row: FileMetadataRow,
}

impl FileDescriptor {
    pub fn from_row(file_metadata_row: FileMetadataRow) -> Self {
        Self { file_metadata_row }
    }

    pub fn try_from_raw(raw: RawFileDescriptor, height: i64) -> Result<Self, Error> {
        let root: [u8; 32] = raw
            .root
            .try_into()
            .map_err(|_| Error::Validation("expected 32 bytes for root".to_string()))?;
        let nonce: [u8; 32] = raw
            .nonce
            .try_into()
            .map_err(|_| Error::Validation("expected 32 bytes for nonce".to_string()))?;
        Ok(Self {
            file_metadata_row: FileMetadataRow::builder()
                .file_id(raw.file_id)
                .object_id(raw.object_id)
                .nonce(nonce)
                .root(root)
                .padded_len(raw.padded_len)
                .original_size(raw.original_size)
                .filename(raw.filename)
                .height(height)
                .build(),
        })
    }

    /// Build a kontor-crypto Challenge from this FileDescriptor and challenge parameters.
    pub fn build_challenge(
        &self,
        block_height: u64,
        num_challenges: u64,
        seed: &[u8],
        prover_id: String,
    ) -> Result<Challenge, Error> {
        // Convert root bytes to FieldElement
        let root = bytes_to_field_element(&self.file_metadata_row.root)
            .ok_or_else(|| Error::Validation("Invalid root field element".to_string()))?;

        let seed_field = seed_to_field(seed)?;

        let file_metadata = CryptoFileMetadata {
            file_id: self.file_metadata_row.file_id.clone(),
            object_id: self.file_metadata_row.object_id.clone(),
            nonce: self.file_metadata_row.nonce.into(),
            root,
            padded_len: self.file_metadata_row.padded_len as usize,
            original_size: self.file_metadata_row.original_size as usize,
            filename: self.file_metadata_row.filename.clone(),
        };

        Ok(Challenge::new(
            file_metadata,
            block_height,
            num_challenges as usize,
            seed_field,
            prover_id,
        ))
    }

    /// Compute a deterministic challenge ID for this file descriptor.
    pub fn compute_challenge_id(
        &self,
        block_height: u64,
        num_challenges: u64,
        seed: &[u8],
        prover_id: String,
    ) -> Result<String, Error> {
        let challenge = self.build_challenge(block_height, num_challenges, seed, prover_id)?;
        Ok(hex::encode(challenge.id().0))
    }
}

fn seed_to_field(seed: &[u8]) -> Result<kontor_crypto::FieldElement, Error> {
    let uniform: [u8; 64] = seed
        .try_into()
        .map_err(|_| Error::Validation("Seed must be 64 bytes".to_string()))?;
    Ok(kontor_crypto::field_from_uniform_bytes(&uniform))
}

/// A deserialized proof-of-retrievability proof resource.
/// Wraps kontor_crypto::Proof and provides methods for verification.
pub struct Proof {
    pub inner: CryptoProof,
}

impl Proof {
    /// Deserialize a proof from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let inner = CryptoProof::from_bytes(bytes)
            .map_err(|e| Error::Validation(format!("Failed to deserialize proof: {}", e)))?;
        Ok(Self { inner })
    }

    /// Get the challenge IDs this proof covers (hex-encoded).
    pub fn challenge_ids(&self) -> Vec<String> {
        self.inner
            .challenge_ids
            .iter()
            .map(|id| hex::encode(id.0))
            .collect()
    }
}
