use std::pin::Pin;

use futures_util::Stream;
pub use indexer_types::Signer;

use crate::database::types::{FileMetadataRow, bytes_to_field_element};
use crate::runtime::kontor::built_in::context::HolderRef;
use crate::runtime::kontor::built_in::{error::Error, file_registry::RawFileDescriptor};
use kontor_crypto::Proof as CryptoProof;
use kontor_crypto::api::{Challenge, FileMetadata as CryptoFileMetadata};
use kontor_crypto::field_from_uniform_bytes;

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

pub struct Holder {
    pub holder_ref: super::kontor::built_in::context::HolderRef,
    pub identity: Option<crate::database::types::Identity>,
}

impl From<&Signer> for HolderRef {
    fn from(signer: &Signer) -> Self {
        match signer {
            Signer::XOnlyPubKey(s) => HolderRef::XOnlyPubkey(s.clone()),
            Signer::ContractId { id_str, .. } => HolderRef::ContractId(id_str.clone()),
            Signer::Core(_) => HolderRef::Core,
            Signer::Nobody => HolderRef::Core,
        }
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
        if bytes_to_field_element(&root).is_none() {
            return Err(Error::Validation(
                "root bytes are not a valid field element".to_string(),
            ));
        }
        Ok(Self {
            file_metadata_row: FileMetadataRow::builder()
                .file_id(raw.file_id)
                .object_id(raw.object_id)
                .nonce(raw.nonce)
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
        // Convert root bytes to FieldElement (root is a Poseidon hash output, already valid)
        let root = bytes_to_field_element(&self.file_metadata_row.root)
            .ok_or_else(|| Error::Validation("Invalid root field element".to_string()))?;

        // Convert 64-byte seed to FieldElement using from_uniform_bytes.
        // The HKDF host function generates 64 bytes for unbiased field element conversion.
        let seed_bytes: [u8; 64] = seed
            .try_into()
            .map_err(|_| Error::Validation("Invalid seed length, expected 64 bytes".to_string()))?;

        // Convert to field element with proper modular reduction (never fails)
        let seed_field = field_from_uniform_bytes(&seed_bytes);

        let file_metadata = CryptoFileMetadata {
            file_id: self.file_metadata_row.file_id.clone(),
            object_id: self.file_metadata_row.object_id.clone(),
            nonce: self.file_metadata_row.nonce.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{create_fake_file_metadata, valid_seed_field};

    #[test]
    fn test_build_challenge_success() {
        let metadata = create_fake_file_metadata("file1", "test.txt", 800000);
        let descriptor = FileDescriptor::from_row(metadata);
        let seed = valid_seed_field(1);
        let result = descriptor.build_challenge(800000, 100, &seed.bytes, "prover1".to_string());
        assert!(result.is_ok());
        let challenge = result.unwrap();
        assert_eq!(challenge.block_height, 800000);
        assert_eq!(challenge.num_challenges, 100);
        assert_eq!(challenge.prover_id, "prover1");
    }

    #[test]
    fn test_build_challenge_invalid_seed_length() {
        let metadata = create_fake_file_metadata("file1", "test.txt", 800000);
        let descriptor = FileDescriptor::from_row(metadata);
        let result = descriptor.build_challenge(800000, 100, &[0u8; 16], "prover1".to_string());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Validation(_)));
    }

    #[test]
    fn test_build_challenge_empty_seed() {
        let metadata = create_fake_file_metadata("file1", "test.txt", 800000);
        let descriptor = FileDescriptor::from_row(metadata);
        assert!(
            descriptor
                .build_challenge(800000, 100, &[], "prover1".to_string())
                .is_err()
        );
    }

    #[test]
    fn test_compute_challenge_id_success() {
        let metadata = create_fake_file_metadata("file1", "test.txt", 800000);
        let descriptor = FileDescriptor::from_row(metadata);
        let seed = valid_seed_field(1);
        let id = descriptor
            .compute_challenge_id(800000, 100, &seed.bytes, "prover1".to_string())
            .unwrap();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_build_challenge_uses_correct_file_metadata() {
        let metadata = create_fake_file_metadata("my_file_id", "metadata_test.txt", 800000);
        let expected_file_id = metadata.file_id.clone();
        let expected_padded_len = metadata.padded_len;
        let expected_original_size = metadata.original_size;
        let expected_filename = metadata.filename.clone();
        let descriptor = FileDescriptor::from_row(metadata);
        let seed = valid_seed_field(1);
        let c = descriptor
            .build_challenge(800000, 100, &seed.bytes, "prover1".to_string())
            .unwrap();
        assert_eq!(c.file_metadata.file_id, expected_file_id);
        assert_eq!(c.file_metadata.padded_len, expected_padded_len as usize);
        assert_eq!(
            c.file_metadata.original_size,
            expected_original_size as usize
        );
        assert_eq!(c.file_metadata.filename, expected_filename);
    }

    #[test]
    fn test_proof_from_bytes_invalid_bytes_fails() {
        assert!(matches!(
            Proof::from_bytes(&[0u8; 100]),
            Err(Error::Validation(_))
        ));
    }

    #[test]
    fn test_proof_from_bytes_empty_bytes_fails() {
        assert!(Proof::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_proof_from_bytes_truncated_header_fails() {
        assert!(Proof::from_bytes(&[0u8; 5]).is_err());
    }

    #[test]
    fn test_proof_from_bytes_wrong_magic_fails() {
        let mut bytes = vec![0u8; 20];
        bytes[0..4].copy_from_slice(b"XXXX");
        assert!(Proof::from_bytes(&bytes).is_err());
    }
}
