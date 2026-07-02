use std::pin::Pin;
use std::str::FromStr;

use bitcoin::{Txid, XOnlyPublicKey};
use futures_util::Stream;

use crate::database::types::{
    CORE_SIGNER_ID, FileMeta, Identity, bytes_to_field_element, validate_padded_len, validate_root,
};
use crate::runtime::Runtime;
use crate::runtime::kontor::built_in::context::HolderRef;
use crate::runtime::kontor::built_in::{error::Error, file_registry_types::RawFileDescriptor};
use kontor_crypto::Proof as CryptoProof;
use kontor_crypto::api::{Challenge, FileMetadata as CryptoFileMetadata};
use kontor_crypto::field_from_uniform_bytes;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Signer {
    Id(Identity),
    Core(Box<Signer>),
    Contract {
        id: u64,
        signer_id: u64,
        key: String,
    },
    Nobody,
}

impl Signer {
    pub fn new_contract(id: u64, signer_id: u64) -> Self {
        Self::Contract {
            id,
            signer_id,
            key: signer_id.to_string(),
        }
    }

    pub fn is_core(&self) -> bool {
        matches!(self, Signer::Core(_))
    }

    /// The effective signer_id for attribution purposes.
    /// - `Id` → the identity's signer_id
    /// - `Core(Nobody)` → the reserved `CORE_SIGNER_ID`
    /// - `Core(inner)` → unwraps to inner's signer_id
    /// - `Contract` → the contract's signer_id
    /// - `Nobody` → None (only valid inside `Core`)
    pub fn signer_id(&self) -> Option<u64> {
        match self {
            Signer::Id(identity) => Some(identity.signer_id()),
            Signer::Core(inner) => match inner.as_ref() {
                Signer::Nobody => Some(CORE_SIGNER_ID),
                _ => inner.signer_id(),
            },
            Signer::Contract { signer_id, .. } => Some(*signer_id),
            Signer::Nobody => None,
        }
    }
}

impl core::ops::Deref for Signer {
    type Target = str;

    fn deref(&self) -> &str {
        match self {
            Self::Id(identity) => identity.key(),
            Self::Core(_) => "core",
            Self::Contract { key, .. } => key,
            Self::Nobody => "nobody",
        }
    }
}

impl core::fmt::Display for Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", &**self)
    }
}

impl From<&Signer> for HolderRef {
    fn from(signer: &Signer) -> Self {
        match signer {
            Signer::Id(identity) => HolderRef::SignerId(identity.signer_id()),
            Signer::Contract { signer_id, .. } => HolderRef::SignerId(*signer_id),
            Signer::Core(_) => HolderRef::Core,
            Signer::Nobody => unreachable!("Nobody signer has no HolderRef"),
        }
    }
}
pub trait HasContractId: 'static {
    fn get_contract_id(&self) -> u64;
}

pub struct ViewContext {
    pub contract_id: u64,
}

impl HasContractId for ViewContext {
    fn get_contract_id(&self) -> u64 {
        self.contract_id
    }
}

pub struct ViewStorage {
    pub contract_id: u64,
}

impl HasContractId for ViewStorage {
    fn get_contract_id(&self) -> u64 {
        self.contract_id
    }
}

pub struct ProcStorage {
    pub contract_id: u64,
}

impl HasContractId for ProcStorage {
    fn get_contract_id(&self) -> u64 {
        self.contract_id
    }
}

pub struct ProcContext {
    pub contract_id: u64,
    pub signer: Signer,
    /// Who pays this op's gas. A `Holder` (not a `Signer`) by design —
    /// contracts can credit but not spend on the payer's behalf, since
    /// the payer only consented to pay this op's gas. Defaults to
    /// `signer.as_holder()`; redirected by a cross-input `Sponsor` Inst
    /// (direct context) or by `AggregateSigner.sponsored = true`
    /// (aggregate context). Constructed at the top-level call site from
    /// `op.metadata.payment.signer_id`.
    pub payer: Holder,
}

impl HasContractId for ProcContext {
    fn get_contract_id(&self) -> u64 {
        self.contract_id
    }
}

pub struct FallContext {
    pub contract_id: u64,
    pub signer: Option<Signer>,
    /// See `ProcContext.payer`. `None` when `signer` is also `None` (a
    /// fall context with no acting signer has no payer either).
    pub payer: Option<Holder>,
}

impl HasContractId for FallContext {
    fn get_contract_id(&self) -> u64 {
        self.contract_id
    }
}

pub struct Keys {
    // Each item is a child key's codec element bytes (see stdlib::keycodec); the
    // guest decodes it to `K`.
    pub stream:
        Pin<Box<dyn Stream<Item = Result<Vec<u8>, crate::database::queries::Error>> + Send>>,
}

pub struct IndexRows {
    // The covering-scan cursor: each item is `(member-element, projection-value)` for
    // one live index leaf (see the `index-rows` WIT resource). The member is the same
    // bytes `Keys` yields; the value is the leaf's covering projection.
    pub stream: Pin<
        Box<dyn Stream<Item = Result<(Vec<u8>, Vec<u8>), crate::database::queries::Error>> + Send>,
    >,
}

pub struct CoreContext {
    pub contract_id: u64,
    pub signer: Signer,
}

impl HasContractId for CoreContext {
    fn get_contract_id(&self) -> u64 {
        self.contract_id
    }
}

/// Host-side state for the `kontor:built-in/context.contract` resource.
/// Holds the executing contract's address as known to the runtime; the
/// resource handle is the integrity-bound proof that the executing
/// contract IS this address — only the host can populate one (via
/// `proc-context.self` / `core-context.self`), so a contract can never
/// fabricate a handle pointing at a different address.
#[derive(Clone)]
pub struct Contract {
    pub address: crate::runtime::ContractAddress,
}

#[derive(Clone)]
pub struct Holder {
    pub holder_ref: HolderRef,
}

impl Holder {
    /// Build a Holder for a known signer_id without a DB lookup. Used at
    /// op-execution time to construct `ProcContext.payer` from
    /// `op.metadata.payment.signer_id`, which is already a resolved
    /// signer (set by `walker.materialize` per the override rules).
    pub fn for_signer_id(signer_id: u64) -> Self {
        Self {
            holder_ref: HolderRef::SignerId(signer_id),
        }
    }

    pub async fn from_holder_ref(
        mut holder_ref: HolderRef,
        runtime: &Runtime,
    ) -> Result<Self, Error> {
        match &holder_ref {
            HolderRef::XOnlyPubkey(s) => {
                // Canonicalize to lowercase hex. Whether we *resolve*
                // (lookup) or *resolve-or-create* the signer row is the
                // runtime's call: inside a view frame, this is
                // lookup-only and yields a deterministic Err on miss
                // rather than silently inserting signer rows from a
                // read-only API path.
                let pk = XOnlyPublicKey::from_str(s)
                    .map_err(|e| Error::Validation(format!("invalid x-only-pubkey: {e}")))?;
                let identity = runtime
                    .get_or_create_identity(&pk.to_string())
                    .await
                    .map_err(|e| Error::Validation(format!("identity resolution failed: {e}")))?;
                holder_ref = HolderRef::SignerId(identity.signer_id());
            }
            HolderRef::SignerId(_) => {}
            HolderRef::Utxo(out_point) => {
                Txid::from_str(&out_point.txid)
                    .map_err(|e| Error::Validation(format!("invalid txid: {e}")))?;
            }
            HolderRef::Core | HolderRef::Burner => {}
        }

        Ok(Self { holder_ref })
    }
}

pub struct Transaction {}

pub struct FileDescriptor {
    pub meta: FileMeta,
}

impl FileDescriptor {
    pub fn from_meta(meta: FileMeta) -> Self {
        Self { meta }
    }

    pub fn try_from_raw(raw: RawFileDescriptor) -> Result<Self, Error> {
        let (root, _) = validate_root(&raw.root).map_err(|m| Error::Validation(m.to_string()))?;
        validate_padded_len(raw.padded_len).map_err(|m| Error::Validation(m.to_string()))?;
        Ok(Self {
            meta: FileMeta::builder()
                .file_id(raw.file_id)
                .object_id(raw.object_id)
                .nonce(raw.nonce)
                .root(root)
                .padded_len(raw.padded_len)
                .original_size(raw.original_size)
                .filename(raw.filename)
                .build(),
        })
    }

    /// Build a kontor-crypto Challenge from this FileDescriptor and challenge parameters.
    pub fn build_challenge(
        &self,
        block_height: u64,
        num_challenges: u64,
        seed: &[u8],
        prover_id: u64,
    ) -> Result<Challenge, Error> {
        // Convert root bytes to FieldElement (root is a Poseidon hash output, already valid)
        let root = bytes_to_field_element(&self.meta.root)
            .ok_or_else(|| Error::Validation("Invalid root field element".to_string()))?;

        // Convert 64-byte seed to FieldElement using from_uniform_bytes.
        // The HKDF host function generates 64 bytes for unbiased field element conversion.
        let seed_bytes: [u8; 64] = seed
            .try_into()
            .map_err(|_| Error::Validation("Invalid seed length, expected 64 bytes".to_string()))?;

        // Convert to field element with proper modular reduction (never fails)
        let seed_field = field_from_uniform_bytes(&seed_bytes);

        let file_metadata = CryptoFileMetadata {
            file_id: self.meta.file_id.clone(),
            object_id: self.meta.object_id.clone(),
            nonce: self.meta.nonce.clone(),
            root,
            padded_len: self.meta.padded_len as usize,
            original_size: self.meta.original_size as usize,
            filename: self.meta.filename.clone(),
        };

        Ok(Challenge::new(
            file_metadata,
            block_height,
            num_challenges as usize,
            seed_field,
            prover_challenge_key(prover_id),
        ))
    }

    /// Compute a deterministic challenge ID for this file descriptor.
    pub fn compute_challenge_id(
        &self,
        block_height: u64,
        num_challenges: u64,
        seed: &[u8],
        prover_id: u64,
    ) -> Result<String, Error> {
        let challenge = self.build_challenge(block_height, num_challenges, seed, prover_id)?;
        Ok(hex::encode(challenge.id().0))
    }
}

/// The single source of truth for how a prover's `signer_id` is bound into a
/// challenge hash: as its decimal string. Both the host (`build_challenge`) and
/// the test proof generators go through this, so the format that feeds the
/// (consensus-relevant) challenge id is defined in exactly one place.
pub fn prover_challenge_key(signer_id: u64) -> String {
    signer_id.to_string()
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{create_fake_file_metadata, valid_seed_field};

    #[test]
    fn test_signer_signer_id_id() {
        let signer = Signer::Id(Identity::new(42));
        assert_eq!(signer.signer_id(), Some(42));
    }

    #[test]
    fn test_signer_signer_id_core_nobody() {
        let signer = Signer::Core(Box::new(Signer::Nobody));
        assert_eq!(signer.signer_id(), Some(CORE_SIGNER_ID));
    }

    #[test]
    fn test_signer_signer_id_core_id_unwraps() {
        let signer = Signer::Core(Box::new(Signer::Id(Identity::new(42))));
        assert_eq!(signer.signer_id(), Some(42));
    }

    #[test]
    fn test_signer_signer_id_core_core_recursive() {
        let signer = Signer::Core(Box::new(Signer::Core(Box::new(Signer::Id(Identity::new(
            42,
        ))))));
        assert_eq!(signer.signer_id(), Some(42));
    }

    #[test]
    fn test_signer_signer_id_contract() {
        let signer = Signer::new_contract(3, 7);
        assert_eq!(signer.signer_id(), Some(7));
    }

    #[test]
    fn test_signer_signer_id_nobody() {
        assert_eq!(Signer::Nobody.signer_id(), None);
    }

    #[test]
    fn test_build_challenge_success() {
        let metadata = create_fake_file_metadata("file1", "test.txt");
        let descriptor = FileDescriptor::from_meta(metadata);
        let seed = valid_seed_field(1);
        let result = descriptor.build_challenge(800000, 100, &seed.bytes, 1u64);
        assert!(result.is_ok());
        let challenge = result.unwrap();
        assert_eq!(challenge.block_height, 800000);
        assert_eq!(challenge.num_challenges, 100);
        // `build_challenge` binds the prover as its decimal string (see
        // `prover_challenge_key`).
        assert_eq!(challenge.prover_id, "1");
    }

    #[test]
    fn test_build_challenge_invalid_seed_length() {
        let metadata = create_fake_file_metadata("file1", "test.txt");
        let descriptor = FileDescriptor::from_meta(metadata);
        let result = descriptor.build_challenge(800000, 100, &[0u8; 16], 1u64);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Validation(_)));
    }

    #[test]
    fn test_build_challenge_empty_seed() {
        let metadata = create_fake_file_metadata("file1", "test.txt");
        let descriptor = FileDescriptor::from_meta(metadata);
        assert!(descriptor.build_challenge(800000, 100, &[], 1u64).is_err());
    }

    #[test]
    fn test_compute_challenge_id_success() {
        let metadata = create_fake_file_metadata("file1", "test.txt");
        let descriptor = FileDescriptor::from_meta(metadata);
        let seed = valid_seed_field(1);
        let id = descriptor
            .compute_challenge_id(800000, 100, &seed.bytes, 1u64)
            .unwrap();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_build_challenge_uses_correct_file_metadata() {
        let metadata = create_fake_file_metadata("my_file_id", "metadata_test.txt");
        let expected_file_id = metadata.file_id.clone();
        let expected_padded_len = metadata.padded_len;
        let expected_original_size = metadata.original_size;
        let expected_filename = metadata.filename.clone();
        let descriptor = FileDescriptor::from_meta(metadata);
        let seed = valid_seed_field(1);
        let c = descriptor
            .build_challenge(800000, 100, &seed.bytes, 1u64)
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
