use bon::Builder;
use ff::PrimeField;
use kontor_crypto::{FieldElement, FileDescriptor};

pub use super::storage_identity::CORE_SIGNER_ID;

/// Convert a 32-byte array to a FieldElement.
/// Returns None if the bytes don't represent a valid field element.
pub fn bytes_to_field_element(bytes: &[u8; 32]) -> Option<FieldElement> {
    FieldElement::from_repr((*bytes).into()).into_option()
}

/// Convert a FieldElement to a 32-byte array.
pub fn field_element_to_bytes(fe: &FieldElement) -> [u8; 32] {
    fe.to_repr().into()
}

/// Merkle tree depth for a file whose padded leaf count is `padded_len` (a power of
/// two): `log2(padded_len)`, or 0 for an empty file. Assumes `padded_len` was already
/// validated by [`validate_padded_len`] at the host trust boundary — `trailing_zeros`
/// silently yields a wrong depth for a non-power-of-two.
pub fn padded_len_to_depth(padded_len: u64) -> usize {
    if padded_len == 0 {
        0
    } else {
        padded_len.trailing_zeros() as usize
    }
}

/// Validate that `padded_len` is a positive power of two (the leaf count of a full
/// binary Merkle tree) and return its depth. The contract enforces this too, but the
/// host re-checks at its trust boundary: a non-power-of-two would pass `trailing_zeros`
/// and produce a wrong depth → wrong aggregated root / challenge indices.
pub fn validate_padded_len(padded_len: u64) -> Result<usize, &'static str> {
    if padded_len == 0 || !padded_len.is_power_of_two() {
        return Err("padded_len must be a positive power of 2");
    }
    Ok(padded_len.trailing_zeros() as usize)
}

/// Validate that `root` is exactly 32 bytes encoding a canonical field element,
/// returning both the byte array (for storage) and the decoded `FieldElement`. The
/// `Err` is a ready-to-show message; callers wrap it in their error type. This is
/// the single root-validation gate shared by descriptor parsing and `aggregate_root`.
pub fn validate_root(root: &[u8]) -> Result<([u8; 32], FieldElement), &'static str> {
    let bytes: [u8; 32] = root.try_into().map_err(|_| "expected 32 bytes for root")?;
    let fe = bytes_to_field_element(&bytes).ok_or("root bytes are not a valid field element")?;
    Ok((bytes, fe))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    signer_id: u64,
    key: String,
}

impl Identity {
    pub fn new(signer_id: u64) -> Self {
        Self {
            signer_id,
            key: signer_id.to_string(),
        }
    }

    pub fn signer_id(&self) -> u64 {
        self.signer_id
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

/// In-memory file metadata carried by the `FileDescriptor` host resource — the
/// fields the deleted `file_metadata` DB row held, minus the row bookkeeping
/// (`id`/`height`/`historical_root`). Matches kontor-crypto's `FileMetadata`.
#[derive(Debug, Clone, Builder)]
pub struct FileMeta {
    pub file_id: String,
    pub object_id: String,
    pub nonce: Vec<u8>,
    pub root: [u8; 32],
    pub padded_len: u64,
    pub original_size: u64,
    pub filename: String,
}

impl FileDescriptor for FileMeta {
    fn file_id(&self) -> &str {
        &self.file_id
    }

    fn root(&self) -> FieldElement {
        bytes_to_field_element(&self.root).expect("Invalid field element bytes for root")
    }

    fn depth(&self) -> usize {
        padded_len_to_depth(self.padded_len)
    }
}
