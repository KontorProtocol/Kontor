use sha2::{Digest, Sha256};

use super::Decimal;

#[derive(Clone, Debug)]
pub struct GenesisParameters {
    pub sigma_min: Decimal,
    pub validators: Vec<GenesisValidator>,
}

#[derive(Clone, Debug)]
pub struct GenesisValidator {
    pub x_only_pubkey: String,
    pub stake: Decimal,
    pub ed25519_pubkey: Vec<u8>,
}

pub fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.into()
}
