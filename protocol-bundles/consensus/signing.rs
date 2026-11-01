use sha3::{Digest, Keccak256};

#[cfg(test)]
pub(crate) use malachitebft_signing_ed25519::PrivateKey;
pub(crate) use malachitebft_signing_ed25519::{Ed25519, PublicKey};

pub(crate) trait Hashable {
    type Output;
    fn hash(&self) -> Self::Output;
}

impl Hashable for PublicKey {
    type Output = [u8; 32];

    fn hash(&self) -> Self::Output {
        Keccak256::digest(self.as_bytes()).into()
    }
}
