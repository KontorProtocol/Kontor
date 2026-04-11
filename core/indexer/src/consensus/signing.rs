use async_trait::async_trait;
use bytes::Bytes;

use malachitebft_core_types::{SignedExtension, SignedProposal, SignedVote};
use malachitebft_signing::{Error, SigningProvider, VerificationResult};

use crate::consensus::{Ctx, Proposal, Vote};

pub use malachitebft_signing_ed25519::*;

/// Generate a deterministic private key from a seed byte array.
pub fn private_key_from_seed(seed: [u8; 32]) -> PrivateKey {
    PrivateKey::from(seed)
}

/// Generate a random private key (for follower/sync-only nodes).
pub fn generate_random_private_key() -> PrivateKey {
    let key_bytes: [u8; 32] = rand::random();
    PrivateKey::from(key_bytes)
}

/// Parse a hex-encoded Ed25519 private key.
pub fn private_key_from_hex(hex_str: &str) -> PrivateKey {
    let key_bytes = hex::decode(hex_str).expect("Invalid consensus private key hex");
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .expect("Ed25519 private key must be 32 bytes");
    PrivateKey::from(key_array)
}

pub trait Hashable {
    type Output;
    fn hash(&self) -> Self::Output;
}

impl Hashable for PublicKey {
    type Output = [u8; 32];

    fn hash(&self) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(self.as_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug)]
pub struct Ed25519Provider {
    private_key: PrivateKey,
}

impl Ed25519Provider {
    pub fn new(private_key: PrivateKey) -> Self {
        Self { private_key }
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        self.private_key.sign(data)
    }

    pub fn verify(&self, data: &[u8], signature: &Signature, public_key: &PublicKey) -> bool {
        public_key.verify(data, signature).is_ok()
    }
}

#[async_trait]
impl SigningProvider<Ctx> for Ed25519Provider {
    async fn sign_bytes(&self, bytes: &[u8]) -> Result<Signature, Error> {
        Ok(self.sign(bytes))
    }

    async fn verify_signed_bytes(
        &self,
        bytes: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        if self.verify(bytes, signature, public_key) {
            Ok(VerificationResult::Valid)
        } else {
            Ok(VerificationResult::Invalid)
        }
    }

    async fn sign_vote(&self, vote: Vote) -> Result<SignedVote<Ctx>, Error> {
        let signature = self.sign(&vote.to_sign_bytes());
        Ok(SignedVote::new(vote, signature))
    }

    async fn verify_signed_vote(
        &self,
        vote: &Vote,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(
            public_key.verify(&vote.to_sign_bytes(), signature).is_ok(),
        ))
    }

    async fn sign_proposal(&self, proposal: Proposal) -> Result<SignedProposal<Ctx>, Error> {
        let signature = self.private_key.sign(&proposal.to_sign_bytes());
        Ok(SignedProposal::new(proposal, signature))
    }

    async fn verify_signed_proposal(
        &self,
        proposal: &Proposal,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(
            public_key
                .verify(&proposal.to_sign_bytes(), signature)
                .is_ok(),
        ))
    }

    async fn sign_vote_extension(&self, extension: Bytes) -> Result<SignedExtension<Ctx>, Error> {
        let signature = self.private_key.sign(extension.as_ref());
        Ok(malachitebft_core_types::SignedMessage::new(
            extension, signature,
        ))
    }

    async fn verify_signed_vote_extension(
        &self,
        extension: &Bytes,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(
            public_key.verify(extension.as_ref(), signature).is_ok(),
        ))
    }
}
