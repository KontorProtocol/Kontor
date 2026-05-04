use std::path::Path;

use anyhow::{Context, anyhow, bail};
use async_trait::async_trait;
use bytes::Bytes;

use malachitebft_core_types::{SignedExtension, SignedProposal, SignedVote};
use malachitebft_signing::{Error, SigningProvider, VerificationResult};

use crate::consensus::{Ctx, Proposal, Vote};

pub use malachitebft_signing_ed25519::*;

/// Generate a random private key (for follower/sync-only nodes).
pub fn generate_random_private_key() -> PrivateKey {
    let key_bytes: [u8; 32] = rand::random();
    PrivateKey::from(key_bytes)
}

/// Parse a hex-encoded Ed25519 private key.
pub fn private_key_from_hex(hex_str: &str) -> anyhow::Result<PrivateKey> {
    let key_bytes = hex::decode(hex_str).context("Invalid consensus private key hex")?;
    let key_array: [u8; 32] = key_bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!("Ed25519 private key must be 32 bytes, got {}", v.len())
    })?;
    Ok(PrivateKey::from(key_array))
}

/// Resolve the consensus private key from config: prefer the inline hex
/// value, fall back to reading from a file path (`_FILE` convention for
/// k8s-mounted secrets), refuse to start if both are set, otherwise
/// generate a random key and run as a sync-only follower.
///
/// Returns `(key, consensus_enabled)` — `consensus_enabled` is false
/// only when neither source was provided (the random-key follower path).
pub fn resolve_consensus_private_key(
    inline_hex: Option<&str>,
    file_path: Option<&Path>,
) -> anyhow::Result<(PrivateKey, bool)> {
    if inline_hex.is_some() && file_path.is_some() {
        bail!(
            "both --consensus-private-key and --consensus-private-key-file are set; \
             pick one (typically the file form for k8s)"
        );
    }
    if let Some(hex) = inline_hex {
        return Ok((private_key_from_hex(hex)?, true));
    }
    if let Some(path) = file_path {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading consensus private key from {}", path.display()))?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(anyhow!(
                "consensus private key file {} is empty",
                path.display()
            ));
        }
        return Ok((private_key_from_hex(trimmed)?, true));
    }
    Ok((generate_random_private_key(), false))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    const KEY_HEX: &str = "8a9314fb7c22dc4ab1cb39fe1041be2923b4c78ce99ba0e04497e5e006a1cd35";

    #[test]
    fn resolve_inline_hex() {
        let (_pk, enabled) = resolve_consensus_private_key(Some(KEY_HEX), None).unwrap();
        assert!(enabled);
    }

    #[test]
    fn resolve_from_file() {
        let mut f = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, KEY_HEX.as_bytes()).unwrap();
        let (_pk, enabled) = resolve_consensus_private_key(None, Some(f.path())).unwrap();
        assert!(enabled);
    }

    #[test]
    fn resolve_from_file_trims_whitespace_and_newline() {
        // K8s-mounted secrets usually end with a trailing newline; make sure we strip.
        let mut f = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, format!("  {KEY_HEX}\n").as_bytes()).unwrap();
        let (_pk, enabled) = resolve_consensus_private_key(None, Some(f.path())).unwrap();
        assert!(enabled);
    }

    #[test]
    fn resolve_inline_and_file_set_is_rejected() {
        let f = NamedTempFile::new().unwrap();
        let err = resolve_consensus_private_key(Some(KEY_HEX), Some(f.path())).unwrap_err();
        assert!(err.to_string().contains("both"));
    }

    #[test]
    fn resolve_empty_file_is_rejected() {
        let f = NamedTempFile::new().unwrap();
        let err = resolve_consensus_private_key(None, Some(f.path())).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn resolve_neither_falls_back_to_follower() {
        let (_pk, enabled) = resolve_consensus_private_key(None, None).unwrap();
        assert!(!enabled);
    }

    #[test]
    fn resolve_missing_file_is_rejected() {
        let err = resolve_consensus_private_key(None, Some(Path::new("/nonexistent/path")))
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("reading"));
    }
}
