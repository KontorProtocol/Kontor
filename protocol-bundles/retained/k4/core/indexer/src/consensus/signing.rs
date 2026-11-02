use std::path::Path;

use anyhow::{Context, anyhow, bail};
use async_trait::async_trait;
use bytes::Bytes;
use sha3::{Digest, Keccak256};

use malachitebft_core_types::{
    NilOrVal, SignedExtension, SignedMessage, SignedProposal, SignedVote, ValidatorProof,
    VoteExtensionScope,
};
use malachitebft_signing::{Error, Signer, VerificationResult, Verifier};

use crate::consensus::{Ctx, Proposal, Vote};

const VOTE_EXTENSION_DOMAIN: &[u8] = b"kontor/vote-extension/v1\0";

fn vote_extension_sign_bytes(scope: &VoteExtensionScope<Ctx>, extension: &Bytes) -> Vec<u8> {
    let precommit = Vote::new_precommit(
        scope.height,
        scope.round,
        NilOrVal::Val(scope.value_id),
        scope.validator_address,
    );
    let precommit_bytes = precommit.to_sign_bytes();
    let mut bytes = Vec::with_capacity(
        VOTE_EXTENSION_DOMAIN.len() + 16 + precommit_bytes.len() + extension.len(),
    );
    bytes.extend_from_slice(VOTE_EXTENSION_DOMAIN);
    bytes.extend_from_slice(&(precommit_bytes.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&precommit_bytes);
    bytes.extend_from_slice(&(extension.len() as u64).to_be_bytes());
    bytes.extend_from_slice(extension);
    bytes
}

pub use indexer_types::ConsensusMode;
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

/// Resolve the consensus private key based on the explicit mode.
///
/// - `Follower`: ignore any key config, generate a random key. Whether key
///   args were supplied or not is irrelevant — followers never sign.
/// - `Validator`: require exactly one of `inline_hex` or `file_path`. If
///   neither is set, or both are, refuse to start. The file form trims
///   surrounding whitespace and rejects an empty file.
pub fn resolve_consensus_private_key(
    mode: ConsensusMode,
    inline_hex: Option<&str>,
    file_path: Option<&Path>,
) -> anyhow::Result<PrivateKey> {
    match mode {
        ConsensusMode::Follower => Ok(generate_random_private_key()),
        ConsensusMode::Validator => match (inline_hex, file_path) {
            (Some(_), Some(_)) => bail!(
                "validator mode: both --consensus-private-key and \
                 --consensus-private-key-file are set; pick one \
                 (typically the file form for k8s)"
            ),
            (None, None) => bail!(
                "validator mode requires --consensus-private-key or \
                 --consensus-private-key-file"
            ),
            (Some(hex), None) => private_key_from_hex(hex),
            (None, Some(path)) => {
                let raw = std::fs::read_to_string(path).with_context(|| {
                    format!("reading consensus private key from {}", path.display())
                })?;
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(anyhow!(
                        "consensus private key file {} is empty",
                        path.display()
                    ));
                }
                private_key_from_hex(trimmed)
            }
        },
    }
}

pub trait Hashable {
    type Output;
    fn hash(&self) -> Self::Output;
}

impl Hashable for PublicKey {
    type Output = [u8; 32];

    fn hash(&self) -> [u8; 32] {
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
impl Verifier<Ctx> for Ed25519Provider {
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

    async fn verify_signed_vote_extension(
        &self,
        scope: &VoteExtensionScope<Ctx>,
        extension: &Bytes,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(
            public_key
                .verify(&vote_extension_sign_bytes(scope, extension), signature)
                .is_ok(),
        ))
    }

    // PoV is network-agnostic: verify the canonical preimage with no domain prefix.
    async fn verify_validator_proof(
        &self,
        proof: &ValidatorProof<Ctx>,
    ) -> Result<VerificationResult, Error> {
        let public_key = proof.decoded_public_key().map_err(|e| {
            Error::from_source(format!("Invalid public key in validator proof: {e}"))
        })?;
        Ok(VerificationResult::from_bool(self.verify(
            &proof.preimage(),
            &proof.signature,
            &public_key,
        )))
    }
}

#[async_trait]
impl Signer<Ctx> for Ed25519Provider {
    async fn sign_vote(&self, vote: Vote) -> Result<SignedVote<Ctx>, Error> {
        let signature = self.sign(&vote.to_sign_bytes());
        Ok(SignedVote::new(vote, signature))
    }

    async fn sign_proposal(&self, proposal: Proposal) -> Result<SignedProposal<Ctx>, Error> {
        let signature = self.private_key.sign(&proposal.to_sign_bytes());
        Ok(SignedProposal::new(proposal, signature))
    }

    async fn sign_vote_extension(
        &self,
        scope: VoteExtensionScope<Ctx>,
        extension: Bytes,
    ) -> Result<SignedExtension<Ctx>, Error> {
        let signature = self
            .private_key
            .sign(&vote_extension_sign_bytes(&scope, &extension));
        Ok(SignedMessage::new(extension, signature))
    }

    // PoV is network-agnostic: sign the canonical preimage with no domain prefix.
    async fn sign_validator_proof(
        &self,
        public_key: Vec<u8>,
        peer_id: Vec<u8>,
    ) -> Result<ValidatorProof<Ctx>, Error> {
        let preimage = ValidatorProof::<Ctx>::signing_bytes(&public_key, &peer_id);
        let signature = self.private_key.sign(&preimage);
        Ok(ValidatorProof::new(public_key, peer_id, signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Address, Height, ValueId};
    use malachitebft_core_types::Round;
    use tempfile::NamedTempFile;

    const KEY_HEX: &str = "8a9314fb7c22dc4ab1cb39fe1041be2923b4c78ce99ba0e04497e5e006a1cd35";

    #[test]
    fn validator_with_inline_hex_resolves() {
        resolve_consensus_private_key(ConsensusMode::Validator, Some(KEY_HEX), None).unwrap();
    }

    #[test]
    fn validator_with_file_resolves() {
        let mut f = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, KEY_HEX.as_bytes()).unwrap();
        resolve_consensus_private_key(ConsensusMode::Validator, None, Some(f.path())).unwrap();
    }

    #[test]
    fn validator_file_trims_whitespace_and_newline() {
        // K8s-mounted secrets usually end with a trailing newline; make sure we strip.
        let mut f = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, format!("  {KEY_HEX}\n").as_bytes()).unwrap();
        resolve_consensus_private_key(ConsensusMode::Validator, None, Some(f.path())).unwrap();
    }

    #[test]
    fn validator_with_both_inline_and_file_is_rejected() {
        let f = NamedTempFile::new().unwrap();
        let err =
            resolve_consensus_private_key(ConsensusMode::Validator, Some(KEY_HEX), Some(f.path()))
                .unwrap_err();
        assert!(err.to_string().contains("both"));
    }

    #[test]
    fn validator_with_neither_is_rejected() {
        let err = resolve_consensus_private_key(ConsensusMode::Validator, None, None).unwrap_err();
        assert!(err.to_string().contains("requires"));
    }

    #[test]
    fn validator_with_empty_file_is_rejected() {
        let f = NamedTempFile::new().unwrap();
        let err = resolve_consensus_private_key(ConsensusMode::Validator, None, Some(f.path()))
            .unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn validator_with_missing_file_is_rejected() {
        let err = resolve_consensus_private_key(
            ConsensusMode::Validator,
            None,
            Some(Path::new("/nonexistent/path")),
        )
        .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("reading"));
    }

    #[test]
    fn follower_ignores_key_config() {
        // Follower mode never reads keys — even if pointing at a bogus file
        // or supplying a malformed hex, it must not error.
        resolve_consensus_private_key(ConsensusMode::Follower, None, None).unwrap();
        resolve_consensus_private_key(ConsensusMode::Follower, Some("garbage-hex"), None).unwrap();
        resolve_consensus_private_key(
            ConsensusMode::Follower,
            None,
            Some(Path::new("/nonexistent/path")),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn vote_extension_signature_is_bound_to_its_precommit() {
        let provider = Ed25519Provider::new(PrivateKey::from([7; 32]));
        let public_key = provider.private_key().public_key();
        let address = Address::from_public_key(&public_key);
        let scope = VoteExtensionScope::new(
            Height::new(4),
            Round::new(1),
            ValueId::new([9; 32]),
            address,
        );
        let signed = provider
            .sign_vote_extension(scope.clone(), Bytes::from_static(b"extension"))
            .await
            .unwrap();

        let valid = provider
            .verify_signed_vote_extension(&scope, &signed.message, &signed.signature, &public_key)
            .await
            .unwrap();
        assert!(valid.is_valid());

        let wrong_height =
            VoteExtensionScope::new(Height::new(5), scope.round, scope.value_id, address);
        let invalid = provider
            .verify_signed_vote_extension(
                &wrong_height,
                &signed.message,
                &signed.signature,
                &public_key,
            )
            .await
            .unwrap();
        assert!(invalid.is_invalid());
    }
}
