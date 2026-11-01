use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use malachitebft_app_channel::ConsensusContext;
use malachitebft_codec::Codec;
use malachitebft_core_types::{
    NilOrVal, SignedExtension, SignedProposal, SignedVote, ValidatorProof, VoteExtensionScope,
    VoteType,
};
use malachitebft_signing::{Error, Signer, VerificationResult, Verifier};
use malachitebft_signing_ed25519::{PublicKey, Signature};

use crate::authority_api::{Authority, SigningError, SigningRequest, SigningService, VoteStep};
use crate::consensus::{Address, Ctx, Proposal, Vote};
use crate::wire::WireCodec;

struct VerifierAdapter;

#[async_trait]
impl Verifier<Ctx> for VerifierAdapter {
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
        _scope: &VoteExtensionScope<Ctx>,
        _extension: &Bytes,
        _signature: &Signature,
        _public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::Invalid)
    }

    async fn verify_validator_proof(
        &self,
        proof: &ValidatorProof<Ctx>,
    ) -> Result<VerificationResult, Error> {
        let public_key = proof
            .decoded_public_key()
            .map_err(|error| Error::from_source(error.to_string()))?;
        Ok(VerificationResult::from_bool(
            public_key
                .verify(&proof.preimage(), &proof.signature)
                .is_ok(),
        ))
    }
}

struct SignerAdapter {
    generation: u64,
    service: Arc<dyn SigningService>,
}

impl SignerAdapter {
    async fn sign(&self, request: SigningRequest) -> Result<Signature, Error> {
        let service = Arc::clone(&self.service);
        let signature = tokio::task::spawn_blocking(move || service.sign(request))
            .await
            .map_err(|error| Error::from_source(error.to_string()))?
            .map_err(Error::from_source)?;
        Ok(Signature::from_bytes(signature))
    }
}

#[async_trait]
impl Signer<Ctx> for SignerAdapter {
    async fn sign_vote(&self, vote: Vote) -> Result<SignedVote<Ctx>, Error> {
        let step = match vote.typ {
            VoteType::Prevote => VoteStep::Prevote,
            VoteType::Precommit => VoteStep::Precommit,
        };
        let round = vote.round.as_u32().ok_or_else(Error::new)?;
        let value_id = match &vote.value {
            NilOrVal::Nil => None,
            NilOrVal::Val(value_id) => Some(value_id.0),
        };
        let request = SigningRequest::Vote {
            generation: self.generation,
            height: vote.height.as_u64(),
            round,
            step,
            value_id,
            validator_address: vote.validator_address.into_inner(),
            preimage: vote.to_sign_bytes().to_vec(),
        };
        let signature = self.sign(request).await?;
        Ok(SignedVote::new(vote, signature))
    }

    async fn sign_proposal(&self, proposal: Proposal) -> Result<SignedProposal<Ctx>, Error> {
        let round = proposal.round.as_u32().ok_or_else(Error::new)?;
        let request = SigningRequest::Proposal {
            generation: self.generation,
            height: proposal.height.as_u64(),
            round,
            pol_round: proposal.pol_round.as_u32(),
            validator_address: proposal.validator_address.into_inner(),
            descriptor: proposal.value.descriptor_bytes().to_vec(),
            preimage: proposal.to_sign_bytes().to_vec(),
        };
        let signature = self.sign(request).await?;
        Ok(SignedProposal::new(proposal, signature))
    }

    async fn sign_vote_extension(
        &self,
        _scope: VoteExtensionScope<Ctx>,
        _extension: Bytes,
    ) -> Result<SignedExtension<Ctx>, Error> {
        // This consensus graph sets VoteExtensionPolicy::Disabled at every height.
        Err(Error::new())
    }

    async fn sign_validator_proof(
        &self,
        public_key: Vec<u8>,
        peer_id: Vec<u8>,
    ) -> Result<ValidatorProof<Ctx>, Error> {
        let public_key_array: [u8; 32] =
            public_key.as_slice().try_into().map_err(|_| Error::new())?;
        let preimage = ValidatorProof::<Ctx>::signing_bytes(&public_key, &peer_id);
        let request = SigningRequest::ValidatorProof {
            generation: self.generation,
            public_key: public_key_array,
            network_peer_id: peer_id.clone(),
            preimage,
        };
        let signature = self.sign(request).await?;
        Ok(ValidatorProof::new(public_key, peer_id, signature))
    }
}

pub(crate) fn context(
    authority: Authority,
    generation: u64,
    network_peer_id: Vec<u8>,
) -> Result<(ConsensusContext<Ctx>, Option<Vec<u8>>), SigningError> {
    if generation == 0 {
        return Err(SigningError::InvalidRequest("zero generation".into()));
    }
    match authority {
        Authority::Follower => Ok((
            ConsensusContext::new_full_node(Address::new([0; 20]), Box::new(VerifierAdapter)),
            None,
        )),
        Authority::Validator { public_key, signer } => {
            let key = PublicKey::from_bytes(public_key)
                .map_err(|error| SigningError::InvalidRequest(error.to_string()))?;
            let address = Address::from_public_key(&key);
            if network_peer_id.is_empty() {
                return Err(SigningError::InvalidRequest("empty network peer ID".into()));
            }
            let preimage = ValidatorProof::<Ctx>::signing_bytes(&public_key, &network_peer_id);
            let signature = signer.sign(SigningRequest::ValidatorProof {
                generation,
                public_key,
                network_peer_id: network_peer_id.clone(),
                preimage,
            })?;
            let proof = ValidatorProof::<Ctx>::new(
                public_key.to_vec(),
                network_peer_id,
                Signature::from_bytes(signature),
            );
            let proof_bytes = WireCodec
                .encode(&proof)
                .map_err(|error| SigningError::InvalidRequest(error.to_string()))?
                .to_vec();
            Ok((
                ConsensusContext::new_validator(
                    address,
                    Box::new(VerifierAdapter),
                    Box::new(SignerAdapter {
                        generation,
                        service: signer,
                    }),
                ),
                Some(proof_bytes),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use malachitebft_core_types::Round;

    use super::*;
    use crate::consensus::signing::PrivateKey;
    use crate::consensus::test_fixtures;
    use crate::consensus::{Height, ValueId};

    struct RecordingService {
        key: PrivateKey,
        requests: Mutex<Vec<SigningRequest>>,
    }

    impl SigningService for RecordingService {
        fn sign(&self, request: SigningRequest) -> Result<[u8; 64], SigningError> {
            let preimage = match &request {
                SigningRequest::Vote { preimage, .. }
                | SigningRequest::Proposal { preimage, .. }
                | SigningRequest::ValidatorProof { preimage, .. } => preimage.as_slice(),
                SigningRequest::ProposalFin { digest, .. } => digest,
            };
            let signature = self.key.sign(preimage).to_bytes();
            self.requests.lock().unwrap().push(request);
            Ok(signature)
        }
    }

    fn service() -> Arc<RecordingService> {
        Arc::new(RecordingService {
            key: PrivateKey::from([11; 32]),
            requests: Mutex::new(Vec::new()),
        })
    }

    #[test]
    fn follower_has_verifier_but_no_signer_or_validator_proof() {
        let (context, proof) = context(Authority::Follower, 1, Vec::new()).unwrap();
        assert!(context.signer.is_none());
        assert!(proof.is_none());
    }

    #[tokio::test]
    async fn validator_proof_and_callbacks_use_typed_signing_requests() {
        let service = service();
        let public_key = *service.key.public_key().as_bytes();
        let peer_id = vec![7; 38];
        let (context, proof_bytes) = context(
            Authority::Validator {
                public_key,
                signer: service.clone(),
            },
            9,
            peer_id.clone(),
        )
        .unwrap();
        let proof: ValidatorProof<Ctx> = WireCodec.decode(proof_bytes.unwrap().into()).unwrap();
        assert_eq!(proof.public_key, public_key);
        assert_eq!(proof.peer_id, peer_id);
        assert!(
            service
                .key
                .public_key()
                .verify(&proof.preimage(), &proof.signature)
                .is_ok()
        );

        let address = Address::from_public_key(&service.key.public_key());
        let vote = Vote::new_prevote(
            Height::new(4),
            Round::new(2),
            NilOrVal::Val(ValueId([3; 32])),
            address,
        );
        context
            .signer
            .as_ref()
            .unwrap()
            .sign_vote(vote.clone())
            .await
            .unwrap();
        let value = test_fixtures::block();
        let proposal = Proposal::new(
            Height::new(4),
            Round::new(2),
            value.clone(),
            Round::Nil,
            address,
        );
        context
            .signer
            .as_ref()
            .unwrap()
            .sign_proposal(proposal.clone())
            .await
            .unwrap();
        assert!(
            context
                .signer
                .as_ref()
                .unwrap()
                .sign_vote_extension(
                    VoteExtensionScope::new(
                        Height::new(4),
                        Round::new(2),
                        ValueId([3; 32]),
                        address
                    ),
                    Bytes::from_static(b"disabled"),
                )
                .await
                .is_err()
        );

        let requests = service.requests.lock().unwrap();
        assert!(
            matches!(&requests[0], SigningRequest::ValidatorProof { generation: 9, public_key: key, network_peer_id, preimage } if *key == public_key && *network_peer_id == peer_id && *preimage == proof.preimage())
        );
        assert!(
            matches!(&requests[1], SigningRequest::Vote { generation: 9, height: 4, round: 2, step: VoteStep::Prevote, value_id: Some(id), validator_address, preimage } if *id == [3; 32] && *validator_address == address.into_inner() && *preimage == vote.to_sign_bytes())
        );
        assert!(
            matches!(&requests[2], SigningRequest::Proposal { generation: 9, height: 4, round: 2, pol_round: None, validator_address, descriptor, preimage } if *validator_address == address.into_inner() && *descriptor == value.descriptor_bytes() && *preimage == proposal.to_sign_bytes())
        );
    }
}
