mod ownership;
mod store;

use std::fmt;
use std::path::Path;

use malachitebft_core_types::{NilOrVal, Round, ValidatorProof, VoteType};
use malachitebft_signing_ed25519::PrivateKey;
use sha3::{Digest, Keccak256};

use crate::consensus::{Address, Ctx, Proposal, ValueId, Vote};
use crate::protocol::coordinator::certified_decision::CommitteeRecord;
use crate::protocol::coordinator::certified_input::{Descriptor, EraContext};

use self::store::{EntryRole, HeightAuthorization, Store, ValidatedRequest};
#[cfg(kontor_managed)]
pub(crate) use ownership::GenerationOwner;
pub(crate) use ownership::OwnedGeneration;

const MAX_SIGNING_PREIMAGE_BYTES: usize = 4_200_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignerIdentity {
    pub(crate) context: EraContext,
    pub(crate) generation: u64,
    pub(crate) network_peer_id: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VoteStep {
    Prevote,
    Precommit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SigningRequest {
    Vote {
        generation: u64,
        height: u64,
        round: u32,
        step: VoteStep,
        value_id: Option<[u8; 32]>,
        validator_address: [u8; 20],
        preimage: Vec<u8>,
    },
    Proposal {
        generation: u64,
        height: u64,
        round: u32,
        pol_round: Option<u32>,
        validator_address: [u8; 20],
        descriptor: Vec<u8>,
        preimage: Vec<u8>,
    },
    ProposalFin {
        generation: u64,
        height: u64,
        round: u32,
        descriptor: Vec<u8>,
        digest: [u8; 32],
    },
    ValidatorProof {
        generation: u64,
        public_key: [u8; 32],
        network_peer_id: Vec<u8>,
        preimage: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SigningError {
    InvalidRequest(String),
    Conflict,
    Stale,
    Fenced,
    Storage(String),
    Fault(String),
}

impl fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => write!(formatter, "invalid signing request: {reason}"),
            Self::Conflict => formatter.write_str("conflicting consensus signature request"),
            Self::Stale => formatter.write_str("regressing consensus signature request"),
            Self::Fenced => formatter.write_str("consensus signing generation is fenced"),
            Self::Storage(reason) => write!(formatter, "durable signing storage failed: {reason}"),
            Self::Fault(reason) => write!(formatter, "durable signing authority fault: {reason}"),
        }
    }
}

impl std::error::Error for SigningError {}

pub(crate) struct DurableSigner {
    identity: SignerIdentity,
    public_key: [u8; 32],
    address: [u8; 20],
    store: Store,
    owned_generation: Option<OwnedGeneration>,
}

impl DurableSigner {
    pub(crate) fn open(
        directory: &Path,
        identity: SignerIdentity,
        private_key: PrivateKey,
    ) -> Result<Self, SigningError> {
        if identity.generation == 0
            || identity.network_peer_id.is_empty()
            || identity.network_peer_id.len() > 256
        {
            return Err(SigningError::InvalidRequest(
                "invalid generation or network peer ID length".into(),
            ));
        }
        let public_key = private_key.public_key();
        let address = Address::from_public_key(&public_key).into_inner();
        let key_bytes = *public_key.as_bytes();
        let store = Store::open(directory, &identity, private_key)?;
        Ok(Self {
            identity,
            public_key: key_bytes,
            address,
            store,
            owned_generation: None,
        })
    }

    pub(crate) fn open_owned(
        generation: OwnedGeneration,
        context: EraContext,
        private_key: PrivateKey,
    ) -> Result<Self, SigningError> {
        generation.with_active(|| {
            let identity = generation.signer_identity(context, &private_key)?;
            let directory = generation.signer_directory(private_key.public_key().as_bytes())?;
            let mut signer = Self::open(&directory, identity, private_key)?;
            signer.owned_generation = Some(generation.clone());
            Ok(signer)
        })
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub(crate) fn authorize_height(
        &self,
        committee: &CommitteeRecord,
        completed_closure: [u8; 32],
    ) -> Result<(), SigningError> {
        if committee.context.chain != self.identity.context.chain
            || committee.height == 0
            || completed_closure == [0; 32]
        {
            return invalid("height authority chain, height, or closure differs");
        }
        let committee_id = committee
            .id()
            .map_err(|error| SigningError::InvalidRequest(error.to_string()))?;
        let authorization = HeightAuthorization {
            generation: self.identity.generation,
            height: committee.height,
            context: committee.context,
            committee: committee_id,
            predecessor_decision: committee.decision,
            completed_closure,
            member: committee
                .members
                .iter()
                .any(|member| member.key == self.public_key),
            reconciled: false,
        };
        let authorize = || self.store.authorize_height(authorization);
        match &self.owned_generation {
            Some(generation) => generation.with_active(authorize),
            None => authorize(),
        }
    }

    pub(crate) fn sign(&self, request: SigningRequest) -> Result<[u8; 64], SigningError> {
        let sign = || {
            let validated = self.validate(request)?;
            self.store.sign(validated)
        };
        match &self.owned_generation {
            Some(generation) => generation.with_active(sign),
            None => sign(),
        }
    }

    pub(crate) fn sign_proposal_fin(
        &self,
        height: u64,
        round: u32,
        descriptor: &[u8],
        digest: [u8; 32],
    ) -> Result<[u8; 64], SigningError> {
        self.sign(SigningRequest::ProposalFin {
            generation: self.identity.generation,
            height,
            round,
            descriptor: descriptor.to_vec(),
            digest,
        })
    }

    pub(crate) fn fence_generation(&self, generation: u64) -> Result<(), SigningError> {
        self.store.fence_generation(generation)
    }

    fn validate(&self, request: SigningRequest) -> Result<ValidatedRequest, SigningError> {
        match request {
            SigningRequest::Vote {
                generation,
                height,
                round,
                step,
                value_id,
                validator_address,
                preimage,
            } => {
                let expected_type = match step {
                    VoteStep::Prevote => VoteType::Prevote,
                    VoteStep::Precommit => VoteType::Precommit,
                };
                if preimage.len() > MAX_SIGNING_PREIMAGE_BYTES {
                    return invalid("vote preimage exceeds bound");
                }
                let vote = Vote::from_sign_bytes(&preimage)
                    .map_err(|error| SigningError::InvalidRequest(error.to_string()))?;
                if height == 0
                    || vote.height.as_u64() != height
                    || vote.round != Round::new(round)
                    || vote.typ != expected_type
                    || vote.validator_address.into_inner() != validator_address
                    || validator_address != self.address
                    || vote.to_sign_bytes().as_ref() != preimage
                    || vote.extension.is_some()
                {
                    return invalid("vote coordinates or canonical bytes differ");
                }
                let decoded_value = match vote.value {
                    NilOrVal::Nil => None,
                    NilOrVal::Val(ValueId(value)) => Some(value),
                };
                if decoded_value != value_id {
                    return invalid("vote value differs");
                }
                Ok(ValidatedRequest {
                    generation,
                    height,
                    round,
                    role: match step {
                        VoteStep::Prevote => EntryRole::Prevote,
                        VoteStep::Precommit => EntryRole::Precommit,
                    },
                    commitment: None,
                    preimage,
                })
            }
            SigningRequest::Proposal {
                generation,
                height,
                round,
                pol_round,
                validator_address,
                descriptor,
                preimage,
            } => {
                if preimage.len() > MAX_SIGNING_PREIMAGE_BYTES {
                    return invalid("proposal preimage exceeds bound");
                }
                let proposal = Proposal::from_sign_bytes(&preimage)
                    .map_err(|error| SigningError::InvalidRequest(error.to_string()))?;
                if height == 0
                    || proposal.height.as_u64() != height
                    || proposal.round != Round::new(round)
                    || proposal.pol_round.as_u32() != pol_round
                    || proposal.validator_address.into_inner() != validator_address
                    || validator_address != self.address
                    || proposal.value.descriptor_bytes() != descriptor
                    || proposal.to_sign_bytes().as_ref() != preimage
                {
                    return invalid("proposal coordinates or canonical bytes differ");
                }
                self.validate_descriptor(&descriptor)?;
                Ok(ValidatedRequest {
                    generation,
                    height,
                    round,
                    role: EntryRole::Proposal,
                    commitment: Some(descriptor),
                    preimage,
                })
            }
            SigningRequest::ProposalFin {
                generation,
                height,
                round,
                descriptor,
                digest,
            } => {
                if height == 0 {
                    return invalid("zero proposal height");
                }
                self.validate_descriptor(&descriptor)?;
                let mut hash = Keccak256::new();
                hash.update(b"kontor/proposal-parts/v1\0");
                hash.update(height.to_be_bytes());
                hash.update((round as i64).to_be_bytes());
                hash.update(&descriptor);
                let canonical: [u8; 32] = hash.finalize().into();
                if digest != canonical {
                    return invalid("proposal Fin digest differs from canonical descriptor");
                }
                Ok(ValidatedRequest {
                    generation,
                    height,
                    round,
                    role: EntryRole::ProposalFin,
                    commitment: Some(descriptor),
                    preimage: digest.to_vec(),
                })
            }
            SigningRequest::ValidatorProof {
                generation,
                public_key,
                network_peer_id,
                preimage,
            } => {
                if public_key != self.public_key
                    || network_peer_id != self.identity.network_peer_id
                    || preimage
                        != ValidatorProof::<Ctx>::signing_bytes(&public_key, &network_peer_id)
                {
                    return invalid("validator proof identity or preimage differs");
                }
                Ok(ValidatedRequest {
                    generation,
                    height: 0,
                    round: 0,
                    role: EntryRole::ValidatorProof,
                    commitment: None,
                    preimage,
                })
            }
        }
    }

    fn validate_descriptor(&self, bytes: &[u8]) -> Result<(), SigningError> {
        let descriptor = Descriptor::decode(bytes)
            .map_err(|error| SigningError::InvalidRequest(error.to_string()))?;
        if descriptor
            .encode()
            .map_err(|error| SigningError::InvalidRequest(error.to_string()))?
            != bytes
        {
            return invalid("proposal descriptor canonical bytes differ");
        }
        Ok(())
    }
}

fn invalid<T>(reason: &str) -> Result<T, SigningError> {
    Err(SigningError::InvalidRequest(reason.into()))
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::{Arc, Barrier};

    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, BlockHash, ScriptBuf, Transaction, TxIn, TxOut};
    use malachitebft_signing_ed25519::Signature;
    use tempfile::TempDir;

    use super::*;
    use crate::consensus::test_fixtures;
    use crate::consensus::{Height, ProposalData, Value};
    use crate::protocol::coordinator::certified_decision::AuthorityMember;
    use crate::protocol::coordinator::certified_input::MAX_BATCH_BYTES;

    fn identity(generation: u64) -> SignerIdentity {
        SignerIdentity {
            context: test_fixtures::context(),
            generation,
            network_peer_id: vec![42; 38],
        }
    }

    fn key() -> PrivateKey {
        PrivateKey::from([11; 32])
    }

    fn open(directory: &Path, generation: u64) -> DurableSigner {
        DurableSigner::open(directory, identity(generation), key()).unwrap()
    }

    fn committee(signer: &DurableSigner, height: u64, decision: [u8; 32]) -> CommitteeRecord {
        CommitteeRecord {
            context: signer.identity.context,
            height,
            decision,
            stage: 0,
            lineage: [0; 32],
            members: vec![AuthorityMember {
                holder: "validator".into(),
                generation: [1; 32],
                address: signer.address,
                key: signer.public_key,
                power: 1,
            }],
        }
    }

    fn authorize(signer: &DurableSigner, height: u64) {
        signer
            .authorize_height(&committee(signer, height, [7; 32]), [9; 32])
            .unwrap();
    }

    fn vote(signer: &DurableSigner, height: u64, round: u32) -> SigningRequest {
        let vote = Vote::new_prevote(
            Height::new(height),
            Round::new(round),
            NilOrVal::Nil,
            Address::new(signer.address),
        );
        SigningRequest::Vote {
            generation: signer.identity.generation,
            height,
            round,
            step: VoteStep::Prevote,
            value_id: None,
            validator_address: signer.address,
            preimage: vote.to_sign_bytes().to_vec(),
        }
    }

    fn proposal(signer: &DurableSigner, height: u64, round: u32) -> SigningRequest {
        let value = test_fixtures::block();
        let proposal = Proposal::new(
            Height::new(height),
            Round::new(round),
            value.clone(),
            Round::Nil,
            Address::new(signer.address),
        );
        SigningRequest::Proposal {
            generation: signer.identity.generation,
            height,
            round,
            pol_round: None,
            validator_address: signer.address,
            descriptor: value.descriptor_bytes().to_vec(),
            preimage: proposal.to_sign_bytes().to_vec(),
        }
    }

    fn fin(signer: &DurableSigner, height: u64, round: u32) -> SigningRequest {
        let data = ProposalData::new(test_fixtures::block());
        SigningRequest::ProposalFin {
            generation: signer.identity.generation,
            height,
            round,
            descriptor: data.value().descriptor_bytes().to_vec(),
            digest: data.signing_digest(Height::new(height), Round::new(round)),
        }
    }

    fn transaction_with_size(size: usize) -> Transaction {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0; size - 64]),
            }],
        };
        assert_eq!(tx.total_size(), size);
        tx
    }

    #[test]
    fn canonical_vote_retry_conflict_and_reopen() {
        let directory = TempDir::new().unwrap();
        let signer = open(directory.path(), 1);
        authorize(&signer, 5);
        let request = vote(&signer, 5, 2);
        let signature = signer.sign(request.clone()).unwrap();
        assert_eq!(signer.sign(request.clone()).unwrap(), signature);
        let preimage = match &request {
            SigningRequest::Vote { preimage, .. } => preimage,
            _ => unreachable!(),
        };
        assert_eq!(
            hex::encode(preimage),
            "0801100518022a160a14bf25802c1e2d88037e5d769938d1ddd2e5400563"
        );
        assert_eq!(
            hex::encode(signature),
            "b3710e6d75bfbc85fd0407824a9844bb6f5d615d008759fb1ff0674e72e1c14f4d605da36892859495238d244d7dc11c8c7401940f90e81ab0bd8c422d482a04"
        );
        key()
            .public_key()
            .verify(preimage, &Signature::from_bytes(signature))
            .unwrap();
        let mut conflict = request.clone();
        if let SigningRequest::Vote {
            value_id, preimage, ..
        } = &mut conflict
        {
            *value_id = Some([7; 32]);
            let vote = Vote::new_prevote(
                Height::new(5),
                Round::new(2),
                NilOrVal::Val(ValueId([7; 32])),
                Address::new(signer.address),
            );
            *preimage = vote.to_sign_bytes().to_vec();
        }
        assert_eq!(signer.sign(conflict.clone()), Err(SigningError::Conflict));
        assert!(matches!(
            DurableSigner::open(directory.path(), identity(1), key()),
            Err(SigningError::Storage(_))
        ));
        drop(signer);
        let reopened = open(directory.path(), 1);
        assert_eq!(reopened.sign(conflict), Err(SigningError::Conflict));
        assert_eq!(reopened.sign(request).unwrap(), signature);
    }

    #[test]
    fn maximal_valid_proposal_uses_small_durable_record() {
        let directory = TempDir::new().unwrap();
        let signer = open(directory.path(), 1);
        authorize(&signer, 4);
        let value = Value::new_batch_raw(
            test_fixtures::context(),
            4,
            BlockHash::all_zeros(),
            vec![
                transaction_with_size(4_000_000),
                transaction_with_size(MAX_BATCH_BYTES - 12 - 4_000_000),
            ],
        )
        .unwrap();
        assert_eq!(value.input().body().len(), MAX_BATCH_BYTES);
        let proposal = Proposal::new(
            Height::new(4),
            Round::new(0),
            value.clone(),
            Round::Nil,
            Address::new(signer.address),
        );
        let request = SigningRequest::Proposal {
            generation: 1,
            height: 4,
            round: 0,
            pol_round: None,
            validator_address: signer.address,
            descriptor: value.descriptor_bytes().to_vec(),
            preimage: proposal.to_sign_bytes().to_vec(),
        };
        let signature = signer.sign(request.clone()).unwrap();
        assert!(
            std::fs::metadata(directory.path().join("signatures.log"))
                .unwrap()
                .len()
                < 4096
        );
        drop(signer);
        let reopened = open(directory.path(), 1);
        assert_eq!(reopened.sign(request).unwrap(), signature);
    }

    #[test]
    fn proposal_roles_share_commitment_in_either_callback_order() {
        for proposal_first in [true, false] {
            let directory = TempDir::new().unwrap();
            let signer = open(directory.path(), 1);
            authorize(&signer, 8);
            let proposal = proposal(&signer, 8, 1);
            let fin = fin(&signer, 8, 1);
            if proposal_first {
                signer.sign(proposal.clone()).unwrap();
                let mut changed = fin.clone();
                if let SigningRequest::ProposalFin {
                    descriptor, digest, ..
                } = &mut changed
                {
                    let mut value = Descriptor::decode(descriptor).unwrap();
                    value.body_digest[0] ^= 1;
                    *descriptor = value.encode().unwrap();
                    let mut hash = Keccak256::new();
                    hash.update(b"kontor/proposal-parts/v1\0");
                    hash.update(8u64.to_be_bytes());
                    hash.update(1i64.to_be_bytes());
                    hash.update(descriptor);
                    *digest = hash.finalize().into();
                }
                assert_eq!(signer.sign(changed), Err(SigningError::Conflict));
                signer.sign(fin).unwrap();
            } else {
                signer.sign(fin).unwrap();
                signer.sign(proposal).unwrap();
            }
        }
    }

    #[test]
    fn validator_proof_is_only_for_own_key_and_bound_network_peer() {
        let directory = TempDir::new().unwrap();
        let signer = open(directory.path(), 1);
        assert_eq!(signer.public_key(), *key().public_key().as_bytes());
        let request = SigningRequest::ValidatorProof {
            generation: 1,
            public_key: signer.public_key(),
            network_peer_id: signer.identity.network_peer_id.clone(),
            preimage: ValidatorProof::<Ctx>::signing_bytes(
                &signer.public_key(),
                &signer.identity.network_peer_id,
            ),
        };
        let signature = signer.sign(request.clone()).unwrap();
        assert_eq!(signer.sign(request.clone()).unwrap(), signature);
        let mut wrong = request;
        if let SigningRequest::ValidatorProof {
            network_peer_id, ..
        } = &mut wrong
        {
            network_peer_id[0] ^= 1;
        }
        assert!(matches!(
            signer.sign(wrong),
            Err(SigningError::InvalidRequest(_))
        ));
        assert!(matches!(
            signer.sign_proposal_fin(2, 0, &[1, 2, 3], [0; 32]),
            Err(SigningError::InvalidRequest(_))
        ));
    }

    #[test]
    fn later_round_rejects_new_old_round_but_preserves_exact_retry() {
        let directory = TempDir::new().unwrap();
        let signer = open(directory.path(), 1);
        authorize(&signer, 9);
        let first = vote(&signer, 9, 1);
        let signature = signer.sign(first.clone()).unwrap();
        signer.sign(vote(&signer, 9, 2)).unwrap();
        assert_eq!(signer.sign(first).unwrap(), signature);
        let precommit = Vote::new_precommit(
            Height::new(9),
            Round::new(1),
            NilOrVal::Nil,
            Address::new(signer.address),
        );
        let stale = SigningRequest::Vote {
            generation: 1,
            height: 9,
            round: 1,
            step: VoteStep::Precommit,
            value_id: None,
            validator_address: signer.address,
            preimage: precommit.to_sign_bytes().to_vec(),
        };
        assert_eq!(signer.sign(stale), Err(SigningError::Stale));
    }

    #[test]
    fn generation_fence_and_old_snapshot_are_durable() {
        let directory = TempDir::new().unwrap();
        let signer = open(directory.path(), 1);
        authorize(&signer, 5);
        signer.sign(vote(&signer, 5, 0)).unwrap();
        signer.fence_generation(1).unwrap();
        assert_eq!(signer.sign(vote(&signer, 5, 0)), Err(SigningError::Fenced));
        drop(signer);
        assert!(matches!(
            DurableSigner::open(directory.path(), identity(1), key()),
            Err(SigningError::Fenced)
        ));
        let next = open(directory.path(), 2);
        authorize(&next, 6);
        next.sign(vote(&next, 6, 0)).unwrap();
        drop(next);
        assert!(matches!(
            DurableSigner::open(directory.path(), identity(1), key()),
            Err(SigningError::Stale)
        ));
    }

    #[test]
    fn partial_journal_tail_fails_closed() {
        let directory = TempDir::new().unwrap();
        let signer = open(directory.path(), 1);
        authorize(&signer, 1);
        signer.sign(vote(&signer, 1, 0)).unwrap();
        drop(signer);
        OpenOptions::new()
            .append(true)
            .open(directory.path().join("signatures.log"))
            .unwrap()
            .write_all(&[1])
            .unwrap();
        assert!(DurableSigner::open(directory.path(), identity(1), key()).is_err());
    }

    #[test]
    fn concurrent_fence_and_sign_never_sign_after_fence() {
        let directory = TempDir::new().unwrap();
        let signer = Arc::new(open(directory.path(), 1));
        authorize(&signer, 1);
        let barrier = Arc::new(Barrier::new(3));
        let signing = Arc::clone(&signer);
        let start = Arc::clone(&barrier);
        let request = vote(&signer, 1, 0);
        let signed = std::thread::spawn(move || {
            start.wait();
            signing.sign(request)
        });
        let fencing = Arc::clone(&signer);
        let start = Arc::clone(&barrier);
        let fenced = std::thread::spawn(move || {
            start.wait();
            fencing.fence_generation(1)
        });
        barrier.wait();
        let result = signed.join().unwrap();
        fenced.join().unwrap().unwrap();
        assert!(result.is_ok() || result == Err(SigningError::Fenced));
        assert_eq!(signer.sign(vote(&signer, 2, 0)), Err(SigningError::Fenced));
    }

    #[test]
    fn nil_vote_and_proposal_fin_require_height_authorization() {
        let directory = TempDir::new().unwrap();
        let signer = open(directory.path(), 1);
        assert!(matches!(
            signer.sign(vote(&signer, 5, 0)),
            Err(SigningError::InvalidRequest(_))
        ));
        assert!(matches!(
            signer.sign(fin(&signer, 5, 0)),
            Err(SigningError::InvalidRequest(_))
        ));
        authorize(&signer, 5);
        signer.sign(vote(&signer, 5, 0)).unwrap();
        signer.sign(fin(&signer, 5, 0)).unwrap();
    }

    #[test]
    fn authorization_binds_committee_context_and_completed_closure() {
        let directory = TempDir::new().unwrap();
        let signer = open(directory.path(), 1);
        let authority = committee(&signer, 5, [7; 32]);
        assert!(matches!(
            signer.authorize_height(&authority, [0; 32]),
            Err(SigningError::InvalidRequest(_))
        ));
        let mut wrong_context = authority.clone();
        wrong_context.context.chain.0[0] ^= 1;
        assert!(matches!(
            signer.authorize_height(&wrong_context, [9; 32]),
            Err(SigningError::InvalidRequest(_))
        ));
        let mut wrong_member = authority.clone();
        wrong_member.members.clear();
        assert!(matches!(
            signer.authorize_height(&wrong_member, [9; 32]),
            Err(SigningError::InvalidRequest(_))
        ));
        signer.authorize_height(&authority, [9; 32]).unwrap();
        signer.authorize_height(&authority, [9; 32]).unwrap();
        assert_eq!(
            signer.authorize_height(&authority, [8; 32]),
            Err(SigningError::Conflict)
        );
        let mut changed_committee = authority;
        changed_committee.members[0].power = 2;
        assert_eq!(
            signer.authorize_height(&changed_committee, [9; 32]),
            Err(SigningError::Conflict)
        );
    }

    #[test]
    fn old_height_only_allows_exact_retry_after_advancing_and_reopening() {
        let directory = TempDir::new().unwrap();
        let signer = open(directory.path(), 1);
        authorize(&signer, 5);
        let first = vote(&signer, 5, 0);
        let signature = signer.sign(first.clone()).unwrap();
        authorize(&signer, 6);
        assert_eq!(signer.sign(first.clone()).unwrap(), signature);
        assert_eq!(signer.sign(vote(&signer, 5, 1)), Err(SigningError::Stale));
        drop(signer);

        let restarted = open(directory.path(), 2);
        assert_eq!(restarted.sign(vote(&restarted, 5, 0)).unwrap(), signature);
        assert!(matches!(
            restarted.sign(vote(&restarted, 6, 0)),
            Err(SigningError::InvalidRequest(_))
        ));
        authorize(&restarted, 6);
        restarted.sign(vote(&restarted, 6, 0)).unwrap();
        assert_eq!(
            restarted.authorize_height(&committee(&restarted, 5, [7; 32]), [9; 32]),
            Err(SigningError::Stale)
        );
        drop(restarted);
        let reopened = open(directory.path(), 3);
        assert_eq!(reopened.sign(vote(&reopened, 5, 0)).unwrap(), signature);
    }

    #[test]
    fn same_generation_era_transition_uses_authorized_descriptor_context() {
        let directory = TempDir::new().unwrap();
        let signer = open(directory.path(), 1);
        authorize(&signer, 5);
        let old_vote = vote(&signer, 5, 0);
        let old_signature = signer.sign(old_vote.clone()).unwrap();

        let mut next = committee(&signer, 6, [8; 32]);
        next.context.era[0] ^= 1;
        next.context.protocol.0[0] ^= 1;
        signer.authorize_height(&next, [10; 32]).unwrap();
        assert_eq!(signer.sign(old_vote).unwrap(), old_signature);
        signer.sign(vote(&signer, 6, 0)).unwrap();
        assert!(matches!(
            signer.sign(fin(&signer, 6, 0)),
            Err(SigningError::InvalidRequest(_))
        ));

        let value = Value::new_batch_raw(next.context, 6, BlockHash::all_zeros(), vec![]).unwrap();
        let proposal = Proposal::new(
            Height::new(6),
            Round::new(0),
            value.clone(),
            Round::Nil,
            Address::new(signer.address),
        );
        signer
            .sign(SigningRequest::Proposal {
                generation: 1,
                height: 6,
                round: 0,
                pol_round: None,
                validator_address: signer.address,
                descriptor: value.descriptor_bytes().to_vec(),
                preimage: proposal.to_sign_bytes().to_vec(),
            })
            .unwrap();
        drop(signer);
        let reopened = open(directory.path(), 2);
        assert_eq!(reopened.sign(vote(&reopened, 5, 0)).unwrap(), old_signature);
        reopened.authorize_height(&next, [10; 32]).unwrap();
    }

    #[test]
    fn missing_membership_and_unverified_height_gap_block_new_slots() {
        let directory = TempDir::new().unwrap();
        let signer = open(directory.path(), 1);
        authorize(&signer, 5);
        let old_vote = vote(&signer, 5, 0);
        let signature = signer.sign(old_vote.clone()).unwrap();
        assert_eq!(
            signer.authorize_height(&committee(&signer, 7, [7; 32]), [9; 32]),
            Err(SigningError::Stale)
        );
        let other = PrivateKey::from([12; 32]);
        let mut next = committee(&signer, 6, [8; 32]);
        next.members[0].key = *other.public_key().as_bytes();
        next.members[0].address = Address::from_public_key(&other.public_key()).into_inner();
        signer.authorize_height(&next, [10; 32]).unwrap();
        assert!(matches!(
            signer.sign(vote(&signer, 6, 0)),
            Err(SigningError::InvalidRequest(_))
        ));
        assert_eq!(signer.sign(old_vote).unwrap(), signature);
        drop(signer);

        let reopened = open(directory.path(), 2);
        reopened
            .authorize_height(&committee(&reopened, 8, [11; 32]), [12; 32])
            .unwrap();
        reopened.sign(vote(&reopened, 8, 0)).unwrap();
    }

    #[test]
    fn concurrent_authorization_and_nil_vote_replay_in_journal_order() {
        let directory = TempDir::new().unwrap();
        let signer = Arc::new(open(directory.path(), 1));
        let authority = committee(&signer, 1, [7; 32]);
        let barrier = Arc::new(Barrier::new(3));
        let vote_request = vote(&signer, 1, 0);
        let signing = Arc::clone(&signer);
        let start = Arc::clone(&barrier);
        let vote_thread = std::thread::spawn(move || {
            start.wait();
            signing.sign(vote_request)
        });
        let authorizing = Arc::clone(&signer);
        let start = Arc::clone(&barrier);
        let auth_thread = std::thread::spawn(move || {
            start.wait();
            authorizing.authorize_height(&authority, [9; 32])
        });
        barrier.wait();
        let first = vote_thread.join().unwrap();
        auth_thread.join().unwrap().unwrap();
        assert!(first.is_ok() || matches!(first, Err(SigningError::InvalidRequest(_))));
        let signature = signer.sign(vote(&signer, 1, 0)).unwrap();
        drop(signer);
        let reopened = open(directory.path(), 1);
        assert_eq!(reopened.sign(vote(&reopened, 1, 0)).unwrap(), signature);
    }
}
