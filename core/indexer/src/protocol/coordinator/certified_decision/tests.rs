use bitcoin::{BlockHash, hashes::Hash};
use malachitebft_core_types::CommitSignature;

use super::*;
use crate::consensus::codec::encode_commit_certificate;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{CommitCertificate, Ctx};
use crate::protocol::identity::{ChainId, ProtocolId};

pub(crate) fn fixture() -> (CommitteeRecord, ExactInput, Decision, Vec<PrivateKey>) {
    let context = EraContext {
        chain: ChainId([1; 32]),
        era: [2; 32],
        protocol: ProtocolId([3; 32]),
        codec: 1,
    };
    let keys = (1..=4)
        .map(|n| PrivateKey::from([n; 32]))
        .collect::<Vec<_>>();
    let authority = CommitteeRecord {
        context,
        height: 1,
        decision: [4; 32],
        stage: 0,
        lineage: [5; 32],
        members: keys
            .iter()
            .enumerate()
            .map(|(i, key)| AuthorityMember {
                holder: i.to_string(),
                generation: [i as u8 + 10; 32],
                address: Address::from_public_key(&key.public_key()).into_inner(),
                key: *key.public_key().as_bytes(),
                power: 1,
            })
            .collect(),
    };
    let input = ExactInput::batch(context, 0, BlockHash::all_zeros(), &[]).unwrap();
    let decision = Decision {
        height: 1,
        predecessor: authority.decision,
        committee: authority.id().unwrap(),
        descriptor: input.descriptor().clone(),
    };
    (authority, input, decision, keys)
}

pub(crate) fn proof(
    decision: &Decision,
    keys: &[PrivateKey],
    indices: &[usize],
    round: u32,
) -> Vec<u8> {
    let height = Height::new(decision.height);
    let round = Round::new(round);
    let value_id = ValueId::new(decision.descriptor.id().unwrap());
    let certificate: CommitCertificate<Ctx> = CommitCertificate {
        height,
        round,
        value_id,
        commit_signatures: indices
            .iter()
            .map(|i| {
                let key = &keys[*i];
                let address = Address::from_public_key(&key.public_key());
                let vote = Vote::new_precommit(height, round, NilOrVal::Val(value_id), address);
                CommitSignature::new(address, key.sign(&vote.to_sign_bytes()))
            })
            .collect(),
    };
    encode_commit_certificate(&certificate)
        .unwrap()
        .encode_to_vec()
}

#[test]
fn signer_subsets_and_rounds_do_not_change_decision_identity() {
    let (authority, input, decision, keys) = fixture();
    let first = AuthenticatedDecision::verify(
        decision.clone(),
        input.clone(),
        proof(&decision, &keys, &[0, 1, 2], 0),
        &authority,
    )
    .unwrap();
    let second = AuthenticatedDecision::verify(
        decision.clone(),
        input,
        proof(&decision, &keys, &[3, 2, 1], 9),
        &authority,
    )
    .unwrap();
    assert_ne!(first.proof(), second.proof());
    assert_eq!(first.decision().id(), second.decision().id());
    assert_eq!(Decision::decode(&decision.encode().unwrap()), Ok(decision));
    assert_eq!(
        CommitteeRecord::decode(&authority.encode().unwrap()).unwrap(),
        authority
    );
}

#[test]
fn insufficient_duplicate_unknown_and_invalid_signers_are_rejected() {
    let (authority, _, decision, mut keys) = fixture();
    keys.push(PrivateKey::from([99; 32]));
    for indices in [
        vec![],
        vec![0, 1],
        vec![0, 0, 1],
        vec![0, 1, 4],
        vec![0, 1, 2, 3, 3],
    ] {
        assert!(
            verify_certificate(&decision, &proof(&decision, &keys, &indices, 0), &authority)
                .is_err()
        );
    }
    let mut invalid = proof(&decision, &keys, &[0, 1, 2], 0);
    *invalid.last_mut().unwrap() ^= 1;
    assert!(verify_certificate(&decision, &invalid, &authority).is_err());
    // Strictly greater than two thirds, including an exact threshold at 2/3.
    let mut three = authority.clone();
    three.members.pop();
    let mut decision = decision;
    decision.committee = three.id().unwrap();
    assert!(verify_certificate(&decision, &proof(&decision, &keys, &[0, 1], 0), &three).is_err());
    assert!(verify_certificate(&decision, &proof(&decision, &keys, &[0, 1, 2], 0), &three).is_ok());
}

#[test]
fn certificate_context_and_all_wire_fields_are_checked() {
    let (authority, _, decision, keys) = fixture();
    let valid = proof(&decision, &keys, &[0, 1, 2], 1);
    for length in 0..valid.len() {
        assert!(verify_certificate(&decision, &valid[..length], &authority).is_err());
    }
    let mut changed = decision.clone();
    changed.height += 1;
    assert!(verify_certificate(&changed, &valid, &authority).is_err());
    changed = decision.clone();
    changed.committee[0] ^= 1;
    assert!(verify_certificate(&changed, &valid, &authority).is_err());
    changed = decision.clone();
    changed.descriptor.context.era[0] ^= 1;
    assert!(verify_certificate(&changed, &valid, &authority).is_err());
    let mut wrong_round = valid.clone();
    assert_eq!(&wrong_round[..4], &[8, 1, 16, 1]);
    wrong_round[3] = 2;
    assert!(verify_certificate(&decision, &wrong_round, &authority).is_err());
    let mut trailing = valid.clone();
    trailing.extend_from_slice(&[40, 1]);
    assert!(verify_certificate(&decision, &trailing, &authority).is_err());
    let mut nonminimal = valid;
    nonminimal.splice(1..2, [0x81, 0]);
    assert!(verify_certificate(&decision, &nonminimal, &authority).is_err());
    assert!(
        verify_certificate(
            &decision,
            &vec![0; authority.maximum_proof_bytes().unwrap() + 1],
            &authority
        )
        .is_err()
    );
}

#[test]
fn authority_preserves_order_and_binds_registration_provenance() {
    let (authority, _, _, _) = fixture();
    let id = authority.id().unwrap();
    let mut changed = authority.clone();
    changed.members.reverse();
    assert_ne!(changed.id().unwrap(), id);
    changed = authority.clone();
    changed.members[0].generation[0] ^= 1;
    assert_ne!(changed.id().unwrap(), id);
    changed = authority.clone();
    changed.lineage[0] ^= 1;
    assert_ne!(changed.id().unwrap(), id);
    changed = authority.clone();
    changed.members[0].address[0] ^= 1;
    assert!(changed.validate().is_err());
    changed = authority.clone();
    changed.members.push(changed.members[0].clone());
    assert!(changed.validate().is_err());
    changed = authority.clone();
    changed.members[0].power = 0;
    assert!(changed.validate().is_err());
    changed.members[0].power = u64::MAX / 3;
    assert!(changed.validate().is_err());
    changed.members.clear();
    assert!(matches!(
        changed
            .validate()
            .unwrap_err()
            .downcast_ref::<AuthorityError>(),
        Some(AuthorityError::NoActiveValidators)
    ));
}
