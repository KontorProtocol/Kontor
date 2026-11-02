use std::fs;
use std::path::Path;

use kontor_consensus_first::{WalInspection, WalResumeContext, inspect_protected_wal};
use malachitebft_signing_ed25519::PrivateKey;
use malachitebft_wal as wal;
use prost::Message;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

#[allow(dead_code)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/consensus.v1.rs"));
}

fn resumed(height: u64) -> WalResumeContext {
    WalResumeContext {
        height,
        chain: [1; 32],
        era: [2; 32],
        protocol: [3; 32],
        codec: 1,
    }
}

fn batch_value(era: u8) -> proto::Value {
    let body = [0u8; 4];
    let mut digest = Sha256::new();
    digest.update(b"kontor/certified-input-body/v1");
    digest.update([0]);
    digest.update(body);
    let mut descriptor = Vec::new();
    descriptor.extend_from_slice(b"KVD1");
    descriptor.extend_from_slice(&[1; 32]);
    descriptor.extend_from_slice(&[era; 32]);
    descriptor.extend_from_slice(&[3; 32]);
    descriptor.extend_from_slice(&1u32.to_be_bytes());
    descriptor.push(0);
    descriptor.extend_from_slice(&0u64.to_be_bytes());
    descriptor.extend_from_slice(&[0; 32]);
    descriptor.extend_from_slice(&0u32.to_be_bytes());
    descriptor.extend_from_slice(&4u32.to_be_bytes());
    descriptor.extend_from_slice(&digest.finalize());
    proto::Value {
        descriptor: descriptor.into(),
        body: body.to_vec().into(),
    }
}

fn address(key: &PrivateKey) -> proto::Address {
    let hash: [u8; 32] = Keccak256::digest(key.public_key().as_bytes()).into();
    proto::Address {
        value: hash[..20].to_vec().into(),
    }
}

fn signature(bytes: [u8; 64]) -> proto::Signature {
    proto::Signature {
        bytes: bytes.to_vec().into(),
    }
}

fn signed_proposal(height: u64, era: u8) -> Vec<u8> {
    let key = PrivateKey::from([11; 32]);
    let proposal = proto::Proposal {
        height,
        round: 0,
        value: Some(batch_value(era)),
        pol_round: None,
        validator_address: Some(address(&key)),
    };
    let signed = proto::SignedMessage {
        signature: Some(signature(key.sign(&proposal.encode_to_vec()).to_bytes())),
        message: Some(proto::signed_message::Message::Proposal(proposal)),
    };
    encoded_input(1, &signed)
}

fn signed_vote(height: u64) -> Vec<u8> {
    let key = PrivateKey::from([11; 32]);
    let vote = proto::Vote {
        vote_type: proto::VoteType::Prevote as i32,
        height,
        round: 0,
        value: None,
        validator_address: Some(address(&key)),
    };
    let signed = proto::SignedMessage {
        signature: Some(signature(key.sign(&vote.encode_to_vec()).to_bytes())),
        message: Some(proto::signed_message::Message::Vote(vote)),
    };
    encoded_input(1, &signed)
}

fn proposed_value(height: u64, era: u8) -> Vec<u8> {
    let key = PrivateKey::from([11; 32]);
    encoded_input(
        4,
        &proto::ProposedValue {
            height,
            round: 0,
            valid_round: None,
            proposer: Some(address(&key)),
            value: Some(batch_value(era)),
            validity: true,
        },
    )
}

fn polka_certificate(height: u64) -> Vec<u8> {
    encoded_input(
        8,
        &proto::PolkaCertificate {
            height,
            round: 0,
            value_id: Some(proto::ValueId {
                value: Some(vec![7; 32].into()),
            }),
            signatures: Vec::new(),
        },
    )
}

fn encoded_input(tag: u8, message: &impl Message) -> Vec<u8> {
    let payload = message.encode_to_vec();
    let mut encoded = Vec::with_capacity(9 + payload.len());
    encoded.push(tag);
    encoded.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&payload);
    encoded
}

fn write_wal(path: &Path, height: u64, entries: &[Vec<u8>]) {
    let mut log = wal::Log::open(path).unwrap();
    log.reset(height).unwrap();
    for entry in entries {
        log.write_raw(entry).unwrap();
    }
}

#[test]
fn missing_and_valid_empty_wal_are_distinct() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wal");
    assert_eq!(
        inspect_protected_wal(&path, resumed(9)).unwrap(),
        WalInspection::Missing
    );
    let mut log = wal::Log::open(&path).unwrap();
    log.reset(9).unwrap();
    drop(log);
    let original = fs::read(&path).unwrap();
    assert_eq!(
        inspect_protected_wal(&path, resumed(9)).unwrap(),
        WalInspection::Present {
            height: 9,
            entries: 0
        }
    );
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn valid_entry_and_corrupt_or_truncated_tails() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wal");
    let mut log = wal::Log::open(&path).unwrap();
    log.reset(12).unwrap();
    let encoded = [2, 2, 0, 0, 0, 0, 0, 0, 0, 2];
    log.write_raw(encoded).unwrap();
    drop(log);
    let valid = fs::read(&path).unwrap();
    assert_eq!(
        inspect_protected_wal(&path, resumed(12)).unwrap(),
        WalInspection::Present {
            height: 12,
            entries: 1
        }
    );
    assert_eq!(fs::read(&path).unwrap(), valid);

    fs::write(&path, &valid[..valid.len() - 1]).unwrap();
    assert!(inspect_protected_wal(&path, resumed(12)).is_err());
    assert_eq!(fs::read(&path).unwrap(), valid[..valid.len() - 1]);

    let mut corrupted = valid;
    *corrupted.last_mut().unwrap() ^= 1;
    fs::write(&path, &corrupted).unwrap();
    assert!(inspect_protected_wal(&path, resumed(12)).is_err());
    assert_eq!(fs::read(&path).unwrap(), corrupted);

    fs::write(&path, []).unwrap();
    assert!(inspect_protected_wal(&path, resumed(12)).is_err());
}

#[test]
fn same_height_values_require_the_resumed_context_without_changing_wal() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wal");
    for entry in [signed_proposal(12, 9), proposed_value(12, 9)] {
        write_wal(&path, 12, &[entry]);
        let original = fs::read(&path).unwrap();
        assert!(inspect_protected_wal(&path, resumed(12)).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        let mut matching = resumed(12);
        matching.era = [9; 32];
        assert_eq!(
            inspect_protected_wal(&path, matching).unwrap(),
            WalInspection::Present {
                height: 12,
                entries: 1
            }
        );
    }
}

#[test]
fn older_foreign_context_is_allowed_and_mixed_entry_heights_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wal");
    write_wal(&path, 11, &[signed_proposal(11, 9), proposed_value(11, 9)]);
    assert_eq!(
        inspect_protected_wal(&path, resumed(12)).unwrap(),
        WalInspection::Present {
            height: 11,
            entries: 2
        }
    );
    for entry in [
        signed_vote(12),
        signed_proposal(12, 2),
        proposed_value(12, 2),
        polka_certificate(12),
    ] {
        write_wal(&path, 12, &[entry]);
        assert_eq!(
            inspect_protected_wal(&path, resumed(12)).unwrap(),
            WalInspection::Present {
                height: 12,
                entries: 1
            }
        );
    }
    for entry in [
        signed_vote(13),
        signed_proposal(13, 2),
        proposed_value(13, 2),
        polka_certificate(13),
    ] {
        write_wal(&path, 12, &[entry]);
        let original = fs::read(&path).unwrap();
        assert!(inspect_protected_wal(&path, resumed(12)).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}
