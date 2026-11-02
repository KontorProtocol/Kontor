use std::time::Duration;

use bytes::Bytes;
use malachitebft_core_consensus::MisbehaviorEvidence;
use malachitebft_core_types::{
    CommitCertificate, Round, Validity, VoteExtensionPolicy, VoteExtensions,
};
use tokio::sync::oneshot;

use super::*;
use crate::api::{ProposalBytes, SyncedValueBytes, ValueBytes};
use crate::bridge_types::test_params;
use crate::consensus::Address;
use crate::consensus::codec::decode_commit_certificate;
use crate::consensus::test_fixtures;

fn certificate() -> CommitCertificate<Ctx> {
    CommitCertificate::new(
        Height::new(5),
        Round::ZERO,
        test_fixtures::block().id(),
        vec![],
    )
}

#[test]
fn ready_and_finalized_keep_private_replies_until_matching_ack() {
    let mut bridge = Bridge::new(9, 4).unwrap();
    let (sender, mut receiver) = oneshot::channel();
    let event = bridge
        .event(AppMsg::ConsensusReady { reply: sender })
        .unwrap()
        .unwrap();
    assert_eq!((event.generation, event.request), (9, Request::Ready));
    bridge
        .respond(event.reply.unwrap(), Response::Ready(test_params(5)))
        .unwrap();
    assert_eq!(
        receiver.try_recv().unwrap(),
        height_params(test_params(5)).unwrap()
    );

    let (sender, mut receiver) = oneshot::channel();
    let event = bridge
        .event(AppMsg::Finalized {
            certificate: certificate(),
            extensions: VoteExtensions::default(),
            evidence: MisbehaviorEvidence {
                proposals: Default::default(),
                votes: Default::default(),
            },
            reply: sender,
        })
        .unwrap()
        .unwrap();
    let Request::Finalized {
        certificate: bytes,
        evidence,
    } = event.request
    else {
        panic!("wrong event")
    };
    let cert =
        decode_commit_certificate(proto::CommitCertificate::decode(bytes.0.as_slice()).unwrap())
            .unwrap();
    assert_eq!(cert, certificate());
    assert!(!evidence.is_empty());
    let token = event.reply.unwrap();
    let response = Response::Finalized(NextHeight::Start(test_params(6)));
    let stale = ReplyToken {
        generation: 8,
        ..token
    };
    assert_eq!(
        bridge.respond(stale, response.clone()),
        Err(ReplyError::StaleGeneration)
    );
    assert_eq!(
        bridge.respond(token, Response::Decided),
        Err(ReplyError::WrongOperation)
    );
    bridge.respond(token, response.clone()).unwrap();
    match receiver.try_recv().unwrap() {
        Next::Start(height, actual) => {
            assert_eq!((height, actual), height_params(test_params(6)).unwrap())
        }
        Next::Restart(..) => panic!("wrong action"),
    }
    assert_eq!(
        bridge.respond(token, response),
        Err(ReplyError::UnknownToken)
    );
}

#[test]
fn get_value_preserves_real_input_and_rejects_wrong_position() {
    let mut bridge = Bridge::new(2, 2).unwrap();
    for reply_height in [5, 6] {
        let (sender, mut receiver) = oneshot::channel();
        let event = bridge
            .event(AppMsg::GetValue {
                height: Height::new(5),
                round: Round::new(3),
                timeout: Duration::from_millis(57),
                reply: sender,
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            event.request,
            Request::GetValue {
                height: 5,
                round: Some(3),
                timeout: Duration::from_millis(57)
            }
        );
        let value = test_fixtures::block();
        let response = Response::Value {
            height: reply_height,
            round: Some(3),
            value: ValueBytes(encode_message(&value).unwrap()),
        };
        let result = bridge.respond(event.reply.unwrap(), response);
        if reply_height == 5 {
            result.unwrap();
            let actual = receiver.try_recv().unwrap();
            assert_eq!(actual.value.input(), value.input());
            assert_eq!(actual.value.id(), value.id());
        } else {
            assert!(matches!(result, Err(ReplyError::Malformed(_))));
            assert_eq!(
                receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            );
        }
    }
}

#[test]
fn decision_ack_does_not_complete_before_reply_and_retirement_drops_it() {
    let mut bridge = Bridge::new(1, 2).unwrap();
    let (sender, mut receiver) = oneshot::channel();
    let event = bridge
        .event(AppMsg::Decided {
            certificate: certificate(),
            extensions: VoteExtensions::default(),
            reply: sender,
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    );
    bridge.retire();
    assert_eq!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    );
    assert!(
        bridge
            .respond(event.reply.unwrap(), Response::Decided)
            .is_err()
    );
    let (sender, _receiver) = oneshot::channel();
    assert!(
        bridge
            .event(AppMsg::GetHistoryMinHeight { reply: sender })
            .is_err()
    );
}

#[test]
fn synced_peer_fault_and_local_failure_remain_distinct() {
    let mut bridge = Bridge::new(1, 2).unwrap();
    for outcome in [SyncOutcome::PeerFault, SyncOutcome::LocalTransientError] {
        let (sender, mut receiver) = oneshot::channel();
        let event = bridge
            .event(AppMsg::ProcessSyncedValue {
                height: Height::new(5),
                round: Round::ZERO,
                proposer: Address::new([1; 20]),
                value_bytes: Bytes::from_static(b"retained wire input"),
                reply: sender,
            })
            .unwrap()
            .unwrap();
        bridge
            .respond(event.reply.unwrap(), Response::SyncedValue(outcome.clone()))
            .unwrap();
        assert!(matches!(
            (outcome, receiver.try_recv().unwrap()),
            (SyncOutcome::PeerFault, SyncedValueOutcome::PeerFault)
                | (
                    SyncOutcome::LocalTransientError,
                    SyncedValueOutcome::LocalTransientError
                )
        ));
    }
}

#[test]
fn malformed_inner_payload_retires_other_pending_replies() {
    let mut bridge = Bridge::new(1, 2).unwrap();
    let (other, mut other_receiver) = oneshot::channel();
    bridge
        .event(AppMsg::GetHistoryMinHeight { reply: other })
        .unwrap();
    let (sender, mut receiver) = oneshot::channel();
    let event = bridge
        .event(AppMsg::StartedRound {
            height: Height::new(5),
            round: Round::ZERO,
            proposer: Address::new([1; 20]),
            role: Role::Validator,
            reply_value: sender,
        })
        .unwrap()
        .unwrap();
    assert!(matches!(
        bridge.respond(
            event.reply.unwrap(),
            Response::StartedRound(vec![ProposalBytes(vec![255])])
        ),
        Err(ReplyError::Malformed(_))
    ));
    assert!(receiver.try_recv().is_err());
    assert_eq!(
        other_receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    );
}

#[test]
fn unsupported_extensions_never_acquire_a_reply_capability() {
    let mut bridge = Bridge::new(1, 1).unwrap();
    let (sender, mut receiver) = oneshot::channel();
    assert!(
        bridge
            .event(AppMsg::ExtendVote {
                height: Height::new(1),
                round: Round::ZERO,
                value_id: test_fixtures::block().id(),
                vote_extension_policy: VoteExtensionPolicy::Disabled,
                reply: sender,
            })
            .unwrap()
            .is_none()
    );
    assert_eq!(receiver.try_recv().unwrap(), None);
    let (sender, mut receiver) = oneshot::channel();
    let address = Address::new([1; 20]);
    assert!(
        bridge
            .event(AppMsg::VerifyVoteExtensions {
                height: Height::new(1),
                round: Round::ZERO,
                value_id: test_fixtures::block().id(),
                extensions: vec![(address, Bytes::new())],
                reply: sender,
            })
            .unwrap()
            .is_none()
    );
    assert_eq!(
        receiver.try_recv().unwrap(),
        vec![(address, Err(VoteExtensionError::InvalidVoteExtension))]
    );
    let (sender, mut receiver) = oneshot::channel();
    assert!(
        bridge
            .event(AppMsg::ExtendVote {
                height: Height::new(1),
                round: Round::ZERO,
                value_id: test_fixtures::block().id(),
                vote_extension_policy: VoteExtensionPolicy::Required,
                reply: sender,
            })
            .is_err()
    );
    assert_eq!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    );
}

#[test]
fn history_reply_preserves_input_and_rejects_duplicates_or_out_of_range() {
    for heights in [vec![5, 6], vec![5, 5], vec![6, 5], vec![4]] {
        let mut bridge = Bridge::new(1, 1).unwrap();
        let (sender, mut receiver) = oneshot::channel();
        let event = bridge
            .event(AppMsg::GetDecidedValues {
                range: Height::new(5)..=Height::new(6),
                reply: sender,
            })
            .unwrap()
            .unwrap();
        assert_eq!(event.request, Request::DecidedValues { start: 5, end: 6 });
        let encoded = heights
            .iter()
            .map(|height| {
                let mut cert = certificate();
                cert.height = Height::new(*height);
                SyncedValueBytes(
                    proto::SyncedValue {
                        value_bytes: Bytes::from_static(b"retained input"),
                        certificate: Some(encode_commit_certificate(&cert).unwrap()),
                    }
                    .encode_to_vec(),
                )
            })
            .collect();
        let result = bridge.respond(event.reply.unwrap(), Response::DecidedValues(encoded));
        if heights == [5, 6] {
            result.unwrap();
            let values = receiver.try_recv().unwrap();
            assert_eq!(
                values
                    .iter()
                    .map(|v| v.certificate.height.as_u64())
                    .collect::<Vec<_>>(),
                heights
            );
            assert!(
                values
                    .iter()
                    .all(|v| v.value_bytes.as_ref() == b"retained input")
            );
        } else {
            assert!(matches!(result, Err(ReplyError::Malformed(_))));
            assert!(receiver.try_recv().is_err());
        }
    }
}

#[test]
fn synced_verdict_must_match_height_round_and_proposer() {
    for (height, round, proposer) in [(5, 2, 1), (6, 2, 1), (5, 3, 1), (5, 2, 2)] {
        let mut bridge = Bridge::new(1, 1).unwrap();
        let (sender, mut receiver) = oneshot::channel();
        let event = bridge
            .event(AppMsg::ProcessSyncedValue {
                height: Height::new(5),
                round: Round::new(2),
                proposer: Address::new([1; 20]),
                value_bytes: Bytes::from_static(b"retained input"),
                reply: sender,
            })
            .unwrap()
            .unwrap();
        let value = ProposedValue {
            height: Height::new(height),
            round: Round::new(round),
            valid_round: Round::Nil,
            proposer: Address::new([proposer; 20]),
            value: test_fixtures::block(),
            validity: Validity::Valid,
        };
        let response = Response::SyncedValue(SyncOutcome::Verdict(ProposalBytes(
            encode_message(&value).unwrap(),
        )));
        let result = bridge.respond(event.reply.unwrap(), response);
        if (height, round, proposer) == (5, 2, 1) {
            result.unwrap();
            let SyncedValueOutcome::Verdict(actual) = receiver.try_recv().unwrap() else {
                panic!("wrong verdict")
            };
            assert_eq!(actual, value);
        } else {
            assert!(matches!(result, Err(ReplyError::Malformed(_))));
            assert!(receiver.try_recv().is_err());
        }
    }
}
