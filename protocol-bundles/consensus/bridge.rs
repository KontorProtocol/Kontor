use anyhow::{Error, Result, bail, ensure};
use malachitebft_app_channel::AppMsg;
use malachitebft_core_consensus::{LocallyProposedValue, ProposedValue, Role, VoteExtensionError};
use malachitebft_engine::host::{Next, SyncedValueOutcome};
use prost::Message;

use crate::bridge_codec::{
    DECIDED, FINALIZED, HISTORY, MIN_HEIGHT, PART, READY, RESTREAM, ROUND, SYNCED, VALUE, decode,
    get_height_params, get_message, get_round, put_duration, put_message, put_round,
};
use crate::consensus::codec::{decode_synced_value, encode_commit_certificate};
use crate::consensus::proto;
use crate::consensus::{Ctx, Height};
use crate::protocol::canonical_codec::Encoder;
use crate::replies::{Delivery, Replies, ReplyError};

type Event = (u64, u8, u64, Vec<u8>);

pub(crate) struct Bridge {
    generation: u64,
    retired: bool,
    replies: Replies,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use malachitebft_core_consensus::MisbehaviorEvidence;
    use malachitebft_core_types::{
        CommitCertificate, HeightParams, LinearTimeouts, Round, VoteExtensionPolicy, VoteExtensions,
    };
    use tokio::sync::oneshot;

    use super::*;
    use crate::bridge_codec::{get_duration, put_height_params};
    use crate::consensus::codec::decode_commit_certificate;
    use crate::consensus::signing::PrivateKey;
    use crate::consensus::test_fixtures;
    use crate::consensus::{Address, Validator, ValidatorSet};
    use crate::protocol::canonical_codec::Decoder;

    fn params() -> HeightParams<Ctx> {
        HeightParams::new(
            ValidatorSet::new([Validator::new(PrivateKey::from([7; 32]).public_key(), 1)]),
            LinearTimeouts::default(),
            Some(Duration::new(2, 3)),
        )
    }

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
        assert_eq!((event.0, event.1, event.3), (9, READY, vec![]));
        let mut bytes = Encoder::default();
        put_height_params(&mut bytes, Height::new(5), &params()).unwrap();
        bridge.respond(9, READY, event.2, &bytes.finish()).unwrap();
        assert_eq!(receiver.try_recv().unwrap(), (Height::new(5), params()));

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
        let mut input = Decoder::new(&event.3);
        let cert = decode_commit_certificate(
            proto::CommitCertificate::decode(input.bytes().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(cert, certificate());
        assert!(!input.string().unwrap().is_empty());
        input.finish().unwrap();
        let mut bytes = Encoder::default();
        bytes.tag(0).unwrap();
        put_height_params(&mut bytes, Height::new(6), &params()).unwrap();
        let bytes = bytes.finish();
        assert!(bridge.respond(8, FINALIZED, event.2, &bytes).is_err());
        assert!(bridge.respond(9, DECIDED, event.2, &[]).is_err());
        bridge.respond(9, FINALIZED, event.2, &bytes).unwrap();
        match receiver.try_recv().unwrap() {
            Next::Start(height, actual) => assert_eq!((height, actual), (Height::new(6), params())),
            Next::Restart(..) => panic!("wrong action"),
        }
        assert!(bridge.respond(9, FINALIZED, event.2, &bytes).is_err());
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
            let mut input = Decoder::new(&event.3);
            assert_eq!(input.u64().unwrap(), 5);
            assert_eq!(get_round(&mut input).unwrap(), Round::new(3));
            assert_eq!(get_duration(&mut input).unwrap(), Duration::from_millis(57));
            input.finish().unwrap();
            let value = test_fixtures::block();
            let mut bytes = Encoder::default();
            bytes.u64(reply_height).unwrap();
            put_round(&mut bytes, Round::new(3)).unwrap();
            put_message(&mut bytes, &value).unwrap();
            let result = bridge.respond(2, VALUE, event.2, &bytes.finish());
            if reply_height == 5 {
                result.unwrap();
                let actual = receiver.try_recv().unwrap();
                assert_eq!(actual.value.input(), value.input());
                assert_eq!(actual.value.id(), value.id());
            } else {
                assert!(result.is_err());
                assert!(receiver.try_recv().is_err());
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
        assert!(bridge.respond(1, DECIDED, event.2, &[]).is_err());
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
        for tag in [1, 2] {
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
            bridge.respond(1, SYNCED, event.2, &[tag]).unwrap();
            assert!(matches!(
                (tag, receiver.try_recv().unwrap()),
                (1, SyncedValueOutcome::PeerFault) | (2, SyncedValueOutcome::LocalTransientError)
            ));
        }
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
}

impl Bridge {
    pub(crate) fn new(generation: u64, capacity: usize) -> Result<Self> {
        Ok(Self {
            generation,
            retired: false,
            replies: Replies::new(generation, capacity).map_err(Error::msg)?,
        })
    }

    pub(crate) fn retire(&mut self) {
        self.retired = true;
        self.replies.retire();
    }

    pub(crate) fn respond(
        &mut self,
        generation: u64,
        operation: u8,
        token: u64,
        payload: &[u8],
    ) -> Result<Delivery, ReplyError> {
        let result = self.replies.respond(generation, token, operation, payload);
        if matches!(result, Err(ReplyError::Malformed(_))) {
            self.retire();
        }
        result
    }

    pub(crate) fn event(&mut self, message: AppMsg<Ctx>) -> Result<Option<Event>> {
        ensure!(!self.retired, "engine bridge retired");
        let result = self.encode_event(message);
        if result.is_err() {
            // Losing an engine request cannot be retried with a different token.
            // The owner must stop on this error and retain ownership until joined.
            self.retire();
        }
        result
    }

    fn encode_event(&mut self, message: AppMsg<Ctx>) -> Result<Option<Event>> {
        let mut out = Encoder::default();
        let (operation, token) = match message {
            AppMsg::ConsensusReady { reply } => {
                let token = self
                    .replies
                    .insert(READY, reply, |bytes| decode(bytes, get_height_params))
                    .map_err(Error::msg)?;
                (READY, token)
            }
            AppMsg::StartedRound {
                height,
                round,
                proposer,
                role,
                reply_value,
            } => {
                out.u64(height.as_u64())?;
                put_round(&mut out, round)?;
                out.fixed(&proposer.into_inner())?;
                out.tag(match role {
                    Role::Proposer => 1,
                    Role::Validator => 2,
                    Role::None => 3,
                })?;
                let token = self
                    .replies
                    .insert(ROUND, reply_value, move |bytes| {
                        decode(bytes, |input| {
                            let count = input.count(4)?;
                            let mut values = Vec::new();
                            values.try_reserve(count)?;
                            for _ in 0..count {
                                let value: ProposedValue<Ctx> = get_message(input)?;
                                ensure!(
                                    value.height == height,
                                    "recovered proposal height mismatch"
                                );
                                values.push(value);
                            }
                            Ok(values)
                        })
                    })
                    .map_err(Error::msg)?;
                (ROUND, token)
            }
            AppMsg::GetValue {
                height,
                round,
                timeout,
                reply,
            } => {
                out.u64(height.as_u64())?;
                put_round(&mut out, round)?;
                put_duration(&mut out, timeout)?;
                let token = self
                    .replies
                    .insert(VALUE, reply, move |bytes| {
                        decode(bytes, |input| {
                            let reply_height = Height::new(input.u64()?);
                            let reply_round = get_round(input)?;
                            ensure!(
                                reply_height == height && reply_round == round,
                                "local proposal position mismatch"
                            );
                            Ok(LocallyProposedValue::new(
                                height,
                                round,
                                get_message(input)?,
                            ))
                        })
                    })
                    .map_err(Error::msg)?;
                (VALUE, token)
            }
            AppMsg::ReceivedProposalPart {
                from,
                published_by,
                part,
                reply,
            } => {
                out.bytes(&from.to_bytes())?;
                match published_by {
                    None => out.tag(0)?,
                    Some(peer) => {
                        out.tag(1)?;
                        out.bytes(&peer.to_bytes())?;
                    }
                }
                put_message(&mut out, &part)?;
                let token = self
                    .replies
                    .insert(PART, reply, |bytes| {
                        decode(bytes, |input| match input.tag()? {
                            0 => Ok(None),
                            1 => Ok(Some(get_message(input)?)),
                            _ => bail!("invalid proposal-part reply"),
                        })
                    })
                    .map_err(Error::msg)?;
                (PART, token)
            }
            AppMsg::Decided {
                certificate,
                extensions,
                reply,
            } => {
                ensure!(
                    extensions.extensions.is_empty(),
                    "decided vote extensions unsupported"
                );
                out.bytes(&encode_commit_certificate(&certificate)?.encode_to_vec())?;
                let token = self
                    .replies
                    .insert(DECIDED, reply, |bytes| decode(bytes, |_| Ok(())))
                    .map_err(Error::msg)?;
                (DECIDED, token)
            }
            AppMsg::Finalized {
                certificate,
                extensions,
                evidence,
                reply,
            } => {
                ensure!(
                    extensions.extensions.is_empty(),
                    "finalized vote extensions unsupported"
                );
                out.bytes(&encode_commit_certificate(&certificate)?.encode_to_vec())?;
                // The current reactor logs this evidence; it does not use it for
                // state transitions. Preserve diagnostics without exporting types.
                out.bytes(format!("{evidence:?}").as_bytes())?;
                let token = self
                    .replies
                    .insert(FINALIZED, reply, |bytes| {
                        decode(bytes, |input| {
                            let action = input.tag()?;
                            let (height, params) = get_height_params(input)?;
                            match action {
                                0 => Ok(Next::Start(height, params)),
                                1 => Ok(Next::Restart(height, params)),
                                _ => bail!("invalid next-height action"),
                            }
                        })
                    })
                    .map_err(Error::msg)?;
                (FINALIZED, token)
            }
            AppMsg::GetHistoryMinHeight { reply } => {
                let token = self
                    .replies
                    .insert(MIN_HEIGHT, reply, |bytes| {
                        decode(bytes, |input| {
                            let height = input.u64()?;
                            ensure!(height > 0, "invalid minimum history height");
                            Ok(Height::new(height))
                        })
                    })
                    .map_err(Error::msg)?;
                (MIN_HEIGHT, token)
            }
            AppMsg::GetDecidedValues { range, reply } => {
                out.u64(range.start().as_u64())?;
                out.u64(range.end().as_u64())?;
                let token = self
                    .replies
                    .insert(HISTORY, reply, move |bytes| {
                        decode(bytes, |input| {
                            let count = input.count(4)?;
                            let mut values = Vec::new();
                            values.try_reserve(count)?;
                            let mut previous = None;
                            for _ in 0..count {
                                let value = decode_synced_value(proto::SyncedValue::decode(
                                    input.bytes()?,
                                )?)?;
                                let height = value.certificate.height;
                                ensure!(
                                    range.contains(&height),
                                    "history reply outside requested range"
                                );
                                ensure!(
                                    previous.is_none_or(|previous| previous < height),
                                    "unordered history reply"
                                );
                                ensure!(
                                    value
                                        .certificate
                                        .commit_signatures
                                        .iter()
                                        .all(|s| s.extension.is_none()),
                                    "history vote extensions unsupported"
                                );
                                previous = Some(height);
                                values.push(value);
                            }
                            Ok(values)
                        })
                    })
                    .map_err(Error::msg)?;
                (HISTORY, token)
            }
            AppMsg::ProcessSyncedValue {
                height,
                round,
                proposer,
                value_bytes,
                reply,
            } => {
                out.u64(height.as_u64())?;
                put_round(&mut out, round)?;
                out.fixed(&proposer.into_inner())?;
                out.bytes(&value_bytes)?;
                let token = self
                    .replies
                    .insert(SYNCED, reply, move |bytes| {
                        decode(bytes, |input| match input.tag()? {
                            0 => {
                                let value: ProposedValue<Ctx> = get_message(input)?;
                                ensure!(
                                    value.height == height
                                        && value.round == round
                                        && value.proposer == proposer,
                                    "synced proposal position mismatch"
                                );
                                Ok(SyncedValueOutcome::Verdict(value))
                            }
                            1 => Ok(SyncedValueOutcome::PeerFault),
                            2 => Ok(SyncedValueOutcome::LocalTransientError),
                            _ => bail!("invalid synced-value outcome"),
                        })
                    })
                    .map_err(Error::msg)?;
                (SYNCED, token)
            }
            AppMsg::RestreamProposal {
                height,
                round,
                valid_round,
                address,
                value_id,
            } => {
                out.u64(height.as_u64())?;
                put_round(&mut out, round)?;
                put_round(&mut out, valid_round)?;
                out.fixed(&address.into_inner())?;
                out.fixed(&value_id.0)?;
                (RESTREAM, 0)
            }
            AppMsg::ExtendVote {
                vote_extension_policy,
                reply,
                ..
            } => {
                ensure!(
                    vote_extension_policy.is_disabled(),
                    "required vote extensions unsupported"
                );
                reply
                    .send(None)
                    .map_err(|_| Error::msg("extension reply closed"))?;
                return Ok(None);
            }
            AppMsg::VerifyVoteExtensions {
                extensions, reply, ..
            } => {
                let verdicts = extensions
                    .into_iter()
                    .map(|(address, _)| (address, Err(VoteExtensionError::InvalidVoteExtension)))
                    .collect();
                reply
                    .send(verdicts)
                    .map_err(|_| Error::msg("extension verdict reply closed"))?;
                return Ok(None);
            }
        };
        Ok(Some((self.generation, operation, token, out.finish())))
    }
}
