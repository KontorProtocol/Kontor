use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use malachitebft_app_channel::AppMsg;
use malachitebft_app_channel::app::types::PeerId;
use malachitebft_codec::Codec;
use malachitebft_core_consensus::{LocallyProposedValue, ProposedValue, Role as ConsensusRole};
use malachitebft_core_types::{HeightParams, Round, VoteExtensions};
use malachitebft_engine::host::{Next, SyncedValueOutcome};
use malachitebft_proto::Error as ProtoError;
use malachitebft_sync::RawDecidedValue;
use prost::Message as ProstMessage;
use tokio::sync::{oneshot, watch};
use tokio::time::{Instant, timeout_at};

use super::control::{Control, EngineSlot, Status};
use super::startup::{Configuration, Runtime};
use super::types::{
    Delivery, EngineError, EngineState, Event, HeightParameters, NextHeight, ProposalBytes,
    ProposalPartBytes, PublishError, ReplyError, ReplyToken, Request, Response, Role, SyncOutcome,
    SyncedValueBytes, Timeouts, Validator, ValueBytes,
};
use crate::consensus::codec::{ProtobufCodec, decode_commit_certificate, encode_synced_value};
use crate::consensus::{Address, CommitCertificate, Ctx, Height, ValueId, proto};
use crate::protocol::coordinator::durable_signer::{DurableSigner, OwnedGeneration};
use crate::reactor::message::Message;

type Reply =
    Pin<Box<dyn Future<Output = Result<(ReplyToken, Response), EngineError>> + Send + Sync>>;
type Outgoing = Pin<Box<dyn Future<Output = Result<Delivery, EngineError>> + Send + Sync>>;

pub(crate) struct ReactorEngine {
    generation: u64,
    capacity: usize,
    retired: bool,
    control: Control,
    status: watch::Receiver<Status>,
    replies: FuturesUnordered<Reply>,
    outgoing: Option<Outgoing>,
}

impl ReactorEngine {
    #[cfg(test)]
    pub(crate) fn start(
        slot: &EngineSlot,
        bundle: Runtime,
        config: Configuration,
        signer: Option<Arc<DurableSigner>>,
    ) -> Result<Self, EngineError> {
        let generation = config.generation;
        let capacity = config.channel_capacity;
        let control = slot.start(bundle, config, signer)?;
        Ok(Self::from_control(generation, capacity, control))
    }

    pub(crate) fn start_owned(
        slot: &EngineSlot,
        bundle: Runtime,
        config: Configuration,
        signer: Option<Arc<DurableSigner>>,
        ownership: OwnedGeneration,
    ) -> Result<Self, EngineError> {
        let generation = config.generation;
        let capacity = config.channel_capacity;
        let control = slot.start_owned(bundle, config, signer, ownership)?;
        Ok(Self::from_control(generation, capacity, control))
    }

    fn from_control(generation: u64, capacity: usize, control: Control) -> Self {
        Self {
            generation,
            capacity,
            retired: false,
            status: control.subscribe(),
            control,
            replies: FuturesUnordered::new(),
            outgoing: None,
        }
    }

    pub(crate) fn signer(&self) -> Option<Arc<DurableSigner>> {
        self.control.signer()
    }

    pub(crate) async fn next(&mut self) -> Result<Option<Message>, EngineError> {
        let result = self.next_inner().await;
        if result.is_err() {
            self.retire();
        }
        result
    }

    async fn next_inner(&mut self) -> Result<Option<Message>, EngineError> {
        loop {
            if self.retired {
                return Ok(None);
            }
            let status = self.status.borrow().clone();
            if let Some(error) = status.failure {
                return Err(error);
            }
            if matches!(status.state, EngineState::Stopping | EngineState::Joined) {
                return Ok(None);
            }
            tokio::select! {
                biased;
                result = async {
                    match self.outgoing.as_mut() { Some(reply) => reply.await, None => pending().await }
                } => {
                    self.outgoing = None;
                    match result {
                        Ok(_) | Err(EngineError::Reply(ReplyError::UnknownToken)) => {}
                        Err(error) => return Err(error),
                    }
                }
                Some(reply) = self.replies.next(), if self.outgoing.is_none() && !self.replies.is_empty() => {
                    let (token, response) = reply?;
                    // Keep this future in the owner across cancellation of next().
                    self.outgoing = Some(Box::pin(self.control.begin_response(token, response)));
                }
                changed = self.status.changed() => {
                    if changed.is_err() { return Err(EngineError::Failed("consensus control status closed".into())) }
                }
                event = self.control.events.recv(), if self.replies.len() + usize::from(self.outgoing.is_some()) < self.capacity => {
                    let Some(event) = event else {
                        let status = self.control.status();
                        return match status.failure { Some(error) => Err(error), None => Ok(None) }
                    };
                    let (message, reply) = decode(self.generation, event)?;
                    if let Some(reply) = reply { self.replies.push(reply); }
                    return Ok(Some(message));
                }
            }
        }
    }

    pub(crate) async fn publish(&mut self, part: ProposalPartBytes) -> Result<(), PublishError> {
        self.control.publish(self.generation, part).await
    }

    pub(crate) async fn request_listen_address(&mut self) -> Result<bool, EngineError> {
        self.control.request_listen_address().await
    }

    pub(crate) async fn poll_listen_address(&mut self) -> Result<Option<String>, EngineError> {
        self.control.poll_listen_address().await
    }

    pub(crate) fn retire(&mut self) {
        self.control.request_stop();
        self.retired = true;
        self.control.events.close();
        while self.control.events.try_recv().is_ok() {}
        self.replies.clear();
        self.outgoing = None;
    }

    pub(crate) async fn revoke_signing(&mut self) -> Result<(), EngineError> {
        self.control.revoke_signing().await
    }

    pub(crate) async fn wait_stopped(&mut self, timeout: Duration) -> Result<bool, EngineError> {
        self.control.wait_stopped(timeout).await
    }
}

fn reply<T, F>(
    token: ReplyToken,
    deadline: Option<Duration>,
    convert: F,
) -> (oneshot::Sender<T>, Reply)
where
    T: Send + 'static,
    F: FnOnce(T) -> Result<Response, EngineError> + Send + Sync + 'static,
{
    let (send, receive) = oneshot::channel();
    let deadline = deadline.map(|duration| Instant::now() + duration);
    let future = Box::pin(async move {
        let value = match deadline {
            Some(deadline) => timeout_at(deadline, receive)
                .await
                .ok()
                .and_then(Result::ok),
            None => receive.await.ok(),
        };
        let response = match value {
            Some(value) => convert(value)?,
            None => Response::Abandon,
        };
        Ok((token, response))
    });
    (send, future)
}

fn decode(generation: u64, event: Event) -> Result<(Message, Option<Reply>), EngineError> {
    if event.generation != generation {
        return Err(EngineError::StaleGeneration);
    }
    if let Request::RestreamProposal {
        height,
        round,
        valid_round,
        address,
        value_id,
    } = event.request
    {
        if event.reply.is_some() {
            return Err(malformed("restream request has a reply token"));
        }
        return Ok((
            AppMsg::RestreamProposal {
                height: Height::new(height),
                round: Round::from(round),
                valid_round: Round::from(valid_round),
                address: Address::new(address),
                value_id: ValueId(value_id),
            }
            .into(),
            None,
        ));
    }
    let token = event
        .reply
        .ok_or_else(|| malformed("engine request lacks reply token"))?;
    let (message, pending) = match event.request {
        Request::Ready => {
            let (send, pending) = reply(token, None, |(height, value)| {
                Ok(Response::Ready(parameters(height, value)?))
            });
            (AppMsg::ConsensusReady { reply: send }.into(), pending)
        }
        Request::StartedRound {
            height,
            round,
            proposer,
            role,
        } => {
            let (send, pending) = reply(token, None, |values: Vec<ProposedValue<Ctx>>| {
                Ok(Response::StartedRound(
                    values
                        .iter()
                        .map(|value| encode(value).map(ProposalBytes))
                        .collect::<Result<_, _>>()?,
                ))
            });
            (
                AppMsg::StartedRound {
                    height: Height::new(height),
                    round: Round::from(round),
                    proposer: Address::new(proposer),
                    role: match role {
                        Role::Proposer => ConsensusRole::Proposer,
                        Role::Validator => ConsensusRole::Validator,
                        Role::Observer => ConsensusRole::None,
                    },
                    reply_value: send,
                }
                .into(),
                pending,
            )
        }
        Request::GetValue {
            height,
            round,
            timeout,
        } => {
            let (send, pending) =
                reply(token, Some(timeout), |value: LocallyProposedValue<Ctx>| {
                    Ok(Response::Value {
                        height: value.height.as_u64(),
                        round: value.round.as_u32(),
                        value: ValueBytes(encode(&value.value)?),
                    })
                });
            (
                AppMsg::GetValue {
                    height: Height::new(height),
                    round: Round::from(round),
                    timeout,
                    reply: send,
                }
                .into(),
                pending,
            )
        }
        Request::ProposalPart {
            from,
            published_by,
            part,
        } => {
            let (send, pending) = reply(token, None, |value: Option<ProposedValue<Ctx>>| {
                Ok(Response::ProposalPart(
                    value
                        .as_ref()
                        .map(|value| encode(value).map(ProposalBytes))
                        .transpose()?,
                ))
            });
            (
                AppMsg::ReceivedProposalPart {
                    from: PeerId::from_bytes(&from).map_err(codec)?,
                    published_by: published_by
                        .map(|bytes| PeerId::from_bytes(&bytes).map_err(codec))
                        .transpose()?,
                    part: ProtobufCodec.decode(Bytes::from(part.0)).map_err(codec)?,
                    reply: send,
                }
                .into(),
                pending,
            )
        }
        Request::Decided { certificate } => {
            let (send, pending) = reply(token, None, |()| Ok(Response::Decided));
            (
                AppMsg::Decided {
                    certificate: certificate_decode(&certificate.0)?,
                    extensions: VoteExtensions::default(),
                    reply: send,
                }
                .into(),
                pending,
            )
        }
        Request::Finalized {
            certificate,
            evidence,
        } => {
            let (send, pending) = reply(token, None, |next| {
                Ok(Response::Finalized(match next {
                    Next::Start(height, value) => NextHeight::Start(parameters(height, value)?),
                    Next::Restart(height, value) => NextHeight::Restart(parameters(height, value)?),
                }))
            });
            (
                Message::Finalized {
                    certificate: certificate_decode(&certificate.0)?,
                    evidence,
                    reply: send,
                },
                pending,
            )
        }
        Request::HistoryMinHeight => {
            let (send, pending) = reply(token, None, |height: Height| {
                Ok(Response::HistoryMinHeight(height.as_u64()))
            });
            (AppMsg::GetHistoryMinHeight { reply: send }.into(), pending)
        }
        Request::DecidedValues { start, end } => {
            let (send, pending) = reply(token, None, |values: Vec<RawDecidedValue<Ctx>>| {
                Ok(Response::DecidedValues(
                    values
                        .iter()
                        .map(|value| {
                            encode_synced_value(value)
                                .map(|value| SyncedValueBytes(value.encode_to_vec()))
                                .map_err(codec)
                        })
                        .collect::<Result<_, _>>()?,
                ))
            });
            (
                AppMsg::GetDecidedValues {
                    range: Height::new(start)..=Height::new(end),
                    reply: send,
                }
                .into(),
                pending,
            )
        }
        Request::SyncedValue {
            height,
            round,
            proposer,
            value,
        } => {
            let (send, pending) = reply(token, None, |value| {
                Ok(Response::SyncedValue(match value {
                    SyncedValueOutcome::Verdict(value) => {
                        SyncOutcome::Verdict(ProposalBytes(encode(&value)?))
                    }
                    SyncedValueOutcome::PeerFault => SyncOutcome::PeerFault,
                    SyncedValueOutcome::LocalTransientError => SyncOutcome::LocalTransientError,
                }))
            });
            (
                AppMsg::ProcessSyncedValue {
                    height: Height::new(height),
                    round: Round::from(round),
                    proposer: Address::new(proposer),
                    value_bytes: Bytes::from(value),
                    reply: send,
                }
                .into(),
                pending,
            )
        }
        Request::RestreamProposal { .. } => unreachable!(),
    };
    Ok((message, Some(pending)))
}

fn encode<T>(value: &T) -> Result<Vec<u8>, EngineError>
where
    ProtobufCodec: Codec<T, Error = ProtoError>,
{
    ProtobufCodec
        .encode(value)
        .map(|bytes| bytes.to_vec())
        .map_err(codec)
}

fn certificate_decode(bytes: &[u8]) -> Result<CommitCertificate<Ctx>, EngineError> {
    decode_commit_certificate(proto::CommitCertificate::decode(bytes).map_err(codec)?)
        .map_err(codec)
}

fn parameters(height: Height, value: HeightParams<Ctx>) -> Result<HeightParameters, EngineError> {
    if !value.vote_extension_policy.is_disabled() {
        return Err(malformed("vote extensions unsupported"));
    }
    let t = value.timeouts;
    Ok(HeightParameters {
        height: height.as_u64(),
        validators: value
            .validator_set
            .validators
            .iter()
            .map(|v| Validator {
                public_key: *v.public_key.as_bytes(),
                voting_power: v.voting_power,
            })
            .collect(),
        timeouts: Timeouts {
            propose: t.propose,
            propose_delta: t.propose_delta,
            prevote: t.prevote,
            prevote_delta: t.prevote_delta,
            precommit: t.precommit,
            precommit_delta: t.precommit_delta,
            rebroadcast: t.rebroadcast,
            max_timeout: t.max_timeout,
        },
        target_time: value.target_time,
    })
}

fn codec(error: impl std::fmt::Display) -> EngineError {
    malformed(&error.to_string())
}
fn malformed(reason: &str) -> EngineError {
    EngineError::Reply(ReplyError::Malformed(reason.into()))
}

#[cfg(test)]
#[path = "reactor_tests.rs"]
mod tests;
