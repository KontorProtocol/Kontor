use anyhow::{Error, Result, bail, ensure};
use malachitebft_app_channel::AppMsg;
use malachitebft_core_consensus::{LocallyProposedValue, ProposedValue, Role, VoteExtensionError};
use malachitebft_engine::host::{Next, SyncedValueOutcome};
use prost::Message;
use tokio::sync::oneshot::Sender;

use crate::api::{
    CertificateBytes, Event, NextHeight, ProposalPartBytes, ReplyKind, ReplyToken, Request,
    Response, Role as PublicRole, SyncOutcome,
};
use crate::bridge_types::{check_length, encode_message, height_params, message, round};
use crate::consensus::codec::{decode_synced_value, encode_commit_certificate};
use crate::consensus::proto;
use crate::consensus::{Ctx, Height};
use crate::replies::{Delivery, Replies, ReplyError};

pub(crate) struct Bridge {
    generation: u64,
    retired: bool,
    replies: Replies,
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
        token: ReplyToken,
        response: Response,
    ) -> Result<Delivery, ReplyError> {
        let result = self.replies.respond(token, response);
        if matches!(result, Err(ReplyError::Malformed(_))) {
            self.retire();
        }
        result
    }

    fn register<T: Send + 'static>(
        &mut self,
        kind: ReplyKind,
        sender: Sender<T>,
        convert: impl FnOnce(Response) -> Result<T> + Send + 'static,
    ) -> Result<ReplyToken> {
        self.replies
            .insert(kind, sender, |response| {
                convert(response).map_err(|e| e.to_string())
            })
            .map_err(Error::msg)
    }

    pub(crate) fn event(&mut self, message: AppMsg<Ctx>) -> Result<Option<Event>> {
        ensure!(!self.retired, "engine bridge retired");
        let result = self.convert_event(message);
        if result.is_err() {
            // Losing an engine request cannot be retried with a different token.
            // The owner must stop and retain ownership until joined.
            self.retire();
        }
        result
    }

    fn convert_event(&mut self, msg: AppMsg<Ctx>) -> Result<Option<Event>> {
        let (request, token) = match msg {
            AppMsg::ConsensusReady { reply } => {
                let token = self.register(ReplyKind::Ready, reply, |response| {
                    let Response::Ready(params) = response else {
                        bail!("wrong ready response")
                    };
                    height_params(params)
                })?;
                (Request::Ready, Some(token))
            }
            AppMsg::StartedRound {
                height,
                round,
                proposer,
                role,
                reply_value,
            } => {
                let token =
                    self.register(ReplyKind::StartedRound, reply_value, move |response| {
                        let Response::StartedRound(encoded) = response else {
                            bail!("wrong round response")
                        };
                        check_length(encoded.len())?;
                        let mut values = Vec::new();
                        values.try_reserve(encoded.len())?;
                        for bytes in encoded {
                            let value: ProposedValue<Ctx> = message(bytes.0)?;
                            ensure!(value.height == height, "recovered proposal height mismatch");
                            values.push(value);
                        }
                        Ok(values)
                    })?;
                let role = match role {
                    Role::Proposer => PublicRole::Proposer,
                    Role::Validator => PublicRole::Validator,
                    Role::None => PublicRole::Observer,
                };
                (
                    Request::StartedRound {
                        height: height.as_u64(),
                        round: round.as_u32(),
                        proposer: proposer.into_inner(),
                        role,
                    },
                    Some(token),
                )
            }
            AppMsg::GetValue {
                height,
                round: request_round,
                timeout,
                reply,
            } => {
                let token = self.register(ReplyKind::Value, reply, move |response| {
                    let Response::Value {
                        height: reply_height,
                        round: reply_round,
                        value,
                    } = response
                    else {
                        bail!("wrong value response")
                    };
                    ensure!(
                        reply_height == height.as_u64() && round(reply_round) == request_round,
                        "local proposal position mismatch"
                    );
                    Ok(LocallyProposedValue::new(
                        height,
                        request_round,
                        message(value.0)?,
                    ))
                })?;
                (
                    Request::GetValue {
                        height: height.as_u64(),
                        round: request_round.as_u32(),
                        timeout,
                    },
                    Some(token),
                )
            }
            AppMsg::ReceivedProposalPart {
                from,
                published_by,
                part,
                reply,
            } => {
                let from = from.to_bytes();
                let published_by = published_by.map(|peer| peer.to_bytes());
                check_length(from.len())?;
                if let Some(peer) = &published_by {
                    check_length(peer.len())?;
                }
                let part = ProposalPartBytes(encode_message(&part)?);
                let token = self.register(ReplyKind::ProposalPart, reply, |response| {
                    let Response::ProposalPart(value) = response else {
                        bail!("wrong proposal part response")
                    };
                    value.map(|bytes| message(bytes.0)).transpose()
                })?;
                (
                    Request::ProposalPart {
                        from,
                        published_by,
                        part,
                    },
                    Some(token),
                )
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
                let bytes = encode_commit_certificate(&certificate)?.encode_to_vec();
                check_length(bytes.len())?;
                let token = self.register(ReplyKind::Decided, reply, |response| {
                    ensure!(
                        matches!(response, Response::Decided),
                        "wrong decided response"
                    );
                    Ok(())
                })?;
                (
                    Request::Decided {
                        certificate: CertificateBytes(bytes),
                    },
                    Some(token),
                )
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
                let bytes = encode_commit_certificate(&certificate)?.encode_to_vec();
                check_length(bytes.len())?;
                // Evidence is diagnostic only in the existing reactor.
                let evidence = format!("{evidence:?}");
                check_length(evidence.len())?;
                let token = self.register(ReplyKind::Finalized, reply, |response| {
                    let Response::Finalized(next) = response else {
                        bail!("wrong finalized response")
                    };
                    Ok(match next {
                        NextHeight::Start(params) => {
                            let (height, params) = height_params(params)?;
                            Next::Start(height, params)
                        }
                        NextHeight::Restart(params) => {
                            let (height, params) = height_params(params)?;
                            Next::Restart(height, params)
                        }
                    })
                })?;
                (
                    Request::Finalized {
                        certificate: CertificateBytes(bytes),
                        evidence,
                    },
                    Some(token),
                )
            }
            AppMsg::GetHistoryMinHeight { reply } => {
                let token = self.register(ReplyKind::HistoryMinHeight, reply, |response| {
                    let Response::HistoryMinHeight(height) = response else {
                        bail!("wrong history minimum response")
                    };
                    ensure!(height > 0, "invalid minimum history height");
                    Ok(Height::new(height))
                })?;
                (Request::HistoryMinHeight, Some(token))
            }
            AppMsg::GetDecidedValues { range, reply } => {
                let (start, end) = (range.start().as_u64(), range.end().as_u64());
                let token = self.register(ReplyKind::DecidedValues, reply, move |response| {
                    let Response::DecidedValues(encoded) = response else {
                        bail!("wrong history response")
                    };
                    check_length(encoded.len())?;
                    let mut values = Vec::new();
                    values.try_reserve(encoded.len())?;
                    let mut previous = None;
                    for bytes in encoded {
                        check_length(bytes.0.len())?;
                        let value =
                            decode_synced_value(proto::SyncedValue::decode(bytes.0.as_slice())?)?;
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
                })?;
                (Request::DecidedValues { start, end }, Some(token))
            }
            AppMsg::ProcessSyncedValue {
                height,
                round,
                proposer,
                value_bytes,
                reply,
            } => {
                check_length(value_bytes.len())?;
                let token = self.register(ReplyKind::SyncedValue, reply, move |response| {
                    let Response::SyncedValue(outcome) = response else {
                        bail!("wrong synced value response")
                    };
                    Ok(match outcome {
                        SyncOutcome::Verdict(bytes) => {
                            let value: ProposedValue<Ctx> = message(bytes.0)?;
                            ensure!(
                                value.height == height
                                    && value.round == round
                                    && value.proposer == proposer,
                                "synced proposal position mismatch"
                            );
                            SyncedValueOutcome::Verdict(value)
                        }
                        SyncOutcome::PeerFault => SyncedValueOutcome::PeerFault,
                        SyncOutcome::LocalTransientError => SyncedValueOutcome::LocalTransientError,
                    })
                })?;
                (
                    Request::SyncedValue {
                        height: height.as_u64(),
                        round: round.as_u32(),
                        proposer: proposer.into_inner(),
                        value: value_bytes.to_vec(),
                    },
                    Some(token),
                )
            }
            AppMsg::RestreamProposal {
                height,
                round,
                valid_round,
                address,
                value_id,
            } => (
                Request::RestreamProposal {
                    height: height.as_u64(),
                    round: round.as_u32(),
                    valid_round: valid_round.as_u32(),
                    address: address.into_inner(),
                    value_id: value_id.0,
                },
                None,
            ),
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
        Ok(Some(Event {
            generation: self.generation,
            request,
            reply: token,
        }))
    }
}

#[cfg(test)]
#[path = "bridge_tests.rs"]
mod tests;
