use std::time::Duration;

use kontor_consensus_first::Engine;

use super::types::{
    Delivery, EngineError, EnginePoll, EngineState, ProposalPartBytes, Publish, PublishError,
    ReplyToken, Response,
};

pub(super) mod runtime {
    use kontor_consensus_first::api as bundle;

    use super::super::types::{
        CertificateBytes, Delivery, EngineError, EnginePoll, EngineState, Event, HeightParameters,
        NextHeight, ProposalPartBytes, Publish, ReplyError, ReplyToken, Request, Response, Role,
        SyncOutcome,
    };

    fn parameters(value: HeightParameters) -> bundle::HeightParameters {
        bundle::HeightParameters {
            height: value.height,
            validators: value
                .validators
                .into_iter()
                .map(|validator| bundle::Validator {
                    public_key: validator.public_key,
                    voting_power: validator.voting_power,
                })
                .collect(),
            timeouts: bundle::Timeouts {
                propose: value.timeouts.propose,
                propose_delta: value.timeouts.propose_delta,
                prevote: value.timeouts.prevote,
                prevote_delta: value.timeouts.prevote_delta,
                precommit: value.timeouts.precommit,
                precommit_delta: value.timeouts.precommit_delta,
                rebroadcast: value.timeouts.rebroadcast,
                max_timeout: value.timeouts.max_timeout,
            },
            target_time: value.target_time,
        }
    }

    pub(super) fn response(value: Response) -> bundle::Response {
        match value {
            Response::Abandon => bundle::Response::Abandon,
            Response::Ready(value) => bundle::Response::Ready(parameters(value)),
            Response::StartedRound(values) => bundle::Response::StartedRound(
                values
                    .into_iter()
                    .map(|value| bundle::ProposalBytes(value.0))
                    .collect(),
            ),
            Response::Value {
                height,
                round,
                value,
            } => bundle::Response::Value {
                height,
                round,
                value: bundle::ValueBytes(value.0),
            },
            Response::ProposalPart(value) => {
                bundle::Response::ProposalPart(value.map(|value| bundle::ProposalBytes(value.0)))
            }
            Response::Decided => bundle::Response::Decided,
            Response::Finalized(next) => bundle::Response::Finalized(match next {
                NextHeight::Start(value) => bundle::NextHeight::Start(parameters(value)),
                NextHeight::Restart(value) => bundle::NextHeight::Restart(parameters(value)),
            }),
            Response::HistoryMinHeight(height) => bundle::Response::HistoryMinHeight(height),
            Response::DecidedValues(values) => bundle::Response::DecidedValues(
                values
                    .into_iter()
                    .map(|value| bundle::SyncedValueBytes(value.0))
                    .collect(),
            ),
            Response::SyncedValue(outcome) => bundle::Response::SyncedValue(match outcome {
                SyncOutcome::Verdict(value) => {
                    bundle::SyncOutcome::Verdict(bundle::ProposalBytes(value.0))
                }
                SyncOutcome::PeerFault => bundle::SyncOutcome::PeerFault,
                SyncOutcome::LocalTransientError => bundle::SyncOutcome::LocalTransientError,
            }),
        }
    }

    fn event(value: bundle::Event) -> Event {
        let request = match value.request {
            bundle::Request::Ready => Request::Ready,
            bundle::Request::StartedRound {
                height,
                round,
                proposer,
                role,
            } => Request::StartedRound {
                height,
                round,
                proposer,
                role: match role {
                    bundle::Role::Proposer => Role::Proposer,
                    bundle::Role::Validator => Role::Validator,
                    bundle::Role::Observer => Role::Observer,
                },
            },
            bundle::Request::GetValue {
                height,
                round,
                timeout,
            } => Request::GetValue {
                height,
                round,
                timeout,
            },
            bundle::Request::ProposalPart {
                from,
                published_by,
                part,
            } => Request::ProposalPart {
                from,
                published_by,
                part: ProposalPartBytes(part.0),
            },
            bundle::Request::Decided { certificate } => Request::Decided {
                certificate: CertificateBytes(certificate.0),
            },
            bundle::Request::Finalized {
                certificate,
                evidence,
            } => Request::Finalized {
                certificate: CertificateBytes(certificate.0),
                evidence,
            },
            bundle::Request::HistoryMinHeight => Request::HistoryMinHeight,
            bundle::Request::DecidedValues { start, end } => Request::DecidedValues { start, end },
            bundle::Request::SyncedValue {
                height,
                round,
                proposer,
                value,
            } => Request::SyncedValue {
                height,
                round,
                proposer,
                value,
            },
            bundle::Request::RestreamProposal {
                height,
                round,
                valid_round,
                address,
                value_id,
            } => Request::RestreamProposal {
                height,
                round,
                valid_round,
                address,
                value_id,
            },
        };
        Event {
            generation: value.generation,
            request,
            reply: value.reply.map(ReplyToken),
        }
    }

    pub(super) fn poll(value: bundle::EnginePoll) -> EnginePoll {
        match value {
            bundle::EnginePoll::Idle => EnginePoll::Idle,
            bundle::EnginePoll::Handled => EnginePoll::Handled,
            bundle::EnginePoll::Event(value) => EnginePoll::Event(event(value)),
        }
    }

    pub(super) fn state(value: bundle::EngineState) -> EngineState {
        match value {
            bundle::EngineState::Starting => EngineState::Starting,
            bundle::EngineState::Initializing => EngineState::Initializing,
            bundle::EngineState::Running => EngineState::Running,
            bundle::EngineState::Stopping => EngineState::Stopping,
            bundle::EngineState::Joined => EngineState::Joined,
        }
    }

    pub(crate) fn error(value: bundle::EngineError) -> EngineError {
        match value {
            bundle::EngineError::InvalidConfiguration(value) => {
                EngineError::InvalidConfiguration(value)
            }
            bundle::EngineError::NotRunning => EngineError::NotRunning,
            bundle::EngineError::Stopping => EngineError::Stopping,
            bundle::EngineError::ReadinessTimeout => EngineError::ReadinessTimeout,
            bundle::EngineError::StaleGeneration => EngineError::StaleGeneration,
            bundle::EngineError::Failed(value) => EngineError::Failed(value),
            bundle::EngineError::Panicked => EngineError::Panicked,
            bundle::EngineError::Reply(value) => EngineError::Reply(match value {
                bundle::ReplyError::StaleGeneration => ReplyError::StaleGeneration,
                bundle::ReplyError::UnknownToken => ReplyError::UnknownToken,
                bundle::ReplyError::WrongOperation => ReplyError::WrongOperation,
                bundle::ReplyError::Malformed(value) => ReplyError::Malformed(value),
            }),
        }
    }

    pub(super) fn delivery(value: bundle::Delivery) -> Delivery {
        match value {
            bundle::Delivery::Delivered => Delivery::Delivered,
            bundle::Delivery::Expired => Delivery::Expired,
        }
    }

    pub(super) fn publish(value: bundle::Publish) -> Publish {
        match value {
            bundle::Publish::Sent => Publish::Sent,
            bundle::Publish::Full => Publish::Full,
            bundle::Publish::Closed => Publish::Closed,
        }
    }

    pub(super) fn part(value: ProposalPartBytes) -> bundle::ProposalPartBytes {
        bundle::ProposalPartBytes(value.0)
    }

    #[cfg(test)]
    mod tests {
        use std::time::Duration;

        use super::super::super::types::{
            EngineError, EnginePoll, HeightParameters, NextHeight, ProposalBytes, Request,
            Response, SyncOutcome, Timeouts, Validator,
        };
        use super::{bundle, error, parameters, poll, response};

        #[test]
        fn height_parameters_preserve_committee_order_and_all_timeouts() {
            let input = HeightParameters {
                height: 17,
                validators: vec![
                    Validator {
                        public_key: [2; 32],
                        voting_power: 29,
                    },
                    Validator {
                        public_key: [1; 32],
                        voting_power: 31,
                    },
                ],
                timeouts: Timeouts {
                    propose: Duration::from_nanos(1),
                    propose_delta: Duration::from_nanos(2),
                    prevote: Duration::from_nanos(3),
                    prevote_delta: Duration::from_nanos(4),
                    precommit: Duration::from_nanos(5),
                    precommit_delta: Duration::from_nanos(6),
                    rebroadcast: Duration::from_nanos(7),
                    max_timeout: Duration::from_nanos(8),
                },
                target_time: Some(Duration::from_nanos(9)),
            };
            let expected = bundle::HeightParameters {
                height: 17,
                validators: vec![
                    bundle::Validator {
                        public_key: [2; 32],
                        voting_power: 29,
                    },
                    bundle::Validator {
                        public_key: [1; 32],
                        voting_power: 31,
                    },
                ],
                timeouts: bundle::Timeouts {
                    propose: Duration::from_nanos(1),
                    propose_delta: Duration::from_nanos(2),
                    prevote: Duration::from_nanos(3),
                    prevote_delta: Duration::from_nanos(4),
                    precommit: Duration::from_nanos(5),
                    precommit_delta: Duration::from_nanos(6),
                    rebroadcast: Duration::from_nanos(7),
                    max_timeout: Duration::from_nanos(8),
                },
                target_time: Some(Duration::from_nanos(9)),
            };
            assert_eq!(parameters(input.clone()), expected);
            assert_eq!(
                response(Response::Finalized(NextHeight::Restart(input))),
                bundle::Response::Finalized(bundle::NextHeight::Restart(expected))
            );
        }

        #[test]
        fn event_keeps_generation_rounds_and_canonical_payload() {
            let event = bundle::Event {
                generation: 71,
                request: bundle::Request::SyncedValue {
                    height: 23,
                    round: None,
                    proposer: [3; 20],
                    value: vec![0, 255, 7],
                },
                reply: None,
            };
            let EnginePoll::Event(event) = poll(bundle::EnginePoll::Event(event)) else {
                panic!("missing event")
            };
            assert_eq!(event.generation, 71);
            assert_eq!(event.reply, None);
            assert_eq!(
                event.request,
                Request::SyncedValue {
                    height: 23,
                    round: None,
                    proposer: [3; 20],
                    value: vec![0, 255, 7],
                }
            );
            let replies = response(Response::StartedRound(vec![
                ProposalBytes(vec![8]),
                ProposalBytes(vec![2]),
            ]));
            assert_eq!(
                replies,
                bundle::Response::StartedRound(vec![
                    bundle::ProposalBytes(vec![8]),
                    bundle::ProposalBytes(vec![2])
                ])
            );
        }

        #[test]
        fn local_failure_is_not_reclassified_as_a_peer_fault() {
            assert_eq!(
                response(Response::SyncedValue(SyncOutcome::LocalTransientError)),
                bundle::Response::SyncedValue(bundle::SyncOutcome::LocalTransientError)
            );
            assert_eq!(
                error(bundle::EngineError::ReadinessTimeout),
                EngineError::ReadinessTimeout
            );
            assert_eq!(error(bundle::EngineError::Panicked), EngineError::Panicked);
        }
    }
}

pub(crate) struct RuntimeEngine(pub(super) Engine);

impl RuntimeEngine {
    pub(crate) fn state(&self) -> EngineState {
        runtime::state(self.0.state())
    }
    pub(crate) fn failure(&self) -> Option<EngineError> {
        self.0.failure().cloned().map(runtime::error)
    }
    pub(crate) fn poll(&mut self) -> Result<EnginePoll, EngineError> {
        self.0.poll().map(runtime::poll).map_err(runtime::error)
    }
    pub(crate) fn respond(
        &mut self,
        token: ReplyToken,
        response: Response,
    ) -> Result<Delivery, EngineError> {
        self.0
            .respond(token.0, runtime::response(response))
            .map(runtime::delivery)
            .map_err(runtime::error)
    }
    pub(crate) fn publish(
        &mut self,
        generation: u64,
        part: ProposalPartBytes,
    ) -> Result<(), PublishError> {
        let part = runtime::part(part);
        let outcome = self
            .0
            .publish(generation, &part)
            .map(runtime::publish)
            .map_err(runtime::error);
        publication(outcome, ProposalPartBytes(part.0))
    }
    pub(crate) fn request_stop(&mut self) -> Result<(), EngineError> {
        self.0.request_stop().map_err(runtime::error)
    }
    pub(crate) fn wait_stopped(&mut self, timeout: Duration) -> Result<bool, EngineError> {
        self.0.wait_stopped(timeout).map_err(runtime::error)
    }
    pub(crate) fn request_listen_address(&mut self) -> Result<bool, EngineError> {
        self.0.request_listen_address().map_err(runtime::error)
    }
    pub(crate) fn poll_listen_address(&mut self) -> Result<Option<String>, EngineError> {
        self.0.poll_listen_address().map_err(runtime::error)
    }
}

fn publication(
    outcome: Result<Publish, EngineError>,
    part: ProposalPartBytes,
) -> Result<(), PublishError> {
    match outcome {
        Ok(Publish::Sent) => Ok(()),
        Ok(Publish::Full) => Err(PublishError::Full(part)),
        Ok(Publish::Closed) => Err(PublishError::Closed(part)),
        Err(error) => Err(PublishError::Engine(error, part)),
    }
}

#[cfg(test)]
mod tests {
    use super::{EngineError, ProposalPartBytes, Publish, PublishError, publication};

    #[test]
    fn publication_rejection_returns_the_original_buffer_for_retry() {
        for outcome in [
            Ok(Publish::Full),
            Ok(Publish::Closed),
            Err(EngineError::Stopping),
        ] {
            let part = ProposalPartBytes(vec![8, 0, 255, 1]);
            let original = part.0.as_ptr();
            let returned = match publication(outcome, part).unwrap_err() {
                PublishError::Unconfirmed => panic!("direct publication always returns an outcome"),
                PublishError::Full(part)
                | PublishError::Closed(part)
                | PublishError::Engine(_, part) => part,
            };
            assert_eq!(returned.0.as_ptr(), original);
            assert_eq!(returned.0, [8, 0, 255, 1]);
        }
        assert!(publication(Ok(Publish::Sent), ProposalPartBytes(vec![1])).is_ok());
    }
}
