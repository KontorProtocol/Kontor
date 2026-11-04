//! Shared standard-library facade of the pinned consensus runtime.
pub(crate) use kontor_consensus_first::api::{
    Delivery, EngineError, EnginePoll, EngineState, Event, HeightParameters, NextHeight,
    ProposalBytes, ProposalPartBytes, Publish, ReplyError, ReplyToken, Request, Response, Role,
    SyncOutcome, SyncedValueBytes, Timeouts, Validator, ValueBytes,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublishError {
    Unconfirmed,
    Full(ProposalPartBytes),
    Closed(ProposalPartBytes),
    Engine(EngineError, ProposalPartBytes),
}
