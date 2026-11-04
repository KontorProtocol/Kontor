use std::time::Duration;

use kontor_consensus_first::Engine;

use super::types::{
    Delivery, EngineError, EnginePoll, EngineState, ProposalPartBytes, Publish, PublishError,
    ReplyToken, Response,
};

pub(crate) struct RuntimeEngine(pub(super) Engine);

impl RuntimeEngine {
    pub(crate) fn state(&self) -> EngineState {
        self.0.state()
    }
    pub(crate) fn failure(&self) -> Option<EngineError> {
        self.0.failure().cloned()
    }
    pub(crate) fn poll(&mut self) -> Result<EnginePoll, EngineError> {
        self.0.poll()
    }
    pub(crate) fn respond(
        &mut self,
        token: ReplyToken,
        response: Response,
    ) -> Result<Delivery, EngineError> {
        self.0.respond(token, response)
    }
    pub(crate) fn publish(
        &mut self,
        generation: u64,
        part: ProposalPartBytes,
    ) -> Result<(), PublishError> {
        let outcome = self.0.publish(generation, &part);
        publication(outcome, part)
    }
    pub(crate) fn request_stop(&mut self) -> Result<(), EngineError> {
        self.0.request_stop()
    }
    pub(crate) fn wait_stopped(&mut self, timeout: Duration) -> Result<bool, EngineError> {
        self.0.wait_stopped(timeout)
    }
    pub(crate) fn request_listen_address(&mut self) -> Result<bool, EngineError> {
        self.0.request_listen_address()
    }
    pub(crate) fn poll_listen_address(&mut self) -> Result<Option<String>, EngineError> {
        self.0.poll_listen_address()
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
