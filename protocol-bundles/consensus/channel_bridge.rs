use anyhow::{Error, Result, ensure};
use bytes::Bytes;
use malachitebft_app_channel::{AppMsg, NetworkMsg};
use malachitebft_codec::Codec;
use tokio::sync::mpsc::{Receiver, Sender, error::TryRecvError, error::TrySendError};

use crate::bridge::Bridge;
use crate::consensus::Ctx;
use crate::consensus::codec::ProtobufCodec;
use crate::replies::{Delivery, ReplyError};

pub(crate) enum Poll {
    Idle,
    Closed,
    Handled,
    Event(u64, u8, u64, Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Publish {
    Sent,
    Full,
    Closed,
}

// Called only by the engine's control thread. Tokio channel objects stay inside
// the independently linked graph; polling never enters or blocks a node runtime.
pub(crate) struct ChannelBridge {
    generation: u64,
    retired: bool,
    bridge: Bridge,
    incoming: Receiver<AppMsg<Ctx>>,
    outgoing: Sender<NetworkMsg<Ctx>>,
}

impl ChannelBridge {
    pub(crate) fn new(
        generation: u64,
        capacity: usize,
        incoming: Receiver<AppMsg<Ctx>>,
        outgoing: Sender<NetworkMsg<Ctx>>,
    ) -> Result<Self> {
        Ok(Self {
            generation,
            retired: false,
            bridge: Bridge::new(generation, capacity)?,
            incoming,
            outgoing,
        })
    }

    pub(crate) fn poll(&mut self) -> Result<Poll> {
        ensure!(!self.retired, "engine channels retired");
        match self.incoming.try_recv() {
            Ok(message) => match self.bridge.event(message) {
                Ok(Some((generation, operation, token, payload))) => {
                    Ok(Poll::Event(generation, operation, token, payload))
                }
                Ok(None) => Ok(Poll::Handled),
                Err(error) => {
                    self.retire();
                    Err(error)
                }
            },
            Err(TryRecvError::Empty) => Ok(Poll::Idle),
            Err(TryRecvError::Disconnected) => {
                self.retire();
                Ok(Poll::Closed)
            }
        }
    }

    pub(crate) fn respond(
        &mut self,
        generation: u64,
        operation: u8,
        token: u64,
        payload: &[u8],
    ) -> Result<Delivery, ReplyError> {
        let result = self.bridge.respond(generation, operation, token, payload);
        if matches!(result, Err(ReplyError::Malformed(_))) {
            self.retire();
        }
        result
    }

    pub(crate) fn publish(&mut self, generation: u64, payload: &[u8]) -> Result<Publish> {
        ensure!(
            !self.retired && generation == self.generation,
            "stale proposal publication"
        );
        let part = ProtobufCodec
            .decode(Bytes::copy_from_slice(payload))
            .map_err(Error::from)?;
        Ok(
            match self
                .outgoing
                .try_send(NetworkMsg::PublishProposalPart(part))
            {
                Ok(()) => Publish::Sent,
                Err(TrySendError::Full(_)) => Publish::Full,
                Err(TrySendError::Closed(_)) => Publish::Closed,
            },
        )
    }

    pub(crate) fn retire(&mut self) {
        self.retired = true;
        self.bridge.retire();
        // Closing prevents new events; draining drops replies already buffered
        // before the fence instead of letting them survive until owner teardown.
        self.incoming.close();
        while self.incoming.try_recv().is_ok() {}
    }
}

#[cfg(test)]
mod tests {
    use malachitebft_engine::util::streaming::{StreamContent, StreamId, StreamMessage};
    use tokio::sync::{mpsc, oneshot};

    use super::*;
    use crate::bridge_codec::MIN_HEIGHT;
    use crate::consensus::ProposalPart;

    #[test]
    fn retirement_closes_both_buffered_and_delivered_replies() {
        let (events, incoming) = mpsc::channel(2);
        let (outgoing, _network) = mpsc::channel(1);
        let mut bridge = ChannelBridge::new(7, 2, incoming, outgoing).unwrap();
        assert!(matches!(bridge.poll().unwrap(), Poll::Idle));
        let (first, mut first_reply) = oneshot::channel();
        events
            .try_send(AppMsg::GetHistoryMinHeight { reply: first })
            .unwrap();
        let Poll::Event(generation, operation, token, payload) = bridge.poll().unwrap() else {
            panic!("missing event")
        };
        assert_eq!((generation, operation, payload), (7, MIN_HEIGHT, vec![]));
        let (second, mut second_reply) = oneshot::channel();
        events
            .try_send(AppMsg::GetHistoryMinHeight { reply: second })
            .unwrap();
        bridge.retire();
        assert_eq!(
            first_reply.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        );
        assert_eq!(
            second_reply.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        );
        assert!(events.is_closed());
        assert!(bridge.poll().is_err());
        assert_eq!(
            bridge.respond(7, MIN_HEIGHT, token, &1u64.to_be_bytes()),
            Err(ReplyError::StaleGeneration)
        );
    }

    #[test]
    fn bounded_publication_reports_backpressure_without_sending_duplicates() {
        let (_events, incoming) = mpsc::channel(1);
        let (outgoing, mut network) = mpsc::channel(1);
        let mut bridge = ChannelBridge::new(7, 1, incoming, outgoing).unwrap();
        let part = StreamMessage::<ProposalPart>::new(
            StreamId::new(Bytes::from_static(b"stream")),
            1,
            StreamContent::Fin,
        );
        let bytes = ProtobufCodec.encode(&part).unwrap();
        assert!(bridge.publish(6, &bytes).is_err());
        assert_eq!(bridge.publish(7, &bytes).unwrap(), Publish::Sent);
        assert_eq!(bridge.publish(7, &bytes).unwrap(), Publish::Full);
        let NetworkMsg::PublishProposalPart(actual) = network.try_recv().unwrap();
        assert_eq!(ProtobufCodec.encode(&actual).unwrap(), bytes);
        assert!(network.try_recv().is_err());
        assert_eq!(bridge.publish(7, &bytes).unwrap(), Publish::Sent);
        bridge.retire();
        assert!(bridge.publish(7, &bytes).is_err());
        network.try_recv().unwrap();
        assert!(network.try_recv().is_err());
    }
}
