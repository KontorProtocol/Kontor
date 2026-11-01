use std::time::Duration;

use bytes::Bytes;
use indexer::consensus::codec::ProtobufCodec;
use indexer::consensus::signing::PrivateKey;
use indexer::consensus::{Ctx, Height, ProposalData, ProposalPart, Validator, ValidatorSet, Value};
use indexer::reactor::engine::{EngineConfig, start};
use malachitebft_app::engine::util::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app::types::PeerId;
use malachitebft_app_channel::{AppMsg, EngineHandle, NetworkMsg, NetworkRequest};
use malachitebft_codec::Codec;
use malachitebft_core_types::HeightParams;
use malachitebft_proto::Protobuf;
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout};

use super::{batch, maximal_batches, transaction};

type Received = (PeerId, Option<PeerId>, StreamMessage<ProposalPart>);

struct Peer {
    handle: EngineHandle,
    application: JoinHandle<()>,
    network: mpsc::Sender<NetworkMsg<Ctx>>,
    requests: mpsc::Sender<NetworkRequest>,
    received: mpsc::Receiver<Received>,
    _directory: TempDir,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.handle.actor.stop(None);
        self.application.abort();
    }
}

impl Peer {
    async fn start(key: u8, persistent_peers: Vec<String>) -> Self {
        let directory = TempDir::new().unwrap();
        let engine = start(EngineConfig {
            private_key: PrivateKey::from([key; 32]),
            listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
            persistent_peers,
            data_dir: directory.path().to_path_buf(),
            consensus_enabled: true,
            discovery: Default::default(),
        })
        .await
        .unwrap();
        let (ready, ready_rx) = oneshot::channel();
        let (received_tx, received) = mpsc::channel(4);
        let mut messages = engine.channels.consensus;
        let application = tokio::spawn(async move {
            let mut ready = Some(ready);
            while let Some(message) = messages.recv().await {
                match message {
                    AppMsg::ConsensusReady { reply } => {
                        // Neither transport peer is this validator, so no value
                        // production or database is needed for the framing test.
                        let committee = ValidatorSet::new([Validator::new(
                            PrivateKey::from([93; 32]).public_key(),
                            1,
                        )]);
                        assert!(
                            reply
                                .send((
                                    Height::new(1),
                                    HeightParams::new(committee, Default::default(), None,)
                                ))
                                .is_ok()
                        );
                        ready.take().unwrap().send(()).unwrap();
                    }
                    AppMsg::StartedRound { reply_value, .. } => {
                        assert!(reply_value.send(Vec::new()).is_ok());
                    }
                    AppMsg::GetHistoryMinHeight { reply } => {
                        assert!(reply.send(Height::new(1)).is_ok());
                    }
                    AppMsg::GetDecidedValues { reply, .. } => {
                        assert!(reply.send(Vec::new()).is_ok());
                    }
                    AppMsg::ReceivedProposalPart {
                        from,
                        published_by,
                        part,
                        reply,
                    } => {
                        assert!(reply.send(None).is_ok());
                        received_tx.send((from, published_by, part)).await.unwrap();
                    }
                    other => panic!("unexpected application request: {other:?}"),
                }
            }
        });
        let peer = Self {
            handle: engine._handle,
            application,
            network: engine.channels.network,
            requests: engine.channels.net_requests,
            received,
            _directory: directory,
        };
        timeout(Duration::from_secs(10), ready_rx)
            .await
            .unwrap()
            .unwrap();
        peer
    }

    async fn stop(&mut self) {
        self.handle.actor.stop(None);
        timeout(Duration::from_secs(10), &mut self.handle.handle)
            .await
            .unwrap()
            .unwrap();
        self.application.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maximal_batches_cross_the_signed_gossip_transport() {
    let mut sender = Peer::start(91, Vec::new()).await;
    let dump = NetworkRequest::dump_state(&sender.requests)
        .await
        .unwrap()
        .unwrap();
    let publisher = PeerId::from_bytes(&dump.local_node.peer_id.to_bytes()).unwrap();
    let address = dump.local_node.listen_addr.to_string();
    assert!(!address.ends_with("/0"));
    let mut receiver = Peer::start(92, vec![address]).await;
    let receiver_address = NetworkRequest::dump_state(&receiver.requests)
        .await
        .unwrap()
        .unwrap()
        .local_node
        .listen_addr;
    NetworkRequest::add_persistent_peer(&sender.requests, receiver_address)
        .await
        .unwrap()
        .unwrap();
    let probe_id = StreamId::new(Bytes::from(vec![255; 12]));
    // Persistent peers need not be mesh members. Establish readiness by receiving
    // a small message through the same signed channel before testing its limit.
    timeout(Duration::from_secs(15), async {
        let mut tick = interval(Duration::from_millis(100));
        let mut sequence = 0;
        loop {
            tokio::select! {
                received = receiver.received.recv() => {
                    let (from, declared, _) = received.unwrap();
                    assert_eq!(from, publisher);
                    assert_eq!(declared, Some(publisher));
                    break;
                }
                _ = tick.tick() => {
                    let value = Value::from_proto(batch(&[transaction(0)])).unwrap();
                    let probe = StreamMessage::new(probe_id.clone(), sequence,
                        StreamContent::Data(ProposalPart::Data(ProposalData::new(value))));
                    sender.network.send(NetworkMsg::PublishProposalPart(probe)).await.unwrap();
                    sequence += 1;
                }
            }
        }
    })
    .await
    .unwrap();
    for (index, transactions) in maximal_batches().into_iter().enumerate() {
        let value = Value::from_proto(batch(&transactions)).unwrap();
        let message = StreamMessage::new(
            StreamId::new(Bytes::from(vec![index as u8; 12])),
            u64::MAX,
            StreamContent::Data(ProposalPart::Data(ProposalData::new(value))),
        );
        let expected = ProtobufCodec.encode(&message).unwrap();
        sender
            .network
            .send(NetworkMsg::PublishProposalPart(message))
            .await
            .unwrap();
        let (from, declared_publisher, received) = timeout(Duration::from_secs(15), async {
            loop {
                let received = receiver.received.recv().await.unwrap();
                if received.2.stream_id != probe_id {
                    break received;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(from, publisher);
        assert_eq!(declared_publisher, Some(publisher));
        assert_eq!(ProtobufCodec.encode(&received).unwrap(), expected);
    }
    receiver.stop().await;
    sender.stop().await;
}
