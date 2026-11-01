use futures_util::FutureExt;
use malachitebft_core_types::LinearTimeouts;
use malachitebft_signing_ed25519::PrivateKey;
use tempfile::TempDir;
use tokio::time::timeout;

use super::*;
use crate::consensus::{Validator as NodeValidator, ValidatorSet};
use crate::protocol::coordinator::managed::startup::{Bootstrap, PeerSelection};

fn config(directory: &TempDir, generation: u64) -> Configuration {
    Configuration {
        generation,
        channel_capacity: 4,
        moniker: "reactor-bridge-test".into(),
        network_key: [7; 32],
        listen_address: "/ip4/127.0.0.1/tcp/0".into(),
        persistent_peers: vec![],
        wal_path: directory.path().join(format!("consensus-{generation}.wal")),
        discovery_enabled: false,
        bootstrap: Bootstrap::Full,
        peer_selection: PeerSelection::Random,
        readiness_timeout: Duration::from_secs(10),
    }
}

fn params() -> HeightParams<Ctx> {
    let key = PrivateKey::from([11; 32]).public_key();
    HeightParams::new(
        ValidatorSet::new([NodeValidator::new(key, 1)]),
        LinearTimeouts::default(),
        None,
    )
}

async fn ready(engine: &mut ReactorEngine) -> oneshot::Sender<(Height, HeightParams<Ctx>)> {
    match timeout(Duration::from_secs(10), engine.next())
        .await
        .unwrap()
        .unwrap()
    {
        Some(Message::Application(AppMsg::ConsensusReady { reply })) => reply,
        _ => panic!("expected real engine readiness"),
    }
}

#[tokio::test]
async fn reactor_poll_cancellation_preserves_delayed_reply_for_both_bundles() {
    let directory = TempDir::new().unwrap();
    let slot = EngineSlot::default();
    for (bundle, generation) in [(Bundle::First, 1), (Bundle::Second, 2)] {
        let mut engine =
            ReactorEngine::start(&slot, bundle, config(&directory, generation), None).unwrap();
        let sender = ready(&mut engine).await;
        assert!(engine.next().now_or_never().is_none());
        assert!(!sender.is_closed());
        sender.send((Height::new(1), params())).unwrap();
        let mut status = engine.control.subscribe();
        timeout(Duration::from_secs(5), async {
            loop {
                if status.borrow().state == EngineState::Running {
                    break;
                }
                tokio::select! {
                    result = engine.next() => { assert!(result.unwrap().is_some()); }
                    changed = status.changed() => { changed.unwrap(); }
                }
            }
        })
        .await
        .unwrap();
        engine.retire();
        assert!(engine.wait_stopped(Duration::from_secs(10)).await.unwrap());
        assert!(engine.next().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn dropped_reactor_startup_reply_fails_and_joins_the_actual_engine() {
    let directory = TempDir::new().unwrap();
    let slot = EngineSlot::default();
    let mut engine =
        ReactorEngine::start(&slot, Bundle::First, config(&directory, 1), None).unwrap();
    drop(ready(&mut engine).await);
    assert!(matches!(
        timeout(Duration::from_secs(5), engine.next())
            .await
            .unwrap(),
        Err(EngineError::Failed(_))
    ));
    assert!(engine.wait_stopped(Duration::from_secs(10)).await.is_err());
    assert!(engine.control.has_joined());
}

#[tokio::test]
async fn outgoing_reply_survives_cancelled_reactor_poll() {
    let directory = TempDir::new().unwrap();
    let slot = EngineSlot::default();
    let mut engine =
        ReactorEngine::start(&slot, Bundle::First, config(&directory, 1), None).unwrap();
    let event = timeout(Duration::from_secs(10), engine.control.events.recv())
        .await
        .unwrap()
        .unwrap();
    let token = event.reply.unwrap();
    let response = engine.control.begin_response(
        token,
        Response::Ready(parameters(Height::new(1), params()).unwrap()),
    );
    let (release, gate) = oneshot::channel();
    engine.outgoing = Some(Box::pin(async move {
        gate.await.unwrap();
        response.await
    }));
    assert!(engine.next().now_or_never().is_none());
    assert!(engine.outgoing.is_some());
    release.send(()).unwrap();
    let mut status = engine.control.subscribe();
    timeout(Duration::from_secs(5), async {
        loop {
            if status.borrow().state == EngineState::Running {
                break;
            }
            tokio::select! {
                result = engine.next() => { assert!(result.unwrap().is_some()); }
                changed = status.changed() => { changed.unwrap(); }
            }
        }
    })
    .await
    .unwrap();
    engine.retire();
    assert!(engine.wait_stopped(Duration::from_secs(10)).await.unwrap());
}
