use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use malachitebft_app::config::NodeConfig;
use malachitebft_app_channel::ConsensusContext;

use super::*;
use crate::api::{Bootstrap, Discovery, EngineConfig, PeerSelection};
use crate::bridge_types::test_params;
use crate::config::Config;
use crate::consensus::Address;
use crate::factory::{network_peer_id, start_with_context};
use crate::owner::tests::{Directory, RejectVerifier};

fn config(directory: &Directory) -> EngineConfig {
    EngineConfig {
        generation: 1,
        channel_capacity: 16,
        moniker: "typed-factory-test".into(),
        network_key: [7; 32],
        listen_address: "/ip4/127.0.0.1/tcp/0".into(),
        persistent_peers: vec![],
        wal_path: directory.0.join("consensus.wal"),
        discovery: Discovery {
            enabled: false,
            bootstrap: Bootstrap::Full,
            selection: PeerSelection::Random,
        },
        readiness_timeout: Duration::from_secs(10),
    }
}

fn follower(config: EngineConfig) -> Result<Engine, EngineError> {
    start_with_context(
        config,
        ConsensusContext::new_full_node(Address::new([0; 20]), Box::new(RejectVerifier)),
        None,
    )
}

fn ready(engine: &mut Engine) -> ReplyToken {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match engine.poll().unwrap() {
            EnginePoll::Event(event) => {
                assert_eq!(event.request, Request::Ready);
                return event.reply.unwrap();
            }
            EnginePoll::Idle | EnginePoll::Handled => {}
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn typed_factory_requires_ready_ack_before_running_and_preserves_follower_mode() {
    let directory = Directory::new();
    let config = config(&directory);
    let prepared = Config::prepare(&config, false).unwrap();
    assert!(!prepared.config.consensus().enabled);
    assert_eq!(
        prepared.keypair.public().to_peer_id().to_bytes(),
        network_peer_id(&config.network_key).unwrap()
    );
    let mut engine = follower(config).unwrap();
    assert_eq!(engine.state(), EngineState::Starting);
    let token = ready(&mut engine);
    assert_eq!(engine.state(), EngineState::Initializing);
    assert_eq!(
        engine.publish(1, &ProposalPartBytes(vec![])),
        Err(EngineError::NotRunning)
    );
    assert_eq!(
        engine.respond(token, Response::Decided),
        Err(EngineError::Reply(ReplyError::WrongOperation))
    );
    assert_eq!(engine.state(), EngineState::Initializing);
    assert_eq!(
        engine.respond(token, Response::Ready(test_params(1))),
        Ok(Delivery::Delivered)
    );
    assert_eq!(engine.state(), EngineState::Running);
    assert_eq!(
        engine.publish(2, &ProposalPartBytes(vec![])),
        Err(EngineError::StaleGeneration)
    );
    assert_eq!(engine.state(), EngineState::Running);
    engine.request_stop().unwrap();
    assert_eq!(engine.state(), EngineState::Stopping);
    assert_eq!(
        engine.respond(token, Response::Ready(test_params(1))),
        Err(EngineError::Stopping)
    );
    assert!(engine.wait_stopped(Duration::from_secs(10)).unwrap());
    assert_eq!(engine.state(), EngineState::Joined);
    assert!(engine.wait_stopped(Duration::ZERO).unwrap());
}

#[test]
fn occupied_listener_cannot_be_reported_as_a_running_engine() {
    let directory = Directory::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut input = config(&directory);
    input.listen_address = format!("/ip4/127.0.0.1/tcp/{}", address.port());
    input.readiness_timeout = Duration::from_millis(200);
    let mut engine = follower(input).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match engine.poll() {
            Err(EngineError::ReadinessTimeout | EngineError::Failed(_)) => break,
            Ok(EnginePoll::Idle | EnginePoll::Handled) => {}
            other => panic!("listener failure became ready: {other:?}"),
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(engine.state(), EngineState::Stopping);
    assert!(engine.failure().is_some());
    assert!(engine.wait_stopped(Duration::from_secs(10)).is_err());
    assert_eq!(engine.state(), EngineState::Joined);
    assert_eq!(listener.local_addr().unwrap(), address);
}

#[test]
fn unacknowledged_readiness_times_out_and_retires_reply() {
    let directory = Directory::new();
    let mut engine = follower(config(&directory)).unwrap();
    let token = ready(&mut engine);
    engine.deadline = Instant::now();
    assert_eq!(
        engine.respond(token, Response::Ready(test_params(1))),
        Err(EngineError::ReadinessTimeout)
    );
    assert_eq!(engine.state(), EngineState::Stopping);
    assert!(engine.wait_stopped(Duration::from_secs(10)).is_err());
    assert_eq!(engine.state(), EngineState::Joined);
}

#[test]
fn public_operation_panic_is_contained_and_owner_is_retained_until_join() {
    let directory = Directory::new();
    let mut engine = follower(config(&directory)).unwrap();
    ready(&mut engine);
    let result: Result<(), EngineError> = engine.guarded(|_| panic!("operation fault injection"));
    assert_eq!(result, Err(EngineError::Panicked));
    assert_eq!(engine.state(), EngineState::Stopping);
    assert_eq!(engine.failure(), Some(&EngineError::Panicked));
    assert!(engine.wait_stopped(Duration::from_secs(10)).is_err());
    assert_eq!(engine.state(), EngineState::Joined);
    assert_eq!(engine.failure(), Some(&EngineError::Panicked));
}

#[test]
fn invalid_configuration_is_rejected_before_wal_creation() {
    let directory = Directory::new();
    for invalid in [0, 1, 2, 3, 4] {
        let mut input = config(&directory);
        match invalid {
            0 => input.generation = 0,
            1 => input.channel_capacity = 0,
            2 => input.listen_address = "invalid".into(),
            3 => input.persistent_peers = vec!["invalid".into()],
            4 => input.readiness_timeout = Duration::ZERO,
            _ => unreachable!(),
        }
        assert!(matches!(
            follower(input),
            Err(EngineError::InvalidConfiguration(_))
        ));
        assert!(!directory.0.join("consensus.wal").exists());
    }
}
