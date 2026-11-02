use std::sync::mpsc as blocking;

use malachitebft_core_types::{NilOrVal, Round};
use malachitebft_signing_ed25519::PrivateKey;
use tempfile::TempDir;
use tokio::time::timeout;

use super::*;
use crate::consensus::{Address, Height, Vote, test_fixtures};
use crate::protocol::coordinator::certified_decision::{AuthorityMember, CommitteeRecord};
use crate::protocol::coordinator::durable_signer::{
    GenerationOwner, SigningError, SigningRequest, VoteStep,
};
use crate::protocol::coordinator::managed::startup::{Bootstrap, PeerSelection};
use crate::protocol::coordinator::managed::types::{
    HeightParameters, Request, Timeouts, Validator,
};

fn config(directory: &TempDir, generation: u64) -> Configuration {
    Configuration {
        generation,
        channel_capacity: 2,
        moniker: "node-control-test".into(),
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

fn params() -> HeightParameters {
    let time = Duration::from_secs(1);
    HeightParameters {
        height: 1,
        validators: vec![Validator {
            public_key: *PrivateKey::from([11; 32]).public_key().as_bytes(),
            voting_power: 1,
        }],
        timeouts: Timeouts {
            propose: time,
            propose_delta: time,
            prevote: time,
            prevote_delta: time,
            precommit: time,
            precommit_delta: time,
            rebroadcast: time,
            max_timeout: time,
        },
        target_time: None,
    }
}

async fn ready(control: &mut Control) -> ReplyToken {
    let event = timeout(Duration::from_secs(10), control.events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.request, Request::Ready);
    event.reply.unwrap()
}

#[tokio::test]
async fn control_thread_drives_real_bundles_and_releases_slot_only_after_join() {
    let directory = TempDir::new().unwrap();
    let slot = EngineSlot::default();
    let owner = GenerationOwner::open(
        &directory.path().join("authority"),
        test_fixtures::context().chain,
    )
    .unwrap();
    for (bundle, generation) in [(Bundle::First, 1), (Bundle::Second, 2)] {
        let ownership = owner.reserve(None).unwrap();
        assert_eq!(ownership.generation(), generation);
        let mut wrong = config(&directory, generation + 1);
        wrong.network_key = ownership.network_key();
        assert!(matches!(
            slot.start_owned(bundle, wrong, None, ownership.clone()),
            Err(EngineError::InvalidConfiguration(_))
        ));
        let wrong_network = config(&directory, generation);
        assert!(matches!(
            slot.start_owned(bundle, wrong_network, None, ownership.clone()),
            Err(EngineError::InvalidConfiguration(_))
        ));
        let mut input = config(&directory, generation);
        input.network_key = ownership.network_key();
        let mut control = slot.start_owned(bundle, input, None, ownership).unwrap();
        assert!(owner.reserve(None).is_err());
        let token = ready(&mut control).await;
        assert_eq!(
            control
                .respond(token, Response::Ready(params()))
                .await
                .unwrap(),
            Delivery::Delivered
        );
        let mut status = control.subscribe();
        timeout(Duration::from_secs(5), async {
            while status.borrow().state != EngineState::Running {
                status.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(control.request_listen_address().await.unwrap());
        let address = timeout(Duration::from_secs(5), async {
            loop {
                if let Some(address) = control.poll_listen_address().await.unwrap() {
                    break address;
                }
                sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .unwrap();
        assert!(address.starts_with("/ip4/127.0.0.1/tcp/"));
        assert!(
            slot.start(bundle, config(&directory, generation + 1), None)
                .is_err()
        );
        control.request_stop();
        assert!(control.wait_stopped(Duration::from_secs(10)).await.unwrap());
        assert!(control.has_joined());
        assert_eq!(control.status().state, EngineState::Joined);
        assert!(matches!(
            control.respond(token, Response::Ready(params())).await,
            Err(EngineError::Stopping)
        ));
    }
}

#[tokio::test]
async fn blocked_control_thread_does_not_block_node_revocation_or_allow_competing_engine() {
    let directory = TempDir::new().unwrap();
    let slot = EngineSlot::default();
    let mut input = config(&directory, 1);
    let key = PrivateKey::from([11; 32]);
    let owner = GenerationOwner::open(
        &directory.path().join("authority"),
        test_fixtures::context().chain,
    )
    .unwrap();
    let ownership = owner.reserve(Some(*key.public_key().as_bytes())).unwrap();
    input.network_key = ownership.network_key();
    let signer = Arc::new(
        DurableSigner::open_owned(ownership.clone(), test_fixtures::context(), key.clone())
            .unwrap(),
    );
    let address = Address::from_public_key(&key.public_key());
    let committee = CommitteeRecord {
        context: test_fixtures::context(),
        height: 1,
        decision: [7; 32],
        stage: 0,
        lineage: [0; 32],
        members: vec![AuthorityMember {
            holder: "validator".into(),
            generation: [1; 32],
            address: address.into_inner(),
            key: *key.public_key().as_bytes(),
            power: 1,
        }],
    };
    signer.authorize_height(&committee, [9; 32]).unwrap();
    let vote = Vote::new_prevote(Height::new(1), Round::new(0), NilOrVal::Nil, address);
    let request = SigningRequest::Vote {
        generation: 1,
        height: 1,
        round: 0,
        step: VoteStep::Prevote,
        value_id: None,
        validator_address: address.into_inner(),
        preimage: vote.to_sign_bytes().to_vec(),
    };
    signer.sign(request.clone()).unwrap();
    let (entered, waiting) = oneshot::channel();
    let (release, gate) = blocking::sync_channel(1);
    let authority = signer.clone();
    let mut control = slot
        .spawn(
            1,
            2,
            Duration::from_secs(10),
            Some(signer.clone()),
            Some(ownership),
            move || {
                let engine = Bundle::First.start(input, Some(authority))?;
                let _ = entered.send(());
                gate.recv_timeout(Duration::from_secs(10))
                    .expect("test releases blocked control thread");
                Ok(engine)
            },
        )
        .unwrap();
    timeout(Duration::from_secs(10), waiting)
        .await
        .unwrap()
        .unwrap();
    control.request_stop();
    timeout(Duration::from_secs(2), control.revoke_signing())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(signer.sign(request), Err(SigningError::Fenced));
    assert!(
        !control
            .wait_stopped(Duration::from_millis(20))
            .await
            .unwrap()
    );
    assert!(!control.has_joined());
    assert!(owner.reserve(None).is_err());
    assert!(
        slot.start(Bundle::Second, config(&directory, 2), None)
            .is_err()
    );
    release.send(()).unwrap();
    assert!(control.wait_stopped(Duration::from_secs(10)).await.unwrap());
    assert!(control.has_joined());
    let next_ownership = owner.reserve(None).unwrap();
    assert_eq!(next_ownership.generation(), 2);
    let mut input = config(&directory, 2);
    input.network_key = next_ownership.network_key();
    let mut next = slot
        .start_owned(Bundle::Second, input, None, next_ownership)
        .unwrap();
    ready(&mut next).await;
    next.request_stop();
    assert!(next.wait_stopped(Duration::from_secs(10)).await.unwrap());
}

#[tokio::test]
async fn failed_start_and_abandoned_handle_do_not_release_slot() {
    let directory = TempDir::new().unwrap();
    let slot = EngineSlot::default();
    let mut input = config(&directory, 1);
    input.listen_address = "invalid".into();
    let mut control = slot.start(Bundle::First, input, None).unwrap();
    assert!(
        timeout(Duration::from_secs(5), control.events.recv())
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        control.wait_stopped(Duration::from_secs(5)).await,
        Err(EngineError::InvalidConfiguration(_))
    ));
    assert!(control.has_joined());
    assert!(
        slot.start(Bundle::Second, config(&directory, 2), None)
            .is_err()
    );

    let slot = EngineSlot::default();
    let mut control = slot
        .start(Bundle::First, config(&directory, 3), None)
        .unwrap();
    ready(&mut control).await;
    let mut status = control.subscribe();
    drop(control);
    timeout(Duration::from_secs(5), async {
        while status.borrow().state != EngineState::Joined {
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(
        slot.start(Bundle::Second, config(&directory, 4), None)
            .is_err()
    );
}

#[tokio::test]
async fn unacknowledged_ready_expires_and_stopped_publication_returns_buffer() {
    let directory = TempDir::new().unwrap();
    let slot = EngineSlot::default();
    let mut input = config(&directory, 1);
    input.readiness_timeout = Duration::from_secs(1);
    let mut control = slot.start(Bundle::First, input, None).unwrap();
    ready(&mut control).await;
    let mut status = control.subscribe();
    timeout(Duration::from_secs(5), async {
        while status.borrow().state != EngineState::Joined {
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(
        control.wait_stopped(Duration::from_secs(5)).await,
        Err(EngineError::ReadinessTimeout)
    );
    let part = ProposalPartBytes(vec![9, 8, 7]);
    let allocation = part.0.as_ptr();
    let Err(PublishError::Closed(part)) = control.publish(1, part).await else {
        panic!("missing rejected publication")
    };
    assert_eq!(part.0.as_ptr(), allocation);
}

#[tokio::test]
async fn dropped_follower_handle_keeps_os_ownership_until_blocked_worker_finishes() {
    let directory = TempDir::new().unwrap();
    let authority_path = directory.path().join("authority");
    let chain = test_fixtures::context().chain;
    let owner = GenerationOwner::open(&authority_path, chain).unwrap();
    let ownership = owner.reserve(None).unwrap();
    let mut input = config(&directory, ownership.generation());
    input.network_key = ownership.network_key();
    let slot = EngineSlot::default();
    let (entered, waiting) = oneshot::channel();
    let (release, gate) = blocking::sync_channel(1);
    let control = slot
        .spawn(
            1,
            2,
            Duration::from_secs(10),
            None,
            Some(ownership),
            move || {
                let engine = Bundle::First.start(input, None)?;
                let _ = entered.send(());
                gate.recv_timeout(Duration::from_secs(10))
                    .expect("test releases worker");
                Ok(engine)
            },
        )
        .unwrap();
    timeout(Duration::from_secs(10), waiting)
        .await
        .unwrap()
        .unwrap();
    drop(control);
    drop(owner);
    assert!(GenerationOwner::open(&authority_path, chain).is_err());
    release.send(()).unwrap();
    let reopened = timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(owner) = GenerationOwner::open(&authority_path, chain) {
                break owner;
            }
            sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(reopened.reserve(None).unwrap().generation(), 2);
    assert!(
        slot.start(Bundle::Second, config(&directory, 2), None)
            .is_err()
    );
}
