use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use malachitebft_app::config::{ConsensusConfig, NodeConfig, ValueSyncConfig};
use malachitebft_app::types::Keypair;
use malachitebft_app_channel::{ConsensusContext, NetworkIdentity};
use malachitebft_core_types::{HeightParams, LinearTimeouts, ValidatorProof, VoteExtensionScope};
use malachitebft_signing::{Error as SigningError, VerificationResult, Verifier};
use malachitebft_signing_ed25519::{PublicKey, Signature};

use super::{Owner, State};
use crate::bridge_codec::{READY, put_height_params};
use crate::channel_bridge::Poll;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Address, Ctx, Height, Proposal, Validator, ValidatorSet, Vote};
use crate::protocol::canonical_codec::Encoder;
use crate::replies::{Delivery, ReplyError};

// Lifecycle tests do not exercise signature acceptance. Refuse everything and
// construct a follower with no consensus signer or private consensus key.
struct RejectVerifier;

#[async_trait]
impl Verifier<Ctx> for RejectVerifier {
    async fn verify_signed_vote(
        &self,
        _: &Vote,
        _: &Signature,
        _: &PublicKey,
    ) -> Result<VerificationResult, SigningError> {
        Ok(VerificationResult::Invalid)
    }
    async fn verify_signed_proposal(
        &self,
        _: &Proposal,
        _: &Signature,
        _: &PublicKey,
    ) -> Result<VerificationResult, SigningError> {
        Ok(VerificationResult::Invalid)
    }
    async fn verify_signed_vote_extension(
        &self,
        _: &VoteExtensionScope<Ctx>,
        _: &Bytes,
        _: &Signature,
        _: &PublicKey,
    ) -> Result<VerificationResult, SigningError> {
        Ok(VerificationResult::Invalid)
    }
    async fn verify_validator_proof(
        &self,
        _: &ValidatorProof<Ctx>,
    ) -> Result<VerificationResult, SigningError> {
        Ok(VerificationResult::Invalid)
    }
}

#[derive(Default)]
struct Gate {
    state: Mutex<(bool, bool)>,
    wake: Condvar,
}

impl Gate {
    fn enter(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.wake.notify_all();
        while !state.1 {
            state = self.wake.wait(state).unwrap();
        }
    }

    fn wait_entered(&self) {
        let state = self.state.lock().unwrap();
        let (state, timeout) = self
            .wake
            .wait_timeout_while(state, Duration::from_secs(10), |s| !s.0)
            .unwrap();
        assert!(state.0 && !timeout.timed_out(), "worker did not enter gate");
    }

    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.wake.notify_all();
    }
}

struct Config {
    consensus: ConsensusConfig,
    sync: ValueSyncConfig,
    startup: Option<Arc<Gate>>,
    worker: Option<Arc<Gate>>,
    launched: AtomicBool,
    sync_calls: AtomicUsize,
}

impl Config {
    fn new(address: &str) -> Self {
        let mut consensus = ConsensusConfig::default();
        consensus.p2p.listen_addr = address.parse().unwrap();
        Self {
            consensus,
            sync: ValueSyncConfig::default(),
            startup: None,
            worker: None,
            launched: AtomicBool::new(false),
            sync_calls: AtomicUsize::new(0),
        }
    }
}

impl NodeConfig for Config {
    fn moniker(&self) -> &str {
        "kontor-owner-test"
    }
    fn consensus(&self) -> &ConsensusConfig {
        if !self.launched.swap(true, Ordering::AcqRel) {
            if let Some(gate) = self.worker.clone() {
                tokio::task::spawn_blocking(move || gate.enter());
            }
        }
        &self.consensus
    }
    fn consensus_mut(&mut self) -> &mut ConsensusConfig {
        &mut self.consensus
    }
    fn value_sync(&self) -> &ValueSyncConfig {
        if self.sync_calls.fetch_add(1, Ordering::Relaxed) == 1 {
            if let Some(gate) = &self.startup {
                gate.enter();
            }
        }
        &self.sync
    }
    fn value_sync_mut(&mut self) -> &mut ValueSyncConfig {
        &mut self.sync
    }
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "kontor-consensus-owner-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn start(config: Config, directory: &Directory, generation: u64) -> Owner {
    let network = Keypair::ed25519_from_bytes([7; 32]).unwrap();
    Owner::start(
        generation,
        16,
        config,
        directory.0.join("consensus.wal"),
        NetworkIdentity::new("kontor-owner-test".into(), network, None),
        ConsensusContext::new_full_node(Address::new([0; 20]), Box::new(RejectVerifier)),
    )
    .unwrap()
}

fn ready(owner: &mut Owner) -> (u64, u8, u64, Vec<u8>) {
    assert!(owner.wait_channels(Duration::from_secs(10)).unwrap());
    assert_eq!(owner.state(), State::ChannelsReady);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match owner.poll().unwrap() {
            Poll::Event(generation, operation, token, payload) => {
                assert_eq!(operation, READY);
                return (generation, operation, token, payload);
            }
            Poll::Idle | Poll::Handled => {}
            Poll::Closed => panic!("engine closed before ready"),
        }
        assert!(Instant::now() < deadline, "engine did not become ready");
        thread::sleep(Duration::from_millis(2));
    }
}

fn listen_address(owner: &mut Owner) -> String {
    assert!(owner.request_listen_address().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(address) = owner.poll_listen_address().unwrap() {
            return address;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn real_engine_ready_reply_stop_and_reopen_same_wal_and_port() {
    let directory = Directory::new();
    let mut owner = start(Config::new("/ip4/127.0.0.1/tcp/0"), &directory, 1);
    let event = ready(&mut owner);
    let address = listen_address(&mut owner);
    assert!(!address.ends_with("/0"));
    let key = PrivateKey::from([9; 32]).public_key();
    let params = HeightParams::new(
        ValidatorSet::new([Validator::new(key, 1)]),
        LinearTimeouts::default(),
        None,
    );
    let mut bytes = Encoder::default();
    put_height_params(&mut bytes, Height::new(1), &params).unwrap();
    assert_eq!(
        owner.respond(event.0, event.1, event.2, &bytes.finish()),
        Ok(Delivery::Delivered)
    );
    owner.request_stop();
    assert_eq!(owner.state(), State::Stopping);
    assert!(owner.wait_stopped(Duration::from_secs(10)).unwrap());
    assert_eq!(owner.state(), State::Joined);
    assert!(owner.wait_stopped(Duration::ZERO).unwrap());
    assert_eq!(
        owner.respond(1, READY, event.2, &[]),
        Err(ReplyError::StaleGeneration)
    );
    let mut next = start(Config::new(&address), &directory, 2);
    ready(&mut next);
    next.request_stop();
    assert!(next.wait_stopped(Duration::from_secs(10)).unwrap());
}

#[test]
fn startup_and_shutdown_timeouts_keep_owner_and_callbacks_retired() {
    let directory = Directory::new();
    let startup = Arc::new(Gate::default());
    let worker = Arc::new(Gate::default());
    let mut config = Config::new("/ip4/127.0.0.1/tcp/0");
    config.startup = Some(startup.clone());
    config.worker = Some(worker.clone());
    let mut owner = start(config, &directory, 5);
    // Release gates even if an assertion fails, so ManagedEngine's mandatory
    // join cannot hide a test failure behind a blocked worker destructor.
    struct Release(Arc<Gate>, Arc<Gate>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
            self.1.release();
        }
    }
    let release = Release(startup.clone(), worker.clone());
    startup.wait_entered();
    assert!(!owner.wait_channels(Duration::ZERO).unwrap());
    assert_eq!(owner.state(), State::Starting);
    startup.release();
    let event = ready(&mut owner);
    worker.wait_entered();
    owner.request_stop();
    assert!(!owner.wait_stopped(Duration::ZERO).unwrap());
    assert_eq!(owner.state(), State::Stopping);
    assert!(owner.poll().is_err());
    assert_eq!(
        owner.respond(5, READY, event.2, &[]),
        Err(ReplyError::StaleGeneration)
    );
    drop(release);
    assert!(owner.wait_stopped(Duration::from_secs(10)).unwrap());
    assert_eq!(owner.state(), State::Joined);
}

#[test]
fn partial_start_failure_is_joined_and_never_becomes_ready() {
    let directory = Directory::new();
    // Network construction precedes WAL construction. A directory at the WAL
    // filename fails startup after networking has acquired its resources.
    fs::create_dir(directory.0.join("consensus.wal")).unwrap();
    let mut owner = start(Config::new("/ip4/127.0.0.1/tcp/0"), &directory, 1);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if owner.wait_channels(Duration::from_millis(10)).is_err() {
            break;
        }
        if owner.state() == State::ChannelsReady {
            match owner.poll() {
                Err(_) | Ok(Poll::Closed) => break,
                Ok(Poll::Event(_, READY, _, _)) => panic!("started with invalid WAL"),
                _ => {}
            }
        }
        assert!(Instant::now() < deadline, "WAL failure did not propagate");
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(owner.state(), State::Stopping);
    assert!(owner.failure().is_some());
    assert!(owner.wait_stopped(Duration::from_secs(10)).is_err());
    assert_eq!(owner.state(), State::Joined);
    let first = owner.failure().unwrap().to_owned();
    assert!(owner.wait_stopped(Duration::ZERO).is_err());
    assert_eq!(owner.failure(), Some(first.as_str()));
}
