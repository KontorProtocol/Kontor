use std::any::Any;
use std::path::PathBuf;
use std::time::Duration;

use malachite::app::config::{ConsensusConfig, NodeConfig, ValueSyncConfig};
use malachite::app::types::core::HeightParams;
use malachite::app::types::{Keypair, LocallyProposedValue};
use malachite::{
    AppMsg, Channels, ConsensusContext, EngineBuilder, ManagedEngine, NetworkContext,
    NetworkIdentity, NetworkRequest, RequestContext, SyncContext, WalContext,
};
use malachite_test::codec::{json::JsonCodec, proto::ProtobufCodec};
use malachite_test::{
    Address, Ed25519Signer, Ed25519Verifier, Height, PrivateKey, TestContext, Validator,
    ValidatorSet, Value,
};
use tokio::runtime::{Builder, Runtime};
use tokio::time::{sleep, timeout};

pub type HostCall = Box<dyn Fn(Vec<u8>) -> Result<Vec<u8>, String> + Send + Sync>;

#[derive(Default)]
struct Config {
    consensus: ConsensusConfig,
    sync: ValueSyncConfig,
}

impl NodeConfig for Config {
    fn moniker(&self) -> &str {
        "kontor-bundle-proof"
    }
    fn consensus(&self) -> &ConsensusConfig {
        &self.consensus
    }
    fn consensus_mut(&mut self) -> &mut ConsensusConfig {
        &mut self.consensus
    }
    fn value_sync(&self) -> &ValueSyncConfig {
        &self.sync
    }
    fn value_sync_mut(&mut self) -> &mut ValueSyncConfig {
        &mut self.sync
    }
}

struct Owner {
    engine: ManagedEngine<TestContext>,
    channels: Channels<TestContext>,
    runtime: Runtime,
    height: u64,
    host: HostCall,
}

pub fn start(
    address: String,
    wal: PathBuf,
    height: u64,
    host: HostCall,
) -> Result<Box<dyn Any + Send>, String> {
    let mut config = Config::default();
    config.consensus.p2p.listen_addr = address
        .parse()
        .map_err(|error| format!("address: {error}"))?;
    let identity = NetworkIdentity::new(
        "kontor-bundle-proof".into(),
        Keypair::ed25519_from_bytes([7; 32]).map_err(|error| error.to_string())?,
        None,
    );
    let key = PrivateKey::from([9; 32]);
    let mut engine = EngineBuilder::new(TestContext::default(), config)
        .with_default_network(NetworkContext::new(identity, JsonCodec))
        .with_default_wal(WalContext::new(wal, ProtobufCodec))
        .with_default_sync(SyncContext::new(JsonCodec))
        .with_default_consensus(ConsensusContext::new_validator(
            Address::from_public_key(&key.public_key()),
            Box::new(Ed25519Verifier),
            Box::new(Ed25519Signer::new(key)),
        ))
        .with_default_request(RequestContext::new(16))
        .start_managed()
        .map_err(|error| error.to_string())?;
    let channels = engine
        .wait_ready(Duration::from_secs(10))
        .map_err(|error| error.to_string())?
        .ok_or("engine startup timeout")?;
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        timeout(Duration::from_secs(10), async {
            loop {
                let state = NetworkRequest::dump_state(&channels.net_requests)
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or("network unavailable")?;
                if !state.local_node.listen_addr.to_string().contains("0.0.0.0") {
                    return Ok::<(), String>(());
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|error| error.to_string())?
    })?;
    Ok(Box::new(Owner {
        engine,
        channels,
        runtime,
        height,
        host,
    }))
}

pub fn decide(handle: &mut (dyn Any + Send)) -> Result<u64, String> {
    let owner = handle
        .downcast_mut::<Owner>()
        .ok_or("engine belongs to another bundle")?;
    owner.runtime.block_on(async {
        timeout(Duration::from_secs(10), async {
            while let Some(message) = owner.channels.consensus.recv().await {
                match message {
                    AppMsg::ConsensusReady { reply } => {
                        let validator = Validator::new(PrivateKey::from([9; 32]).public_key(), 1);
                        reply
                            .send((
                                Height::new(owner.height),
                                HeightParams::new(
                                    ValidatorSet::new([validator]),
                                    Default::default(),
                                    None,
                                ),
                            ))
                            .map_err(|_| "startup reply closed")?;
                    }
                    AppMsg::StartedRound { reply_value, .. } => {
                        reply_value
                            .send(Vec::new())
                            .map_err(|_| "round reply closed")?;
                    }
                    AppMsg::GetValue {
                        height,
                        round,
                        reply,
                        ..
                    } => {
                        let bytes = (owner.host)(height.as_u64().to_le_bytes().to_vec())?;
                        let value =
                            u64::from_le_bytes(bytes.try_into().map_err(|_| "host value width")?);
                        reply
                            .send(LocallyProposedValue::new(height, round, Value::new(value)))
                            .map_err(|_| "value reply closed")?;
                    }
                    AppMsg::ExtendVote { reply, .. } => {
                        reply.send(None).map_err(|_| "extension reply closed")?;
                    }
                    AppMsg::GetHistoryMinHeight { reply } => {
                        reply
                            .send(Height::new(owner.height))
                            .map_err(|_| "history reply closed")?;
                    }
                    AppMsg::Decided {
                        certificate, reply, ..
                    } => {
                        if certificate.commit_signatures.len() != 1
                            || certificate.height.as_u64() != owner.height
                        {
                            return Err("unexpected single-validator certificate".into());
                        }
                        reply
                            .send(())
                            .map_err(|_| "commit acknowledgement closed")?;
                        return Ok(certificate.height.as_u64());
                    }
                    other => return Err(format!("unexpected proof engine message: {other:?}")),
                }
            }
            Err("engine closed before deciding".into())
        })
        .await
        .map_err(|error| error.to_string())?
    })
}

pub fn stop(handle: &mut (dyn Any + Send), limit: Duration) -> Result<bool, String> {
    let owner = handle
        .downcast_mut::<Owner>()
        .ok_or("engine belongs to another bundle")?;
    owner.engine.request_stop();
    let stopped = owner
        .engine
        .wait_stopped(limit)
        .map_err(|error| error.to_string())?;
    if stopped && (!owner.channels.requests.is_closed() || !owner.channels.net_requests.is_closed())
    {
        return Err("engine channels survived completed shutdown".into());
    }
    Ok(stopped)
}
