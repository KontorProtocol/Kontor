use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use malachitebft_app_channel::AppMsg;
use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::Keypair;
use malachitebft_core_consensus::{LocallyProposedValue, ProposedValue};
use malachitebft_core_types::{HeightParams, LinearTimeouts, NilOrVal, Round, Validity};
use tempfile::TempDir;
use tokio::time::timeout;

use super::consensus_state::authenticate_proposal;
use super::message::Message;
use super::transport::Engine;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{
    Address, Height, PartStreamsMap, ProposalData, ProposalFin, ProposalInit, ProposalPart,
    Validator, ValidatorSet, Vote, test_fixtures,
};
use crate::protocol::coordinator::durable_signer::{DurableSigner, GenerationOwner};
use crate::protocol::coordinator::managed::control::EngineSlot;
use crate::protocol::coordinator::managed::reactor::ReactorEngine;
use crate::protocol::coordinator::managed::startup::{
    Bootstrap, Bundle, Configuration, PeerSelection,
};

#[tokio::test]
async fn managed_transport_signs_publishes_and_decides_through_both_bundles() -> Result<()> {
    let directory = TempDir::new()?;
    let slot = EngineSlot::default();
    let key = PrivateKey::from([11; 32]);
    let address = Address::from_public_key(&key.public_key());
    let value = test_fixtures::block();
    let owner = GenerationOwner::open(
        &directory.path().join("authority"),
        test_fixtures::context().chain,
    )?;
    for (bundle, generation) in [(Bundle::First, 1), (Bundle::Second, 2)] {
        let ownership = owner.reserve(Some(*key.public_key().as_bytes()))?;
        ensure!(ownership.generation() == generation);
        let peer = Keypair::ed25519_from_bytes(ownership.network_key())?
            .public()
            .to_peer_id()
            .to_bytes();
        ensure!(Bundle::First.network_peer_id(&ownership.network_key())? == peer);
        ensure!(Bundle::Second.network_peer_id(&ownership.network_key())? == peer);
        let config = Configuration {
            generation,
            channel_capacity: 16,
            moniker: "transport-test".into(),
            network_key: ownership.network_key(),
            listen_address: "/ip4/127.0.0.1/tcp/0".into(),
            persistent_peers: vec![],
            wal_path: directory.path().join(format!("{generation}.wal")),
            discovery_enabled: false,
            bootstrap: Bootstrap::Full,
            peer_selection: PeerSelection::Random,
            readiness_timeout: Duration::from_secs(10),
        };
        let signer = Arc::new(DurableSigner::open_owned(
            ownership.clone(),
            test_fixtures::context(),
            key.clone(),
        )?);
        let managed =
            ReactorEngine::start_owned(&slot, bundle, config, Some(signer.clone()), ownership)?;
        let mut engine = Engine::managed(managed);
        drop(signer);
        let height = Height::new(generation);
        let validators = ValidatorSet::new([Validator::new(key.public_key(), 1)]);
        let mut streams = PartStreamsMap::new();
        let result = timeout(Duration::from_secs(15), async {
            loop {
                let message = engine
                    .next()
                    .await?
                    .context("engine closed before decision")?;
                match message {
                    Message::Application(AppMsg::ConsensusReady { reply }) => {
                        let parameters = HeightParams::new(
                            ValidatorSet::new([Validator::new(key.public_key(), 1)]),
                            LinearTimeouts::default(),
                            None,
                        );
                        reply
                            .send((height, parameters))
                            .map_err(|_| anyhow::anyhow!("ready reply closed"))?;
                        ensure!(engine.listen_address().await?.is_some());
                    }
                    Message::Application(AppMsg::StartedRound { reply_value, .. }) => {
                        let _ = reply_value.send(vec![]);
                    }
                    Message::Application(AppMsg::GetValue {
                        height: request_height,
                        round,
                        reply,
                        ..
                    }) => {
                        ensure!(request_height == height);
                        let data = ProposalData::new(value.clone());
                        let digest = data.signing_digest(height, round);
                        let signature = engine
                            .sign_proposal_fin(
                                height.as_u64(),
                                round.as_u32().context("nil round")?,
                                value.descriptor().encode()?,
                                digest,
                            )
                            .await?;
                        key.public_key().verify(&digest, &signature)?;
                        let id = StreamId::new(vec![generation as u8, 1].into());
                        let parts = [
                            ProposalPart::Init(ProposalInit::new(
                                height,
                                round,
                                Round::Nil,
                                address,
                            )),
                            ProposalPart::Data(data),
                            ProposalPart::Fin(ProposalFin::new(signature)),
                        ];
                        for (sequence, part) in parts.into_iter().enumerate() {
                            engine
                                .publish(StreamMessage::new(
                                    id.clone(),
                                    sequence as u64,
                                    StreamContent::Data(part),
                                ))
                                .await?;
                        }
                        engine
                            .publish(StreamMessage::new(id, 3, StreamContent::Fin))
                            .await?;
                        reply
                            .send(LocallyProposedValue::new(height, round, value.clone()))
                            .map_err(|_| anyhow::anyhow!("proposal reply closed"))?;
                    }
                    Message::Application(AppMsg::ReceivedProposalPart {
                        from,
                        part,
                        reply,
                        ..
                    }) => {
                        let proposal = if let Some(parts) = streams
                            .insert(from, part)
                            .map_err(|_| anyhow::anyhow!("proposal reassembly saturated"))?
                        {
                            authenticate_proposal(&validators, address, &parts)
                                .map_err(|error| anyhow::anyhow!(error))?;
                            Some(ProposedValue {
                                height: parts.height,
                                round: parts.round,
                                valid_round: parts
                                    .init()
                                    .context("missing proposal init")?
                                    .pol_round,
                                proposer: parts.proposer,
                                value: parts
                                    .data()
                                    .context("missing proposal data")?
                                    .value()
                                    .clone(),
                                validity: Validity::Valid,
                            })
                        } else {
                            None
                        };
                        let _ = reply.send(proposal);
                    }
                    Message::Application(AppMsg::Decided {
                        certificate, reply, ..
                    }) => {
                        ensure!(certificate.height == height && certificate.value_id == value.id());
                        ensure!(certificate.commit_signatures.len() == 1);
                        let signature = &certificate.commit_signatures[0];
                        ensure!(signature.address == address);
                        let vote = Vote::new_precommit(
                            height,
                            certificate.round,
                            NilOrVal::Val(value.id()),
                            address,
                        );
                        key.public_key()
                            .verify(&vote.to_sign_bytes(), &signature.signature)?;
                        let _ = reply.send(());
                        return Ok(());
                    }
                    Message::Application(AppMsg::GetHistoryMinHeight { reply }) => {
                        let _ = reply.send(Height::new(1));
                    }
                    Message::Application(AppMsg::GetDecidedValues { reply, .. }) => {
                        let _ = reply.send(vec![]);
                    }
                    _ => bail!("unexpected consensus message before decision"),
                }
            }
        })
        .await
        .context("managed transport decision timed out")
        .and_then(|result| result);
        ensure!(
            engine.stop(Duration::from_secs(10)).await?,
            "engine did not join"
        );
        result?;
    }
    Ok(())
}
