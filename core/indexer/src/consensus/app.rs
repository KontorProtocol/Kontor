use std::collections::BTreeMap;

use anyhow::anyhow;
use tracing::{error, info};

use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::codec::Codec;
use malachitebft_app_channel::app::types::core::{Round, Validity};
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_app_channel::{AppMsg, Channels, NetworkMsg};
use malachitebft_core_types::{CommitCertificate, HeightParams, LinearTimeouts};
use malachitebft_engine::host::Next;
use malachitebft_test::codec::proto::ProtobufCodec;
use malachitebft_test::{
    Address, Ed25519Provider, Genesis, Height, ProposalData, ProposalFin, ProposalInit,
    ProposalPart, TestContext, ValidatorSet, Value,
};

/// Minimal consensus app state.
pub struct State {
    signing_provider: Ed25519Provider,
    genesis: Genesis,
    address: Address,
    current_height: Height,
    current_round: Round,
    decided: BTreeMap<Height, (Value, CommitCertificate<TestContext>)>,
    undecided: BTreeMap<(Height, Round), ProposedValue<TestContext>>,
    value_counter: u64,
}

impl State {
    pub fn new(signing_provider: Ed25519Provider, genesis: Genesis, address: Address) -> Self {
        Self {
            signing_provider,
            genesis,
            address,
            current_height: Height::new(1),
            current_round: Round::new(0),
            decided: BTreeMap::new(),
            undecided: BTreeMap::new(),
            value_counter: 0,
        }
    }

    fn validator_set(&self) -> ValidatorSet {
        self.genesis.validator_set.clone()
    }

    fn make_value(&mut self) -> Value {
        self.value_counter += 1;
        Value::new(self.value_counter)
    }

    fn height_params(&self) -> HeightParams<TestContext> {
        HeightParams::new(self.validator_set(), LinearTimeouts::default(), None)
    }

    fn stream_id(&self) -> StreamId {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.current_height.as_u64().to_be_bytes());
        bytes.extend_from_slice(&self.current_round.as_u32().unwrap().to_be_bytes());
        StreamId::new(bytes.into())
    }

    fn stream_proposal(
        &self,
        value: &LocallyProposedValue<TestContext>,
        pol_round: Round,
    ) -> Vec<StreamMessage<ProposalPart>> {
        use sha3::Digest;

        let mut hasher = sha3::Keccak256::new();
        hasher.update(value.height.as_u64().to_be_bytes());
        hasher.update(value.round.as_i64().to_be_bytes());
        hasher.update(value.value.value.to_be_bytes());

        let hash = hasher.finalize();
        let signature = self.signing_provider.sign(&hash);

        let parts = vec![
            ProposalPart::Init(ProposalInit::new(
                value.height,
                value.round,
                pol_round,
                self.address,
            )),
            ProposalPart::Data(ProposalData::new(value.value.value)),
            ProposalPart::Fin(ProposalFin::new(signature)),
        ];

        let stream_id = self.stream_id();
        let mut msgs = Vec::with_capacity(parts.len() + 1);

        for (seq, part) in parts.into_iter().enumerate() {
            msgs.push(StreamMessage::new(
                stream_id.clone(),
                seq as u64,
                StreamContent::Data(part),
            ));
        }
        msgs.push(StreamMessage::new(
            stream_id,
            msgs.len() as u64,
            StreamContent::Fin,
        ));

        msgs
    }
}

/// Run the consensus app loop, handling messages from the engine.
pub async fn run(state: &mut State, channels: &mut Channels<TestContext>) -> anyhow::Result<()> {
    while let Some(msg) = channels.consensus.recv().await {
        match msg {
            AppMsg::ConsensusReady { reply } => {
                let start_height = state.current_height;
                info!(%start_height, "Consensus is ready");

                if reply.send((start_height, state.height_params())).is_err() {
                    error!("Failed to send ConsensusReady reply");
                }
            }

            AppMsg::StartedRound {
                height,
                round,
                proposer,
                role,
                reply_value,
            } => {
                info!(%height, %round, %proposer, ?role, "Started round");
                state.current_height = height;
                state.current_round = round;

                let proposals: Vec<_> = state
                    .undecided
                    .get(&(height, round))
                    .cloned()
                    .into_iter()
                    .collect();

                if reply_value.send(proposals).is_err() {
                    error!("Failed to send StartedRound reply");
                }
            }

            AppMsg::GetValue {
                height,
                round,
                timeout: _,
                reply,
            } => {
                info!(%height, %round, "Building value to propose");

                let proposal = if let Some(existing) = state.undecided.get(&(height, round)) {
                    LocallyProposedValue::new(
                        existing.height,
                        existing.round,
                        existing.value.clone(),
                    )
                } else {
                    let value = state.make_value();
                    let proposed = ProposedValue {
                        height,
                        round,
                        valid_round: Round::Nil,
                        proposer: state.address,
                        value: value.clone(),
                        validity: Validity::Valid,
                    };
                    state.undecided.insert((height, round), proposed);
                    LocallyProposedValue::new(height, round, value)
                };

                if reply.send(proposal.clone()).is_err() {
                    error!("Failed to send GetValue reply");
                }

                for stream_msg in state.stream_proposal(&proposal, Round::Nil) {
                    channels
                        .network
                        .send(NetworkMsg::PublishProposalPart(stream_msg))
                        .await?;
                }
            }

            AppMsg::ReceivedProposalPart {
                from: _,
                part,
                reply,
            } => {
                let height = state.current_height;
                let round = state.current_round;

                let proposed = match &part.content {
                    StreamContent::Data(ProposalPart::Data(data)) => {
                        if !state.undecided.contains_key(&(height, round)) {
                            let value = Value::new(data.factor);
                            let proposed = ProposedValue {
                                height,
                                round,
                                valid_round: Round::Nil,
                                proposer: state.address,
                                value,
                                validity: Validity::Valid,
                            };
                            state.undecided.insert((height, round), proposed.clone());
                            Some(proposed)
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                if reply.send(proposed).is_err() {
                    error!("Failed to send ReceivedProposalPart reply");
                }
            }

            AppMsg::ExtendVote { reply, .. } => {
                if reply.send(None).is_err() {
                    error!("Failed to send ExtendVote reply");
                }
            }

            AppMsg::VerifyVoteExtension { reply, .. } => {
                if reply.send(Ok(())).is_err() {
                    error!("Failed to send VerifyVoteExtension reply");
                }
            }

            AppMsg::Decided {
                certificate,
                extensions: _,
            } => {
                info!(
                    height = %certificate.height,
                    round = %certificate.round,
                    value = %certificate.value_id,
                    "Decided"
                );
            }

            AppMsg::Finalized {
                certificate,
                extensions: _,
                evidence,
                reply,
            } => {
                info!(
                    height = %certificate.height,
                    round = %certificate.round,
                    value = %certificate.value_id,
                    evidence = ?evidence,
                    "Finalized"
                );

                if let Some(proposal) =
                    state.undecided.remove(&(certificate.height, certificate.round))
                {
                    state
                        .decided
                        .insert(certificate.height, (proposal.value, certificate.clone()));
                }

                state.current_height = certificate.height.increment();
                state.current_round = Round::Nil;

                let next = Next::Start(state.current_height, state.height_params());

                if reply.send(next).is_err() {
                    error!("Failed to send Finalized reply");
                }
            }

            AppMsg::GetHistoryMinHeight { reply } => {
                let min = state
                    .decided
                    .keys()
                    .next()
                    .copied()
                    .unwrap_or(Height::new(1));
                if reply.send(min).is_err() {
                    error!("Failed to send GetHistoryMinHeight reply");
                }
            }

            AppMsg::GetDecidedValues { range, reply } => {
                let mut values = Vec::new();
                let start = *range.start();
                let end = *range.end();
                let mut h = start;
                while h <= end {
                    if let Some((value, cert)) = state.decided.get(&h)
                        && let Ok(encoded) = ProtobufCodec.encode(value)
                    {
                        values.push(RawDecidedValue {
                            certificate: cert.clone(),
                            value_bytes: encoded,
                        });
                    }
                    h = h.increment();
                }
                if reply.send(values).is_err() {
                    error!("Failed to send GetDecidedValues reply");
                }
            }

            AppMsg::ProcessSyncedValue {
                height,
                round,
                proposer,
                value_bytes,
                reply,
            } => {
                let result: Option<ProposedValue<TestContext>> =
                    if let Ok(value) = ProtobufCodec.decode(value_bytes) {
                        let proposed = ProposedValue {
                            height,
                            round,
                            valid_round: Round::Nil,
                            proposer,
                            value,
                            validity: Validity::Valid,
                        };
                        state.undecided.insert((height, round), proposed.clone());
                        Some(proposed)
                    } else {
                        None
                    };

                if reply.send(result).is_err() {
                    error!("Failed to send ProcessSyncedValue reply");
                }
            }

            AppMsg::RestreamProposal {
                height,
                round,
                valid_round,
                address: _,
                value_id,
            } => {
                let lookup_round = if valid_round == Round::Nil {
                    round
                } else {
                    valid_round
                };
                if let Some(proposal) = state.undecided.get(&(height, lookup_round))
                    && proposal.value.id() == value_id
                {
                    let locally_proposed =
                        LocallyProposedValue::new(height, round, proposal.value.clone());
                    for stream_msg in state.stream_proposal(&locally_proposed, valid_round) {
                        channels
                            .network
                            .send(NetworkMsg::PublishProposalPart(stream_msg))
                            .await?;
                    }
                }
            }
        }
    }

    Err(anyhow!("Consensus channel closed unexpectedly"))
}
