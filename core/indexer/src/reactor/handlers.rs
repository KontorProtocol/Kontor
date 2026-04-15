use anyhow::{Context, Result};
use malachitebft_app_channel::AppMsg;
use malachitebft_app_channel::app::streaming::{StreamContent, StreamMessage};
use malachitebft_app_channel::app::types::codec::Codec;
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_core_consensus::Role;
use malachitebft_core_types::{Round, Validity};
use tracing::info;

use crate::consensus::codec::ProtobufCodec;
use crate::consensus::{Address, Ctx, Height, ProposalPart, ValueId};

use super::Reactor;
use super::consensus_state;
use super::executor::Executor;

impl<E: Executor> Reactor<E> {
    fn handle_started_round(
        &mut self,
        height: Height,
        round: Round,
        proposer: Address,
        role: Role,
        reply_value: tokio::sync::oneshot::Sender<Vec<ProposedValue<Ctx>>>,
    ) -> Result<()> {
        info!(%height, %round, %proposer, ?role, "Started round");
        self.consensus.current_height = height;
        self.consensus.current_round = round;

        if let Some(pending) = &self.consensus.pending_proposal
            && (pending.height != height || pending.round != round)
        {
            info!(
                pending_height = %pending.height,
                pending_round = %pending.round,
                "Clearing stale pending proposal"
            );
            self.consensus.pending_proposal = None;
        }

        let proposals: Vec<_> = self
            .consensus
            .undecided
            .get(&(height, round))
            .cloned()
            .into_iter()
            .collect();

        reply_value
            .send(proposals)
            .map_err(|_| anyhow::anyhow!("Failed to send StartedRound reply"))?;
        Ok(())
    }

    async fn handle_received_proposal_part(
        &mut self,
        part: StreamMessage<ProposalPart>,
        reply: tokio::sync::oneshot::Sender<Option<ProposedValue<Ctx>>>,
    ) -> Result<()> {
        let height = self.consensus.current_height;
        let round = self.consensus.current_round;

        let proposed = if round == Round::Nil {
            None
        } else {
            match &part.content {
                StreamContent::Data(ProposalPart::Data(data)) => {
                    if !self.consensus.undecided.contains_key(&(height, round)) {
                        self.validate_and_accept_proposal(data, height, round)
                            .await?
                    } else {
                        None
                    }
                }
                _ => None,
            }
        };

        reply
            .send(proposed)
            .map_err(|_| anyhow::anyhow!("Failed to send ReceivedProposalPart reply"))?;
        Ok(())
    }

    async fn handle_get_decided_values(
        &mut self,
        range: std::ops::RangeInclusive<Height>,
        reply: tokio::sync::oneshot::Sender<Vec<RawDecidedValue<Ctx>>>,
    ) -> Result<()> {
        let conn = self.db_conn();
        let decided = self
            .consensus
            .get_decided_range(&conn, *range.start(), *range.end())
            .await?;
        let values: Vec<_> = decided
            .into_iter()
            .map(|(value, cert)| {
                let encoded = ProtobufCodec
                    .encode(&value)
                    .context("Failed to encode value for sync")?;
                Ok(RawDecidedValue {
                    certificate: cert,
                    value_bytes: encoded,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        reply
            .send(values)
            .map_err(|_| anyhow::anyhow!("Failed to send GetDecidedValues reply"))?;
        Ok(())
    }

    fn handle_process_synced_value(
        &mut self,
        height: Height,
        round: Round,
        proposer: Address,
        value_bytes: bytes::Bytes,
        reply: tokio::sync::oneshot::Sender<Option<ProposedValue<Ctx>>>,
    ) -> Result<()> {
        let result: Option<ProposedValue<Ctx>> =
            if let Ok(value) = ProtobufCodec.decode(value_bytes) {
                let proposed = ProposedValue {
                    height,
                    round,
                    valid_round: Round::Nil,
                    proposer,
                    value,
                    validity: Validity::Valid,
                };
                self.consensus
                    .undecided
                    .insert((height, round), proposed.clone());
                Some(proposed)
            } else {
                None
            };

        reply
            .send(result)
            .map_err(|_| anyhow::anyhow!("Failed to send ProcessSyncedValue reply"))?;
        Ok(())
    }

    async fn handle_restream_proposal(
        &mut self,
        height: Height,
        round: Round,
        valid_round: Round,
        value_id: ValueId,
    ) -> Result<()> {
        let lookup_round = if valid_round == Round::Nil {
            round
        } else {
            valid_round
        };
        if let Some(proposal) = self.consensus.undecided.get(&(height, lookup_round))
            && proposal.value.id() == value_id
        {
            let locally_proposed = LocallyProposedValue::new(height, round, proposal.value.clone());
            self.send_proposal_parts(&locally_proposed, valid_round)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn handle_consensus_msg(
        &mut self,
        msg: AppMsg<Ctx>,
    ) -> Result<consensus_state::ConsensusResult> {
        let mut result = consensus_state::ConsensusResult::None;
        match msg {
            AppMsg::ConsensusReady { reply } => {
                let start_height = self.consensus.current_height;
                info!(%start_height, "Consensus is ready");

                reply
                    .send((start_height, self.consensus.height_params()))
                    .map_err(|_| anyhow::anyhow!("Failed to send ConsensusReady reply"))?;
            }

            AppMsg::StartedRound {
                height,
                round,
                proposer,
                role,
                reply_value,
            } => {
                self.handle_started_round(height, round, proposer, role, reply_value)?;
            }

            AppMsg::GetValue {
                height,
                round,
                timeout,
                reply,
            } => {
                self.handle_get_value(height, round, timeout, reply).await?;
            }

            AppMsg::ReceivedProposalPart {
                from: _,
                part,
                reply,
            } => {
                self.handle_received_proposal_part(part, reply).await?;
            }

            AppMsg::ExtendVote { reply, .. } => {
                reply
                    .send(None)
                    .map_err(|_| anyhow::anyhow!("Failed to send ExtendVote reply"))?;
            }

            AppMsg::VerifyVoteExtension { reply, .. } => {
                reply
                    .send(Ok(()))
                    .map_err(|_| anyhow::anyhow!("Failed to send VerifyVoteExtension reply"))?;
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
                result = self.handle_finalized(certificate, reply).await?;
            }

            AppMsg::GetHistoryMinHeight { reply } => {
                let min = self
                    .consensus
                    .min_decided_height(&self.db_conn())
                    .await?
                    .unwrap_or(Height::new(1));
                reply
                    .send(min)
                    .map_err(|_| anyhow::anyhow!("Failed to send GetHistoryMinHeight reply"))?;
            }

            AppMsg::GetDecidedValues { range, reply } => {
                self.handle_get_decided_values(range, reply).await?;
            }

            AppMsg::ProcessSyncedValue {
                height,
                round,
                proposer,
                value_bytes,
                reply,
            } => {
                self.handle_process_synced_value(height, round, proposer, value_bytes, reply)?;
            }

            AppMsg::RestreamProposal {
                height,
                round,
                valid_round,
                address: _,
                value_id,
            } => {
                self.handle_restream_proposal(height, round, valid_round, value_id)
                    .await?;
            }
        }

        Ok(result)
    }
}
