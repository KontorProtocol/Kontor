use anyhow::{Context, Result};
use malachitebft_app_channel::app::streaming::StreamMessage;
use malachitebft_app_channel::app::types::codec::Codec;
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::{LocallyProposedValue, PeerId, ProposedValue};
use malachitebft_app_channel::{AppMsg, NetworkRequest};
use malachitebft_core_consensus::Role;
use malachitebft_core_types::{Round, Validity};
use tracing::{info, warn};

use crate::consensus::codec::ProtobufCodec;
use crate::consensus::{Address, Ctx, Height, ProposalPart, ValueId};

use super::Reactor;
use super::consensus_state;
use super::executor::Executor;

/// Answer a `ReceivedProposalPart` with "not a complete, accepted proposal".
fn reply_none(reply: tokio::sync::oneshot::Sender<Option<ProposedValue<Ctx>>>) -> Result<()> {
    reply
        .send(None)
        .map_err(|_| anyhow::anyhow!("Failed to send ReceivedProposalPart reply"))
}

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
        // Authoritative proposer for this round, straight from the engine. Proposal
        // parts are authenticated against THIS, never a `select_proposer`
        // recomputation (the validator set is refreshed per block and unordered).
        self.consensus.current_proposer = Some(proposer);

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
            .get(&height)
            .and_then(|rounds| rounds.get(&round))
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
        from: PeerId,
        part: StreamMessage<ProposalPart>,
        reply: tokio::sync::oneshot::Sender<Option<ProposedValue<Ctx>>>,
    ) -> Result<()> {
        // Buffer the part; act only once the full stream (Init + Data + Fin) is
        // reassembled. A lone Data part — the shortcut the old code trusted —
        // can no longer claim the round.
        let Some(parts) = self.consensus.part_streams.insert(from, part) else {
            return reply_none(reply);
        };

        let height = self.consensus.current_height;
        let round = self.consensus.current_round;

        // Only the current round is actionable. A proposal for another height/round
        // is dropped (Kontor does not buffer future proposals), and one whose slot
        // is already filled needs no re-validation. Gate BEFORE authenticating so
        // the proposer is checked against THIS round's engine-chosen proposer.
        if round == Round::Nil
            || parts.height != height
            || parts.round != round
            || self
                .consensus
                .undecided
                .get(&height)
                .is_some_and(|rounds| rounds.contains_key(&round))
        {
            return reply_none(reply);
        }

        // Authenticate against the engine's proposer for this round (from
        // StartedRound) and the Fin signature. A forged stream cannot pass — only
        // the proposer's key signs a matching Fin.
        let Some(expected_proposer) = self.consensus.current_proposer else {
            return reply_none(reply);
        };
        if let Err(reason) = self
            .consensus
            .verify_proposal_parts(expected_proposer, &parts)
        {
            warn!(
                proposer = %parts.proposer,
                height = %parts.height,
                round = %parts.round,
                %reason,
                "Rejecting proposal: authentication failed"
            );
            return reply_none(reply);
        }

        let Some(data) = parts.data().cloned() else {
            return reply_none(reply);
        };

        // May defer the reply behind the bitcoind I/O phase. The engine waits on
        // the oneshot exactly as it used to wait on this handler running the RPCs
        // inline; the reactor's loop no longer waits with it.
        self.validate_and_accept_proposal(&data, parts.proposer, height, round, reply)
            .await
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
                    .entry(height)
                    .or_default()
                    .insert(round, proposed.clone());
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
        if let Some(proposal) = self
            .consensus
            .undecided
            .get(&height)
            .and_then(|rounds| rounds.get(&lookup_round))
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

                // `ConsensusReady` is emitted only from the network `Listening`
                // event, and the swarm records its resolved address *before*
                // emitting `Listening` — so by here the address is bound and
                // recorded, and this read is race-free (never the unresolved
                // `/tcp/0`). Publish it once on the watch (surfaced on
                // `/api/status`; in-process cluster tests await it to bootstrap
                // followers). The address is observability-only, so on the
                // unexpected failure paths we just warn and leave it unset rather
                // than block or crash — a genuinely dead swarm surfaces through
                // consensus liveness, not here.
                match NetworkRequest::dump_state(&self.consensus.channels.net_requests).await {
                    Ok(Some(dump)) => {
                        let _ = self
                            .consensus_listen_addr
                            .send(Some(dump.local_node.listen_addr.to_string()));
                    }
                    Ok(None) => {
                        warn!("Network state dump empty; consensus listen address left unset");
                    }
                    Err(e) => {
                        warn!(%e, "Failed to read network state for consensus listen address");
                    }
                }
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

            AppMsg::ReceivedProposalPart { from, part, reply } => {
                self.handle_received_proposal_part(from, part, reply)
                    .await?;
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
                reply,
            } => {
                info!(
                    height = %certificate.height,
                    round = %certificate.round,
                    value = %certificate.value_id,
                    "Decided"
                );
                // The reactor commits decisions in the Finalized handler, so just
                // ack here to let consensus proceed to finalization.
                reply
                    .send(())
                    .map_err(|_| anyhow::anyhow!("Failed to send Decided reply"))?;
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
