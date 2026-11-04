use std::time::Instant;

use anyhow::{Context, Result, ensure};
use malachitebft_app_channel::AppMsg;
use malachitebft_app_channel::app::engine::host::SyncedValueOutcome;
use malachitebft_app_channel::app::streaming::StreamMessage;
use malachitebft_app_channel::app::types::codec::Codec;
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::{LocallyProposedValue, PeerId, ProposedValue};
use malachitebft_core_consensus::Role;
use malachitebft_core_types::{ExtendedCommitCertificate, Round, Validity, VoteExtensions};
use tracing::{info, warn};

use crate::consensus::codec::ProtobufCodec;
use crate::consensus::{
    Address, Ctx, Height, ProposalPart, ProposalParts, ReassemblySaturated, Value, ValueId,
};
use crate::database::certified_history::{branch, proposals};

use super::Reactor;
use super::consensus_state;
use super::executor::Executor;
use super::message::Message;

/// Answer a `ReceivedProposalPart` with "not a complete, accepted proposal".
fn reply_none(reply: tokio::sync::oneshot::Sender<Option<ProposedValue<Ctx>>>) -> Result<()> {
    reply
        .send(None)
        .map_err(|_| anyhow::anyhow!("Failed to send ReceivedProposalPart reply"))
}

impl<E: Executor> Reactor<E> {
    async fn handle_started_round(
        &mut self,
        height: Height,
        round: Round,
        proposer: Address,
        role: Role,
        reply_value: tokio::sync::oneshot::Sender<Vec<ProposedValue<Ctx>>>,
    ) -> Result<()> {
        if round < self.consensus.current_round
            || !self
                .consensus
                .height_is_open(&self.db_conn(), height)
                .await?
        {
            let _ = reply_value.send(Vec::new());
            return Ok(());
        }
        info!(%height, %round, %proposer, ?role, "Started round");
        self.consensus.current_height = height;
        self.consensus.current_round = round;
        self.consensus.round_started_at = Instant::now();
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

        let proposals: Vec<_> = proposals::normal(
            &self.db_conn(),
            height,
            round,
            self.consensus.protocol_context,
        )
        .await?
        .into_iter()
        .collect();

        let early = self.consensus.take_early_proposal(height, round, proposer);
        if let Some(parts) = early {
            let (reply, received) = tokio::sync::oneshot::channel();
            self.accept_proposal_parts(parts, reply).await?;
            // Batch validation may finish through the reactor's I/O queue. Holding
            // the StartedRound reply here would stop that queue from being polled.
            tokio::spawn(async move {
                let mut proposals = proposals;
                if let Ok(Some(proposal)) = received.await {
                    proposals.push(proposal);
                }
                let _ = reply_value.send(proposals);
            });
        } else {
            reply_value
                .send(proposals)
                .map_err(|_| anyhow::anyhow!("Failed to send StartedRound reply"))?;
        }
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
        let parts = match self.consensus.part_streams.insert(from, part) {
            Ok(Some(parts)) => parts,
            Ok(None) | Err(ReassemblySaturated) => return reply_none(reply),
        };

        self.accept_proposal_parts(parts, reply).await
    }

    pub(super) async fn accept_proposal_parts(
        &mut self,
        parts: ProposalParts,
        reply: tokio::sync::oneshot::Sender<Option<ProposedValue<Ctx>>>,
    ) -> Result<()> {
        let height = self.consensus.current_height;
        let round = self.consensus.current_round;

        if parts.height < height || (parts.height == height && parts.round < round) {
            return reply_none(reply);
        }
        if parts.height != height
            || parts.round != round
            || self.consensus.current_proposer.is_none()
        {
            self.consensus.buffer_early_proposal(parts);
            return reply_none(reply);
        }

        if !self
            .consensus
            .height_is_open(&self.db_conn(), height)
            .await?
        {
            return reply_none(reply);
        }
        if round == Round::Nil || proposals::has_normal(&self.db_conn(), height, round).await? {
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
                    certificate: ExtendedCommitCertificate::from_commit_certificate_and_extensions(
                        cert,
                        VoteExtensions::default(),
                    ),
                    value_bytes: encoded,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        reply
            .send(values)
            .map_err(|_| anyhow::anyhow!("Failed to send GetDecidedValues reply"))?;
        Ok(())
    }

    async fn handle_process_synced_value(
        &mut self,
        height: Height,
        round: Round,
        proposer: Address,
        value_bytes: bytes::Bytes,
        reply: tokio::sync::oneshot::Sender<SyncedValueOutcome<Ctx>>,
    ) -> Result<()> {
        if height != self.consensus.current_height {
            // A queued sync response from the previous height cannot install
            // input into the committee/context selected for the next height.
            let _ = reply.send(SyncedValueOutcome::LocalTransientError);
            return Ok(());
        }
        let decoded: Result<Value, _> = ProtobufCodec.decode(value_bytes);
        let result = if let Ok(value) = decoded
            && value.descriptor().context == self.consensus.protocol_context
        {
            if let Err(error) = branch::validate(
                &self.db_conn(),
                self.consensus.protocol_context,
                value.command(),
            )
            .await
            {
                if error.downcast_ref::<branch::Rejected>().is_none() {
                    return Err(error);
                }
                reply
                    .send(SyncedValueOutcome::PeerFault)
                    .map_err(|_| anyhow::anyhow!("Failed to send ProcessSyncedValue rejection"))?;
                return Ok(());
            }
            let proposed = ProposedValue {
                height,
                round,
                valid_round: Round::Nil,
                proposer,
                value,
                validity: Validity::Valid,
            };
            if proposals::accept_synced(&self.db_conn(), height, &proposed.value)
                .await?
                .accepted()
            {
                SyncedValueOutcome::Verdict(proposed)
            } else {
                SyncedValueOutcome::LocalTransientError
            }
        } else {
            SyncedValueOutcome::PeerFault
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
        if let Some(value) = proposals::exact(
            &self.db_conn(),
            height,
            value_id,
            self.consensus.protocol_context,
        )
        .await?
        {
            let locally_proposed = LocallyProposedValue::new(height, round, value);
            self.send_proposal_parts(&locally_proposed, valid_round)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn handle_consensus_msg(
        &mut self,
        msg: impl Into<Message>,
    ) -> Result<consensus_state::ConsensusResult> {
        let mut result = consensus_state::ConsensusResult::None;
        #[cfg(not(kontor_consensus_runtime))]
        let Message::Application(msg) = msg.into();
        #[cfg(kontor_consensus_runtime)]
        let msg = match msg.into() {
            Message::Application(msg) => msg,
            Message::Finalized {
                certificate,
                evidence,
                reply,
            } => {
                info!(height = %certificate.height, round = %certificate.round,
                    value = %certificate.value_id, %evidence, "Finalized");
                return self.handle_finalized(certificate, reply).await;
            }
        };
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
                match self.consensus.engine.listen_address().await {
                    Ok(Some(address)) => {
                        let _ = self.consensus_listen_addr.send(Some(address));
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
                self.handle_started_round(height, round, proposer, role, reply_value)
                    .await?;
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
                from,
                published_by,
                part,
                reply,
            } => {
                // Relay neighbors may differ between parts of the same signed stream.
                self.handle_received_proposal_part(published_by.unwrap_or(from), part, reply)
                    .await?;
            }

            AppMsg::ExtendVote { reply, .. } => {
                reply
                    .send(None)
                    .map_err(|_| anyhow::anyhow!("Failed to send ExtendVote reply"))?;
            }

            AppMsg::VerifyVoteExtensions {
                extensions, reply, ..
            } => {
                let verdicts = extensions
                    .into_iter()
                    .map(|(address, _)| (address, Ok(())))
                    .collect();
                reply
                    .send(verdicts)
                    .map_err(|_| anyhow::anyhow!("Failed to send VerifyVoteExtensions reply"))?;
            }

            AppMsg::Decided {
                certificate,
                extensions,
                reply,
            } => {
                ensure!(
                    extensions.extensions.is_empty(),
                    "vote extensions are not supported in persisted decisions"
                );
                info!(
                    height = %certificate.height,
                    round = %certificate.round,
                    value = %certificate.value_id,
                    "Decided"
                );
                self.consensus
                    .receive_decision(&self.db_conn(), certificate, reply)
                    .await?;
            }

            AppMsg::Finalized {
                certificate,
                extensions,
                evidence,
                reply,
            } => {
                ensure!(
                    extensions.extensions.is_empty(),
                    "vote extensions are not supported in persisted decisions"
                );
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
                self.handle_process_synced_value(height, round, proposer, value_bytes, reply)
                    .await?;
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
