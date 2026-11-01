use anyhow::{Context, Result, ensure};
use libsql::Connection;
use malachitebft_engine::host::Next;
use prost::Message;
use tokio::sync::oneshot;

use super::consensus_state::{ConsensusState, certified_startup};
use crate::consensus::codec::encode_commit_certificate;
use crate::consensus::{CommitCertificate, Ctx, Height, Value, ValueId};
use crate::database::certified_history::{self, Status};
use crate::protocol::coordinator::certified_decision::{
    AuthenticatedDecision, Decision, verify_proof,
};

pub(super) struct PendingDecision {
    height: Height,
    value: ValueId,
    proof: Vec<u8>,
    reply: oneshot::Sender<()>,
}

impl ConsensusState {
    pub(super) async fn receive_decision(
        &mut self,
        conn: &Connection,
        certificate: CommitCertificate<Ctx>,
        reply: oneshot::Sender<()>,
    ) -> Result<()> {
        ensure!(
            self.pending_decision.is_none(),
            "previous decision callback is awaiting input"
        );
        let authority = certified_history::committee(conn, certificate.height.as_u64()).await?;
        ensure!(
            authority.context == self.protocol_context,
            "decision context differs"
        );
        ensure!(
            certificate.commit_signatures.len() <= authority.members.len(),
            "too many certificate signers"
        );
        let proof = encode_commit_certificate(&certificate)?.encode_to_vec();
        verify_proof(
            certificate.height.as_u64(),
            certificate.value_id,
            &proof,
            &authority,
        )?;
        self.pending_decision = Some(PendingDecision {
            height: certificate.height,
            value: certificate.value_id,
            proof,
            reply,
        });
        self.try_acknowledge_decision(conn).await
    }

    pub(super) async fn try_acknowledge_decision(&mut self, conn: &Connection) -> Result<()> {
        let Some(pending) = &self.pending_decision else {
            return Ok(());
        };
        let frontier = certified_history::frontier(conn).await?;
        ensure!(
            frontier.status == Status::Ready && frontier.context == Some(self.protocol_context),
            "decision lacks ready certified history"
        );
        let height = pending.height.as_u64();
        if height <= frontier.authenticated_height {
            let retained = certified_history::load(conn, height).await?;
            ensure!(
                ValueId::new(retained.decision().descriptor.id()?) == pending.value,
                "redelivered decision conflicts with retained history"
            );
        } else {
            ensure!(
                frontier.authenticated_height.checked_add(1) == Some(height),
                "decision history gap"
            );
            let Some(value) = self
                .undecided
                .get(&pending.height)
                .and_then(|rounds| {
                    rounds
                        .values()
                        .find(|proposal| proposal.value.id() == pending.value)
                })
                .map(|proposal| proposal.value.clone())
            else {
                // Keep the verified proof and callback while normal ingestion and
                // value sync continue. Missing bytes cannot authorize an ack.
                return Ok(());
            };
            ensure!(
                value.descriptor().context == self.protocol_context,
                "decision input context differs"
            );
            let authority = certified_history::committee(conn, height).await?;
            let decision = Decision {
                height,
                predecessor: frontier
                    .authenticated_id
                    .context("missing decision predecessor")?,
                committee: authority.id()?,
                descriptor: value.descriptor().clone(),
            };
            let certified = AuthenticatedDecision::verify(
                decision,
                value.input().clone(),
                pending.proof.clone(),
                &authority,
            )?;
            certified_history::append(conn, &certified).await?;
        }
        let pending = self
            .pending_decision
            .take()
            .context("decision callback disappeared")?;
        // The durable record remains useful even if the engine cancelled its
        // receiver after requesting persistence. Redelivery verifies that record.
        let _ = pending.reply.send(());
        Ok(())
    }

    pub(super) async fn closed_next_height(
        &mut self,
        conn: &Connection,
        completed: Height,
    ) -> Result<Option<Next<Ctx>>> {
        let frontier = certified_history::frontier(conn).await?;
        ensure!(
            frontier.status == Status::Ready && frontier.context == Some(self.protocol_context),
            "next height lacks ready certified history"
        );
        if frontier.closed_height < completed.as_u64() {
            return Ok(None);
        }
        ensure!(
            frontier.closed_height == completed.as_u64(),
            "next-height callback is stale"
        );
        let (context, next, authority) = certified_startup(conn).await?;
        ensure!(
            context == self.protocol_context,
            "next-height protocol context differs"
        );
        self.current_validator_set = authority;
        self.validator_index = self
            .current_validator_set
            .iter()
            .position(|validator| validator.address == self.address);
        self.current_height = next;
        Ok(Some(Next::Start(next, self.height_params())))
    }

    pub(super) async fn finalized_value(
        &self,
        conn: &Connection,
        certificate: &CommitCertificate<Ctx>,
    ) -> Result<Value> {
        let original = certified_history::load(conn, certificate.height.as_u64()).await?;
        ensure!(
            original.decision().descriptor.context == self.protocol_context,
            "finalized context differs"
        );
        let authority = certified_history::committee(conn, certificate.height.as_u64()).await?;
        ensure!(
            certificate.commit_signatures.len() <= authority.members.len(),
            "too many finalized signers"
        );
        let augmented = AuthenticatedDecision::verify(
            original.decision().clone(),
            original.input().clone(),
            encode_commit_certificate(certificate)?.encode_to_vec(),
            &authority,
        )?;
        certified_history::augment(conn, &augmented).await?;
        Ok(Value::from_input(original.input().clone())?)
    }
}

#[cfg(feature = "protocol-qualification")]
pub(crate) mod qualification;

mod closure;
