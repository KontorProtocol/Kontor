use anyhow::{Context, Result, ensure};
use libsql::Connection;
use malachitebft_engine::host::Next;
use prost::Message;
use tokio::sync::oneshot;

use super::consensus_state::{ConsensusState, certified_startup};
use crate::consensus::codec::encode_commit_certificate;
use crate::consensus::{CommitCertificate, Ctx, Height, Value, ValueId};
use crate::database::certified_history::{self, Status, proposals};
use crate::protocol::coordinator::certified_decision::{
    AuthenticatedDecision, Decision, verify_proof,
};

impl ConsensusState {
    pub(super) async fn height_is_open(&self, conn: &Connection, height: Height) -> Result<bool> {
        if height != self.current_height || self.pending_next_height.is_some() {
            return Ok(false);
        }
        let frontier = certified_history::frontier(conn).await?;
        Ok(frontier.status == Status::Ready
            && frontier.context == Some(self.protocol_context)
            && frontier.authenticated_height < height.as_u64())
    }

    pub(super) async fn receive_decision(
        &mut self,
        conn: &Connection,
        certificate: CommitCertificate<Ctx>,
        reply: oneshot::Sender<()>,
    ) -> Result<()> {
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
        let frontier = certified_history::frontier(conn).await?;
        ensure!(
            frontier.status == Status::Ready && frontier.context == Some(self.protocol_context),
            "decision lacks ready certified history"
        );
        let height = certificate.height.as_u64();
        if height <= frontier.authenticated_height {
            let retained = certified_history::load(conn, height).await?;
            ensure!(
                ValueId::new(retained.decision().descriptor.id()?) == certificate.value_id,
                "redelivered decision conflicts with retained history"
            );
        } else {
            ensure!(
                frontier.authenticated_height.checked_add(1) == Some(height),
                "decision history gap"
            );
            let value = proposals::exact(
                conn,
                certificate.height,
                certificate.value_id,
                self.protocol_context,
            )
            .await?
            .context("decided proposal missing from durable application storage")?;
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
            let certified =
                AuthenticatedDecision::verify(decision, value.input().clone(), proof, &authority)?;
            certified_history::append(conn, &certified).await?;
        }
        // The durable record remains useful even if the engine cancelled its
        // receiver after requesting persistence. Redelivery verifies that record.
        let _ = reply.send(());
        Ok(())
    }

    pub(super) async fn closed_next_height(
        &mut self,
        conn: &Connection,
        completed: Height,
    ) -> Result<Option<Next<Ctx>>> {
        let frontier = certified_history::frontier(conn).await?;
        ensure!(
            frontier.status == Status::Ready,
            "next height lacks ready certified history"
        );
        if frontier.closed_height < completed.as_u64() {
            return Ok(None);
        }
        ensure!(
            frontier.closed_height == completed.as_u64(),
            "next-height callback is stale"
        );
        let completed_authority = certified_history::committee(conn, completed.as_u64()).await?;
        ensure!(
            completed_authority.context == self.protocol_context,
            "completed height protocol context differs"
        );
        let (context, next, authority) = certified_startup(conn).await?;
        #[cfg(not(kontor_managed))]
        ensure!(
            context == self.protocol_context,
            "protocol transition requires managed execution"
        );
        let committee = certified_history::committee(conn, next.as_u64()).await?;
        self.engine
            .authorize_height(
                committee,
                frontier
                    .closure_id
                    .context("next height lacks completed closure")?,
            )
            .await?;
        self.protocol_context = context;
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
