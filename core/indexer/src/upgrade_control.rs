use anyhow::{Context, Result};
use libsql::Connection;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use ts_rs::TS;

use crate::database::certified_history::{self, Status, branch, control};
use crate::protocol::coordinator::certified_input::{ExactInput, MAX_BATCH_BYTES};
use crate::protocol::coordinator::control::{ControlError, UpgradeControl};

pub const SUBMISSION_BODY_LIMIT: usize = MAX_BATCH_BYTES * 2 + 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitUpgrade {
    pub envelope_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, TS)]
pub struct QueuedUpgrade {
    pub action_id: String,
    pub control_id: String,
    pub status: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SubmissionError {
    #[error("invalid upgrade action: {0}")]
    Invalid(String),
    #[error("another approved upgrade action is queued locally")]
    Busy,
    #[error("upgrade submission requires fully closed consensus history")]
    NotReady,
}

pub struct UpgradeSubmission {
    pub(crate) envelope: UpgradeControl,
    pub(crate) reply: oneshot::Sender<Result<QueuedUpgrade, SubmissionError>>,
}

pub(crate) fn decode_submission(request: SubmitUpgrade) -> Result<UpgradeControl, SubmissionError> {
    if request.envelope_hex.len() > MAX_BATCH_BYTES * 2 {
        return Err(SubmissionError::Invalid(
            "envelope exceeds size limit".into(),
        ));
    }
    let bytes = hex::decode(request.envelope_hex)
        .map_err(|_| SubmissionError::Invalid("envelope must be hexadecimal".into()))?;
    UpgradeControl::decode(&bytes).map_err(|e| SubmissionError::Invalid(e.to_string()))
}

// This is local proposer policy, never persisted authority. Every use rechecks
// the signed envelope without changing any signed field or collecting approvals.
#[derive(Default)]
pub(crate) struct PendingControl(Option<UpgradeControl>);

impl PendingControl {
    pub(crate) async fn submit(
        &mut self,
        conn: &Connection,
        inclusion: u64,
        envelope: UpgradeControl,
    ) -> Result<Result<QueuedUpgrade, SubmissionError>> {
        if let Err(error) = admitted_input(conn, inclusion, &envelope).await? {
            return Ok(Err(error));
        }
        self.input(conn, inclusion).await?;
        if self.0.as_ref().is_some_and(|queued| queued != &envelope) {
            return Ok(Err(SubmissionError::Busy));
        }
        let queued = QueuedUpgrade {
            action_id: hex::encode(envelope.action.id()?),
            control_id: hex::encode(envelope.id()?),
            status: "queued".into(),
        };
        self.0 = Some(envelope);
        Ok(Ok(queued))
    }

    pub(crate) async fn input(
        &mut self,
        conn: &Connection,
        inclusion: u64,
    ) -> Result<Option<ExactInput>> {
        let Some(envelope) = self.0.as_ref() else {
            return Ok(None);
        };
        match admitted_input(conn, inclusion, envelope).await? {
            Ok(input) => Ok(Some(input)),
            Err(SubmissionError::NotReady) => Ok(None),
            Err(_) => {
                self.0 = None;
                Ok(None)
            }
        }
    }
}

async fn admitted_input(
    conn: &Connection,
    inclusion: u64,
    envelope: &UpgradeControl,
) -> Result<Result<ExactInput, SubmissionError>> {
    let frontier = certified_history::frontier(conn).await?;
    if frontier.status != Status::Ready
        || frontier.closed_height == 0
        || frontier.closed_height != frontier.authenticated_height
        || frontier.closed_height.checked_add(1) != Some(inclusion)
    {
        return Ok(Err(SubmissionError::NotReady));
    }
    if frontier.context != Some(envelope.action.context) {
        return Ok(Err(SubmissionError::Invalid("control era differs".into())));
    }
    let (height, hash) = branch::tip_at(conn, frontier.closed_height)
        .await?
        .context("closed history lacks a Bitcoin tip")?;
    let input = match ExactInput::control(envelope.action.context, height, hash, envelope) {
        Ok(input) => input,
        Err(error) => return Ok(Err(SubmissionError::Invalid(error.to_string()))),
    };
    match control::admission::verify(
        conn,
        &input,
        inclusion,
        control::Position {
            decision: inclusion,
            stage: 0,
        },
    )
    .await
    {
        Ok(_) => Ok(Ok(input)),
        Err(error) if error.is::<control::admission::Rejected>() || error.is::<ControlError>() => {
            Ok(Err(SubmissionError::Invalid(error.to_string())))
        }
        Err(error) => Err(error),
    }
}

#[derive(Debug, Serialize, TS)]
pub struct UpgradeAuthority {
    pub key: String,
    pub generation: String,
    pub power: String,
}

#[derive(Debug, Serialize, TS)]
pub struct PendingUpgrade {
    pub plan_id: String,
    pub target_protocol: String,
    pub activation_height: String,
    pub consumed: bool,
    pub manifest_hex: String,
}

#[derive(Debug, Serialize, TS)]
pub struct UpgradeState {
    pub chain_id: String,
    pub era_id: String,
    pub protocol_id: String,
    pub control_head: String,
    pub nonce: String,
    pub reference_height: String,
    pub reference_decision: String,
    pub bitcoin_height: String,
    pub bitcoin_hash: String,
    pub minimum_reference_height: String,
    pub pending: Option<PendingUpgrade>,
    pub inclusion_height: String,
    pub committee: Vec<UpgradeAuthority>,
    pub state_hex: String,
}

pub(crate) async fn snapshot(conn: &Connection) -> Result<UpgradeState> {
    let frontier = certified_history::frontier(conn).await?;
    anyhow::ensure!(
        frontier.status == Status::Ready
            && frontier.closed_height > 0
            && frontier.closed_height == frontier.authenticated_height,
        SubmissionError::NotReady
    );
    let context = frontier
        .context
        .context("closed history lacks protocol context")?;
    let inclusion = frontier
        .closed_height
        .checked_add(1)
        .context("consensus height exhausted")?;
    let reference = certified_history::completion::completed(conn, frontier.closed_height).await?;
    let (bitcoin_height, bitcoin_hash) = branch::tip_at(conn, frontier.closed_height)
        .await?
        .context("closed history lacks Bitcoin tip")?;
    let state = control::admission::state(conn, context).await?;
    let committee = certified_history::committee(conn, inclusion).await?;
    let pending = state
        .pending
        .as_ref()
        .map(|plan| -> Result<PendingUpgrade> {
            Ok(PendingUpgrade {
                plan_id: hex::encode(plan.id.0),
                target_protocol: hex::encode(plan.manifest.id()?.0),
                activation_height: plan.activation.to_string(),
                consumed: plan.consumed,
                manifest_hex: hex::encode(plan.manifest.encode()?),
            })
        })
        .transpose()?;
    Ok(UpgradeState {
        chain_id: hex::encode(context.chain.0),
        era_id: hex::encode(context.era),
        protocol_id: hex::encode(context.protocol.0),
        control_head: hex::encode(state.head),
        nonce: state.nonce.to_string(),
        reference_height: reference.height.to_string(),
        reference_decision: hex::encode(reference.decision),
        bitcoin_height: bitcoin_height.to_string(),
        bitcoin_hash: bitcoin_hash.to_string(),
        minimum_reference_height: control::reference_floor(
            conn,
            control::Position {
                decision: inclusion,
                stage: 0,
            },
        )
        .await?
        .to_string(),
        pending,
        inclusion_height: inclusion.to_string(),
        committee: committee
            .members
            .iter()
            .map(|member| UpgradeAuthority {
                key: hex::encode(member.key),
                generation: hex::encode(member.generation),
                power: member.power.to_string(),
            })
            .collect(),
        state_hex: hex::encode(state.encode()?),
    })
}

#[cfg(test)]
mod tests {
    use super::{SubmitUpgrade, decode_submission};
    use crate::protocol::coordinator::certified_input::MAX_BATCH_BYTES;

    #[test]
    fn malformed_and_oversized_submissions_are_rejected() {
        for envelope_hex in [
            String::new(),
            "zz".into(),
            "f".into(),
            "00".into(),
            "0".repeat(MAX_BATCH_BYTES * 2 + 1),
        ] {
            assert!(decode_submission(SubmitUpgrade { envelope_hex }).is_err());
        }
        assert!(
            serde_json::from_str::<SubmitUpgrade>(r#"{"envelope_hex":"00","sign":true}"#).is_err()
        );
    }
}
