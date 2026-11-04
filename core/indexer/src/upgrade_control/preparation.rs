use anyhow::{Context, Result};
use libsql::Connection;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::SubmissionError;
use crate::database::certified_history::{self, Status, branch, completion, control};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::control::{
    ControlAction, ControlError, ControlOperation, UpgradeControl,
};
use crate::protocol::coordinator::manifest::{MAX_MANIFEST_BYTES, ProtocolManifest};

#[derive(Debug, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PrepareUpgrade {
    pub expires_at: String,
    pub operation: RequestedUpgrade,
}

#[derive(Debug, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestedUpgrade {
    Schedule {
        manifest_hex: String,
        activation_height: String,
    },
    Postpone {
        activation_height: String,
    },
    Cancel,
}

#[derive(Debug, Serialize, TS)]
pub struct PreparedUpgrade {
    pub action_id: String,
    pub action_hex: String,
}

fn invalid(message: impl Into<String>) -> anyhow::Error {
    SubmissionError::Invalid(message.into()).into()
}

fn height(value: &str) -> Result<u64> {
    let parsed: u64 = value
        .parse()
        .map_err(|_| invalid("height must be a decimal u64 string"))?;
    if parsed.to_string() != value {
        return Err(invalid("height must be a canonical decimal u64 string"));
    }
    Ok(parsed)
}

pub(crate) async fn prepare(conn: &Connection, request: PrepareUpgrade) -> Result<PreparedUpgrade> {
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
    let reference = completion::completed(conn, frontier.closed_height).await?;
    let state = control::admission::state(conn, context).await?;
    let expires_at = height(&request.expires_at)?;
    let operation = match request.operation {
        RequestedUpgrade::Schedule {
            manifest_hex,
            activation_height,
        } => {
            if manifest_hex.len() > MAX_MANIFEST_BYTES * 2 {
                return Err(invalid("manifest exceeds size limit"));
            }
            let bytes =
                hex::decode(manifest_hex).map_err(|_| invalid("manifest must be hexadecimal"))?;
            let manifest =
                ProtocolManifest::decode(&bytes).map_err(|error| invalid(error.to_string()))?;
            ControlOperation::Schedule {
                manifest,
                activation: height(&activation_height)?,
            }
        }
        RequestedUpgrade::Postpone { activation_height } => {
            let pending = state
                .pending
                .as_ref()
                .ok_or_else(|| invalid("no pending upgrade to postpone"))?;
            ControlOperation::Postpone {
                target: pending.manifest.id()?,
                previous_activation: pending.activation,
                activation: height(&activation_height)?,
            }
        }
        RequestedUpgrade::Cancel => {
            let pending = state
                .pending
                .as_ref()
                .ok_or_else(|| invalid("no pending upgrade to cancel"))?;
            ControlOperation::Cancel {
                target: pending.manifest.id()?,
                activation: pending.activation,
            }
        }
    };
    let action = ControlAction {
        context,
        head: state.head,
        nonce: state
            .nonce
            .checked_add(1)
            .context("control nonce exhausted")?,
        expected_pending: state.pending.as_ref().map(|plan| plan.id),
        reference_height: reference.height,
        reference_decision: reference.decision,
        expires_at,
        operation,
    };
    let (bitcoin_height, bitcoin_hash) = branch::tip_at(conn, frontier.closed_height)
        .await?
        .context("closed history lacks Bitcoin tip")?;
    let envelope = UpgradeControl {
        action,
        approvals: Vec::new(),
    };
    let input = ExactInput::control(context, bitcoin_height, bitcoin_hash, &envelope)?;
    match control::admission::validate_proposal(
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
        Err(error) if error.is::<ControlError>() || error.is::<control::admission::Rejected>() => {
            return Err(invalid(error.to_string()));
        }
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    Ok(PreparedUpgrade {
        action_id: hex::encode(envelope.action.id()?),
        action_hex: hex::encode(envelope.action.encode()?),
    })
}

#[cfg(test)]
mod tests {
    use super::height;

    #[test]
    fn preparation_height_preserves_u64_and_rejects_ambiguous_numbers() {
        assert_eq!(height("18446744073709551615").unwrap(), u64::MAX);
        assert_eq!(height("9007199254740993").unwrap(), 9_007_199_254_740_993);
        for value in [
            "",
            "01",
            "+1",
            "-1",
            "1e3",
            "1.0",
            " 1",
            "18446744073709551616",
        ] {
            assert!(height(value).is_err(), "{value}");
        }
    }
}
