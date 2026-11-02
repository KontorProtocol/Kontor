use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::consensus::signing::private_key_from_hex;
use crate::protocol::coordinator::certified_input::MAX_BATCH_BYTES;
use crate::protocol::coordinator::control::{
    Approval, ApprovalSigner, ControlAction, ControlOperation, UpgradeControl,
};
use crate::protocol::coordinator::manifest::ProtocolManifest;

const MAX_PREPARATION_FILE_BYTES: usize = MAX_BATCH_BYTES * 2 + 65_536;
const MAX_APPROVAL_FILE_BYTES: usize = 2_048;
const MAX_KEY_FILE_BYTES: usize = 256;

#[derive(Args)]
pub struct UpgradeApprovalArgs {
    #[command(subcommand)]
    pub command: UpgradeApprovalCommand,
}

#[derive(Subcommand)]
pub enum UpgradeApprovalCommand {
    /// Inspect every signed field in a prepared canonical action.
    Inspect {
        #[arg(long)]
        preparation: PathBuf,
    },
    /// Sign one exact prepared action with an explicit local validator key file.
    Sign {
        #[arg(long)]
        preparation: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        registration_generation: String,
        #[arg(long)]
        expected_action_id: String,
    },
    /// Verify explicit approval files and assemble a canonical envelope.
    Assemble {
        #[arg(long)]
        preparation: PathBuf,
        #[arg(long = "approval-file", required = true)]
        approval_files: Vec<PathBuf>,
    },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ApprovalOutput {
    Inspect(InspectedAction),
    Sign(ApprovalFile),
    Assemble(AssembledEnvelope),
}

#[derive(Debug, Serialize)]
pub struct InspectedAction {
    pub action_id: String,
    pub canonical_action_hex: String,
    pub chain_id: String,
    pub era_id: String,
    pub protocol_id: String,
    pub input_codec: String,
    pub control_head: String,
    pub nonce: String,
    pub expected_pending_plan: Option<String>,
    pub reference_height: String,
    pub reference_decision: String,
    pub expires_at_bitcoin_height: String,
    pub operation: InspectedOperation,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InspectedOperation {
    Schedule {
        target: InspectedManifest,
        activation_height: String,
    },
    Postpone {
        target_protocol_id: String,
        previous_activation_height: String,
        activation_height: String,
    },
    Cancel {
        target_protocol_id: String,
        activation_height: String,
    },
}

#[derive(Debug, Serialize)]
pub struct InspectedManifest {
    pub manifest_hex: String,
    pub protocol_id: String,
    pub chain_id: String,
    pub protocol_number: String,
    pub predecessor_protocol_id: String,
    pub execution_definition_id: String,
    pub consensus_definition_id: String,
    pub transaction_formats: Vec<String>,
    pub host_abis: Vec<String>,
    pub bridge_schema: String,
    pub state_schema: String,
    pub certificate_codec: String,
    pub control_codec: String,
    pub parameters_root: String,
    pub native_contracts_root: String,
    pub migration_definition_id: String,
    pub input_state_schema: String,
    pub output_state_schema: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalFile {
    pub action_id: String,
    pub key: String,
    pub generation: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct AssembledEnvelope {
    pub envelope_hex: String,
    pub action_id: String,
    pub control_id: String,
    pub signatures_verified: bool,
    pub current_committee_quorum_verified: bool,
    pub node_admission_verified: bool,
    pub next_step: String,
}

#[derive(Deserialize)]
struct Preparation {
    action_hex: String,
    action_id: String,
}

pub fn run(args: UpgradeApprovalArgs) -> Result<ApprovalOutput> {
    match args.command {
        UpgradeApprovalCommand::Inspect { preparation } => {
            let (action, action_id) = read_preparation(&preparation)?;
            Ok(ApprovalOutput::Inspect(inspect(&action, action_id)?))
        }
        UpgradeApprovalCommand::Sign {
            preparation,
            key_file,
            registration_generation,
            expected_action_id,
        } => {
            let (action, action_id) = read_preparation(&preparation)?;
            ensure!(
                parse_hex::<32>(&expected_action_id, "expected action ID")? == action_id,
                "expected action ID differs from canonical preparation"
            );
            let generation = parse_hex::<32>(&registration_generation, "registration generation")?;
            let key_bytes = read_limited(&key_file, MAX_KEY_FILE_BYTES, "approval key")?;
            let key_text = std::str::from_utf8(&key_bytes)
                .map_err(|_| anyhow!("approval key file must contain UTF-8 hexadecimal"))?;
            let private = private_key_from_hex(key_text.trim()).map_err(|_| {
                anyhow!("approval key file must contain one 32-byte hexadecimal key")
            })?;
            let approval = ApprovalSigner::new(private).sign(&action, generation)?;
            Ok(ApprovalOutput::Sign(ApprovalFile {
                action_id: hex::encode(action_id),
                key: hex::encode(approval.key),
                generation: hex::encode(approval.generation),
                signature: hex::encode(approval.signature),
            }))
        }
        UpgradeApprovalCommand::Assemble {
            preparation,
            approval_files,
        } => {
            ensure!(
                !approval_files.is_empty(),
                "at least one approval file is required"
            );
            ensure!(
                approval_files.len() <= MAX_BATCH_BYTES / 128,
                "approval count exceeds canonical envelope byte limit"
            );
            let (action, action_id) = read_preparation(&preparation)?;
            let mut approvals = Vec::new();
            for path in approval_files {
                let bytes = read_limited(&path, MAX_APPROVAL_FILE_BYTES, "approval")?;
                let entry: ApprovalFile =
                    serde_json::from_slice(&bytes).context("invalid approval JSON")?;
                ensure!(
                    parse_hex::<32>(&entry.action_id, "approval action ID")? == action_id,
                    "approval action ID differs from preparation"
                );
                let approval = Approval {
                    key: parse_hex::<32>(&entry.key, "approval key")?,
                    generation: parse_hex::<32>(&entry.generation, "approval generation")?,
                    signature: parse_hex::<64>(&entry.signature, "approval signature")?,
                };
                approval.verify_for(action_id)?;
                approvals.push(approval);
            }
            approvals.sort_by_key(|entry| entry.key);
            if approvals.windows(2).any(|pair| pair[0].key == pair[1].key) {
                bail!("duplicate approval key");
            }
            let envelope = UpgradeControl { action, approvals };
            Ok(ApprovalOutput::Assemble(AssembledEnvelope {
                envelope_hex: hex::encode(envelope.encode()?),
                action_id: hex::encode(action_id),
                control_id: hex::encode(envelope.id()?),
                signatures_verified: true,
                current_committee_quorum_verified: false,
                node_admission_verified: false,
                next_step: "Submit this envelope to a node for current committee quorum and admission checks".into(),
            }))
        }
    }
}

fn read_preparation(path: &Path) -> Result<(ControlAction, [u8; 32])> {
    let bytes = read_limited(path, MAX_PREPARATION_FILE_BYTES, "preparation")?;
    let prepared: Preparation =
        serde_json::from_slice(&bytes).context("invalid preparation JSON")?;
    ensure!(
        prepared.action_hex.len() <= MAX_BATCH_BYTES * 2,
        "prepared action exceeds canonical byte limit"
    );
    let action_bytes = hex::decode(&prepared.action_hex)
        .map_err(|_| anyhow!("prepared action must be hexadecimal"))?;
    let action = ControlAction::decode(&action_bytes)?;
    let action_id = action.id()?;
    ensure!(
        parse_hex::<32>(&prepared.action_id, "preparation action ID")? == action_id,
        "preparation action ID differs from canonical action"
    );
    Ok((action, action_id))
}

fn read_limited(path: &Path, limit: usize, label: &str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("opening {label} file"))?;
    ensure!(
        file.metadata()?.is_file(),
        "{label} path must name a regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} file"))?;
    ensure!(bytes.len() <= limit, "{label} file exceeds byte limit");
    Ok(bytes)
}

fn parse_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    ensure!(
        value.len() == N * 2,
        "{label} must be {N} bytes of hexadecimal"
    );
    let bytes = hex::decode(value).with_context(|| format!("{label} must be hexadecimal"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} has invalid length"))
}

fn inspect(action: &ControlAction, action_id: [u8; 32]) -> Result<InspectedAction> {
    let operation = match &action.operation {
        ControlOperation::Schedule {
            manifest,
            activation,
        } => InspectedOperation::Schedule {
            target: inspect_manifest(manifest)?,
            activation_height: activation.to_string(),
        },
        ControlOperation::Postpone {
            target,
            previous_activation,
            activation,
        } => InspectedOperation::Postpone {
            target_protocol_id: hex::encode(target.0),
            previous_activation_height: previous_activation.to_string(),
            activation_height: activation.to_string(),
        },
        ControlOperation::Cancel { target, activation } => InspectedOperation::Cancel {
            target_protocol_id: hex::encode(target.0),
            activation_height: activation.to_string(),
        },
    };
    Ok(InspectedAction {
        action_id: hex::encode(action_id),
        canonical_action_hex: hex::encode(action.encode()?),
        chain_id: hex::encode(action.context.chain.0),
        era_id: hex::encode(action.context.era),
        protocol_id: hex::encode(action.context.protocol.0),
        input_codec: action.context.codec.to_string(),
        control_head: hex::encode(action.head),
        nonce: action.nonce.to_string(),
        expected_pending_plan: action.expected_pending.map(|id| hex::encode(id.0)),
        reference_height: action.reference_height.to_string(),
        reference_decision: hex::encode(action.reference_decision),
        expires_at_bitcoin_height: action.expires_at.to_string(),
        operation,
    })
}

fn inspect_manifest(manifest: &ProtocolManifest) -> Result<InspectedManifest> {
    Ok(InspectedManifest {
        manifest_hex: hex::encode(manifest.encode()?),
        protocol_id: hex::encode(manifest.id()?.0),
        chain_id: hex::encode(manifest.chain.0),
        protocol_number: manifest.protocol_number.to_string(),
        predecessor_protocol_id: hex::encode(manifest.predecessor.0),
        execution_definition_id: hex::encode(manifest.executor.0),
        consensus_definition_id: hex::encode(manifest.consensus),
        transaction_formats: manifest
            .transaction_formats
            .iter()
            .map(ToString::to_string)
            .collect(),
        host_abis: manifest.host_abis.iter().map(ToString::to_string).collect(),
        bridge_schema: manifest.bridge_schema.to_string(),
        state_schema: manifest.state_schema.to_string(),
        certificate_codec: manifest.certificate_codec.to_string(),
        control_codec: manifest.control_codec.to_string(),
        parameters_root: hex::encode(manifest.parameters_root),
        native_contracts_root: hex::encode(manifest.native_contracts_root),
        migration_definition_id: hex::encode(manifest.migration.0),
        input_state_schema: manifest.input_state_schema.to_string(),
        output_state_schema: manifest.output_state_schema.to_string(),
    })
}

#[cfg(test)]
mod tests;
