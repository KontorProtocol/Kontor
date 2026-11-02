use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use malachitebft_signing_ed25519::PrivateKey;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::{ApprovalFile, ApprovalOutput, UpgradeApprovalArgs, UpgradeApprovalCommand, run};
use crate::protocol::coordinator::control::{ControlAction, ControlOperation, UpgradeControl};

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    upgrade: UpgradeApprovalArgs,
}

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../protocol/coordinator/control/test-vector.json"
    ))
    .unwrap()
}

fn preparation(dir: &TempDir) -> PathBuf {
    let vector = vector();
    let path = dir.path().join("preparation.json");
    fs::write(
        &path,
        serde_json::to_vec(&json!({
            "action_hex": vector["action_hex"],
            "action_id": vector["action_id"],
            "display_target": "this is intentionally untrusted"
        }))
        .unwrap(),
    )
    .unwrap();
    path
}

fn key_file(dir: &TempDir, contents: &str) -> PathBuf {
    let path = dir.path().join("validator.key");
    fs::write(&path, contents).unwrap();
    path
}

fn sign_args(
    preparation: PathBuf,
    key_file: PathBuf,
    expected_action_id: String,
) -> UpgradeApprovalArgs {
    UpgradeApprovalArgs {
        command: UpgradeApprovalCommand::Sign {
            preparation,
            key_file,
            registration_generation: hex::encode([21; 32]),
            expected_action_id,
        },
    }
}

fn signed_approval(dir: &TempDir, preparation: &Path) -> ApprovalFile {
    let key = key_file(dir, &hex::encode([1; 32]));
    let output = run(sign_args(
        preparation.to_path_buf(),
        key,
        vector()["action_id"].as_str().unwrap().to_owned(),
    ))
    .unwrap();
    match output {
        ApprovalOutput::Sign(value) => value,
        _ => panic!("unexpected signing output"),
    }
}

fn approval_file(dir: &TempDir, name: &str, approval: &ApprovalFile) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, serde_json::to_vec(approval).unwrap()).unwrap();
    path
}

fn assemble(preparation: PathBuf, approval_files: Vec<PathBuf>) -> anyhow::Result<ApprovalOutput> {
    run(UpgradeApprovalArgs {
        command: UpgradeApprovalCommand::Assemble {
            preparation,
            approval_files,
        },
    })
}

#[test]
fn inspect_sign_and_assemble_match_independent_golden_vector() {
    let dir = TempDir::new().unwrap();
    let preparation = preparation(&dir);
    let inspected = run(UpgradeApprovalArgs {
        command: UpgradeApprovalCommand::Inspect {
            preparation: preparation.clone(),
        },
    })
    .unwrap();
    let ApprovalOutput::Inspect(inspected) = inspected else {
        panic!("unexpected inspect output");
    };
    let value = serde_json::to_value(&inspected).unwrap();
    let vector = vector();
    assert_eq!(value["action_id"], vector["action_id"]);
    assert_eq!(value["canonical_action_hex"], vector["action_hex"]);
    assert_eq!(value["chain_id"], hex::encode([1; 32]));
    assert_eq!(value["era_id"], hex::encode([7; 32]));
    assert_eq!(value["input_codec"], "1");
    assert_eq!(value["control_head"], hex::encode([8; 32]));
    assert_eq!(value["nonce"], "1");
    assert!(value["expected_pending_plan"].is_null());
    assert_eq!(value["reference_height"], "9");
    assert_eq!(value["reference_decision"], hex::encode([9; 32]));
    assert_eq!(value["expires_at_bitcoin_height"], "244");
    assert_eq!(value["operation"]["kind"], "schedule");
    assert_eq!(value["operation"]["activation_height"], "1108");
    assert_eq!(value["operation"]["target"]["protocol_number"], "2");
    assert_eq!(
        value["operation"]["target"]["transaction_formats"],
        json!(["1", "2"])
    );
    assert_eq!(value["operation"]["target"]["host_abis"], json!(["1"]));
    assert_eq!(value["operation"]["target"]["state_schema"], "1");
    assert_eq!(value["operation"]["target"]["input_state_schema"], "1");
    assert_eq!(value["operation"]["target"]["output_state_schema"], "1");
    assert!(
        !serde_json::to_string(&value)
            .unwrap()
            .contains("this is intentionally untrusted")
    );

    let approval = signed_approval(&dir, &preparation);
    assert_eq!(approval.action_id, vector["action_id"].as_str().unwrap());
    assert_eq!(approval.key, vector["approval_key"].as_str().unwrap());
    assert_eq!(approval.generation, hex::encode([21; 32]));
    assert_eq!(
        approval.signature,
        vector["approval_signature"].as_str().unwrap()
    );
    let approval_path = approval_file(&dir, "approval.json", &approval);
    let assembled = assemble(preparation, vec![approval_path]).unwrap();
    let ApprovalOutput::Assemble(assembled) = assembled else {
        panic!("unexpected assembly output");
    };
    assert_eq!(
        assembled.envelope_hex,
        vector["control_hex"].as_str().unwrap()
    );
    assert_eq!(assembled.action_id, vector["action_id"].as_str().unwrap());
    assert_eq!(assembled.control_id, vector["control_id"].as_str().unwrap());
    assert!(assembled.signatures_verified);
    assert!(!assembled.current_committee_quorum_verified);
    assert!(!assembled.node_admission_verified);
    assert!(assembled.next_step.contains("Submit"));
    let expected_control_id: [u8; 32] = hex::decode(vector["control_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        UpgradeControl::decode(&hex::decode(assembled.envelope_hex).unwrap())
            .unwrap()
            .id()
            .unwrap(),
        expected_control_id
    );
}

#[test]
fn signing_rejects_wrong_expected_or_mutated_preparation_before_key_read() {
    let dir = TempDir::new().unwrap();
    let preparation = preparation(&dir);
    let missing_key = dir.path().join("missing.key");
    let error = run(sign_args(
        preparation.clone(),
        missing_key.clone(),
        hex::encode([0; 32]),
    ))
    .unwrap_err()
    .to_string();
    assert!(error.contains("expected action ID differs"));
    assert!(!error.contains("key file"));

    let mut changed = hex::decode(vector()["action_hex"].as_str().unwrap()).unwrap();
    changed[143] ^= 1;
    fs::write(
        &preparation,
        serde_json::to_vec(&json!({
            "action_hex": hex::encode(changed),
            "action_id": vector()["action_id"]
        }))
        .unwrap(),
    )
    .unwrap();
    let error = run(sign_args(
        preparation,
        missing_key,
        vector()["action_id"].as_str().unwrap().to_owned(),
    ))
    .unwrap_err()
    .to_string();
    assert!(error.contains("preparation action ID differs"));
}

#[test]
fn assemble_rejects_wrong_binding_signature_and_duplicate_keys() {
    let dir = TempDir::new().unwrap();
    let preparation = preparation(&dir);
    let good = signed_approval(&dir, &preparation);
    let good_path = approval_file(&dir, "good.json", &good);
    assert!(
        assemble(preparation.clone(), vec![good_path.clone(), good_path])
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );

    let mut wrong = ApprovalFile {
        action_id: good.action_id.clone(),
        key: good.key.clone(),
        generation: good.generation.clone(),
        signature: good.signature.clone(),
    };
    wrong.action_id = hex::encode([0; 32]);
    let path = approval_file(&dir, "wrong-action.json", &wrong);
    assert!(
        assemble(preparation.clone(), vec![path])
            .unwrap_err()
            .to_string()
            .contains("action ID differs")
    );
    wrong.action_id = good.action_id.clone();
    wrong.generation = hex::encode([99; 32]);
    let path = approval_file(&dir, "wrong-generation.json", &wrong);
    assert!(
        assemble(preparation.clone(), vec![path])
            .unwrap_err()
            .to_string()
            .contains("signature")
    );
    wrong.generation = good.generation.clone();
    wrong.key = hex::encode(PrivateKey::from([2; 32]).public_key().as_bytes());
    let path = approval_file(&dir, "wrong-key.json", &wrong);
    assert!(
        assemble(preparation.clone(), vec![path])
            .unwrap_err()
            .to_string()
            .contains("signature")
    );
    wrong.key = good.key.clone();
    let mut signature = hex::decode(&wrong.signature).unwrap();
    signature[0] ^= 1;
    wrong.signature = hex::encode(signature);
    let path = approval_file(&dir, "wrong-signature.json", &wrong);
    assert!(
        assemble(preparation, vec![path])
            .unwrap_err()
            .to_string()
            .contains("signature")
    );
}

#[test]
fn assemble_sorts_valid_approvals_and_rejects_rebound_action() {
    let dir = TempDir::new().unwrap();
    let preparation = preparation(&dir);
    let first = signed_approval(&dir, &preparation);
    let second_key = dir.path().join("second.key");
    fs::write(&second_key, hex::encode([2; 32])).unwrap();
    let second = run(UpgradeApprovalArgs {
        command: UpgradeApprovalCommand::Sign {
            preparation: preparation.clone(),
            key_file: second_key,
            registration_generation: hex::encode([22; 32]),
            expected_action_id: vector()["action_id"].as_str().unwrap().to_owned(),
        },
    })
    .unwrap();
    let ApprovalOutput::Sign(second) = second else {
        panic!("unexpected signing output");
    };
    let first_path = approval_file(&dir, "first.json", &first);
    let second_path = approval_file(&dir, "second.json", &second);
    let assembled = assemble(preparation.clone(), vec![first_path, second_path]).unwrap();
    let ApprovalOutput::Assemble(assembled) = assembled else {
        panic!("unexpected assembly output");
    };
    let envelope = UpgradeControl::decode(&hex::decode(assembled.envelope_hex).unwrap()).unwrap();
    assert_eq!(envelope.approvals.len(), 2);
    assert!(envelope.approvals[0].key < envelope.approvals[1].key);

    let mut action =
        ControlAction::decode(&hex::decode(vector()["action_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    action.nonce += 1;
    let changed_id = hex::encode(action.id().unwrap());
    let changed_preparation = dir.path().join("changed-preparation.json");
    fs::write(
        &changed_preparation,
        serde_json::to_vec(&json!({
            "action_hex": hex::encode(action.encode().unwrap()),
            "action_id": changed_id.clone()
        }))
        .unwrap(),
    )
    .unwrap();
    let rebound = ApprovalFile {
        action_id: changed_id,
        key: first.key,
        generation: first.generation,
        signature: first.signature,
    };
    let rebound_path = approval_file(&dir, "rebound.json", &rebound);
    assert!(
        assemble(changed_preparation, vec![rebound_path])
            .unwrap_err()
            .to_string()
            .contains("signature")
    );
}

#[test]
fn inspect_displays_postpone_and_cancel_signed_fields() {
    let dir = TempDir::new().unwrap();
    let base =
        ControlAction::decode(&hex::decode(vector()["action_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    let ControlOperation::Schedule { manifest, .. } = &base.operation else {
        panic!("fixture must schedule");
    };
    let target = manifest.id().unwrap();
    for operation in [
        ControlOperation::Postpone {
            target,
            previous_activation: 1_108,
            activation: 1_200,
        },
        ControlOperation::Cancel {
            target,
            activation: 1_108,
        },
    ] {
        let mut action = base.clone();
        action.operation = operation;
        let preparation = dir.path().join("other-preparation.json");
        fs::write(
            &preparation,
            serde_json::to_vec(&json!({
                "action_hex": hex::encode(action.encode().unwrap()),
                "action_id": hex::encode(action.id().unwrap())
            }))
            .unwrap(),
        )
        .unwrap();
        let inspected = run(UpgradeApprovalArgs {
            command: UpgradeApprovalCommand::Inspect { preparation },
        })
        .unwrap();
        let ApprovalOutput::Inspect(inspected) = inspected else {
            panic!("unexpected inspect output");
        };
        let value = serde_json::to_value(inspected).unwrap();
        assert_eq!(
            value["operation"]["target_protocol_id"],
            hex::encode(target.0)
        );
        assert_eq!(
            value["operation"]["activation_height"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            match action.operation {
                ControlOperation::Postpone { activation, .. }
                | ControlOperation::Cancel { activation, .. } => activation,
                _ => unreachable!(),
            }
        );
    }
}

#[test]
fn key_input_is_file_only_bounded_and_never_echoed() {
    let dir = TempDir::new().unwrap();
    let preparation = preparation(&dir);
    let secret = "TOPSECRET-KEY-MATERIAL";
    let invalid_key = key_file(&dir, secret);
    let error = run(sign_args(
        preparation.clone(),
        invalid_key,
        vector()["action_id"].as_str().unwrap().to_owned(),
    ))
    .unwrap_err()
    .to_string();
    assert!(error.contains("approval key file"));
    assert!(!error.contains(secret));
    let oversized = key_file(&dir, &"x".repeat(257));
    assert!(
        run(sign_args(
            preparation.clone(),
            oversized,
            vector()["action_id"].as_str().unwrap().to_owned(),
        ))
        .unwrap_err()
        .to_string()
        .contains("byte limit")
    );
    let generation = hex::encode([21; 32]);
    let action_id = vector()["action_id"].as_str().unwrap().to_owned();
    let valid_args = vec![
        "kontor".to_owned(),
        "sign".to_owned(),
        "--preparation".to_owned(),
        preparation.to_str().unwrap().to_owned(),
        "--key-file".to_owned(),
        dir.path()
            .join("validator.key")
            .to_str()
            .unwrap()
            .to_owned(),
        "--registration-generation".to_owned(),
        generation,
        "--expected-action-id".to_owned(),
        action_id,
    ];
    assert!(Cli::try_parse_from(valid_args.clone()).is_ok());
    let mut invalid_args = valid_args;
    invalid_args.extend(["--private-key".to_owned(), secret.to_owned()]);
    assert!(Cli::try_parse_from(invalid_args).is_err());
    let approved = signed_approval(&dir, &preparation);
    let serialized = serde_json::to_string(&approved).unwrap();
    assert!(!serialized.contains(&hex::encode([1; 32])));
}
