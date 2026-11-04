use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use tempfile::tempdir;

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned()
}

#[test]
fn cli_emits_machine_readable_selection_and_preserves_existing_outputs() -> Result<()> {
    let root = tempdir()?;
    let event = root.path().join("event.json");
    let output = root.path().join("output");
    fs::write(&event, r#"{"inputs":{"profiles":"full"}}"#)?;
    fs::write(&output, "existing=preserved\n")?;
    let result = Command::new(env!("CARGO_BIN_EXE_kontor-build"))
        .current_dir(repository())
        .args(["ci-scope", "bundles"])
        .env("GITHUB_EVENT_NAME", "workflow_dispatch")
        .env("GITHUB_EVENT_PATH", &event)
        .env("GITHUB_OUTPUT", &output)
        .output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report["required"], true);
    assert_eq!(report["profile_policy"], "full");
    assert_eq!(
        fs::read_to_string(&output)?,
        "existing=preserved\ncontrols=true\nprofile_policy=full\nrequired=true\n"
    );
    fs::write(&event, r#"{"inputs":{"profiles":"typo"}}"#)?;
    let previous = fs::read(&output)?;
    let result = Command::new(env!("CARGO_BIN_EXE_kontor-build"))
        .current_dir(repository())
        .args(["ci-scope", "stack"])
        .env("GITHUB_EVENT_NAME", "workflow_dispatch")
        .env("GITHUB_EVENT_PATH", event)
        .env("GITHUB_OUTPUT", &output)
        .output()?;
    assert!(!result.status.success());
    assert_eq!(fs::read(output)?, previous);
    Ok(())
}

#[test]
fn actual_required_check_gate_rejects_failed_cancelled_missing_or_unselected_success() -> Result<()>
{
    let workflow = fs::read_to_string(repository().join(".github/workflows/ci.yml"))?;
    let gate = workflow
        .split("  required-checks:\n")
        .nth(1)
        .context("required checks job")?;
    assert!(gate.contains("    if: always()\n"));
    let expression = gate
        .split("jq -e '")
        .nth(1)
        .context("jq gate")?
        .split("' <<<\"$NEEDS\"")
        .next()
        .context("gate expression")?;
    let passes = |needs: &Value| -> Result<bool> {
        let mut process = Command::new("jq")
            .args(["-e", expression])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        process
            .stdin
            .take()
            .context("jq stdin")?
            .write_all(&serde_json::to_vec(needs)?)?;
        Ok(process.wait_with_output()?.status.success())
    };
    let mut needs = json!({"scope":{"result":"success","outputs":{"rust":"false","tests":"false","tooling":"false","sdk":"false","reproducible":"false"}},
        "quality-checks":{"result":"skipped"},"test":{"result":"skipped"},
        "tooling":{"result":"skipped"},
        "reproducible-build-setup":{"result":"skipped"},"reproducible-build":{"result":"skipped"},"sdk":{"result":"skipped"}});
    assert!(passes(&needs)?);
    needs["sdk"]["result"] = json!("success");
    assert!(!passes(&needs)?);
    needs["scope"]["outputs"]["sdk"] = json!("true");
    assert!(passes(&needs)?);
    for state in [
        json!("failure"),
        json!("cancelled"),
        json!("skipped"),
        Value::Null,
    ] {
        needs["sdk"]["result"] = state;
        assert!(!passes(&needs)?);
    }
    needs["sdk"]["result"] = json!("success");
    for state in [json!(""), json!(true), Value::Null] {
        needs["scope"]["outputs"]["rust"] = state;
        assert!(!passes(&needs)?);
    }
    needs["scope"]["outputs"]["rust"] = json!("false");
    for flag in ["tests", "tooling"] {
        needs["scope"]["outputs"][flag] = json!("true");
        let job = if flag == "tests" { "test" } else { "tooling" };
        for state in [
            json!("failure"),
            json!("cancelled"),
            json!("skipped"),
            Value::Null,
        ] {
            needs[job]["result"] = state;
            assert!(!passes(&needs)?);
        }
        needs[job]["result"] = json!("success");
        assert!(passes(&needs)?);
        needs["scope"]["outputs"][flag] = Value::Null;
        assert!(!passes(&needs)?);
        needs["scope"]["outputs"][flag] = json!("false");
        needs[job]["result"] = json!("skipped");
    }
    needs["scope"]["result"] = json!("failure");
    assert!(!passes(&needs)?);
    Ok(())
}

#[test]
fn image_publication_is_explicit_and_requires_both_architectures() -> Result<()> {
    let workflow = fs::read_to_string(repository().join(".github/workflows/ci.yml"))?;
    assert!(!workflow.contains("docker/build-push-action"));
    let publication = fs::read_to_string(repository().join(".github/workflows/docker-image.yml"))?;
    assert!(publication.contains("    tags: ['v*']\n  workflow_dispatch:"));
    assert!(!publication.contains("  pull_request:"));
    assert!(!publication.contains("    branches:"));
    assert!(publication.contains("    timeout-minutes: 90\n"));
    assert!(publication.contains("            platform: linux/amd64\n"));
    assert!(publication.contains("            platform: linux/arm64\n"));
    let manifest = publication
        .split("  docker-manifest:\n")
        .nth(1)
        .context("manifest job")?;
    assert!(manifest.contains("    needs: docker-build\n"));
    assert!(!manifest.contains("if: always()"));
    assert!(manifest.contains("type=sha,prefix=sha-"));
    assert!(
        manifest
            .contains("type=semver,pattern={{version}},enable=${{ github.event_name == 'push' }}")
    );
    assert!(!manifest.contains("type=raw,value=latest"));
    let docker = fs::read_to_string(repository().join(".github/workflows/docker-cache.yml"))?;
    assert!(docker.contains("  pull_request:\n  workflow_dispatch:"));
    Ok(())
}
