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
        .context("required checks job")?
        .split("  docker-cache-deps:")
        .next()
        .unwrap();
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
    let mut needs = json!({"scope":{"result":"success","outputs":{"rust":"false","sdk":"false","reproducible":"false"}},
        "quality-checks":{"result":"skipped"},"test":{"result":"skipped"},
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
    needs["scope"]["result"] = json!("failure");
    assert!(!passes(&needs)?);
    Ok(())
}

#[test]
fn main_image_publication_is_not_gated_by_pr_scope() -> Result<()> {
    let workflow = fs::read_to_string(repository().join(".github/workflows/ci.yml"))?;
    let cache = workflow
        .split("  docker-cache-deps:\n")
        .nth(1)
        .context("image cache")?
        .split("  docker-build:")
        .next()
        .unwrap();
    assert!(!cache.contains("    needs:"));
    assert!(workflow.contains("    needs: docker-cache-deps\n"));
    let docker = fs::read_to_string(repository().join(".github/workflows/docker-cache.yml"))?;
    assert!(docker.contains("  pull_request:\n  workflow_dispatch:"));
    Ok(())
}
