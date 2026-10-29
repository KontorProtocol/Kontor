use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::super::{capture, hash_file};

// A typed source object rejects duplicate and unknown nested fields instead of
// silently accepting the last value as serde_json::Value would.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceIdentity {
    git_head_log: String,
    git_status_log: String,
    embedded_source_commit: String,
    rustc_verbose: String,
    target: String,
    profile: String,
    features: Vec<String>,
    core_lockfile_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayRun {
    schema_version: u32,
    fixture_manifest_sha256: String,
    expected_consumer_source: SourceIdentity,
    expected_consumer_binary_sha256: String,
    run_label: String,
}

impl ReplayRun {
    fn parse(bytes: &[u8], fixture_digest: &str) -> Result<Self> {
        let run: Self = serde_json::from_slice(bytes)?;
        ensure!(run.schema_version == 1, "unsupported replay run schema");
        ensure!(
            run.fixture_manifest_sha256 == fixture_digest,
            "replay run fixture binding differs"
        );
        ensure!(!run.run_label.trim().is_empty(), "empty replay run label");
        Ok(run)
    }
}

pub(super) struct ReplayIdentity {
    consumer_source: Value,
    consumer_binary: String,
    evidence: Value,
}

impl ReplayIdentity {
    pub(super) fn load(
        fixture_root: &Path,
        fixture_digest: &str,
        producer_source: &Value,
        producer_binary: &str,
    ) -> Result<Self> {
        let path = env::var_os("KONTOR_WORKLOAD_REPLAY_RUN");
        let digest = env::var_os("KONTOR_WORKLOAD_REPLAY_RUN_SHA256");
        let (consumer_source, consumer_binary, run_evidence) = match (path, digest) {
            (None, None) => (
                producer_source.clone(),
                producer_binary.to_owned(),
                Value::Null,
            ),
            (Some(path), Some(digest)) => {
                let path = PathBuf::from(path).canonicalize()?;
                ensure!(
                    path.is_file() && !path.starts_with(fixture_root),
                    "replay run must be a file outside the fixture directory"
                );
                let digest = digest
                    .into_string()
                    .map_err(|_| anyhow!("replay run digest is not UTF-8"))?;
                let bytes = fs::read(&path)?;
                ensure!(
                    hex::encode(Sha256::digest(&bytes)) == digest,
                    "replay run manifest hash differs"
                );
                let run = ReplayRun::parse(&bytes, fixture_digest)?;
                (
                    serde_json::to_value(run.expected_consumer_source)?,
                    run.expected_consumer_binary_sha256,
                    json!({"manifest_sha256": digest, "run_label": run.run_label}),
                )
            }
            _ => return Err(anyhow!("replay run path and digest must both be supplied")),
        };
        let identity = Self {
            evidence: json!({
                "fixture_manifest_sha256": fixture_digest,
                "producer_source": producer_source,
                "producer_binary_sha256": producer_binary,
                "consumer_source": consumer_source,
                "consumer_binary_sha256": consumer_binary,
                "explicit_run": run_evidence,
                "qualification_claim": "identity binding only; label does not establish engine or performance qualification",
            }),
            consumer_source,
            consumer_binary,
        };
        identity.verify()?;
        Ok(identity)
    }

    pub(super) fn verify(&self) -> Result<()> {
        ensure!(
            hash_file(&env::current_exe()?)? == self.consumer_binary,
            "saved workload binary differs"
        );
        ensure!(
            capture::source()? == self.consumer_source,
            "saved workload source/build differs"
        );
        Ok(())
    }

    pub(super) fn finish(&self) -> Result<()> {
        self.verify()
            .context("consumer identity changed during replay")?;
        eprintln!("workload_replay_identity={}", self.evidence);
        Ok(())
    }
}

#[test]
fn replay_run_rejects_ambiguous_identity() -> Result<()> {
    let source = json!({
        "git_head_log":"head\n", "git_status_log":"", "embedded_source_commit":"head",
        "rustc_verbose":"compiler", "target":"target", "profile":"dev", "features":[],
        "core_lockfile_sha256":"lock",
    });
    let valid = serde_json::to_string(&json!({
        "schema_version":1, "fixture_manifest_sha256":"fixture",
        "expected_consumer_source":source, "expected_consumer_binary_sha256":"binary",
        "run_label":"candidate",
    }))?;
    ReplayRun::parse(valid.as_bytes(), "fixture")?;
    for invalid in [
        valid.replace("\"schema_version\":1", "\"schema_version\":2"),
        valid.replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        ),
        valid.replace(
            "\"profile\":\"dev\"",
            "\"profile\":\"dev\",\"profile\":\"dev\"",
        ),
        valid.replace("\"profile\":\"dev\"", "\"profile\":\"dev\",\"unknown\":0"),
        valid.replace("\"run_label\":\"candidate\"", "\"run_label\":\" \""),
        valid.replace("\"schema_version\":1", "\"schema_version\":1,\"unknown\":0"),
    ] {
        ensure!(ReplayRun::parse(invalid.as_bytes(), "fixture").is_err());
    }
    ensure!(ReplayRun::parse(valid.as_bytes(), "different fixture").is_err());
    Ok(())
}
