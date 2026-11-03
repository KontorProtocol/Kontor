use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::path::PathBuf;

mod build;
pub mod capture;
mod chains;
pub mod comparison;
mod probes;
pub mod smoke;

pub const REPORT_PREFIX: &str = "KONTOR_STACK_REPORT:";
pub const SUMMARY_PREFIX: &str = "KONTOR_STACK_SWEEP_SUMMARY:";
pub const CACHE_MODE: &str = "warm_compiled_cache";
pub const IDENTITY_FIELDS: &[&str] = &["role", "sample_index", "sample_id"];
pub const SWEEP_FIELDS: &[&str] = &[
    "role",
    "sample_index",
    "sample_id",
    "cache_mode",
    "fixture_contracts",
    "reset",
    "call_hook_installed",
];

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    FeaturePolicy,
    Compare {
        directory: PathBuf,
        upstream_status: String,
        source_sha: Option<String>,
        lockfile_sha256: Option<String>,
        component_hashes: Option<Value>,
        profiles: String,
    },
    Chains {
        chains: Value,
        target_os: String,
        target_arch: String,
    },
    OwnedChains {
        owned_chains: Value,
        chains: Value,
        target_os: String,
        target_arch: String,
    },
    BuildProvenance {
        report: Value,
        directory: PathBuf,
        binary: String,
    },
    SmokeTest {
        raw: String,
        name: String,
    },
    SmokeReport {
        path: PathBuf,
        cell: String,
        target: String,
        source_sha: String,
        lockfile_sha256: String,
    },
    SmokeSet {
        directory: PathBuf,
        source_sha: String,
        lockfile_sha256: String,
    },
    ParseSweep {
        raw: String,
        kind: String,
        role: String,
    },
    SweepPair {
        worker: Vec<Value>,
        worker_summary: Value,
        control: Vec<Value>,
        control_summary: Value,
    },
}

pub fn run(request: Request) -> Result<Value> {
    match request {
        Request::FeaturePolicy => Ok(json!({
            "production": build::expected_features("production"),
            "qualification": build::expected_features("qualification"),
        })),
        Request::Compare {
            directory,
            upstream_status,
            source_sha,
            lockfile_sha256,
            component_hashes,
            profiles,
        } => comparison::compare(
            &directory,
            &upstream_status,
            source_sha.as_deref(),
            lockfile_sha256.as_deref(),
            component_hashes.as_ref(),
            &profiles,
        ),
        Request::Chains {
            chains,
            target_os,
            target_arch,
        } => chains::validate(&chains, &target_os, &target_arch),
        Request::OwnedChains {
            owned_chains,
            chains,
            target_os,
            target_arch,
        } => chains::validate_owned(&owned_chains, &chains, &target_os, &target_arch),
        Request::BuildProvenance {
            report,
            directory,
            binary,
        } => {
            build::validate(&report, &directory, &binary)?;
            Ok(Value::Null)
        }
        Request::SmokeTest { raw, name } => {
            smoke::validate_test(&raw, &name)?;
            Ok(Value::Null)
        }
        Request::SmokeReport {
            path,
            cell,
            target,
            source_sha,
            lockfile_sha256,
        } => smoke::validate_report(&path, &cell, &target, &source_sha, &lockfile_sha256),
        Request::SmokeSet {
            directory,
            source_sha,
            lockfile_sha256,
        } => smoke::validate_set(&directory, &source_sha, &lockfile_sha256),
        Request::ParseSweep { raw, kind, role } => {
            let (observations, summary) = parse_sweep(&raw, &kind, &role)?;
            Ok(json!([observations, summary]))
        }
        Request::SweepPair {
            worker,
            worker_summary,
            control,
            control_summary,
        } => {
            validate_pair(&worker, &worker_summary, &control, &control_summary)?;
            Ok(Value::Null)
        }
    }
}

fn reset(sample: &Value, baseline: &str) -> Result<()> {
    let reset = sample["reset"]
        .as_object()
        .context("missing sweep reset evidence")?;
    ensure!(
        reset.len() == 2 && reset.contains_key("pre") && reset.contains_key("post"),
        "missing sweep reset evidence"
    );
    let pre = reset["pre"]
        .as_object()
        .context("invalid sweep reset evidence")?;
    let post = reset["post"]
        .as_object()
        .context("invalid sweep reset evidence")?;
    let count = pre
        .get("baseline_resource_count")
        .and_then(Value::as_u64)
        .context("invalid baseline resources")?;
    for stage in [pre, post] {
        ensure!(
            stage.get("live_invocations").and_then(Value::as_u64) == Some(0),
            "sweep leaked invocation leases"
        );
        ensure!(
            stage.get("stack_empty").and_then(Value::as_bool) == Some(true),
            "sweep leaked call frames"
        );
        ensure!(
            stage.get("resource_count").and_then(Value::as_u64) == Some(count),
            "sweep leaked resources"
        );
    }
    ensure!(
        pre.get("savepoint_intact") == Some(&Value::Bool(true)),
        "call changed the harness savepoint"
    );
    let expected = if sample["outcome"] == "ok" {
        Value::Null
    } else {
        Value::Bool(true)
    };
    ensure!(
        pre.get("failure_rolled_back") == Some(&expected),
        "call rollback was not established before reset"
    );
    for field in [
        "digest_matches",
        "savepoint_restored",
        "balances_restored",
        "floor_restored",
        "supply_restored",
    ] {
        ensure!(
            post.get(field) == Some(&Value::Bool(true)),
            "sweep reset failed: {field}"
        );
    }
    for field in ["persistent_digest_sha256", "baseline_digest_sha256"] {
        ensure!(
            post.get(field).and_then(Value::as_str) == Some(baseline),
            "sweep persistent state was not restored"
        );
    }
    Ok(())
}

pub fn parse_sweep(raw: &str, kind: &str, role: &str) -> Result<(Vec<Value>, Value)> {
    let mut observations: Vec<Value> = Vec::new();
    let mut summary: Option<Value> = None;
    let mut terminal = false;
    for line in raw.lines() {
        if let Some(record) = line.strip_prefix(REPORT_PREFIX) {
            ensure!(summary.is_none(), "sample appeared after sweep summary");
            observations.push(serde_json::from_str(record)?);
        }
        if let Some(record) = line.strip_prefix(SUMMARY_PREFIX) {
            ensure!(summary.is_none(), "duplicate sweep summary");
            summary = Some(serde_json::from_str(record)?);
        }
        if line.starts_with("test result:") {
            ensure!(
                summary.is_some() && !terminal,
                "unexpected sweep test completion"
            );
            ensure!(
                line.starts_with("test result: ok. 1 passed; 0 failed;"),
                "sweep test did not succeed"
            );
            terminal = true;
        }
    }
    let summary = summary.context("incomplete sweep transcript")?;
    ensure!(
        summary.is_object() && terminal,
        "incomplete sweep transcript"
    );
    ensure!(
        !observations.is_empty() && observations.len() <= 128,
        "invalid sweep sample count"
    );
    let contracts = if kind == "paid_reenter" { 65 } else { 1 };
    for (field, expected) in [
        ("role", json!(role)),
        ("kind", json!(kind)),
        ("cache_mode", json!(CACHE_MODE)),
        ("fixture_contracts", json!(contracts)),
    ] {
        ensure!(
            summary.get(field) == Some(&expected),
            "sweep summary has wrong {field}"
        );
        ensure!(
            observations
                .iter()
                .all(|sample| sample.is_object() && sample.get(field) == Some(&expected)),
            "sweep sample has wrong {field}"
        );
    }
    let baseline = summary["baseline_digest_sha256"]
        .as_str()
        .context("invalid sweep baseline digest")?;
    ensure!(
        baseline.len() == 64
            && baseline
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid sweep baseline digest"
    );
    let indices: Vec<usize> = (0..observations.len()).collect();
    let ids: Vec<String> = indices
        .iter()
        .map(|i| format!("{role}:{kind}:{i:04}"))
        .collect();
    ensure!(
        summary["ordered_sample_indices"] == json!(indices),
        "sweep index sequence mismatch"
    );
    ensure!(
        summary["ordered_sample_ids"] == json!(ids),
        "sweep sample ID sequence mismatch"
    );
    let mut depths = Vec::new();
    for (index, sample) in observations.iter().enumerate() {
        ensure!(
            sample["sample_index"].as_u64() == Some(index as u64),
            "duplicate or out-of-order sweep sample"
        );
        ensure!(
            sample["sample_id"] == ids[index],
            "invalid sweep sample identity"
        );
        depths.push(sample["depth"].as_u64().context("invalid sweep depth")?);
        ensure!(
            matches!(
                sample["outcome"].as_str(),
                Some("ok" | "stack_overflow" | "invocation_limit")
            ),
            "sweep process or execution failed"
        );
        ensure!(
            sample["call_hook_installed"] == false,
            "sweep enabled a test-only call hook"
        );
        reset(sample, baseline)?;
    }
    let boundaries = summary["boundaries"]
        .as_object()
        .context("missing sweep boundaries")?;
    if kind == "paid_huge" {
        ensure!(
            summary["boundaries"] == json!({"bounded_depth": 0}) && depths == [0],
            "invalid bounded sweep"
        );
    } else {
        let success = boundaries
            .get("last_success")
            .and_then(Value::as_u64)
            .context("invalid sweep boundary")?;
        let failure = boundaries
            .get("first_failure")
            .and_then(Value::as_u64)
            .context("invalid sweep boundary")?;
        ensure!(
            success.checked_add(1) == Some(failure),
            "invalid sweep boundary"
        );
        let expected = if kind == "paid_reenter" {
            "invocation_limit"
        } else {
            "stack_overflow"
        };
        ensure!(
            boundaries
                .get("first_failure_outcome")
                .and_then(Value::as_str)
                == Some(expected),
            "invalid sweep boundary outcome"
        );
        if role == "control" {
            ensure!(
                depths == [success, failure],
                "control must exercise both boundary depths in order"
            );
        } else if kind == "paid_reenter" {
            ensure!((success, failure) == (63, 64), "invalid reentry boundary");
            ensure!(
                depths == [62, 63, 64, 64, 63, 62, 62, 63, 64],
                "invalid reentry sweep order"
            );
        } else {
            ensure!(depths[0] == 0, "recursion discovery must start at zero");
            ensure!(
                depths.ends_with(&[success, failure, failure, success, success, failure]),
                "missing forward/reverse boundary repeats"
            );
        }
        for (sample, depth) in observations.iter().zip(depths) {
            ensure!(
                sample["outcome"] == if depth <= success { "ok" } else { expected },
                "sweep sample contradicts its boundary"
            );
        }
    }
    Ok((observations, summary))
}

fn semantics(sample: &Value) -> Result<Map<String, Value>> {
    let object = sample
        .as_object()
        .context("sweep observation must be an object")?;
    Ok(object
        .iter()
        .filter(|(key, _)| {
            !IDENTITY_FIELDS.contains(&key.as_str())
                && !["log", "target_os", "target_arch", "error"].contains(&key.as_str())
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

// Both inputs have already passed transcript validation. Keep the raw observations
// intact so later artifact validators can bind them to their original log bytes.
pub fn validate_pair(
    worker: &[Value],
    worker_summary: &Value,
    control: &[Value],
    control_summary: &Value,
) -> Result<()> {
    for field in [
        "boundaries",
        "baseline_digest_sha256",
        "cache_mode",
        "fixture_contracts",
        "kind",
    ] {
        let expected = worker_summary
            .get(field)
            .context("missing sweep summary field")?;
        ensure!(
            control_summary.get(field) == Some(expected),
            "fresh control differs: {field}"
        );
    }
    let candidates = worker.iter().map(semantics).collect::<Result<Vec<_>>>()?;
    for sample in control {
        ensure!(
            candidates.contains(&semantics(sample)?),
            "fresh control execution differs"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
