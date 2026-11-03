use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, ensure};
use clap::Args;
use serde_json::{Map, Value, json};

use super::build::{self, FEATURE_LOGS, FORK_REVISION, artifact_file, hex_digest};
use super::probes::{self, CASES, fields, string};
use super::{chains, smoke};
use crate::container::sha256;
use crate::toolchain::output as command_output;
use crate::write_json;

pub(super) const OWNERSHIP_TESTS: &[&str] = &[
    "canonical_lease_drains_native_guest_before_releasing_runtime",
    "canonical_and_simulation_children_keep_no_yield_policy",
    "nested_api_children_inherit_actual_fuel_yields",
    "cancelling_nested_yielding_api_guest_joins_before_runtime_reuse",
    "cancelling_fuel_yielding_guest_joins_before_pool_reuse",
];
const PLATFORMS: &[(&str, &str, &str, &str)] = &[
    ("macos-15", "macOS-ARM64", "macos", "aarch64"),
    ("ubuntu-24.04", "Linux-X64", "linux", "x86_64"),
    ("ubuntu-24.04-arm", "Linux-ARM64", "linux", "aarch64"),
];
const REPORT_FIELDS: &[&str] = &[
    "schema_version",
    "cell",
    "source_sha",
    "lockfile_sha256",
    "wasmtime_revision",
    "binary",
    "binary_sha256",
    "rustc_version_verbose",
    "host",
    "cases",
    "chains",
    "chain_log",
    "owned_chains",
    "owned_chain_log",
    "ownership_log",
    "log_sha256",
    "wasmtime_features",
    "feature_logs",
    "cargo_log",
];

pub(super) fn report(path: &Path, cell: &str, os: &str, arch: &str) -> Result<(Value, Value)> {
    let directory = path.parent().context("missing report parent")?;
    let path = artifact_file(directory, "qualification.json")?;
    let report: Value = serde_json::from_slice(&fs::read(path)?)?;
    fields(&report, REPORT_FIELDS)?;
    ensure!(
        report["schema_version"].as_u64() == Some(6) && report["cell"] == cell,
        "mislabeled report"
    );
    for (field, len) in [
        ("source_sha", 40),
        ("lockfile_sha256", 64),
        ("binary_sha256", 64),
    ] {
        ensure!(hex_digest(&report[field], len), "invalid {field}");
    }
    let binary = string(&report["binary"])?;
    let profile = if cell.ends_with("/release") {
        "release"
    } else {
        "debug"
    };
    ensure!(
        Path::new(binary)
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("indexer-"))
            && Path::new(binary)
                .components()
                .any(|p| p.as_os_str() == profile),
        "invalid binary provenance"
    );
    ensure!(report["wasmtime_revision"] == FORK_REVISION, "wrong fork");
    build::validate(&report, directory, binary)?;
    ensure!(
        string(&report["rustc_version_verbose"])?
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            == ["rustc", "1.99.1"],
        "wrong compiler"
    );
    ensure!(!string(&report["host"])?.is_empty(), "missing host");
    let cases = report["cases"].as_array().context("invalid cases")?;
    let kinds = cases
        .iter()
        .map(|case| string(&case["kind"]))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        cases.len() == CASES.len() && kinds == CASES.iter().copied().collect(),
        "missing or duplicate case"
    );
    let mut normalized = BTreeMap::new();
    let mut owned = BTreeMap::new();
    let mut logs = BTreeSet::new();
    for case in cases {
        let kind = string(&case["kind"])?;
        normalized.insert(kind, probes::validate_case(case, os, arch, directory)?);
        owned.insert(kind, probes::validate_owned(case, directory)?);
        for samples in ["observations", "control_observations"] {
            for sample in case[samples].as_array().context("missing observations")? {
                ensure!(
                    logs.insert(string(&sample["log"])?.to_owned()),
                    "duplicate probe sample log"
                );
            }
        }
        for field in ["worker_log", "control_log", "owned_log"] {
            ensure!(
                logs.insert(string(&case[field])?.to_owned()),
                "duplicate probe sample log"
            );
        }
    }
    for (field, key, prefix) in [
        ("chain_log", "chains", "CHAIN_PROBE_REPORT:"),
        (
            "owned_chain_log",
            "owned_chains",
            "CHAIN_OWNED_PROBE_REPORT:",
        ),
    ] {
        ensure!(
            logs.insert(string(&report[field])?.to_owned()),
            "duplicate chain log"
        );
        ensure!(
            json!(probes::reports(directory, &report[field], prefix)?) == report[key],
            "raw chain log disagrees with report"
        );
    }
    let lifecycle = string(&report["ownership_log"])?;
    ensure!(
        logs.insert(lifecycle.to_owned()),
        "duplicate ownership lifecycle log"
    );
    let raw = fs::read_to_string(artifact_file(directory, lifecycle)?)?;
    let summaries: Vec<_> = raw
        .lines()
        .filter(|s| s.starts_with("test result:"))
        .collect();
    ensure!(
        summaries.len() == OWNERSHIP_TESTS.len()
            && summaries
                .iter()
                .all(|s| s.starts_with("test result: ok. 1 passed;")),
        "ownership lifecycle controls incomplete"
    );
    for test in OWNERSHIP_TESTS {
        let expected = format!("test runtime::ownership::tests::{test} ... ok");
        ensure!(
            raw.lines().filter(|s| *s == expected).count() == 1,
            "ownership lifecycle control missing or duplicated: {test}"
        );
    }
    ensure!(
        logs.insert(string(&report["cargo_log"])?.to_owned()),
        "duplicate Cargo log"
    );
    for (_, name) in FEATURE_LOGS {
        ensure!(logs.insert((*name).to_owned()), "duplicate feature log");
    }
    let manifest = report["log_sha256"]
        .as_object()
        .context("incomplete raw log manifest")?;
    ensure!(
        manifest.keys().cloned().collect::<BTreeSet<_>>() == logs,
        "incomplete raw log manifest"
    );
    for (name, digest) in manifest {
        ensure!(hex_digest(digest, 64), "invalid raw log hash");
        ensure!(
            *digest == sha256(&artifact_file(directory, name)?)?,
            "raw log hash mismatch"
        );
    }
    let chain = chains::validate(&report["chains"], os, arch)?;
    let owned_chain = chains::validate_owned(&report["owned_chains"], &report["chains"], os, arch)?;
    let validated =
        json!({"probes":normalized,"owned_probes":owned,"chains":chain,"owned_chains":owned_chain});
    Ok((report, validated))
}

pub fn compare(
    directory: &Path,
    upstream_status: &str,
    source: Option<&str>,
    lock: Option<&str>,
    components: Option<&Value>,
    profiles: &str,
) -> Result<Value> {
    ensure!(
        upstream_status == "success",
        "upstream qualification jobs: {upstream_status}"
    );
    ensure!(
        ["release", "full"].contains(&profiles),
        "unknown qualification profile policy"
    );
    let mut expected = BTreeMap::new();
    for (runner, cell, os, arch) in PLATFORMS {
        for profile in ["dev", "release"] {
            if profiles == "release" && profile == "dev" {
                continue;
            }
            expected.insert(
                format!("native-stack-{runner}-{profile}"),
                (format!("{cell}/{profile}"), *os, *arch),
            );
        }
    }
    let root = directory.canonicalize()?;
    let mut found = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.path().is_dir() {
            ensure!(
                entry.path().canonicalize()?.starts_with(&root),
                "cell directory escapes archive"
            );
            found.insert(
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow!("invalid artifact name"))?,
            );
        }
    }
    ensure!(
        found == expected.keys().cloned().collect(),
        "cell keys differ"
    );
    let mut reports = BTreeMap::new();
    let mut cases = BTreeMap::new();
    for (artifact, (cell, os, arch)) in expected {
        let (report, normalized) = report(
            &directory.join(artifact).join("qualification.json"),
            &cell,
            os,
            arch,
        )?;
        reports.insert(cell.clone(), report);
        cases.insert(cell, normalized);
    }
    let first = reports
        .values()
        .next()
        .context("missing qualification cells")?;
    for value in reports.values() {
        ensure!(
            value["source_sha"] == first["source_sha"],
            "source heads differ"
        );
        ensure!(
            value["lockfile_sha256"] == first["lockfile_sha256"],
            "lockfiles differ"
        );
        if let Some(source) = source {
            ensure!(
                value["source_sha"] == source,
                "reports are stale for this source head"
            );
        }
        if let Some(lock) = lock {
            ensure!(
                value["lockfile_sha256"] == lock,
                "reports are stale for this lockfile"
            );
        }
    }
    let mut hashes = BTreeSet::new();
    for value in reports.values() {
        for case in value["cases"].as_array().unwrap() {
            for sample in case["observations"].as_array().unwrap() {
                hashes.insert(string(&sample["component_sha256"])?);
            }
        }
    }
    ensure!(hashes.len() == 1, "component binaries differ");
    let component = hashes
        .into_iter()
        .next()
        .context("missing component hash")?;
    if let Some(components) = components {
        ensure!(
            components["stack_probe"] == component,
            "stack probe differs from source artifact"
        );
        fields(components, &["error_test", "proxy"])?;
        let chain_hashes = probes::select(components, &["error_test", "proxy"]);
        for value in reports.values() {
            for chain in value["chains"].as_array().unwrap() {
                ensure!(
                    chain["component_sha256"] == chain_hashes,
                    "chain probes differ from source artifacts"
                );
            }
        }
    }
    let baseline = cases.values().next().context("missing normalized cases")?;
    ensure!(
        cases.values().all(|v| v == baseline),
        "cross-cell observations differ"
    );
    Ok(
        json!({"schema_version":6,"cells":reports.keys().collect::<Vec<_>>(),"profile_policy":profiles,
        "source_sha":first["source_sha"],"lockfile_sha256":first["lockfile_sha256"],"wasmtime_revision":FORK_REVISION,
        "wasmtime_features":first["wasmtime_features"],"component_sha256":component,"cases":baseline}),
    )
}

#[derive(Args)]
pub struct CompareStackArgs {
    #[arg(long)]
    pub directory: PathBuf,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long)]
    pub upstream_status: String,
    #[arg(long, default_value="full", value_parser=["release","full"])]
    pub profiles: String,
    #[arg(long)]
    pub smoke_directory: Option<PathBuf>,
    #[arg(long, default_value = "core/Cargo.lock")]
    pub lockfile: PathBuf,
}

pub fn compare_stack(root: &Path, args: CompareStackArgs) -> Result<Value> {
    let path = root.join(&args.output);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    let source = command_output(root, Path::new("git"), &["rev-parse", "HEAD"], None)?
        .trim()
        .to_owned();
    let lock = sha256(&root.join(&args.lockfile))?;
    let mut components = Map::new();
    for name in ["stack_probe", "error_test", "proxy"] {
        components.insert(
            name.to_owned(),
            json!(sha256(
                &root.join(format!("test-contracts/binaries/{name}.wasm.br"))
            )?),
        );
    }
    let mut result = compare(
        &root.join(args.directory),
        &args.upstream_status,
        Some(&source),
        Some(&lock),
        Some(&Value::Object(components)),
        &args.profiles,
    )?;
    if args.profiles == "release" {
        let smoke = args
            .smoke_directory
            .context("release policy requires dev smoke evidence")?;
        result["dev_smoke"] = smoke::validate_set(&root.join(smoke), &source, &lock)?;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_json(&path, &result)?;
    Ok(result)
}

#[cfg(test)]
pub(super) mod tests;
