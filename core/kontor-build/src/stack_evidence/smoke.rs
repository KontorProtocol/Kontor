use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::{Value, json};

use super::build::{
    self, FEATURE_LOGS, FORK_REVISION, artifact_file, feature_logs, hex_digest, resolve_features,
    source_identity,
};
use super::test_group;
use crate::container::sha256;
use crate::toolchain::{Environment, output as command_output};
use crate::write_json;

pub const TESTS: &[&str] = &[
    "runtime::ownership::tests::owned_paid_call_matches_direct_value_fuel_receipt_and_settlement",
    "runtime::ownership::tests::canonical_and_simulation_children_keep_no_yield_policy",
    "runtime::ownership::tests::nested_api_children_inherit_actual_fuel_yields",
    "runtime::ownership::tests::cancelling_nested_yielding_api_guest_joins_before_runtime_reuse",
    "runtime::ownership::tests::cancelling_fuel_yielding_guest_joins_before_pool_reuse",
    "runtime::ownership::tests::canonical_drain_waits_for_supervisor_runtime_release",
    "runtime::sequential_tests::invocation_budget_counts_the_root_and_releases_each_store",
    "runtime::call::tests::guest_memory::published_nested_calls_share_and_release_memory_across_cold_and_warm_loads",
];
pub const CELLS: &[(&str, &str, &str)] = &[
    (
        "native-smoke-macOS-ARM64",
        "macOS-ARM64/dev",
        "aarch64-apple-darwin",
    ),
    (
        "native-smoke-Linux-X64",
        "Linux-X64/dev",
        "x86_64-unknown-linux-gnu",
    ),
    (
        "native-smoke-Linux-ARM64",
        "Linux-ARM64/dev",
        "aarch64-unknown-linux-gnu",
    ),
];

pub fn validate_test(raw: &str, name: &str) -> Result<()> {
    test_group::validate(raw, &[name])
}

pub fn validate_report(
    path: &Path,
    cell: &str,
    target: &str,
    source: &str,
    lock: &str,
) -> Result<Value> {
    let directory = path
        .parent()
        .context("smoke report has no parent directory")?;
    let path = artifact_file(
        directory,
        path.file_name()
            .and_then(|p| p.to_str())
            .context("invalid report filename")?,
    )?;
    let report: Value = serde_json::from_slice(&fs::read(&path)?)?;
    ensure!(
        report["schema_version"].as_u64() == Some(2) && report["cell"] == cell,
        "wrong dev smoke cell"
    );
    ensure!(
        report["source_sha"] == source && report["lockfile_sha256"] == lock,
        "stale dev smoke source or lockfile"
    );
    ensure!(
        report["wasmtime_revision"] == FORK_REVISION,
        "wrong dev smoke fork"
    );
    ensure!(
        hex_digest(&report["binary_sha256"], 64),
        "invalid smoke binary hash"
    );
    let binary = report["binary"].as_str().context("invalid smoke binary")?;
    ensure!(
        Path::new(binary)
            .file_name()
            .and_then(|p| p.to_str())
            .is_some_and(|p| p.starts_with("indexer-"))
            && Path::new(binary)
                .components()
                .any(|part| part.as_os_str() == "debug"),
        "smoke is not a dev test binary"
    );
    let compiler = report["rustc_version_verbose"]
        .as_str()
        .context("missing smoke compiler")?;
    ensure!(
        compiler.split_whitespace().take(2).collect::<Vec<_>>() == ["rustc", "1.99.1"],
        "wrong smoke compiler"
    );
    ensure!(
        compiler
            .lines()
            .any(|line| line == format!("host: {target}")),
        "wrong smoke compiler host"
    );
    let artifact = build::validate(&report, directory, binary)?;
    ensure!(
        artifact["profile"]["debug_assertions"] == true,
        "smoke binary lacks debug assertions"
    );
    let tests = report["tests"]
        .as_object()
        .context("missing dev smoke tests")?;
    ensure!(
        tests.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == TESTS.iter().copied().collect(),
        "missing or extra dev smoke test"
    );
    let mut expected_logs: BTreeSet<_> = ["tests.log".to_owned()].into_iter().collect();
    expected_logs.insert("cargo.json".into());
    expected_logs.extend(FEATURE_LOGS.iter().map(|(_, log)| (*log).to_owned()));
    let logs = report["log_sha256"]
        .as_object()
        .context("missing dev smoke log manifest")?;
    ensure!(
        logs.keys().cloned().collect::<BTreeSet<_>>() == expected_logs,
        "incomplete dev smoke log manifest"
    );
    for (name, digest) in logs {
        ensure!(
            digest.as_str() == Some(&sha256(&artifact_file(directory, name)?)?),
            "dev smoke log hash mismatch"
        );
    }
    for name in TESTS {
        ensure!(tests[*name] == "tests.log", "wrong smoke test log");
    }
    test_group::validate(
        &fs::read_to_string(artifact_file(directory, "tests.log")?)?,
        TESTS,
    )?;
    Ok(
        json!({"cell": cell, "tests": TESTS, "binary_sha256": report["binary_sha256"], "report_sha256": sha256(&path)?}),
    )
}

pub fn validate_set(directory: &Path, source: &str, lock: &str) -> Result<Value> {
    let mut directories = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            ensure!(
                path.canonicalize()?.starts_with(directory.canonicalize()?),
                "smoke cell escapes evidence directory"
            );
            directories.insert(
                path.file_name()
                    .and_then(|p| p.to_str())
                    .context("invalid smoke cell name")?
                    .to_owned(),
            );
        }
    }
    ensure!(
        directories
            == CELLS
                .iter()
                .map(|(name, _, _)| (*name).to_owned())
                .collect(),
        "dev smoke cells differ"
    );
    CELLS
        .iter()
        .map(|(artifact, cell, target)| {
            validate_report(
                &directory.join(artifact).join("smoke.json"),
                cell,
                target,
                source,
                lock,
            )
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

#[derive(Debug, Args)]
pub struct SmokeArgs {
    /// Existing dev test binary, relative to the checkout root or absolute.
    #[arg(long)]
    pub binary: PathBuf,
    #[arg(long, value_parser = ["Linux-X64/dev", "Linux-ARM64/dev", "macOS-ARM64/dev"])]
    pub cell: String,
    /// Evidence directory containing cargo.json, relative to the checkout root.
    #[arg(long)]
    pub output: PathBuf,
}

pub fn capture(root: &Path, args: SmokeArgs) -> Result<Value> {
    capture_with_environment(root, args, &env::vars().collect())
}
fn capture_with_environment(
    root: &Path,
    args: SmokeArgs,
    environment: &Environment,
) -> Result<Value> {
    let directory = root.join(args.output);
    fs::create_dir_all(&directory)?;
    let path = directory.join("smoke.json");
    // A failed rerun must not leave an older success next to new partial logs.
    match fs::remove_file(&path) {
        Ok(()) => (),
        Err(error) if error.kind() == ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let (_, cell, target) = CELLS
        .iter()
        .find(|(_, cell, _)| *cell == args.cell)
        .context("unknown smoke cell")?;
    let source = source_identity(root, environment)?;
    let binary = root.join(args.binary).canonicalize()?;
    let binary_hash = sha256(&binary)?;
    let lock_path = root.join("core/Cargo.lock");
    let lock_hash = sha256(&lock_path)?;
    let features = resolve_features(root, environment, target, &directory)?;
    let compiler = command_output(root, Path::new("rustc"), &["-Vv"], Some(environment))?;
    let host = command_output(root, Path::new("uname"), &["-a"], Some(environment))?;
    let mut report = json!({"schema_version": 2, "cell": cell, "source_sha": source,
        "lockfile_sha256": lock_hash, "wasmtime_revision": FORK_REVISION,
        "binary": binary, "binary_sha256": binary_hash, "cargo_log": "cargo.json",
        "rustc_version_verbose": compiler, "host": host.trim(), "wasmtime_features": features,
        "feature_logs": feature_logs(), "tests": {}});
    build::validate(
        &report,
        &directory,
        binary.to_str().context("non-UTF8 binary path")?,
    )?;
    let clean_environment = environment
        .iter()
        .filter(|(name, _)| !name.starts_with("KONTOR_"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    test_group::run(
        &binary,
        root,
        TESTS,
        &directory.join("tests.log"),
        &clean_environment,
        Duration::from_secs(900),
    )?;
    for name in TESTS {
        report["tests"][*name] = json!("tests.log");
    }
    ensure!(
        source_identity(root, environment)? == source
            && sha256(&binary)? == binary_hash
            && sha256(&lock_path)? == lock_hash,
        "smoke inputs changed during execution"
    );
    let mut logs: BTreeSet<String> = report["tests"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    logs.insert("cargo.json".into());
    logs.extend(FEATURE_LOGS.iter().map(|(_, name)| (*name).to_owned()));
    report["log_sha256"] = logs
        .into_iter()
        .map(|name| Ok((name.clone(), json!(sha256(&directory.join(name))?))))
        .collect::<Result<Value>>()?;
    write_json(&path, &report)?;
    if let Err(error) = validate_report(&path, cell, target, &source, &lock_hash) {
        fs::remove_file(&path)?;
        return Err(error);
    }
    Ok(report)
}
#[cfg(test)]
mod tests;
