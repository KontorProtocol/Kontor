use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use crate::toolchain::{Environment, output as command_output};

pub(super) const FORK_REVISION: &str = "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7";
pub(super) const FEATURE_LOGS: [(&str, &str); 2] = [
    ("production", "wasmtime-production-features.txt"),
    ("qualification", "wasmtime-qualification-features.txt"),
];
const PRODUCTION_FEATURES: &str = "anyhow async backtrace component-model component-model-async cranelift gc gc-copying gc-drc gc-null once_cell pooling-allocator pulley runtime std threads wasmtime-jit-icache-coherence wat wave wit-parser";

pub(super) fn expected_features(graph: &str) -> Vec<&'static str> {
    let mut features: Vec<_> = PRODUCTION_FEATURES.split_whitespace().collect();
    if graph == "qualification" {
        features.push("call-hook");
    }
    features.sort_unstable();
    features
}
pub(super) fn feature_logs() -> Value {
    FEATURE_LOGS
        .into_iter()
        .map(|(graph, name)| (graph.to_owned(), json!(name)))
        .collect()
}
pub(super) fn hex_digest(value: &Value, length: usize) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == length
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
pub(super) fn artifact_file(directory: &Path, name: &str) -> Result<PathBuf> {
    ensure!(
        !name.is_empty() && Path::new(name).file_name().and_then(|v| v.to_str()) == Some(name),
        "invalid evidence filename: {name}"
    );
    let path = directory.join(name);
    ensure!(
        path.is_file() && path.canonicalize()?.starts_with(directory.canonicalize()?),
        "missing or escaping evidence file: {name}"
    );
    Ok(path)
}

pub(super) fn validate(report: &Value, directory: &Path, binary: &str) -> Result<Value> {
    let features = report["wasmtime_features"]
        .as_object()
        .context("missing Wasmtime feature closures")?;
    ensure!(
        features.len() == 2
            && features.contains_key("production")
            && features.contains_key("qualification"),
        "missing Wasmtime feature closures"
    );
    for (graph, log) in FEATURE_LOGS {
        let expected = expected_features(graph);
        ensure!(
            features[graph] == json!(expected),
            "{graph}: unexpected Wasmtime feature closure"
        );
        let text = fs::read_to_string(artifact_file(directory, log)?)?;
        ensure!(
            text == expected.join(",") + "\n",
            "{graph}: feature log disagrees with report"
        );
    }
    ensure!(
        report["feature_logs"] == feature_logs(),
        "missing Wasmtime feature logs"
    );
    ensure!(
        report["cargo_log"] == "cargo.json",
        "missing Cargo build log"
    );
    let raw = fs::read_to_string(artifact_file(directory, "cargo.json")?)?;
    let mut artifacts = Vec::new();
    let mut compiled = Vec::new();
    let mut completed = Vec::new();
    let mut last = Value::Null;
    for line in raw.lines() {
        let item: Value = serde_json::from_str(line).context("invalid Cargo build log")?;
        ensure!(item.is_object(), "invalid Cargo build log entry");
        if item["reason"] == "build-finished" {
            completed.push(item["success"].clone());
        }
        let library = item["target"]["kind"]
            .as_array()
            .is_some_and(|kinds| kinds.contains(&json!("lib")));
        if item["reason"] == "compiler-artifact" && library {
            if item["target"]["name"] == "indexer"
                && item["profile"]["test"] == true
                && !item["executable"].is_null()
            {
                artifacts.push(item.clone());
            }
            if item["target"]["name"] == "wasmtime" {
                let prefix =
                    format!("git+https://github.com/wilfreddenton/wasmtime?rev={FORK_REVISION}#");
                ensure!(
                    item["package_id"] == prefix.clone() + "wasmtime@51.0.0-kontor.2"
                        || item["package_id"] == prefix + "51.0.0-kontor.2",
                    "compiled Wasmtime package identity mismatch"
                );
                let features = item["features"]
                    .as_array()
                    .context("missing compiled Wasmtime features")?;
                let mut features = features
                    .iter()
                    .map(|f| f.as_str().context("invalid compiled Wasmtime feature"))
                    .collect::<Result<Vec<_>>>()?;
                ensure!(
                    features.iter().collect::<BTreeSet<_>>().len() == features.len(),
                    "duplicate compiled Wasmtime feature"
                );
                features.sort_unstable();
                compiled.push(json!(features));
            }
        }
        last = item;
    }
    ensure!(
        artifacts.len() == 1 && artifacts[0]["executable"] == binary,
        "Cargo build log disagrees with test binary"
    );
    ensure!(
        compiled == [features["qualification"].clone()],
        "compiled Wasmtime features disagree with resolution"
    );
    ensure!(
        completed == [json!(true)] && last["reason"] == "build-finished",
        "Cargo build log lacks successful terminal completion"
    );
    Ok(artifacts.remove(0))
}

pub(super) fn source_identity(root: &Path, environment: &Environment) -> Result<String> {
    let source = command_output(
        root,
        Path::new("git"),
        &["rev-parse", "HEAD"],
        Some(environment),
    )?;
    ensure!(
        command_output(
            root,
            Path::new("git"),
            &["status", "--porcelain"],
            Some(environment)
        )?
        .trim()
        .is_empty(),
        "qualification source worktree is dirty"
    );
    Ok(source.trim().to_owned())
}

pub(super) fn resolve_features(
    root: &Path,
    environment: &Environment,
    target: &str,
    directory: &Path,
) -> Result<Value> {
    let mut features = json!({});
    for ((graph, log), edges) in FEATURE_LOGS.into_iter().zip(["no-dev", "all"]) {
        let raw = command_output(
            root,
            Path::new("cargo"),
            &[
                "tree",
                "--locked",
                "--offline",
                "--manifest-path",
                "core/Cargo.toml",
                "-p",
                "indexer",
                "-e",
                edges,
                "-i",
                "wasmtime",
                "-f",
                "{f}",
                "--depth",
                "0",
                "--target",
                target,
            ],
            Some(environment),
        )?;
        fs::write(directory.join(log), &raw)?;
        let lines: Vec<_> = raw.lines().collect();
        ensure!(
            lines.len() == 1 && !lines[0].is_empty(),
            "unexpected Wasmtime feature resolution for {edges}"
        );
        let mut list: Vec<_> = lines[0].split(',').collect();
        ensure!(
            !list.contains(&"") && list.iter().collect::<BTreeSet<_>>().len() == list.len(),
            "invalid Wasmtime feature resolution for {edges}"
        );
        list.sort_unstable();
        features[graph] = json!(list);
    }
    Ok(features)
}
