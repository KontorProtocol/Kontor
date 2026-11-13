use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::{field, fields};
use crate::container::sha256;

pub(super) const HISTORICAL_FIXTURES: &[&str] = &[
    "core/indexer/src/protocol_qualification/fixture.rs",
    "tools/protocol-bundles/historical_semantics.rs",
];
pub(super) const LAUNCH_FIXTURES: &[&str] = &["core/indexer/src/protocol_qualification/fixture.rs"];
pub(super) const HISTORICAL_FIXTURE_COPY: &str =
    "tools/protocol-bundles/historical-qualification-fixture.rs";
fn project(observation: &Value) -> Result<Value> {
    let transactions = field(observation, "transactions")?;
    let executions = field(transactions, "executions")?
        .as_array()
        .context("executions must be an array")?;
    ensure!(
        executions.len() == 3 && executions.iter().all(|value| value == &executions[0]),
        "historical comparison requires matching simulation, rollback and commit"
    );
    let mut observations = fields(
        observation,
        &[
            "genesis",
            "active_set",
            "missing_function",
            "committee",
            "malformed_transaction",
            "lifecycle",
        ],
    )?;
    observations.insert(
        "recognition".into(),
        field(transactions, "recognition")?.clone(),
    );
    observations.insert("transaction".into(), executions[2].clone());
    Ok(
        json!({"inputs": fields(transactions, &["raw_sha256", "counter_sha256", "proxy_sha256"])? , "observations":observations}),
    )
}
pub fn verify(
    observations: &Value,
    root: &Path,
    expected_graphs: &[String],
    link_set: Option<&str>,
) -> Result<Value> {
    let root = root.canonicalize()?;
    ensure!(
        super::baseline_graphs(link_set)? == expected_graphs,
        "semantic baseline graph selection differs from link set"
    );
    let historical = link_set == Some("legacy-qualification");
    let source_root = if historical {
        root.join("protocol-bundles/retained/k3").canonicalize()?
    } else {
        root.clone()
    };
    ensure!(
        source_root.starts_with(&root),
        "semantic baseline source root escapes repository"
    );
    let path = source_root.join("tools/protocol-bundles/semantic-baseline.json");
    let expected: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let schema = if historical { 1 } else { 2 };
    ensure!(
        expected["schema"].as_u64() == Some(schema),
        "semantic baseline schema differs from selected link set"
    );
    let fixtures = expected["provenance"]["fixture_sources"]
        .as_object()
        .context("semantic fixture source set changed")?;
    let fixture_paths = if historical {
        HISTORICAL_FIXTURES
    } else {
        LAUNCH_FIXTURES
    };
    ensure!(
        fixtures.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == fixture_paths.iter().copied().collect(),
        "semantic fixture source set changed"
    );
    let log = path.with_extension("log");
    let log_hash = sha256(&log)?;
    ensure!(
        json!(log_hash) == expected["provenance"]["log_sha256"],
        "semantic oracle log changed"
    );
    for (relative, checksum) in fixtures {
        let source = if historical && relative == HISTORICAL_FIXTURES[0] {
            root.join(HISTORICAL_FIXTURE_COPY)
        } else {
            source_root.join(relative)
        }
        .canonicalize()?;
        ensure!(
            source.starts_with(&root) && json!(sha256(&source)?) == *checksum,
            "semantic fixture changed: {relative}"
        );
    }
    if !historical {
        ensure!(
            expected["provenance"]["stdout_sha256"] == log_hash,
            "launch capture stdout differs from baseline log"
        );
        ensure!(
            expected["provenance"]["link_set"] == "managed-node",
            "launch capture used another link set"
        );
        let capture: Value = serde_json::from_slice(&fs::read(&log)?)?;
        let captured_graphs = capture["executors"]
            .as_array()
            .context("launch capture executors missing")?;
        ensure!(
            capture["schema"].as_u64() == Some(1)
                && captured_graphs.len() == 1
                && captured_graphs[0]["graph"] == "first"
                && capture["cases"]
                    .as_array()
                    .is_some_and(|cases| { json!(cases.len()) == expected["provenance"]["cases"] }),
            "launch capture graph or case set changed"
        );
        let captured = project(field(&captured_graphs[0], "observations")?)?;
        for section in ["inputs", "observations"] {
            ensure!(
                captured[section] == *field(&expected, section)?,
                "launch capture projection differs: {section}"
            );
        }
    }
    let graphs = field(observations, "executors")?
        .as_array()
        .context("executors must be an array")?;
    ensure!(
        graphs
            .iter()
            .map(|graph| graph["graph"].clone())
            .collect::<Vec<_>>()
            == expected_graphs
                .iter()
                .map(|graph| json!(graph))
                .collect::<Vec<_>>(),
        "semantic comparison requires the selected graphs"
    );
    for graph in graphs {
        let actual = project(field(graph, "observations")?)?;
        for section in ["inputs", "observations"] {
            ensure!(
                actual[section] == *field(&expected, section)?,
                "semantic comparison differs for {}: {section}",
                graph["graph"]
            );
        }
    }
    let mut result = json!({"schema":schema,"baseline_sha256":sha256(&path)?,
        "matching_observations":true,"graphs":expected_graphs});
    if historical {
        result["historical_source"] = field(&expected, "historical_source")?.clone();
        result["historical_base"] =
            field(field(&expected, "provenance")?, "historical_base")?.clone();
    } else {
        result["capture_source"] = field(&expected, "capture_source")?.clone();
        result["capture_binary_sha256"] =
            field(field(&expected, "provenance")?, "binary_sha256")?.clone();
    }
    Ok(result)
}
