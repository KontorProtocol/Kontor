use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::{field, fields};
use crate::container::sha256;

pub(super) const FIXTURES: &[&str] = &[
    "core/indexer/src/protocol_qualification/fixture.rs",
    "tools/protocol-bundles/historical_semantics.rs",
];
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
pub fn verify(observations: &Value, root: &Path, expected_graphs: &[String]) -> Result<Value> {
    let root = root.canonicalize()?;
    let path = root.join("tools/protocol-bundles/semantic-baseline.json");
    let expected: Value = serde_json::from_slice(&fs::read(&path)?)?;
    ensure!(
        expected["schema"].as_u64() == Some(1),
        "unknown historical semantic baseline schema"
    );
    let fixtures = expected["provenance"]["fixture_sources"]
        .as_object()
        .context("historical semantic fixture source set changed")?;
    ensure!(
        fixtures.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == FIXTURES.iter().copied().collect(),
        "historical semantic fixture source set changed"
    );
    ensure!(
        json!(sha256(&path.with_extension("log"))?) == expected["provenance"]["log_sha256"],
        "historical semantic oracle log changed"
    );
    for (relative, checksum) in fixtures {
        let source = root.join(relative).canonicalize()?;
        ensure!(
            source.starts_with(&root) && json!(sha256(&source)?) == *checksum,
            "historical semantic fixture changed: {relative}"
        );
    }
    ensure!(
        matches!(
            expected_graphs
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
            ["first"] | ["first", "second"] | ["first", "observer"]
        ),
        "unknown historical comparison graph set"
    );
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
        "historical comparison requires the selected retained graphs"
    );
    for graph in graphs {
        let actual = project(field(graph, "observations")?)?;
        for section in ["inputs", "observations"] {
            ensure!(
                actual[section] == *field(&expected, section)?,
                "historical semantic comparison differs for {}: {section}",
                graph["graph"]
            );
        }
    }
    Ok(
        json!({"baseline_sha256":sha256(&path)?, "historical_source":field(&expected, "historical_source")?, "historical_base":field(field(&expected, "provenance")?, "historical_base")?, "matching_observations":true, "graphs":expected_graphs}),
    )
}
