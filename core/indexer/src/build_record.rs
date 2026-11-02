use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use crate::protocol::coordinator::{baseline::Baseline, successor};
use crate::protocol::identity::{ChainId, DefinitionReference};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Graph {
    role: String,
    graph: String,
    definition: String,
    facade_sha256: String,
    build_inputs_sha256: String,
    wire_codec: Option<u32>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildRecord {
    schema: u32,
    link_set: String,
    target: String,
    profile: String,
    compiler_sha256: String,
    source_inputs_sha256: String,
    lock_sha256: String,
    graphs: Vec<Graph>,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_record(input: Option<&str>) -> Result<()> {
    let record: BuildRecord =
        serde_json::from_str(input.context("managed node lacks builder attestation")?)
            .context("invalid managed builder attestation")?;
    ensure!(
        record.schema == 1 && record.link_set == "managed-node",
        "unsupported builder attestation"
    );
    ensure!(
        Some(record.target.as_str()) == option_env!("KONTOR_NODE_TARGET")
            && matches!(record.profile.as_str(), "release" | "dev"),
        "builder target/profile differs"
    );
    ensure!(
        [
            &record.compiler_sha256,
            &record.source_inputs_sha256,
            &record.lock_sha256
        ]
        .into_iter()
        .all(|value| digest(value)),
        "invalid build input digest"
    );
    let first = Baseline::for_node(ChainId([0; 32]))?.manifest;
    let second = successor::manifest(ChainId([0; 32]))?;
    let expected = [
        ("executor", "first", first.executor.0, None),
        ("executor", "observer", second.executor.0, None),
        (
            "consensus",
            "first",
            first.consensus,
            Some(kontor_consensus_first::WIRE_CODEC),
        ),
        (
            "consensus",
            "second",
            second.consensus,
            Some(kontor_consensus_second::WIRE_CODEC),
        ),
    ];
    ensure!(
        record.graphs.len() == expected.len(),
        "builder graph set differs"
    );
    for (graph, (role, label, definition, wire_codec)) in record.graphs.iter().zip(expected) {
        ensure!(
            graph.role == role
                && graph.graph == label
                && graph.definition == hex::encode(definition)
                && graph.wire_codec == wire_codec
                && digest(&graph.facade_sha256)
                && digest(&graph.build_inputs_sha256),
            "builder graph binding differs: {role}/{label}"
        );
    }
    ensure!(
        DefinitionReference::decode(kontor_executor_first::execution_definition())?.id()?
            == first.executor
            && DefinitionReference::decode(kontor_executor_observer::execution_definition())?
                .id()?
                == second.executor,
        "linked executor differs from installed registry"
    );
    Ok(())
}

/// Check the builder's input record against the implementations in this binary.
/// Final executable/native-symbol auditing remains a release-builder check.
pub fn verify() -> Result<()> {
    verify_record(option_env!("KONTOR_NODE_ATTESTATION"))
}

#[cfg(feature = "protocol-qualification")]
pub(crate) fn qualify() -> Result<serde_json::Value> {
    verify()?;
    ensure!(verify_record(None).is_err());
    ensure!(verify_record(Some("{}")).is_err());
    let original: serde_json::Value = serde_json::from_str(
        option_env!("KONTOR_NODE_ATTESTATION").context("missing build record")?,
    )?;
    for field in [
        "schema",
        "link_set",
        "target",
        "profile",
        "compiler_sha256",
        "source_inputs_sha256",
        "lock_sha256",
    ] {
        let mut changed = original.clone();
        changed[field] = serde_json::json!("wrong");
        ensure!(
            verify_record(Some(&serde_json::to_string(&changed)?)).is_err(),
            "accepted changed {field}"
        );
    }
    for index in 0..4 {
        for field in [
            "role",
            "graph",
            "definition",
            "facade_sha256",
            "build_inputs_sha256",
            "wire_codec",
        ] {
            let mut changed = original.clone();
            changed["graphs"][index][field] = serde_json::json!("wrong");
            ensure!(
                verify_record(Some(&serde_json::to_string(&changed)?)).is_err(),
                "accepted changed graph field {field}"
            );
        }
        let mut changed = original.clone();
        changed["graphs"].as_array_mut().unwrap().remove(index);
        ensure!(verify_record(Some(&serde_json::to_string(&changed)?)).is_err());
    }
    Ok(
        serde_json::json!({"embedded_record_verified": true, "missing_record_rejected": true,
        "changed_bindings_rejected": true, "incomplete_graphs_rejected": true}),
    )
}
