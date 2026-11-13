use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::recipes::executor_graphs;

pub mod comparison;
mod qualification;
pub mod runner;
mod semantics;

pub use qualification::{QualifyNodeArgs, qualify_node};
mod transitions;

const CERTIFIED_CHECKS: &[&str] = &[
    "engine_free_recovery",
    "interrupted_replay_matches_uninterrupted",
    "live_closure_driver",
    "automatic_finality_replay",
    "owned_replacement_rollback",
    "bounded_work_plan",
    "replay_plan_publication_atomic",
    "local_reorg_is_not_authority",
    "owned_batch_stages",
    "owned_block_stage",
    "closure_publication_atomic",
    "next_height_after_closure",
    "ack_after_durable_input",
    "interrupted_append_rolled_back",
    "finalization_without_volatile_cache",
    "original_and_one_augmentation",
    "reopen_verified",
];

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Transition {
        root: PathBuf,
        result: Value,
        #[serde(default)]
        semantic_only: bool,
    },
    Recovery {
        result: Value,
    },
    Authorization {
        result: Value,
    },
    Join {
        result: Value,
    },
    Semantics {
        root: PathBuf,
        observations: Value,
        expected_graphs: Vec<String>,
    },
    Certified {
        root: PathBuf,
        observations: Value,
        link_set: Option<String>,
    },
    Storage {
        observations: Value,
        link_set: Option<String>,
    },
    Startup {
        observations: Value,
        link_set: Option<String>,
    },
    Executors {
        observations: Value,
        link_set: Option<String>,
    },
    BaselineGraphs {
        link_set: Option<String>,
    },
}
pub fn run(request: Request) -> Result<Value> {
    match request {
        Request::Transition {
            root,
            result,
            semantic_only,
        } => return transitions::transition(&result, &root, semantic_only),
        Request::Recovery { result } => return transitions::recovery(&result),
        Request::Authorization { result } => return transitions::authorization(&result),
        Request::Join { result } => return transitions::join(&result),
        Request::Semantics {
            root,
            observations,
            expected_graphs,
        } => return semantics::verify(&observations, &root, &expected_graphs),
        Request::Certified {
            root,
            observations,
            link_set,
        } => certified(&observations, link_set.as_deref(), &root)?,
        Request::Storage {
            observations,
            link_set,
        } => storage(&observations, link_set.as_deref())?,
        Request::Startup {
            observations,
            link_set,
        } => startup(&observations, link_set.as_deref())?,
        Request::Executors {
            observations,
            link_set,
        } => executors(&observations, link_set.as_deref())?,
        Request::BaselineGraphs { link_set } => {
            return Ok(json!(baseline_graphs(link_set.as_deref())?));
        }
    }
    Ok(Value::Null)
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .get(name)
        .with_context(|| format!("missing evidence field {name}"))
}
fn fields(value: &Value, names: &[&str]) -> Result<Map<String, Value>> {
    names
        .iter()
        .map(|name| Ok(((*name).into(), field(value, name)?.clone())))
        .collect()
}
fn hashed(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(bytes);
    hex::encode(digest.finalize())
}
fn decoded(value: &Value, name: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(
        field(value, name)?
            .as_str()
            .context("identity must be hexadecimal text")?,
    )?)
}
fn certified(observations: &Value, link_set: Option<&str>, root: &Path) -> Result<()> {
    observations
        .as_object()
        .context("observations must be an object")?;
    executor_graphs(link_set)?;
    let result = &observations["certified_history"];
    if link_set != Some("managed-node") {
        ensure!(
            result.is_null(),
            "legacy qualification cannot claim certified baseline coverage"
        );
        return Ok(());
    }
    let mut checks: Vec<_> = CERTIFIED_CHECKS.to_vec();
    checks.push("migration_rehearsal_cli");
    let expected: BTreeSet<_> = checks
        .iter()
        .copied()
        .chain([
            "authenticated",
            "closed",
            "executor_definition",
            "protocol",
            "chain",
            "manifest",
            "era",
        ])
        .collect();
    ensure!(
        result.as_object().is_some_and(|value| value
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == expected),
        "certified history evidence missing or incomplete"
    );
    ensure!(
        checks.iter().all(|key| result[*key] == json!(true))
            && result["authenticated"].as_u64() == Some(15)
            && result["closed"].as_u64() == Some(15),
        "certified history checks did not complete"
    );
    let valid = (|| -> Result<bool> {
        let manifest = decoded(result, "manifest")?;
        let chain = decoded(result, "chain")?;
        let protocol = decoded(result, "protocol")?;
        let graphs = executor_graphs(link_set)?;
        let graph = &graphs["first"];
        let executor = hashed(
            b"kontor/execution-definition/v1",
            &fs::read(
                root.join(&graph.source_root)
                    .join("protocol-bundles")
                    .join(&graph.directory)
                    .join("definition.bin"),
            )?,
        );
        let consensus = hashed(
            b"kontor/consensus-definition/v1",
            &fs::read(root.join("core/indexer/src/protocol/coordinator/consensus-rules-v1.json"))?,
        );
        Ok(manifest.len() == 272
            && chain.len() == 32
            && protocol.len() == 32
            && &manifest[..4] == b"KPM1"
            && manifest[4..36] == chain
            && manifest[36..44] == 1_u64.to_be_bytes()
            && manifest[44..76] == [0; 32]
            && json!(hex::encode(&manifest[76..108])) == result["executor_definition"]
            && result["executor_definition"] == json!(executor)
            && hex::encode(&manifest[108..140]) == consensus
            && json!(hashed(b"kontor/protocol-manifest/v1", &manifest)) == result["protocol"]
            && json!(hashed(
                b"kontor/genesis-era/v1",
                &[chain, protocol].concat()
            )) == result["era"])
    })();
    ensure!(
        valid.unwrap_or(false),
        "certified baseline identity differs from the selected genesis executor"
    );
    Ok(())
}
fn storage(observations: &Value, link_set: Option<&str>) -> Result<()> {
    let expected: Vec<_> = executor_graphs(link_set)?
        .keys()
        .flat_map(|graph| {
            ["missing", "unknown", "changed", "multiple"]
                .map(|mutation| format!("{graph}:{mutation}"))
        })
        .collect();
    ensure!(
        observations["storage_contracts"] == json!({"rejected_before_construction":expected}),
        "storage contract construction checks missing or incomplete"
    );
    Ok(())
}
fn startup(observations: &Value, link_set: Option<&str>) -> Result<()> {
    observations
        .as_object()
        .context("observations must be an object")?;
    executor_graphs(link_set)?;
    let result = &observations["managed_startup"];
    if link_set != Some("managed-node") {
        ensure!(
            result.is_null(),
            "unmanaged qualification cannot claim managed startup"
        );
        return Ok(());
    }
    let mut expected = fields(
        field(observations, "certified_history")?,
        &["chain", "protocol", "era", "executor_definition"],
    )?;
    for (name, value) in [
        ("rounds_started", 2),
        ("engines_joined", 2),
        ("next_generation", 3),
    ] {
        expected.insert(name.into(), json!(value));
    }
    for name in [
        "same_listener",
        "same_era_wal",
        "database_remained_available",
        "competing_writer_rejected",
    ] {
        expected.insert(name.into(), json!(true));
    }
    ensure!(
        *result == Value::Object(expected),
        "managed startup evidence missing, incomplete or bound to another protocol"
    );
    Ok(())
}
fn baseline_graphs(link_set: Option<&str>) -> Result<Vec<String>> {
    let graphs = executor_graphs(link_set)?;
    // The separate transition suite exercises the successor after its installation
    // migration. The genesis oracle runs against the selected P1 baseline.
    Ok(if link_set == Some("managed-node") {
        vec!["first".into()]
    } else {
        graphs.into_keys().collect()
    })
}
fn executors(observations: &Value, link_set: Option<&str>) -> Result<()> {
    let graphs = field(observations, "executors")?
        .as_array()
        .context("executors must be an array")?;
    ensure!(
        graphs
            .iter()
            .map(|graph| graph["graph"].clone())
            .collect::<Vec<_>>()
            == baseline_graphs(link_set)?
                .iter()
                .map(|name| json!(name))
                .collect::<Vec<_>>(),
        "node execution omitted or mislabeled a retained baseline graph"
    );
    let first = field(&graphs[0], "observations")?;
    ensure!(
        graphs
            .iter()
            .skip(1)
            .all(|graph| graph.get("observations") == Some(first)),
        "retained executor observations disagree"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
