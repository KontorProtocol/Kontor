use super::semantics::{FIXTURES, verify};
use super::*;
use crate::container::sha256;
use std::os::unix::fs::symlink;
use tempfile::{TempDir, tempdir};

pub(super) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}
fn baseline() -> Value {
    serde_json::from_slice(
        &fs::read(root().join("tools/protocol-bundles/semantic-baseline.json")).unwrap(),
    )
    .unwrap()
}
pub(super) fn observations(names: &[&str]) -> Value {
    let baseline = baseline();
    let source = &baseline["observations"];
    let mut observation = source.as_object().unwrap().clone();
    observation.remove("recognition");
    observation.remove("transaction");
    let mut transactions = baseline["inputs"].as_object().unwrap().clone();
    transactions.insert("recognition".into(), source["recognition"].clone());
    transactions.insert(
        "executions".into(),
        json!([
            source["transaction"],
            source["transaction"],
            source["transaction"]
        ]),
    );
    observation.insert("transactions".into(), json!(transactions));
    json!({"executors":names.iter().map(|name| json!({"graph":name,"observations":observation})).collect::<Vec<_>>()})
}
fn names(values: &[&str]) -> Vec<String> {
    values.iter().map(|name| name.to_string()).collect()
}
fn copied_oracle() -> Result<TempDir> {
    let temporary = tempdir()?;
    for relative in FIXTURES.iter().copied().chain([
        "tools/protocol-bundles/semantic-baseline.json",
        "tools/protocol-bundles/semantic-baseline.log",
    ]) {
        let destination = temporary.path().join(relative);
        fs::create_dir_all(destination.parent().unwrap())?;
        fs::copy(root().join(relative), destination)?;
    }
    Ok(temporary)
}
#[test]
fn historical_oracle_accepts_supported_graphs_and_rejects_shared_regressions() -> Result<()> {
    for selected in [
        vec!["first"],
        vec!["first", "second"],
        vec!["first", "observer"],
    ] {
        let mut observations = observations(&selected);
        let report = verify(&observations, &root(), &names(&selected))?;
        assert_eq!(report["graphs"], json!(selected));
        assert_eq!(
            report["baseline_sha256"],
            json!(sha256(
                &root().join("tools/protocol-bundles/semantic-baseline.json")
            )?)
        );
        for executor in observations["executors"].as_array_mut().unwrap() {
            executor["observations"]["missing_function"]["Err"][1] = json!("same regression");
        }
        assert!(
            verify(&observations, &root(), &names(&selected))
                .unwrap_err()
                .to_string()
                .contains("semantic comparison differs")
        );
    }
    Ok(())
}
#[test]
fn historical_comparison_requires_all_graphs_and_all_three_execution_modes() {
    let original = observations(&["first", "second"]);
    for mode in 0..7 {
        let mut value = original.clone();
        match mode {
            0 => {
                value["executors"].as_array_mut().unwrap().pop();
            }
            1 => value["executors"][1]["graph"] = json!("first"),
            2 => value["executors"].as_array_mut().unwrap().reverse(),
            3 => {
                value["executors"][0]["observations"]["transactions"]["executions"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            4 => {
                value["executors"][0]["observations"]["transactions"]["executions"][1]["usage"][0] =
                    json!(99999)
            }
            5 => {
                value["executors"][0]["observations"]
                    .as_object_mut()
                    .unwrap()
                    .remove("lifecycle");
            }
            _ => value["executors"][0]["observations"]["transactions"]["executions"] = json!(null),
        }
        assert!(
            verify(&value, &root(), &names(&["first", "second"])).is_err(),
            "mode {mode}"
        );
    }
    assert!(verify(&original, &root(), &names(&["second", "first"])).is_err());
}
#[test]
fn oracle_binds_sources_log_schema_and_source_containment() -> Result<()> {
    let temporary = copied_oracle()?;
    let root = temporary.path();
    let observations = observations(&["first"]);
    verify(&observations, root, &names(&["first"]))?;
    for relative in FIXTURES
        .iter()
        .copied()
        .chain(["tools/protocol-bundles/semantic-baseline.log"])
    {
        let path = root.join(relative);
        let original = fs::read(&path)?;
        fs::write(&path, b"changed")?;
        assert!(verify(&observations, root, &names(&["first"])).is_err());
        fs::write(path, original)?;
    }
    let path = root.join("tools/protocol-bundles/semantic-baseline.json");
    let original = fs::read(&path)?;
    for schema in [json!(true), json!(1.0), json!(2)] {
        let mut value: Value = serde_json::from_slice(&original)?;
        value["schema"] = schema;
        fs::write(&path, serde_json::to_vec(&value)?)?;
        assert!(verify(&observations, root, &names(&["first"])).is_err());
    }
    let mut value: Value = serde_json::from_slice(&original)?;
    value["provenance"]["fixture_sources"] = json!({});
    fs::write(&path, serde_json::to_vec(&value)?)?;
    assert!(verify(&observations, root, &names(&["first"])).is_err());
    fs::write(path, original)?;
    let fixture = root.join(FIXTURES[0]);
    let outside = tempdir()?;
    let target = outside.path().join("fixture");
    fs::rename(&fixture, &target)?;
    symlink(target, fixture)?;
    assert!(
        verify(&observations, root, &names(&["first"]))
            .unwrap_err()
            .to_string()
            .contains("fixture changed")
    );
    Ok(())
}
pub(super) fn certified_sample(link_set: &str) -> Result<Value> {
    let root = root();
    let graphs = executor_graphs(Some(link_set))?;
    let graph = &graphs[if link_set == "managed-node" {
        "first"
    } else {
        "observer"
    }];
    let execution = hashed(
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
        &fs::read(root.join(if link_set == "managed-node" {
            "core/indexer/src/protocol/coordinator/consensus-rules-v1.json"
        } else {
            "core/indexer/src/protocol/coordinator/baseline/consensus.json"
        }))?,
    );
    let chain = vec![7; 32];
    let mut manifest = b"KPM1".to_vec();
    manifest.extend(&chain);
    manifest.extend(1_u64.to_be_bytes());
    manifest.extend([0; 32]);
    manifest.extend(hex::decode(&execution)?);
    manifest.extend(hex::decode(consensus)?);
    manifest.extend([0; 132]);
    let protocol = hashed(b"kontor/protocol-manifest/v1", &manifest);
    let mut result = json!({"authenticated":15,"closed":15,"executor_definition":execution,"manifest":hex::encode(manifest),"chain":hex::encode(&chain),"protocol":protocol,"era":hashed(b"kontor/genesis-era/v1", &[chain,hex::decode(&protocol)?].concat())});
    for name in CERTIFIED_CHECKS {
        result[*name] = json!(true);
    }
    if link_set == "managed-node" {
        result["migration_rehearsal_cli"] = json!(true);
    }
    Ok(result)
}
#[test]
fn certified_evidence_binds_checks_counts_and_selected_genesis() -> Result<()> {
    for link in ["k4-node", "managed-node"] {
        let sample = certified_sample(link)?;
        certified(&json!({"certified_history":sample}), Some(link), &root())?;
        for key in sample.as_object().unwrap().keys() {
            let mut value = sample.clone();
            value.as_object_mut().unwrap().remove(key);
            assert!(
                certified(&json!({"certified_history":value}), Some(link), &root()).is_err(),
                "missing {key}"
            );
        }
        for (key, wrong) in [
            ("authenticated", json!(15.0)),
            ("closed", json!(true)),
            ("reopen_verified", json!(1)),
            ("manifest", json!("00")),
            ("era", json!("00")),
            ("protocol", json!(false)),
            ("executor_definition", json!("00")),
        ] {
            let mut value = sample.clone();
            value[key] = wrong;
            assert!(
                certified(&json!({"certified_history":value}), Some(link), &root()).is_err(),
                "wrong {key}"
            );
        }
        assert!(
            certified(
                &json!({"certified_history":sample}),
                Some("legacy-qualification"),
                &root()
            )
            .is_err()
        );
    }
    let mut wrong = certified_sample("k4-node")?;
    wrong["migration_rehearsal_cli"] = json!(true);
    assert!(
        certified(
            &json!({"certified_history":wrong}),
            Some("managed-node"),
            &root()
        )
        .is_err()
    );
    certified(&json!({}), None, &root())?;
    Ok(())
}
#[test]
fn startup_storage_and_executor_checks_require_complete_selected_evidence() -> Result<()> {
    let history = certified_sample("managed-node")?;
    let mut managed = fields(
        &history,
        &["chain", "protocol", "era", "executor_definition"],
    )?;
    managed.extend(json!({"rounds_started":2,"engines_joined":2,"next_generation":3,"same_listener":true,"same_era_wal":true,"database_remained_available":true,"competing_writer_rejected":true}).as_object().unwrap().clone());
    let mut value = json!({"certified_history":history,"managed_startup":managed});
    startup(&value, Some("managed-node"))?;
    assert!(startup(&value, Some("k4-node")).is_err());
    value["managed_startup"]["chain"] = json!("other chain");
    assert!(startup(&value, Some("managed-node")).is_err());
    for link in [
        None,
        Some("legacy-qualification"),
        Some("k4-node"),
        Some("managed-node"),
    ] {
        let rejected: Vec<_> = executor_graphs(link)?
            .keys()
            .flat_map(|graph| {
                ["missing", "unknown", "changed", "multiple"]
                    .map(|mutation| format!("{graph}:{mutation}"))
            })
            .collect();
        let mut value = json!({"storage_contracts":{"rejected_before_construction":rejected}});
        storage(&value, link)?;
        value["storage_contracts"]["rejected_before_construction"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(storage(&value, link).is_err());
        let selected = baseline_graphs(link)?;
        let mut value = observations(&selected.iter().map(String::as_str).collect::<Vec<_>>());
        executors(&value, link)?;
        value["executors"]
            .as_array_mut()
            .unwrap()
            .push(json!({"graph":"observer","observations":{}}));
        assert!(executors(&value, link).is_err());
    }
    let mut value = observations(&["first", "second"]);
    value["executors"][1]["observations"]["lifecycle"] = json!("different");
    assert!(executors(&value, None).is_err());
    Ok(())
}

#[test]
fn optional_coverage_still_requires_an_observations_object() {
    for observations in [
        json!(null),
        json!([]),
        json!(17),
        json!(true),
        json!("text"),
    ] {
        for link_set in [
            None,
            Some("legacy-qualification".to_string()),
            Some("managed-node".to_string()),
        ] {
            assert!(
                run(Request::Certified {
                    root: root(),
                    observations: observations.clone(),
                    link_set: link_set.clone()
                })
                .is_err()
            );
            assert!(
                run(Request::Startup {
                    observations: observations.clone(),
                    link_set
                })
                .is_err()
            );
        }
    }
}
