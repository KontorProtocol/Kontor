use super::semantics::{HISTORICAL_FIXTURE_COPY, LAUNCH_FIXTURES, verify};
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
fn baseline(link_set: Option<&str>) -> Value {
    let source_root = if link_set == Some("legacy-qualification") {
        root().join("protocol-bundles/retained/k3")
    } else {
        root()
    };
    serde_json::from_slice(
        &fs::read(source_root.join("tools/protocol-bundles/semantic-baseline.json")).unwrap(),
    )
    .unwrap()
}
pub(super) fn observations(names: &[&str]) -> Value {
    observations_for(names, None)
}
pub(super) fn observations_for(names: &[&str], link_set: Option<&str>) -> Value {
    let baseline = baseline(link_set);
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
fn copied_oracle(link_set: Option<&str>) -> Result<TempDir> {
    let temporary = tempdir()?;
    let paths: Vec<&str> = if link_set == Some("legacy-qualification") {
        vec![
            HISTORICAL_FIXTURE_COPY,
            "protocol-bundles/retained/k3/tools/protocol-bundles/historical_semantics.rs",
            "protocol-bundles/retained/k3/tools/protocol-bundles/semantic-baseline.json",
            "protocol-bundles/retained/k3/tools/protocol-bundles/semantic-baseline.log",
        ]
    } else {
        LAUNCH_FIXTURES
            .iter()
            .copied()
            .chain([
                "tools/protocol-bundles/semantic-baseline.json",
                "tools/protocol-bundles/semantic-baseline.log",
            ])
            .collect()
    };
    for relative in paths {
        let destination = temporary.path().join(relative);
        fs::create_dir_all(destination.parent().unwrap())?;
        fs::copy(root().join(relative), destination)?;
    }
    Ok(temporary)
}
#[test]
fn selected_oracles_reject_shared_regressions() -> Result<()> {
    for (link_set, selected) in [
        (None, vec!["first", "second"]),
        (Some("production-node"), vec!["first"]),
        (Some("managed-node"), vec!["first"]),
        (Some("legacy-qualification"), vec!["first", "second"]),
    ] {
        let mut observations = observations_for(&selected, link_set);
        let report = verify(&observations, &root(), &names(&selected), link_set)?;
        assert_eq!(report["graphs"], json!(selected));
        let source_root = if link_set == Some("legacy-qualification") {
            root().join("protocol-bundles/retained/k3")
        } else {
            root()
        };
        assert_eq!(
            report["baseline_sha256"],
            json!(sha256(
                &source_root.join("tools/protocol-bundles/semantic-baseline.json")
            )?)
        );
        for executor in observations["executors"].as_array_mut().unwrap() {
            executor["observations"]["missing_function"]["Err"][1] = json!("same regression");
        }
        assert!(
            verify(&observations, &root(), &names(&selected), link_set)
                .unwrap_err()
                .to_string()
                .contains("semantic comparison differs")
        );
    }
    Ok(())
}
#[test]
fn semantic_comparison_requires_all_graphs_and_all_three_execution_modes() {
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
            verify(&value, &root(), &names(&["first", "second"]), None).is_err(),
            "mode {mode}"
        );
    }
    assert!(verify(&original, &root(), &names(&["second", "first"]), None).is_err());
}
#[test]
fn oracle_binds_sources_log_schema_and_source_containment() -> Result<()> {
    let temporary = copied_oracle(Some("production-node"))?;
    let root = temporary.path();
    let observations = observations(&["first"]);
    verify(
        &observations,
        root,
        &names(&["first"]),
        Some("production-node"),
    )?;
    for relative in LAUNCH_FIXTURES
        .iter()
        .copied()
        .chain(["tools/protocol-bundles/semantic-baseline.log"])
    {
        let path = root.join(relative);
        let original = fs::read(&path)?;
        fs::write(&path, b"changed")?;
        assert!(
            verify(
                &observations,
                root,
                &names(&["first"]),
                Some("production-node")
            )
            .is_err()
        );
        fs::write(path, original)?;
    }
    let path = root.join("tools/protocol-bundles/semantic-baseline.json");
    let original = fs::read(&path)?;
    for schema in [json!(true), json!(1.0), json!(1)] {
        let mut value: Value = serde_json::from_slice(&original)?;
        value["schema"] = schema;
        fs::write(&path, serde_json::to_vec(&value)?)?;
        assert!(
            verify(
                &observations,
                root,
                &names(&["first"]),
                Some("production-node")
            )
            .is_err()
        );
    }
    let mut value: Value = serde_json::from_slice(&original)?;
    value["provenance"]["fixture_sources"] = json!({});
    fs::write(&path, serde_json::to_vec(&value)?)?;
    assert!(
        verify(
            &observations,
            root,
            &names(&["first"]),
            Some("production-node")
        )
        .is_err()
    );
    fs::write(&path, &original)?;
    let log = root.join("tools/protocol-bundles/semantic-baseline.log");
    let original_log = fs::read(&log)?;
    let mut changed_capture: Value = serde_json::from_slice(&original_log)?;
    changed_capture["executors"][0]["observations"]["missing_function"]["Err"][1] =
        json!("altered capture");
    fs::write(&log, serde_json::to_vec(&changed_capture)?)?;
    let mut changed_baseline: Value = serde_json::from_slice(&original)?;
    let altered_hash = sha256(&log)?;
    changed_baseline["provenance"]["log_sha256"] = json!(altered_hash);
    changed_baseline["provenance"]["stdout_sha256"] = json!(altered_hash);
    fs::write(&path, serde_json::to_vec(&changed_baseline)?)?;
    assert!(
        verify(
            &observations,
            root,
            &names(&["first"]),
            Some("production-node")
        )
        .unwrap_err()
        .to_string()
        .contains("launch capture projection differs")
    );
    fs::write(&log, original_log)?;
    fs::write(&path, &original)?;
    let mut changed_baseline: Value = serde_json::from_slice(&original)?;
    changed_baseline["observations"]["missing_function"]["Err"][1] = json!("altered projection");
    fs::write(&path, serde_json::to_vec(&changed_baseline)?)?;
    assert!(
        verify(
            &observations,
            root,
            &names(&["first"]),
            Some("production-node")
        )
        .unwrap_err()
        .to_string()
        .contains("launch capture projection differs")
    );
    fs::write(&path, original)?;
    let fixture = root.join(LAUNCH_FIXTURES[0]);
    let outside = tempdir()?;
    let target = outside.path().join("fixture");
    fs::rename(&fixture, &target)?;
    symlink(target, fixture)?;
    assert!(
        verify(
            &observations,
            root,
            &names(&["first"]),
            Some("production-node")
        )
        .unwrap_err()
        .to_string()
        .contains("fixture changed")
    );
    Ok(())
}
#[test]
fn archived_oracle_requires_its_schema_sources_and_link_set() -> Result<()> {
    let temporary = copied_oracle(Some("legacy-qualification"))?;
    let root = temporary.path();
    let selected = names(&["first", "second"]);
    let observations = observations_for(&["first", "second"], Some("legacy-qualification"));
    verify(&observations, root, &selected, Some("legacy-qualification"))?;
    assert!(verify(&observations, root, &selected, None).is_err());
    for relative in [
        HISTORICAL_FIXTURE_COPY,
        "protocol-bundles/retained/k3/tools/protocol-bundles/historical_semantics.rs",
        "protocol-bundles/retained/k3/tools/protocol-bundles/semantic-baseline.log",
    ] {
        let path = root.join(relative);
        let original = fs::read(&path)?;
        fs::write(&path, b"changed")?;
        assert!(verify(&observations, root, &selected, Some("legacy-qualification")).is_err());
        fs::write(path, original)?;
    }
    let path =
        root.join("protocol-bundles/retained/k3/tools/protocol-bundles/semantic-baseline.json");
    let original = fs::read(&path)?;
    let mut value: Value = serde_json::from_slice(&original)?;
    value["schema"] = json!(2);
    fs::write(&path, serde_json::to_vec(&value)?)?;
    assert!(verify(&observations, root, &selected, Some("legacy-qualification")).is_err());
    Ok(())
}
pub(super) fn certified_sample() -> Result<Value> {
    let root = root();
    let graphs = executor_graphs(Some("managed-node"))?;
    let graph = &graphs["first"];
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
        &fs::read(root.join("core/indexer/src/protocol/coordinator/consensus-rules-v1.json"))?,
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
    result["migration_rehearsal_cli"] = json!(true);
    Ok(result)
}
#[test]
fn certified_evidence_binds_checks_counts_and_selected_genesis() -> Result<()> {
    {
        let link = "managed-node";
        let sample = certified_sample()?;
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
    certified(&json!({}), None, &root())?;
    assert!(certified(&json!({}), Some("k4-node"), &root()).is_err());
    Ok(())
}
#[test]
fn managed_genesis_rejects_self_consistent_observer_substitution() -> Result<()> {
    let mut sample = certified_sample()?;
    let mut manifest = hex::decode(sample["manifest"].as_str().unwrap())?;
    let wrong = hashed(
        b"kontor/execution-definition/v1",
        &fs::read(root().join("protocol-bundles/executor-observer/definition.bin"))?,
    );
    manifest[76..108].copy_from_slice(&hex::decode(&wrong)?);
    sample["manifest"] = json!(hex::encode(&manifest));
    sample["executor_definition"] = json!(wrong);
    let protocol = hashed(b"kontor/protocol-manifest/v1", &manifest);
    sample["protocol"] = json!(protocol);
    sample["era"] = json!(hashed(
        b"kontor/genesis-era/v1",
        &[
            hex::decode(sample["chain"].as_str().unwrap())?,
            hex::decode(&protocol)?
        ]
        .concat()
    ));
    assert!(
        certified(
            &json!({"certified_history":sample}),
            Some("managed-node"),
            &root()
        )
        .unwrap_err()
        .to_string()
        .contains("selected genesis executor")
    );
    Ok(())
}
#[test]
fn startup_storage_and_executor_checks_require_complete_selected_evidence() -> Result<()> {
    let history = certified_sample()?;
    let mut managed = fields(
        &history,
        &["chain", "protocol", "era", "executor_definition"],
    )?;
    managed.extend(json!({"rounds_started":2,"engines_joined":2,"next_generation":3,"same_listener":true,"same_era_wal":true,"database_remained_available":true,"competing_writer_rejected":true}).as_object().unwrap().clone());
    let mut value = json!({"certified_history":history,"managed_startup":managed});
    startup(&value, Some("managed-node"))?;
    assert!(startup(&value, Some("k4-node")).is_err());
    assert!(startup(&value, Some("legacy-qualification")).is_err());
    value["managed_startup"]["chain"] = json!("other chain");
    assert!(startup(&value, Some("managed-node")).is_err());
    for link in [None, Some("legacy-qualification"), Some("managed-node")] {
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
