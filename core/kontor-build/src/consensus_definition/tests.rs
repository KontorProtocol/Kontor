use super::*;
use std::os::unix::fs::symlink;
use tempfile::tempdir;

fn write(root: &Path, name: &str, contents: &[u8]) -> Result<()> {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(path, contents)?;
    Ok(())
}
fn fixture(root: &Path) -> Result<(Value, Value, Value, Value)> {
    for tree in TREES {
        write(root, &format!("{tree}/rules.rs"), b"rules")?;
    }
    for file in FILES.iter().chain(BUILD_INPUTS).chain(&[
        GRAPH,
        "protocol-bundles/consensus/lib.rs",
        "core/indexer/src/protocol/migration_work.rs",
        "core/indexer/src/protocol/coordinator/activation.rs",
        "core/indexer/src/protocol/coordinator/certified_input.rs",
        "core/indexer/src/protocol/coordinator/certified_decision.rs",
        "core/indexer/src/protocol/coordinator/control.rs",
        "core/indexer/src/protocol/coordinator/manifest.rs",
    ]) {
        write(root, file, b"source")?;
    }
    let names = ROOTS
        .iter()
        .copied()
        .chain(["arc-malachitebft-engine", "transitive", "unrelated"]);
    let mut packages = vec![json!({"id":"node","name":"kontor-node","version":"1"})];
    let mut nodes = vec![];
    let mut locks = vec![];
    let mut direct = vec![];
    for name in names {
        packages.push(json!({"id":name,"name":name,"version":"1","source":"registry+example"}));
        locks.push(json!({"name":name,"version":"1","source":"registry+example","checksum":"01".repeat(32)}));
        let deps = if name == "arc-malachitebft-engine" {
            json!([{"name":"child","pkg":"transitive"}])
        } else {
            json!([])
        };
        nodes.push(json!({"id":name,"features":["std"],"deps":deps}));
        if name != "transitive" {
            let alias = if name == "arc-malachitebft-engine" {
                "malachitebft_engine"
            } else {
                name
            };
            direct.push(json!({"name":alias,"pkg":name}));
        }
    }
    nodes.push(json!({"id":"node","features":[],"deps":direct}));
    let graph = json!({"packages":[
        {"id":"first","name":"kontor-consensus-first","version":"1","manifest_path":root.join(GRAPH)},
        {"id":"transitive","name":"transitive","version":"1","source":"registry+example"}],
        "resolve":{"root":"first","nodes":[
            {"id":"first","features":[],"deps":[{"name":"child","pkg":"transitive","dep_kinds":[{"kind":null,"target":"cfg(unix)"}]}]},
            {"id":"transitive","features":["std"],"deps":[]}]}});
    let graph_lock = json!({"package":[
        {"name":"kontor-consensus-first","version":"1"},
        {"name":"transitive","version":"1","source":"registry+example","checksum":"01".repeat(32)}]});
    Ok((
        json!({"packages":packages,"resolve":{"nodes":nodes}}),
        json!({"package":locks}),
        graph,
        graph_lock,
    ))
}
fn reference(root: &Path, data: &(Value, Value, Value, Value)) -> Result<Value> {
    managed(root, &data.0, &data.1, &data.2, &data.3, "first")
}
#[test]
fn transitive_features_aliases_targets_and_lock_checksums_are_bound() -> Result<()> {
    let dir = tempdir()?;
    let data = fixture(dir.path())?;
    let original = reference(dir.path(), &data)?;
    for field in ["features", "alias", "target", "checksum", "revision"] {
        let mut changed = data.clone();
        match field {
            "features" => changed.2["resolve"]["nodes"][1]["features"] = json!(["extra"]),
            "alias" => changed.2["resolve"]["nodes"][0]["deps"][0]["name"] = json!("other"),
            "target" => {
                changed.2["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0]["target"] =
                    json!("cfg(windows)")
            }
            "checksum" => changed.3["package"][1]["checksum"] = json!("02".repeat(32)),
            _ => {
                changed.2["packages"][1]["source"] = json!("git+example#rev");
                changed.3["package"][1]["source"] = json!("git+example#rev");
            }
        }
        assert_ne!(reference(dir.path(), &changed)?, original, "{field}");
    }
    for name in FILES
        .iter()
        .chain(BUILD_INPUTS)
        .chain(&[GRAPH, "protocol-bundles/consensus/lib.rs"])
    {
        let path = dir.path().join(name);
        let contents = fs::read(&path)?;
        fs::write(&path, b"changed")?;
        assert_ne!(reference(dir.path(), &data)?, original, "{name}");
        fs::write(path, contents)?;
    }
    Ok(())
}
#[test]
fn relocation_metadata_order_and_unreachable_packages_do_not_change_reference() -> Result<()> {
    let first = tempdir()?;
    let second = tempdir()?;
    let mut data = fixture(first.path())?;
    let original = reference(first.path(), &data)?;
    assert_eq!(
        reference(second.path(), &fixture(second.path())?)?,
        original
    );
    data.2["packages"].as_array_mut().unwrap().reverse();
    data.2["resolve"]["nodes"].as_array_mut().unwrap().reverse();
    data.2["packages"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"unused","name":"unused"}));
    data.0["resolve"]["nodes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|n| n["id"] == "unrelated")
        .unwrap()["features"] = json!(["extra"]);
    assert_eq!(reference(first.path(), &data)?, original);
    Ok(())
}
#[test]
fn generated_references_are_excluded_and_verification_never_rewrites() -> Result<()> {
    let dir = tempdir()?;
    let data = fixture(dir.path())?;
    let original = reference(dir.path(), &data)?;
    let destination = destination("first")?;
    write(dir.path(), &destination, &bytes(&original)?)?;
    write(
        dir.path(),
        &format!("{DIRECTORY}future.json"),
        b"not registered",
    )?;
    write(dir.path(), BASELINE, b"old baseline")?;
    assert_eq!(reference(dir.path(), &data)?, original);
    let path = dir.path().join(destination);
    assert_eq!(
        verify(&path, &original, true)?["bytes"],
        bytes(&original)?.len()
    );
    fs::write(&path, b"stale")?;
    assert!(verify(&path, &original, true).is_err());
    assert_eq!(fs::read(path)?, b"stale");
    Ok(())
}
#[test]
fn substituted_graph_missing_dependencies_and_ambiguous_metadata_are_rejected() -> Result<()> {
    let dir = tempdir()?;
    let data = fixture(dir.path())?;
    for case in 0..7 {
        let mut changed = data.clone();
        match case {
            0 => changed.2["packages"][0]["name"] = json!("kontor-consensus-other"),
            1 => changed.3["package"][1]
                .as_object_mut()
                .unwrap()
                .remove("checksum")
                .map(|_| ())
                .unwrap(),
            2 => {
                changed.3["package"].as_array_mut().unwrap().pop();
            }
            3 => {
                changed.2["resolve"]["nodes"].as_array_mut().unwrap().pop();
            }
            4 => {
                let duplicate = changed.2["packages"][0].clone();
                changed.2["packages"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            5 => {
                let duplicate = changed.3["package"][0].clone();
                changed.3["package"].as_array_mut().unwrap().push(duplicate);
            }
            _ => {
                changed.0["resolve"]["nodes"]
                    .as_array_mut()
                    .unwrap()
                    .last_mut()
                    .unwrap()["deps"] = json!([])
            }
        }
        assert!(reference(dir.path(), &changed).is_err(), "case {case}");
    }
    assert!(managed(dir.path(), &data.0, &data.1, &data.2, &data.3, "../first").is_err());
    Ok(())
}
#[test]
fn source_symlink_escapes_and_cycles_are_rejected_but_dependency_cycles_terminate() -> Result<()> {
    let dir = tempdir()?;
    let outside = tempdir()?;
    let mut data = fixture(dir.path())?;
    data.2["resolve"]["nodes"][1]["deps"] = json!([{"name":"back","pkg":"first"}]);
    reference(dir.path(), &data)?;
    let path = dir.path().join("protocol-bundles/consensus/lib.rs");
    fs::remove_file(&path)?;
    fs::write(outside.path().join("lib.rs"), b"outside")?;
    symlink(outside.path().join("lib.rs"), &path)?;
    assert!(
        reference(dir.path(), &data)
            .unwrap_err()
            .to_string()
            .contains("escapes")
    );
    fs::remove_file(&path)?;
    symlink(path.parent().unwrap(), &path)?;
    assert!(
        reference(dir.path(), &data)
            .unwrap_err()
            .to_string()
            .contains("cyclic")
    );
    Ok(())
}
#[test]
fn freeze_requires_explicit_write_and_verifies_saved_metadata() -> Result<()> {
    let dir = tempdir()?;
    let data = fixture(dir.path())?;
    for (name, value) in [("node.json", &data.0), ("graph.json", &data.2)] {
        write(dir.path(), name, &serde_json::to_vec(value)?)?;
    }
    for (name, value) in [
        ("protocol-bundles/node/Cargo.lock", &data.1),
        ("protocol-bundles/consensus-first/Cargo.lock", &data.3),
    ] {
        let mut lock = String::new();
        for package in value["package"].as_array().unwrap() {
            lock.push_str("[[package]]\n");
            for (key, value) in package.as_object().unwrap() {
                lock.push_str(&format!("{key} = {value}\n"));
            }
        }
        write(dir.path(), name, lock.as_bytes())?;
    }
    let args = |write| FreezeArgs {
        baseline: false,
        write,
        graph: "first".into(),
        node_metadata: Some("node.json".into()),
        graph_metadata: Some("graph.json".into()),
    };
    let path = dir.path().join(destination("first")?);
    assert!(freeze(dir.path(), args(false)).is_err());
    assert!(!path.exists());
    let report = freeze(dir.path(), args(true))?;
    assert_eq!(freeze(dir.path(), args(false))?, report);
    fs::write(&path, b"stale")?;
    assert!(freeze(dir.path(), args(false)).is_err());
    assert_eq!(fs::read(path)?, b"stale");
    Ok(())
}
