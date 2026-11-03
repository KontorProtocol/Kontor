use super::*;
use std::os::unix::fs::symlink;
use tempfile::tempdir;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned()
}
fn copy_manifests(root: &Path) -> Result<()> {
    for directory in [
        "first",
        "second",
        "pulley-first",
        "pulley-second",
        "consensus-first",
    ] {
        let path = Path::new("protocol-bundles").join(directory);
        fs::create_dir_all(root.join(&path))?;
        for name in ["Cargo.toml", "Cargo.lock"] {
            fs::copy(
                repository().join(&path).join(name),
                root.join(&path).join(name),
            )?;
        }
    }
    Ok(())
}

#[test]
fn link_sets_keep_retained_and_live_sources_separate() -> Result<()> {
    let managed = executor_graphs(Some("managed-node"))?;
    let legacy = executor_graphs(Some("legacy-qualification"))?;
    assert_eq!(managed["first"].source_root, "protocol-bundles/retained/p1");
    assert_eq!(managed["observer"].source_root, ".");
    assert_eq!(
        legacy["first"].source_snapshot.as_deref(),
        Some(K3_SNAPSHOT)
    );
    assert_ne!(
        managed["first"].source_snapshot,
        legacy["first"].source_snapshot
    );
    assert!(executor_graphs(Some("unknown")).is_err());
    assert!(
        consensus_graphs()
            .values()
            .all(|graph| graph.version.is_none() && graph.revision.is_none())
    );
    assert_eq!(proof_graphs()["second"].lift_rate, 513);
    assert_eq!(current_executors()["second"].lift_rate, 512);
    Ok(())
}

#[test]
fn retained_root_requires_canonical_spelling_containment_and_exact_inventory() -> Result<()> {
    let dir = tempdir()?;
    let outside = tempdir()?;
    fs::create_dir(dir.path().join("retained"))?;
    symlink(outside.path(), dir.path().join("escape"))?;
    let mut graph = current_executors().remove("first").unwrap();
    for spelling in [
        "",
        "../outside",
        "/tmp",
        "./retained",
        "retained/",
        "retained//child",
        "retained/../child",
        "escape",
    ] {
        graph.source_root = spelling.into();
        assert!(
            graph_root(dir.path(), &graph).is_err(),
            "accepted {spelling}"
        );
    }
    graph.source_root = "retained".into();
    let root = dir.path().join("retained");
    fs::write(root.join("source.rs"), "pub fn retained() {}")?;
    fs::write(
        root.join("snapshot.json"),
        serde_json::to_vec(
            &json!({"files":{"source.rs":{"sha256":sha256(&root.join("source.rs"))?}}}),
        )?,
    )?;
    graph.source_snapshot = Some(sha256(&root.join("snapshot.json"))?);
    assert_eq!(graph_root(dir.path(), &graph)?, root.canonicalize()?);
    fs::write(root.join("source.rs"), "changed")?;
    assert!(graph_root(dir.path(), &graph).is_err());
    Ok(())
}

#[test]
fn historical_reservations_and_active_manifest_pins_reject_substitution() -> Result<()> {
    let dir = tempdir()?;
    copy_manifests(dir.path())?;
    let graphs = proof_graphs();
    verify_reservations(dir.path(), &graphs)?;
    for version in [
        "51.0.0-dev",
        "51.0.0+dev",
        "51.0.0-kontor.1",
        "51.0.0-kontor.2",
        "51.0.0+kontor.2",
    ] {
        let mut changed = graphs.clone();
        changed.get_mut("second").unwrap().version = Some(version.into());
        assert!(
            verify_reservations(dir.path(), &changed)
                .unwrap_err()
                .to_string()
                .contains("reserved Wasmtime")
        );
    }
    for graph in graphs.values() {
        let manifest = dir
            .path()
            .join("protocol-bundles")
            .join(&graph.directory)
            .join("Cargo.toml");
        let original = fs::read_to_string(&manifest)?;
        for (before, after) in [
            (graph.revision.as_deref().unwrap(), "0".repeat(40)),
            (graph.version.as_deref().unwrap(), "51.0.0-kontor.99".into()),
        ] {
            fs::write(&manifest, original.replace(before, &after))?;
            assert!(
                verify_reservations(dir.path(), &graphs)
                    .unwrap_err()
                    .to_string()
                    .contains("wrong immutable identity")
            );
        }
        fs::write(manifest, original)?;
    }
    for label in ["first", "second"] {
        for name in ["Cargo.toml", "Cargo.lock"] {
            let path = dir.path().join("protocol-bundles").join(label).join(name);
            let original = fs::read(&path)?;
            fs::write(&path, "substituted")?;
            assert!(
                verify_reservations(dir.path(), &graphs)
                    .unwrap_err()
                    .to_string()
                    .contains("historical proof inputs changed")
            );
            fs::write(path, original)?;
        }
    }
    Ok(())
}

#[test]
fn current_recipe_inputs_preserve_executor_and_proof_identity_separation() -> Result<()> {
    let root = repository();
    let proof = proof_graphs();
    let executor = current_executors();
    for graphs in [&proof, &executor] {
        verify_reservations(&root, graphs)?;
        for label in graphs.keys() {
            let report = json!({"graph":label,"identity":identity(&root, label, graphs)?});
            verify_identity(&root, &report, graphs)?;
        }
    }
    let report = json!({"graph":"first","identity":identity(&root, "first", &executor)?});
    assert!(verify_identity(&root, &report, &proof).is_err());
    let mut mixed = proof;
    mixed.insert("executor".into(), executor["first"].clone());
    assert!(verify_reservations(&root, &mixed).is_err());
    Ok(())
}

#[test]
fn identities_bind_all_execution_fields_and_manifest_bytes() -> Result<()> {
    let dir = tempdir()?;
    copy_manifests(dir.path())?;
    let graphs = proof_graphs();
    let expected = identity(dir.path(), "first", &graphs)?;
    let report = json!({"graph":"first", "identity":expected});
    verify_identity(dir.path(), &report, &graphs)?;
    for key in [
        "directory",
        "source_root",
        "source_snapshot",
        "wasmtime_revision",
        "wasmtime_version",
        "manifest_sha256",
        "lock_sha256",
        "lift_rate",
    ] {
        let mut changed = report.clone();
        changed["identity"][key] = json!("substituted");
        assert!(verify_identity(dir.path(), &changed, &graphs).is_err());
    }
    for key in execution().as_object().unwrap().keys() {
        let mut changed = report.clone();
        changed["identity"]["execution"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(verify_identity(dir.path(), &changed, &graphs).is_err());
    }
    let mut relabelled = report.clone();
    relabelled["graph"] = json!("second");
    assert!(verify_identity(dir.path(), &relabelled, &graphs).is_err());
    fs::write(
        dir.path().join("protocol-bundles/pulley-first/Cargo.lock"),
        "substituted",
    )?;
    assert!(verify_identity(dir.path(), &report, &graphs).is_err());
    Ok(())
}

#[test]
fn consensus_pins_require_engine_roots_and_reject_vm_dependency() -> Result<()> {
    let dir = tempdir()?;
    copy_manifests(dir.path())?;
    let manifest = dir
        .path()
        .join("protocol-bundles/consensus-first/Cargo.toml");
    verify_consensus_manifest(&manifest)?;
    let original = fs::read_to_string(&manifest)?;
    for (before, after) in [
        (MALACHITE_REVISION, "substituted"),
        (
            "https://github.com/KontorProtocol/malachite",
            "https://other.invalid/repo",
        ),
        ("=0.9.0-kontor.1", "0.9.0"),
        ("package = \"arc-malachitebft-app-channel\"", "package = 42"),
    ] {
        fs::write(&manifest, original.replacen(before, after, 1))?;
        assert!(verify_consensus_manifest(&manifest).is_err());
    }
    for text in [
        "[dependencies]\n",
        "[dependencies]\nwasmtime='51'\n",
        "[dependencies]\nplain='1'\n",
    ] {
        fs::write(&manifest, text)?;
        assert!(verify_consensus_manifest(&manifest).is_err());
    }
    Ok(())
}

#[test]
fn observations_require_both_exact_resolved_engines() -> Result<()> {
    let graphs = proof_graphs();
    let items: Vec<_> = graphs
        .iter()
        .map(|(name, graph)| {
            let mut value = execution();
            value["graph"] = json!(name);
            value["lift_rate"] = json!(graph.lift_rate);
            value
        })
        .collect();
    let log = |items: &[Value]| {
        items
            .iter()
            .map(|value| format!("KONTOR_VM_ATTESTATION {value}\n"))
            .collect::<String>()
    };
    assert_eq!(verify_engine_observations(&log(&items))?, items);
    assert!(verify_engine_observations(&log(&items[..1])).is_err());
    let mut duplicate = items.clone();
    duplicate.push(items[0].clone());
    assert_eq!(verify_engine_observations(&log(&duplicate))?, duplicate);
    for field in execution().as_object().unwrap().keys() {
        let mut changed = items.clone();
        changed[1].as_object_mut().unwrap().remove(field);
        assert!(
            verify_engine_observations(&log(&changed)).is_err(),
            "missing {field}"
        );
    }
    for (field, value) in [
        ("target", json!("native")),
        ("lift_rate", json!(512)),
        ("guest_concurrency", json!(0)),
        ("max_wasm_stack", json!(524288.0)),
        ("extra", json!(true)),
    ] {
        let mut changed = items.clone();
        changed[1][field] = value;
        assert!(
            verify_engine_observations(&log(&changed)).is_err(),
            "accepted {field}"
        );
    }
    Ok(())
}
