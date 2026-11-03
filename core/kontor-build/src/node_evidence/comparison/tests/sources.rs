use super::super::sources::verify;
use super::fixtures::{inventory, rebind_source};
use super::*;
use crate::provenance::package_sources;

#[test]
fn source_substitutions_and_comparator_only_reuse_remain_distinct() -> Result<()> {
    let archive = Archive::new(None)?;
    let directory = &archive.cells[0];
    let node = directory.join("node");
    let original = read(&node.join("source-inputs.json"))?;
    for (pointer, wrong, expected) in [
        (
            "/qualification_sources/core~1indexer~1src~1main.rs",
            "stale source",
            "checked-out qualification inputs",
        ),
        (
            "/rust_build_tools/src~1compiler_wrapper.rs",
            "substituted wrapper",
            "Rust build-tool inventory differs",
        ),
        (
            "/packages/0/files/src~1lib.rs",
            "stale arithmetic",
            "local package source differs",
        ),
        (
            "/inherited_manifests_and_configuration/~1fixture~1core~1Cargo.toml",
            "changed workspace",
            "inherited core workspace changed",
        ),
    ] {
        let mut source = original.clone();
        *source
            .pointer_mut(pointer)
            .context("test fixture pointer")? = json!(wrong);
        if expected == "inherited core workspace changed" {
            source["inherited_manifests_and_configuration"]["/cargo/git/checkouts/wasmtime/crates/core/Cargo.toml"] =
                json!(sha256(&root().join("core/Cargo.toml"))?);
        }
        write_json(&node.join("source-inputs.json"), &source)?;
        let error = verify(
            &node,
            &json!({"source_inputs_sha256":fingerprint(&source)?}),
            &root(),
            GraphKind::Node,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains(expected), "{error}");
    }
    let mut source = original;
    source["qualification_sources"]["tools/protocol-bundles/compare_node.py"] =
        json!("previous comparator");
    source["rust_build_tools"]["src/node_evidence/comparison/mod.rs"] =
        json!("previous Rust comparator");
    let mut files = json!(package_sources(
        &root().join("core/kontor-build"),
        Some(&root())
    )?);
    files["src/node_evidence/comparison/sources.rs"] = json!("previous comparator");
    source["packages"]
        .as_array_mut()
        .unwrap()
        .push(json!({"package":"path+file://<repository>/core/kontor-build#0.1.0","files":files}));
    source["inherited_manifests_and_configuration"]["/fixture/core/kontor-build/Cargo.toml"] =
        json!(sha256(&root().join("core/kontor-build/Cargo.toml"))?);
    rebind_source(directory, &source)?;
    archive.compare("release")?;
    Ok(())
}

#[test]
fn retained_sources_bind_current_build_tools_and_reject_escaping_packages() -> Result<()> {
    let root = root();
    let recipe = executor_graphs(Some("legacy-qualification"))?
        .remove("first")
        .unwrap();
    let source_root = graph_root(&root, &recipe)?;
    let directory = tempdir()?;
    let original = inventory(&source_root, GraphKind::Executor, &recipe.directory)?;
    let report = |value: &Value| -> Result<Value> {
        Ok(
            json!({"source_inputs_sha256":fingerprint(value)?,"identity":{"directory":recipe.directory}}),
        )
    };
    write_json(&directory.path().join("source-inputs.json"), &original)?;
    verify(
        directory.path(),
        &report(&original)?,
        &source_root,
        GraphKind::Executor,
        Some(&root),
    )?;
    let mut source = original.clone();
    source["build_tools"]["build.py"] = json!("unrecorded change");
    write_json(&directory.path().join("source-inputs.json"), &source)?;
    assert!(
        verify(
            directory.path(),
            &report(&source)?,
            &source_root,
            GraphKind::Executor,
            Some(&root)
        )
        .unwrap_err()
        .to_string()
        .contains("current build-tool inventory differs")
    );
    let mut source = original;
    source["packages"][0]["package"] =
        json!("path+file://<repository>/../../../../../../../../tmp#escape");
    write_json(&directory.path().join("source-inputs.json"), &source)?;
    assert!(
        verify(
            directory.path(),
            &report(&source)?,
            &source_root,
            GraphKind::Executor,
            Some(&root)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn newly_added_inherited_configuration_invalidates_archived_inputs() -> Result<()> {
    let directory = tempdir()?;
    let checkout = directory.path().join("checkout");
    let evidence = directory.path().join("evidence");
    fs::create_dir_all(&evidence)?;
    let root = root();
    let source = inventory(&root, GraphKind::Node, "node")?;
    let mut paths = BTreeSet::new();
    paths.extend(
        source["qualification_sources"]
            .as_object()
            .unwrap()
            .keys()
            .map(PathBuf::from),
    );
    paths.extend(
        source["rust_build_tools"]
            .as_object()
            .unwrap()
            .keys()
            .map(|path| Path::new("core/kontor-build").join(path)),
    );
    paths.extend(
        source["packages"][0]["files"]
            .as_object()
            .unwrap()
            .keys()
            .map(|path| Path::new("core/numerics").join(path)),
    );
    paths.extend(
        source["inherited_manifests_and_configuration"]
            .as_object()
            .unwrap()
            .keys()
            .filter_map(|path| path.strip_prefix("/fixture/").map(PathBuf::from)),
    );
    for path in paths {
        let target = checkout.join(&path);
        fs::create_dir_all(target.parent().unwrap())?;
        fs::copy(root.join(path), target)?;
    }
    write_json(&evidence.join("source-inputs.json"), &source)?;
    let report = json!({"source_inputs_sha256":fingerprint(&source)?});
    verify(&evidence, &report, &checkout, GraphKind::Node, None)?;
    let config = checkout.join("core/.cargo/config.toml");
    fs::create_dir_all(config.parent().unwrap())?;
    fs::write(config, "[build]\nrustflags = [\"-C\", \"opt-level=1\"]\n")?;
    assert!(
        verify(&evidence, &report, &checkout, GraphKind::Node, None)
            .unwrap_err()
            .to_string()
            .contains("inherited repository input changed: core/.cargo/config.toml")
    );
    Ok(())
}
