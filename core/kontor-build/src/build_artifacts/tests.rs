use super::*;
use std::os::unix::fs::symlink;
use tempfile::tempdir;

fn file(root: &Path, name: &str, contents: &str) -> Result<PathBuf> {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(&path, contents)?;
    Ok(path)
}
fn record(root: &Path, name: &str, value: &Value) -> Result<PathBuf> {
    file(root, name, &serde_json::to_string(value)?)
}
#[test]
fn audit_roles_preserve_original_graph_provenance_and_canonical_hashes() -> Result<()> {
    let dir = tempdir()?;
    let facade = file(dir.path(), "facade.rlib", "compiled")?;
    let graph = json!({"graph":"first","namespace":"executor","facade":facade,"link_inputs":dir.path(),"unicode":"\u{1f680}"});
    let mut consensus = graph.clone();
    consensus["namespace"] = json!("consensus");
    let graphs = vec![graph.clone()];
    let result = node_link_inputs(&graphs, &[consensus.clone()], dir.path())?;
    assert_eq!(result["audited"][0]["graph"], "executor-first");
    assert_eq!(result["audited"][1]["graph"], "consensus-first");
    assert_eq!(result["audited"][1]["namespace"], "consensus");
    assert_eq!(result["libraries"][0]["graph"], "first");
    assert_eq!(result["libraries"][1]["role"], "consensus");
    assert_ne!(
        result["libraries"][0]["build_inputs_sha256"],
        result["libraries"][1]["build_inputs_sha256"]
    );
    assert_eq!(graphs[0], graph);
    assert_eq!(
        node_link_inputs(&graphs, &[], dir.path())?["audited"],
        json!(graphs)
    );
    Ok(())
}
#[test]
fn node_dependencies_reject_execution_graphs_and_external_native_sources() -> Result<()> {
    let dir = tempdir()?;
    node_dependencies(
        dir.path(),
        &json!({"packages":[{"name":"libsql"}]}),
        dir.path(),
    )?;
    for name in [
        "wasmtime",
        "wasmtime-internal-cranelift",
        "kontor-executor-first",
        "kontor-consensus-first",
    ] {
        assert!(
            node_dependencies(dir.path(), &json!({"packages":[{"name":name}]}), dir.path())
                .unwrap_err()
                .to_string()
                .contains("retained execution")
        );
    }
    for name in ["psm", "ring", "blst", "secp256k1-sys", "wit-bindgen"] {
        let manifest = file(
            dir.path(),
            &format!("core/vendor/{name}/Cargo.toml"),
            "patched",
        )?;
        node_dependencies(
            dir.path(),
            &json!({"packages":[{"name":name,"manifest_path":manifest}]}),
            dir.path(),
        )?;
        assert!(
            node_dependencies(
                dir.path(),
                &json!({"packages":[{"name":name,"manifest_path":"registry/Cargo.toml"}]}),
                dir.path()
            )
            .is_err()
        );
    }
    Ok(())
}
#[test]
fn codegen_capture_binds_spec_and_object_bytes_without_reordering() -> Result<()> {
    let dir = tempdir()?;
    let spec = file(dir.path(), "spec.json", "{}")?;
    let object = file(dir.path(), "code.o", "machine code")?;
    let value = json!({"spec_sha256":sha256(&spec)?,"objects":[{"path":"code.o","sha256":sha256(&object)?}]});
    let path = record(dir.path(), "record.json", &value)?;
    assert_eq!(
        node_codegen_objects(&path, &spec, dir.path())?,
        vec![PathBuf::from("code.o")]
    );
    fs::write(&spec, "changed")?;
    assert!(
        node_codegen_objects(&path, &spec, dir.path())
            .unwrap_err()
            .to_string()
            .contains("link specification")
    );
    fs::write(&spec, "{}")?;
    fs::write(&object, "changed")?;
    assert!(
        node_codegen_objects(&path, &spec, dir.path())
            .unwrap_err()
            .to_string()
            .contains("object changed")
    );
    record(
        dir.path(),
        "record.json",
        &json!({"spec_sha256":sha256(&spec)?,"objects":[]}),
    )?;
    assert!(node_codegen_objects(&path, &spec, dir.path()).is_err());
    Ok(())
}
#[test]
fn executable_must_be_unambiguous_in_current_cargo_messages() -> Result<()> {
    let dir = tempdir()?;
    let log = file(dir.path(), "cargo.log", "diagnostic\nnull\n")?;
    assert!(node_executable(&log).is_err());
    let message = json!({"reason":"compiler-artifact","target":{"name":"kontor","kind":["bin"]},"executable":"target/kontor"});
    fs::write(&log, format!("noise\n{message}\n{message}\n"))?;
    assert_eq!(node_executable(&log)?, PathBuf::from("target/kontor"));
    let mut other = message.clone();
    other["executable"] = json!("target/other");
    fs::write(&log, format!("{message}\n{other}"))?;
    assert!(
        node_executable(&log)
            .unwrap_err()
            .to_string()
            .contains("ambiguous")
    );
    Ok(())
}
#[test]
fn installation_is_atomic_and_preserves_previous_executable_after_failed_audit() -> Result<()> {
    let dir = tempdir()?;
    let source = file(dir.path(), "source", "audited executable")?;
    let node = json!({"executable":"source","executable_sha256":sha256(&source)?});
    let destination = Path::new("bin/kontor");
    let result = install_node(&node, destination, dir.path())?;
    let installed = dir.path().join(destination);
    assert_eq!(result["sha256"], sha256(&installed)?);
    assert_eq!(
        fs::metadata(&installed)?.permissions().mode() & 0o777,
        0o755
    );
    fs::write(&source, "changed after audit")?;
    assert!(
        install_node(&node, destination, dir.path())
            .unwrap_err()
            .to_string()
            .contains("changed after")
    );
    assert_eq!(fs::read_to_string(&installed)?, "audited executable");
    assert_eq!(fs::read_dir(installed.parent().unwrap())?.count(), 1);
    assert!(install_node(&node, &source, dir.path()).is_err());
    symlink(&source, dir.path().join("alias"))?;
    assert!(install_node(&node, Path::new("alias"), dir.path()).is_err());
    fs::write(&source, "audited executable")?;
    fs::remove_file(&installed)?;
    fs::create_dir(&installed)?;
    assert!(install_node(&node, destination, dir.path()).is_err());
    assert_eq!(fs::read_dir(installed.parent().unwrap())?.count(), 1);
    Ok(())
}
#[test]
fn staging_uses_only_selected_artifacts_and_mutations_in_all_roles_are_rejected() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    file(root, "archive/libfacade-abc.rlib", "facade")?;
    file(root, "archive/libstale-old.rlib", "stale")?;
    file(root, "native/deep/libnative.a", "native")?;
    file(root, "native/other.txt", "ignored")?;
    file(root, "outside/libskip.a", "not traversed")?;
    symlink(root.join("outside"), root.join("native/alias"))?;
    file(root, "macro/libderive-123.so", "plugin")?;
    file(root, "output/link-inputs/obsolete.rlib", "old")?;
    let wrapper = file(root, "wrapper", "compiler")?;
    let selected = json!({"archives":["archive/libfacade-abc.rlib"],"facade":"archive/libfacade-abc.rlib",
        "native_outputs":[{"out_dir":"native"}],"proc_macros":["macro/libderive-123.so"]});
    let mut staged = stage_artifacts(Path::new("output"), &selected, "namespace", root)?;
    assert_eq!(staged["artifacts"].as_array().unwrap().len(), 1);
    assert_eq!(staged["native_artifacts"].as_array().unwrap().len(), 1);
    assert_eq!(
        staged["compiler_proc_macros"][0]["staged"],
        "output/link-inputs/libderive-namespace-123.so"
    );
    assert!(!root.join("output/link-inputs/obsolete.rlib").exists());
    assert!(!root.join("output/link-inputs/libstale-old.rlib").exists());
    staged["wrapper"] = json!("wrapper");
    staged["wrapper_binary_sha256"] = json!(sha256(&wrapper)?);
    verify_staged_inputs(&staged, root)?;
    for path in [
        "wrapper",
        "output/link-inputs/libfacade-abc.rlib",
        "output/link-inputs/native/0/libnative.a",
        "output/link-inputs/libderive-namespace-123.so",
    ] {
        let path = root.join(path);
        let original = fs::read(&path)?;
        fs::write(&path, "substituted")?;
        assert!(verify_staged_inputs(&staged, root).is_err());
        fs::write(path, original)?;
    }
    Ok(())
}
