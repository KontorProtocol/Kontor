use super::*;
use tempfile::tempdir;

fn options(link_set: &str) -> Options {
    Options {
        build: BuildOptions {
            target: "x86_64-unknown-linux-gnu".into(),
            profile: "release".into(),
            jobs: 1,
            offline: true,
        },
        link_set: link_set.into(),
        node_qualification: false,
    }
}
fn file(root: &Path, name: &str, contents: &str) -> Result<PathBuf> {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(&path, contents)?;
    Ok(path)
}
#[test]
fn node_graph_selection_requires_exact_roles_order_and_membership() -> Result<()> {
    let graphs = vec![json!({"graph":"first"}), json!({"graph":"observer"})];
    let consensus = vec![json!({"graph":"first"})];
    selected_graphs("managed-node", &graphs, &consensus)?;
    selected_graphs("k4-node", &graphs, &[])?;
    assert!(selected_graphs("managed-node", &graphs, &[]).is_err());
    assert!(selected_graphs("k4-node", &graphs, &consensus).is_err());
    let mut reversed = graphs.clone();
    reversed.reverse();
    assert!(selected_graphs("managed-node", &reversed, &consensus).is_err());
    assert!(selected_graphs("managed-node", &graphs[..1], &consensus).is_err());
    assert!(selected_graphs("managed-node", &graphs, &[json!({"graph":"second"})]).is_err());
    assert!(selected_graphs("other", &graphs, &consensus).is_err());
    Ok(())
}
#[test]
fn node_environment_clears_graph_namespace_without_mutating_caller() -> Result<()> {
    let base = Environment::from([
        ("KONTOR_PROTOCOL_BUNDLE".into(), "1".into()),
        ("KONTOR_NATIVE_NAMESPACE".into(), "executor".into()),
        ("BUNDLE_GRAPH".into(), "first".into()),
        ("BUNDLE_LIFT_RATE".into(), "512".into()),
        ("RUSTC_WRAPPER".into(), "executor wrapper".into()),
        ("RUSTFLAGS".into(), "old".into()),
        ("RUSTC".into(), "pinned compiler".into()),
    ]);
    let env = environment(&base, Path::new("node"))?;
    assert_eq!(env["RUSTFLAGS"], "-Cpanic=unwind");
    assert_eq!(env["RUSTC_WRAPPER"], "");
    assert_eq!(env["CARGO_TARGET_DIR"], "node/target");
    assert_eq!(env["RUSTC"], base["RUSTC"]);
    assert!(!env.contains_key("KONTOR_PROTOCOL_BUNDLE"));
    assert!(!env.contains_key("KONTOR_NATIVE_NAMESPACE"));
    assert!(!env.contains_key("BUNDLE_GRAPH"));
    assert!(!env.contains_key("BUNDLE_LIFT_RATE"));
    assert_eq!(base["BUNDLE_GRAPH"], "first");
    Ok(())
}
#[test]
fn link_attestation_binds_executor_and_consensus_definitions_without_crossing_roles() -> Result<()>
{
    let dir = tempdir()?;
    let root = dir.path();
    let compiler = file(root, "compiler", "pinned rustc")?;
    let linker = file(root, "linker", "pinned linker wrapper")?;
    let graphs = vec![
        json!({"execution_definition":{"execution_definition_id":"p1"}}),
        json!({"execution_definition":{"execution_definition_id":"p2"}}),
    ];
    let libraries = vec![
        json!({"role":"executor","graph":"first","facade_sha256":"a","build_inputs_sha256":"b"}),
        json!({"role":"executor","graph":"observer","facade_sha256":"c","build_inputs_sha256":"d"}),
        json!({"role":"consensus","graph":"first","facade_sha256":"e","build_inputs_sha256":"f"}),
    ];
    let coordinator = json!({"first":{"consensus_definition":"consensus"}});
    let spec = link_spec(
        root,
        &options("managed-node"),
        &compiler,
        &json!({}),
        "lock",
        &libraries,
        &graphs,
        &coordinator,
        &linker,
        &[],
    )?;
    assert_eq!(spec["attestation"]["graphs"][0]["definition"], "p1");
    assert_eq!(spec["attestation"]["graphs"][1]["definition"], "p2");
    assert_eq!(spec["attestation"]["graphs"][2]["definition"], "consensus");
    assert_eq!(spec["attestation"]["graphs"][0]["wire_codec"], Value::Null);
    assert_eq!(spec["attestation"]["graphs"][2]["wire_codec"], 1);
    assert_eq!(spec["graphs"], json!(libraries));
    assert_eq!(spec["attestation"]["compiler_sha256"], sha256(&compiler)?);
    let mut changed = graphs.clone();
    changed[0]["execution_definition"]["execution_definition_id"] = json!("substituted");
    assert_ne!(
        fingerprint(&spec)?,
        fingerprint(&link_spec(
            root,
            &options("managed-node"),
            &compiler,
            &json!({}),
            "lock",
            &libraries,
            &changed,
            &coordinator,
            &linker,
            &[]
        )?)?
    );
    assert!(
        link_spec(
            root,
            &options("managed-node"),
            &compiler,
            &json!({}),
            "lock",
            &libraries,
            &graphs,
            &json!({}),
            &linker,
            &[]
        )
        .is_err()
    );
    let legacy = link_spec(
        root,
        &options("k4-node"),
        &compiler,
        &json!({}),
        "lock",
        &libraries[..2],
        &graphs,
        &coordinator,
        &linker,
        &[],
    )?;
    assert!(legacy.get("attestation").is_none());
    Ok(())
}
#[test]
fn completed_compiler_output_is_required_and_bound_to_the_linker_record() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let output = file(root, "node", "final compiler bytes")?;
    let spec = file(root, "spec.json", "{}")?;
    let tool =
        json!({"invocation_path":"/usr/bin/cc","path":"/usr/bin/cc","sha256":"ab".repeat(32)});
    let record = json!({"schema":1,"spec_sha256":sha256(&spec)?,"output_sha256":"cd".repeat(32),"output":output,"driver":tool,"backend":tool,
        "arguments":["-o",output],"expanded_arguments":["-o",output],"working_directory":root,
        "selection":{"method":"compiler-driver-plan","command":["/usr/bin/cc","-###","-o",output],"stderr":"selected linker"}});
    let path = root.join("linker-record.json");
    write_json(&path, &record)?;
    let compiler = json!({"compiler_output":{"path":output,"sha256":sha256(&output)?},"linker_record_sha256":sha256(&path)?});
    write_json(&root.join("root-objects.json"), &compiler)?;
    completed_link(root, &spec, &output)?;
    let mut changed = compiler.clone();
    changed.as_object_mut().unwrap().remove("compiler_output");
    write_json(&root.join("root-objects.json"), &changed)?;
    assert!(
        completed_link(root, &spec, &output)
            .unwrap_err()
            .to_string()
            .contains("missing completed")
    );
    changed = compiler.clone();
    changed["linker_record_sha256"] = json!("ff".repeat(32));
    write_json(&root.join("root-objects.json"), &changed)?;
    assert!(
        completed_link(root, &spec, &output)
            .unwrap_err()
            .to_string()
            .contains("records disagree")
    );
    write_json(&root.join("root-objects.json"), &compiler)?;
    fs::write(&output, "substituted")?;
    assert!(
        completed_link(root, &spec, &output)
            .unwrap_err()
            .to_string()
            .contains("compiler output")
    );
    Ok(())
}
#[test]
fn audit_reports_preserve_python_spaced_json_bytes() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("report.json");
    write_audit(&path, &json!({"z":[1,{"unicode":"🚀"}],"a":true}))?;
    assert_eq!(
        fs::read_to_string(path)?,
        "{\"a\": true, \"z\": [1, {\"unicode\": \"\\ud83d\\ude80\"}]}\n"
    );
    Ok(())
}
