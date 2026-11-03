use super::*;
use crate::node_evidence::tests::root;
use std::os::unix::fs::symlink;
use tempfile::tempdir;

mod fixtures;
mod sources;
use fixtures::{Archive, bind, change, rejects};

#[test]
fn supported_archive_policies() -> Result<()> {
    for link in [
        None,
        Some("legacy-qualification"),
        Some("k4-node"),
        Some("managed-node"),
    ] {
        let archive = Archive::new(link)?;
        assert_eq!(
            archive.compare("release")?["cells"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert!(archive.compare("full").is_err());
        if link.is_none() {
            for target in TARGETS {
                archive.cell(target, "dev")?;
            }
            assert_eq!(
                archive.compare("full")?["cells"].as_array().unwrap().len(),
                6
            );
            rejects(&archive, "unexpected");
        }
    }
    Ok(())
}
#[test]
fn failed_comparison_replaces_stale_success_and_never_passes_missing_cells() -> Result<()> {
    let directory = tempdir()?;
    let root = directory.path();
    let output = root.join("result.json");
    for status in ["failure", "cancelled", "success"] {
        fs::write(&output, b"{\"status\":\"passed\"}")?;
        let result = compare_node(
            root,
            CompareNodeArgs {
                directory: "missing".into(),
                output: "result.json".into(),
                profiles: "release".into(),
                upstream_status: status.into(),
                link_set: "managed-node".into(),
            },
        );
        assert!(result.is_err());
        let failure = read(&output)?;
        assert_eq!(failure["status"], "failed");
        assert_eq!(failure["upstream_status"], status);
        assert!(failure.get("matching_observations").is_none());
    }
    assert!(compare(root, root, "unexpected", "success", None).is_err());
    Ok(())
}

#[test]
fn missing_duplicate_failed_and_wrong_link_cells_reject() -> Result<()> {
    let archive = Archive::new(Some("k4-node"))?;
    for link in [None, Some("legacy-qualification"), Some("unknown")] {
        assert!(
            compare(
                archive.temporary.path(),
                &root(),
                "release",
                "success",
                link
            )
            .is_err()
        );
    }
    assert!(
        compare(
            archive.temporary.path(),
            &root(),
            "release",
            "failure",
            archive.link
        )
        .is_err()
    );
    let duplicate = archive.temporary.path().join("duplicate");
    fs::create_dir(&duplicate)?;
    // A second report can reference the same immutable evidence directory.
    for entry in fs::read_dir(&archive.cells[0])? {
        let entry = entry?;
        symlink(entry.path(), duplicate.join(entry.file_name()))?;
    }
    rejects(&archive, "duplicate");
    fs::remove_dir_all(duplicate)?;
    fs::remove_dir_all(&archive.cells[0])?;
    rejects(&archive, "missing required");
    Ok(())
}

#[test]
fn managed_lifecycle_raw_evidence_is_required_and_revalidated() -> Result<()> {
    let archive = Archive::new(Some("managed-node"))?;
    let directory = &archive.cells[0];
    let execution = directory.join("node-execution.json");
    let original = read(&execution)?;
    for (name, field, value, expected) in [
        (
            "transition",
            "closed_decisions",
            json!(5),
            "transition checks",
        ),
        (
            "join",
            "required_promoted_vote",
            json!(false),
            "join did not verify",
        ),
        (
            "recovery",
            "finality_replay",
            json!([]),
            "recovery replay cases missing",
        ),
        (
            "authorization",
            "orphaned_p2_batch_not_replayed",
            json!(false),
            "authorization replay evidence missing",
        ),
    ] {
        change(&execution, |v| {
            v.as_object_mut().unwrap().remove(name);
        })?;
        rejects(&archive, &format!("missing managed {name} evidence"));
        write_json(&execution, &original)?;
        let raw = directory.join(format!("node-{name}.stdout.json"));
        let saved = fs::read(&raw)?;
        change(&raw, |v| v[field] = value)?;
        rejects(&archive, "hash mismatch");
        let hash = sha256(&raw)?;
        change(&execution, |v| v[name]["stdout_sha256"] = json!(hash))?;
        rejects(&archive, expected);
        fs::write(raw, saved)?;
        write_json(&execution, &original)?;
    }
    Ok(())
}

#[test]
fn consensus_controls_and_certified_history_cannot_be_substituted() -> Result<()> {
    let archive = Archive::new(Some("managed-node"))?;
    let directory = &archive.cells[0];
    let build_path = directory.join("node-build.json");
    let original = read(&build_path)?;
    for mode in 0..4 {
        let mut build = original.clone();
        match mode {
            0 => {
                build["consensus_graphs"].as_array_mut().unwrap().clear();
            }
            1 => build["consensus_graphs"][0] = build["graphs"][0].clone(),
            2 => {
                build["node"]["consensus_adapter_checks"]["graph_inputs"]["first"] =
                    json!("other build")
            }
            _ => {
                build["node"]["consensus_interface_checks"]["report_sha256"] = json!("other report")
            }
        }
        write_json(&build_path, &build)?;
        bind(directory)?;
        assert!(archive.compare("release").is_err());
    }
    let log = directory.join("node/consensus/node-adapter/test.log");
    fs::write(
        &log,
        fs::read_to_string(&log)?.replace("0 ignored", "1 ignored"),
    )?;
    let mut build = original;
    build["node"]["consensus_adapter_checks"]["test_log_sha256"] = json!(sha256(&log)?);
    write_json(&build_path, &build)?;
    bind(directory)?;
    rejects(&archive, "tests missing or failed");
    let archive = Archive::new(Some("k4-node"))?;
    let directory = &archive.cells[0];
    change(&directory.join("node-execution.stdout.json"), |v| {
        v.as_object_mut().unwrap().remove("certified_history");
    })?;
    bind(directory)?;
    rejects(&archive, "certified history evidence");
    Ok(())
}

#[test]
fn rehashed_observation_case_and_compiler_changes_reject() -> Result<()> {
    let archive = Archive::new(None)?;
    let directory = &archive.cells[0];
    let raw = directory.join("node-execution.stdout.json");
    let original = read(&raw)?;
    change(&raw, |v| {
        for graph in v["executors"].as_array_mut().unwrap() {
            graph["observations"]["gas"] = json!(1);
        }
    })?;
    bind(directory)?;
    rejects(&archive, "cross-platform execution");
    write_json(&raw, &original)?;
    change(&raw, |v| {
        v["cases"].as_array_mut().unwrap().pop();
    })?;
    bind(directory)?;
    rejects(&archive, "case set");
    write_json(&raw, &original)?;
    bind(directory)?;
    let build = directory.join("node-build.json");
    let original_build = read(&build)?;
    change(&build, |v| {
        v["compiler"] = json!(v["compiler"].as_str().unwrap().replace(TOOLCHAIN, "0.0.0"));
        v["toolchain_inputs"]["compiler"] = v["compiler"].clone();
    })?;
    bind(directory)?;
    rejects(&archive, "wrong compiler");
    write_json(&build, &original_build)?;
    for directory in &archive.cells {
        change(&directory.join("node-execution.stdout.json"), |v| {
            for graph in v["executors"].as_array_mut().unwrap() {
                graph["observations"]["malformed_transaction"] = json!("shared regression");
            }
        })?;
        bind(directory)?;
    }
    rejects(&archive, "historical semantic comparison differs");
    Ok(())
}

#[test]
fn raw_audits_wrapper_identity_and_interface_errors_remain_bound() -> Result<()> {
    let archive = Archive::new(None)?;
    let directory = &archive.cells[0];
    for name in [
        "node-execution.stderr.log",
        "node/build.log",
        "first/build.log",
        "node/final-ownership.json",
        "node/node-input-ownership.json",
        "node/root-objects.json",
    ] {
        let path = directory.join(name);
        let saved = fs::read(&path)?;
        fs::write(&path, [saved.as_slice(), b"changed"].concat())?;
        rejects(&archive, "hash mismatch");
        fs::write(path, saved)?;
    }
    let build_path = directory.join("node-build.json");
    let original = read(&build_path)?;
    for (field, value) in [
        ("wrapper_binary_sha256", json!("")),
        ("wrapper_binary_sha256", json!("ab".repeat(32))),
        ("wrapper", json!("/synthetic/other")),
        ("wrapper_sha256", json!("00".repeat(32))),
    ] {
        let mut build = original.clone();
        build["node"][field] = value;
        write_json(&build_path, &build)?;
        bind(directory)?;
        assert!(archive.compare("release").is_err());
    }
    let checks = directory.join("node/type-boundary");
    let log = checks.join("wasmtime-engine.log");
    fs::write(
        &log,
        json!({"level":"error","code":{"code":"E0463"}}).to_string(),
    )?;
    let hash = sha256(&log)?;
    change(&checks.join("result.json"), |v| {
        v["controls"]["wasmtime-engine"]["diagnostics_sha256"] = json!(hash)
    })?;
    let mut build = original;
    build["node"]["interface_checks"]["report_sha256"] =
        json!(sha256(&checks.join("result.json"))?);
    write_json(&build_path, &build)?;
    bind(directory)?;
    rejects(&archive, "interface control failed");
    Ok(())
}

#[test]
fn completed_compiler_output_preserves_post_link_stage_bindings() -> Result<()> {
    let archive = Archive::new(None)?;
    let directory = &archive.cells[0];
    let node = directory.join("node");
    let build_path = directory.join("node-build.json");
    let mut build = read(&build_path)?;
    let root_path = node.join("root-objects.json");
    let original = read(&root_path)?;
    for capture in [
        Value::Null,
        json!({}),
        json!({"path":"/other","sha256":build["node"]["executable_sha256"]}),
        json!({"path":"/synthetic/kontor","sha256":"00".repeat(32)}),
    ] {
        let mut record = original.clone();
        record["compiler_output"] = capture;
        write_json(&root_path, &record)?;
        build["node"]["root_codegen_sha256"] = json!(sha256(&root_path)?);
        write_json(&build_path, &build)?;
        bind(directory)?;
        rejects(&archive, "compiler output");
    }
    change(&node.join("linker-record.json"), |v| {
        v["output_sha256"] = json!("ab".repeat(32))
    })?;
    let hash = sha256(&node.join("linker-record.json"))?;
    build["node"]["linker_record_sha256"] = json!(hash);
    let mut record = original;
    record["linker_record_sha256"] = json!(hash);
    write_json(&root_path, &record)?;
    build["node"]["root_codegen_sha256"] = json!(sha256(&root_path)?);
    write_json(&build_path, &build)?;
    bind(directory)?;
    archive.compare("release")?;
    change(&root_path, |v| {
        v["linker_record_sha256"] = json!("00".repeat(32))
    })?;
    build["node"]["root_codegen_sha256"] = json!(sha256(&root_path)?);
    write_json(&build_path, &build)?;
    bind(directory)?;
    rejects(&archive, "compiler and linker records disagree");
    Ok(())
}
