use super::super::tests::{certified_sample, observations, root};
use super::*;
use std::os::unix::fs::PermissionsExt;
use tempfile::{TempDir, tempdir};

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}
fn script(path: &Path, body: &str) -> Result<()> {
    fs::write(path, format!("#!/bin/sh\nset -eu\n{body}\n"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/node-evidence")
        .join(format!("{name}.json"))
}
pub(crate) fn sample(link: Option<&str>) -> Result<Value> {
    let graphs = executor_graphs(link)?;
    let names: Vec<_> = graphs.keys().map(String::as_str).collect();
    let baseline = baseline_graphs(link)?;
    let mut value = observations(&baseline.iter().map(String::as_str).collect::<Vec<_>>());
    value["schema"] = json!(1);
    value["cases"] = json!(CASES);
    value["storage_contracts"] = json!({"rejected_before_construction":names.iter().flat_map(|graph| ["missing","unknown","changed","multiple"].map(|mutation|format!("{graph}:{mutation}"))).collect::<Vec<_>>()});
    if link == Some("managed-node") {
        let history = certified_sample()?;
        value["managed_startup"] = json!({"chain":history["chain"], "protocol":history["protocol"], "era":history["era"], "executor_definition":history["executor_definition"],
                "rounds_started":2,"engines_joined":2,"next_generation":3,"same_listener":true,"same_era_wal":true,"database_remained_available":true,"competing_writer_rejected":true});
        value["certified_history"] = history;
    }
    Ok(value)
}
fn prepare(link: Option<&str>, observations: &Value, tail: &str) -> Result<TempDir> {
    let directory = tempdir()?;
    let path = directory.path();
    let binary = path.join("kontor");
    let mut body = format!(
        "case \"$*\" in\nqualify-executors) printf '%s\\n' {} ;;\n",
        quote(&serde_json::to_string(observations)?)
    );
    for check in [
        Check::Transition,
        Check::Recovery,
        Check::Authorization,
        Check::Join,
    ] {
        let (name, arg, _) = check.spec();
        body.push_str(&format!(
            "'qualify-protocol-transition {arg}') cat {} ;;\n",
            quote(fixture(name).to_str().unwrap())
        ));
    }
    body.push_str(&format!("*) exit 44 ;;\nesac\n{tail}"));
    script(&binary, &body)?;
    let hash = sha256(&binary)?;
    let graphs: Vec<_> = executor_graphs(link)?
        .keys()
        .map(|name| json!({"graph":name}))
        .collect();
    let consensus: Vec<_> = if link == Some("managed-node") {
        consensus_graphs()
            .keys()
            .map(|name| json!({"graph":name}))
            .collect()
    } else {
        vec![]
    };
    write_json(
        &path.join("node-build.json"),
        &json!({"target":"test-target","profile":"dev","link_set":link,"graphs":graphs,"consensus_graphs":consensus,
        "node":{"qualification_command":true,"executable_sha256":hash,"installed":{"path":binary,"sha256":hash}}}),
    )?;
    fs::write(path.join("node-execution.json"), "stale success")?;
    Ok(directory)
}
#[test]
fn actual_processes_bind_all_supported_reports_and_raw_logs() -> Result<()> {
    for link in [None, Some("legacy-qualification"), Some("managed-node")] {
        let directory = prepare(link, &sample(link)?, "printf 'raw stderr\\r\\n' >&2")?;
        let path = directory.path();
        let report = path.join("node-build.json");
        let evidence = execute(&root(), &report, link, &root())?;
        assert_eq!(evidence["node_build_sha256"], sha256(&report)?);
        assert_eq!(evidence["executable_sha256"], sha256(&path.join("kontor"))?);
        assert_eq!(
            evidence["stdout_sha256"],
            sha256(&path.join("node-execution.stdout.json"))?
        );
        assert_eq!(
            fs::read(path.join("node-execution.stderr.log"))?,
            b"raw stderr\r\n"
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(path.join("node-execution.json"))?)?,
            evidence
        );
        if link == Some("managed-node") {
            for name in ["transition", "recovery", "authorization", "join"] {
                assert_eq!(
                    evidence[name]["stdout_sha256"],
                    sha256(&path.join(format!("node-{name}.stdout.json")))?
                );
            }
        } else {
            assert!(evidence.get("transition").is_none());
        }
    }
    Ok(())
}
#[test]
fn failures_and_substitutions_remove_stale_success() -> Result<()> {
    for mode in 0..10 {
        let mut value = sample(None)?;
        match mode {
            0 => {
                value["cases"].as_array_mut().unwrap().pop();
            }
            1 => value["cases"][0] = value["cases"][1].clone(),
            2 => value["schema"] = json!(true),
            3 => value["executors"][1]["observations"]["lifecycle"] = json!("different"),
            4 => {
                for item in value["executors"].as_array_mut().unwrap() {
                    item["observations"]["malformed_transaction"] = json!("shared regression");
                }
            }
            _ => (),
        }
        let tail = match mode {
            5 => "exit 7",
            6 => "printf ' ' >> \"$0\"",
            7 => "printf ' ' >> \"$(dirname \"$0\")/node-build.json\"",
            _ => "",
        };
        let directory = prepare(None, &value, tail)?;
        let path = directory.path();
        let report = path.join("node-build.json");
        if mode == 8 {
            fs::write(path.join("kontor"), "substituted")?;
        }
        if mode == 9 {
            let mut value: Value = serde_json::from_slice(&fs::read(&report)?)?;
            value["node"]["installed"]["sha256"] = json!("wrong");
            write_json(&report, &value)?;
        }
        assert!(
            execute(&root(), &report, None, &root()).is_err(),
            "mode {mode}"
        );
        assert!(!path.join("node-execution.json").exists(), "mode {mode}");
    }
    Ok(())
}
#[test]
fn mismatched_graphs_and_missing_managed_results_cannot_publish() -> Result<()> {
    for mode in 0..7 {
        let mut value = sample(Some("managed-node"))?;
        if mode == 0 {
            value.as_object_mut().unwrap().remove("certified_history");
        }
        if mode == 1 {
            value.as_object_mut().unwrap().remove("managed_startup");
        }
        let directory = prepare(Some("managed-node"), &value, "")?;
        let path = directory.path();
        let report = path.join("node-build.json");
        let mut build: Value = serde_json::from_slice(&fs::read(&report)?)?;
        match mode {
            2 => build["consensus_graphs"] = json!([]),
            3 => build["graphs"].as_array_mut().unwrap().reverse(),
            4 => build["node"]["qualification_command"] = json!(false),
            5 => build["link_set"] = json!("k4-node"),
            6 => build["graphs"] = json!([{"graph":"first"}]),
            _ => (),
        }
        write_json(&report, &build)?;
        assert!(
            execute(&root(), &report, Some("managed-node"), &root()).is_err(),
            "mode {mode}"
        );
        assert!(!path.join("node-execution.json").exists());
    }
    Ok(())
}
#[test]
fn timeout_reaps_child_and_preserves_logs_and_signal_status() -> Result<()> {
    let directory = tempdir()?;
    let path = directory.path();
    let binary = path.join("child");
    script(
        &binary,
        "echo $$; printf 'before timeout' >&2; exec sleep 10",
    )?;
    let error = capture(
        &binary,
        path,
        "execution",
        &[],
        Duration::from_millis(50),
        path,
    )
    .unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert_eq!(
        fs::read_to_string(path.join("node-execution.stderr.log"))?,
        "before timeout"
    );
    let pid = fs::read_to_string(path.join("node-execution.stdout.json"))?;
    let status = Command::new("kill")
        .args(["-0", pid.trim()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(!status.success(), "timed-out child remains alive");
    for (body, message) in [
        ("printf '{}'; kill -TERM $$", "failed (-15)"),
        ("printf '{}'; exit 7", "failed (7)"),
        ("printf invalid", "invalid node execution JSON"),
    ] {
        script(&binary, body)?;
        assert!(
            capture(
                &binary,
                path,
                "execution",
                &[],
                Duration::from_secs(5),
                path
            )
            .unwrap_err()
            .to_string()
            .contains(message)
        );
    }
    Ok(())
}
#[test]
fn each_lifecycle_check_rejects_failed_or_malformed_child_output() -> Result<()> {
    let directory = tempdir()?;
    let path = directory.path();
    let binary = path.join("child");
    for check in [
        Check::Transition,
        Check::Recovery,
        Check::Authorization,
        Check::Join,
    ] {
        let (label, _, _) = check.spec();
        for tail in ["", "exit 8"] {
            script(
                &binary,
                &format!("cat {}\n{tail}", quote(fixture(label).to_str().unwrap())),
            )?;
            let result = execute_check(check, &binary, path, &root(), path);
            assert_eq!(result.is_ok(), tail.is_empty());
        }
        script(&binary, "printf '{}'")?;
        assert!(execute_check(check, &binary, path, &root(), path).is_err());
    }
    Ok(())
}

#[test]
fn caller_directory_controls_relative_binary_and_child_file_access() -> Result<()> {
    let directory = prepare(None, &sample(None)?, "")?;
    let path = directory.path();
    let binary = path.join("kontor");
    let original = fs::read_to_string(&binary)?;
    fs::write(path.join("cwd-marker"), "expected marker")?;
    fs::write(
        &binary,
        original.replace(
            "set -eu",
            "set -eu\ntest \"$(cat cwd-marker)\" = 'expected marker'",
        ),
    )?;
    let report = path.join("node-build.json");
    let mut build: Value = serde_json::from_slice(&fs::read(&report)?)?;
    let checksum = sha256(&binary)?;
    build["node"]["executable_sha256"] = json!(checksum);
    build["node"]["installed"] = json!({"path":"./kontor", "sha256":checksum});
    write_json(&report, &build)?;
    run(Request::Node {
        root: root(),
        working_directory: path.into(),
        report: "node-build.json".into(),
        link_set: None,
    })?;
    script(
        &binary,
        &format!(
            "test \"$(cat cwd-marker)\" = 'expected marker'\ncat {}",
            quote(fixture("join").to_str().unwrap())
        ),
    )?;
    run(Request::Check {
        root: root(),
        working_directory: path.into(),
        executable: "./kontor".into(),
        directory: ".".into(),
        check: Check::Join,
    })?;
    Ok(())
}
