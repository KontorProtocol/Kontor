use std::env;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;

use super::{
    CELLS, SmokeArgs, TESTS, capture_with_environment, validate_report, validate_set, validate_test,
};
use crate::container::sha256;
use crate::stack_evidence::build::{
    self, FEATURE_LOGS, FORK_REVISION, expected_features, feature_logs,
};
use crate::stack_evidence::test_group::{self, run as run_tests};
use crate::toolchain::Environment;
use crate::write_json;

fn fixture(directory: &Path, cell: &str, target: &str, binary: &str) -> Value {
    fs::create_dir_all(directory).unwrap();
    let mut features = json!({});
    for (graph, name) in FEATURE_LOGS {
        let list = expected_features(graph);
        fs::write(directory.join(name), list.join(",") + "\n").unwrap();
        features[graph] = json!(list);
    }
    let cargo = vec![
        json!({"reason":"compiler-artifact", "target":{"name":"indexer", "kind":["lib"]},
            "profile":{"test":true,"debug_assertions":true}, "executable":binary}),
        json!({"reason":"compiler-artifact", "target":{"name":"wasmtime","kind":["lib"]},
            "package_id":format!("git+https://github.com/wilfreddenton/wasmtime?rev={FORK_REVISION}#wasmtime@51.0.0-kontor.2"),
            "features":features["qualification"]}),
        json!({"reason":"build-finished","success":true}),
    ];
    write_cargo(directory, &cargo);
    let mut tests = json!({});
    for name in TESTS {
        tests[*name] = json!("tests.log");
    }
    fs::write(directory.join("tests.log"), group_log(TESTS)).unwrap();
    let mut report = json!({"schema_version":2, "cell":cell,"source_sha":"a".repeat(40),"lockfile_sha256":"b".repeat(64),
        "wasmtime_revision":FORK_REVISION,"binary":binary,"binary_sha256":"c".repeat(64),"cargo_log":"cargo.json",
        "rustc_version_verbose":format!("rustc 1.99.1\nhost: {target}\n"),"wasmtime_features":features,"feature_logs":feature_logs(),"tests":tests});
    rehash(directory, &mut report);
    write_json(&directory.join("smoke.json"), &report).unwrap();
    report
}
fn test_log(name: &str) -> String {
    format!("test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n")
}
fn group_log(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| format!("test {name} ... ok\n"))
        .collect::<String>()
        + &format!(
            "test result: ok. {} passed; 0 failed; 0 ignored;\n",
            names.len()
        )
}
fn write_cargo(directory: &Path, cargo: &[Value]) {
    fs::write(
        directory.join("cargo.json"),
        cargo.iter().map(|v| format!("{v}\n")).collect::<String>(),
    )
    .unwrap();
}
fn rehash(directory: &Path, report: &mut Value) {
    let mut logs = json!({});
    for name in ["tests.log".to_owned(), "cargo.json".to_owned()]
        .into_iter()
        .chain(FEATURE_LOGS.iter().map(|(_, n)| (*n).to_owned()))
    {
        logs[&name] = json!(sha256(&directory.join(&name)).unwrap());
    }
    report["log_sha256"] = logs;
}
fn validate(directory: &Path) -> anyhow::Result<Value> {
    validate_report(
        &directory.join("smoke.json"),
        "Linux-X64/dev",
        "x86_64-unknown-linux-gnu",
        &"a".repeat(40),
        &"b".repeat(64),
    )
}
fn one_fixture(directory: &Path) -> Value {
    fixture(
        directory,
        "Linux-X64/dev",
        "x86_64-unknown-linux-gnu",
        "/target/debug/deps/indexer-fixture",
    )
}

#[test]
fn complete_smoke_set_requires_every_cell_and_test() {
    let temp = TempDir::new().unwrap();
    for (artifact, cell, target) in CELLS {
        fixture(
            &temp.path().join(artifact),
            cell,
            target,
            "/target/debug/deps/indexer-fixture",
        );
    }
    let verify = || validate_set(temp.path(), &"a".repeat(40), &"b".repeat(64));
    assert_eq!(verify().unwrap().as_array().unwrap().len(), 3);
    let directory = temp.path().join(CELLS[0].0);
    let unexpected = temp.path().join("unexpected");
    fs::rename(&directory, &unexpected).unwrap();
    assert!(verify().is_err());
    fs::rename(&unexpected, &directory).unwrap();
    let path = directory.join("smoke.json");
    let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    report["tests"].as_object_mut().unwrap().remove(TESTS[0]);
    write_json(&path, &report).unwrap();
    assert!(verify().is_err());
}

#[test]
fn smoke_rejects_stale_identity_profile_compiler_logs_and_test_results() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path();
    let original = one_fixture(dir);
    validate(dir).unwrap();
    for (field, value) in [
        ("schema_version", json!(true)),
        ("schema_version", json!(1.0)),
        ("cell", json!("Linux-ARM64/dev")),
        ("source_sha", json!("d".repeat(40))),
        ("lockfile_sha256", json!("d".repeat(64))),
        ("binary", json!("/target/release/deps/indexer-example")),
        ("binary_sha256", json!("invalid")),
        (
            "rustc_version_verbose",
            json!("rustc 1.99.1\nhost: aarch64-apple-darwin\n"),
        ),
        (
            "rustc_version_verbose",
            json!("rustc 1.99.0\nhost: x86_64-unknown-linux-gnu\n"),
        ),
        ("wasmtime_revision", json!("wrong")),
        ("feature_logs", json!({})),
    ] {
        let mut report = original.clone();
        report[field] = value;
        write_json(&dir.join("smoke.json"), &report).unwrap();
        assert!(validate(dir).is_err(), "{field}");
    }
    write_json(&dir.join("smoke.json"), &original).unwrap();
    fs::write(dir.join("tests.log"), group_log(TESTS) + "tampered\n").unwrap();
    assert!(validate(dir).is_err());
    let valid = test_log(TESTS[0]);
    for raw in [
        String::new(),
        valid.replace("1 passed", "0 passed"),
        valid.replace("0 ignored", "1 ignored"),
        valid.replace(TESTS[0], "wrong_test"),
        valid.replace("0 failed", "1 failed"),
        valid.clone() + &valid,
    ] {
        assert!(validate_test(&raw, TESTS[0]).is_err());
        fs::write(dir.join("tests.log"), raw).unwrap();
        let mut report = original.clone();
        rehash(dir, &mut report);
        write_json(&dir.join("smoke.json"), &report).unwrap();
        assert!(validate(dir).is_err());
    }
}

#[test]
fn cargo_provenance_rejects_rehashed_build_feature_and_artifact_substitution() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path();
    let original = one_fixture(dir);
    let cargo: Vec<Value> = fs::read_to_string(dir.join("cargo.json"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let mut mutations = Vec::new();
    for pointer in [
        "/0/profile/test",
        "/0/profile/debug_assertions",
        "/2/success",
    ] {
        let mut bad = cargo.clone();
        let mut value = json!(bad);
        *value.pointer_mut(pointer).unwrap() = json!(false);
        bad = value.as_array().unwrap().clone();
        mutations.push(bad);
    }
    let mut bad = cargo.clone();
    bad.pop();
    mutations.push(bad);
    let mut bad = cargo.clone();
    bad.push(json!({"reason":"compiler-message"}));
    mutations.push(bad);
    let mut bad = cargo.clone();
    bad.insert(0, cargo[0].clone());
    mutations.push(bad);
    let mut bad = cargo.clone();
    bad.insert(0, cargo[1].clone());
    mutations.push(bad);
    let mut bad = cargo.clone();
    bad.push(cargo[2].clone());
    mutations.push(bad);
    let mut bad = cargo.clone();
    bad[1]["package_id"] = json!("wrong");
    mutations.push(bad);
    let mut bad = cargo.clone();
    bad[1]["features"]
        .as_array_mut()
        .unwrap()
        .push(json!("profiling"));
    mutations.push(bad);
    let mut bad = cargo.clone();
    bad[1]["features"]
        .as_array_mut()
        .unwrap()
        .push(json!("pulley"));
    mutations.push(bad);
    for bad in mutations {
        write_cargo(dir, &bad);
        let mut report = original.clone();
        rehash(dir, &mut report);
        write_json(&dir.join("smoke.json"), &report).unwrap();
        assert!(validate(dir).is_err());
    }
    write_cargo(dir, &cargo);
    for graph in ["production", "qualification"] {
        for feature in ["cache", "profiling", "debug-builtins", "unexpected"] {
            let mut report = original.clone();
            report["wasmtime_features"][graph]
                .as_array_mut()
                .unwrap()
                .push(json!(feature));
            assert!(build::validate(&report, dir, original["binary"].as_str().unwrap()).is_err());
        }
    }
    for raw in ["", "not JSON\n", "null\n"] {
        fs::write(dir.join("cargo.json"), raw).unwrap();
        assert!(build::validate(&original, dir, original["binary"].as_str().unwrap()).is_err());
    }
}

#[test]
fn evidence_cannot_escape_through_symlinks() {
    let root = TempDir::new().unwrap();
    let external = TempDir::new().unwrap();
    one_fixture(root.path());
    fs::rename(
        root.path().join("tests.log"),
        external.path().join("test.log"),
    )
    .unwrap();
    symlink(
        external.path().join("test.log"),
        root.path().join("tests.log"),
    )
    .unwrap();
    assert!(validate(root.path()).is_err());
    let cells = TempDir::new().unwrap();
    symlink(root.path(), cells.path().join(CELLS[0].0)).unwrap();
    assert!(validate_set(cells.path(), &"a".repeat(40), &"b".repeat(64)).is_err());
}

fn executable(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
#[test]
fn subprocess_failures_and_timeouts_keep_raw_logs_and_reap_child() {
    let temp = TempDir::new().unwrap();
    let binary = temp.path().join("binary");
    let log = temp.path().join("test.log");
    let environment: Environment = env::vars().collect();
    executable(
        &binary,
        "test \"$1\" = --exact\ntest \"$2\" = --test-threads=1\nshift 5\necho diagnostic >&2\nprintf 'test %s ... ok\\ntest result: ok. 1 passed; 0 failed; 0 ignored;\\n' \"$1\"",
    );
    run_tests(
        &binary,
        temp.path(),
        &TESTS[..1],
        &log,
        &environment,
        Duration::from_secs(1),
    )
    .unwrap();
    assert!(
        fs::read_to_string(&log)
            .unwrap()
            .starts_with("diagnostic\n")
    );
    for body in [
        "echo failure; exit 1",
        "echo abort; kill -TERM $$",
        "echo 'test result: ok. 0 passed; 0 failed; 0 ignored;'",
        "echo $$; while :; do :; done",
    ] {
        executable(&binary, body);
        assert!(
            run_tests(
                &binary,
                temp.path(),
                &TESTS[..1],
                &log,
                &environment,
                Duration::from_millis(50)
            )
            .is_err()
        );
        assert!(!fs::read(&log).unwrap().is_empty());
        if body.starts_with("echo $$") {
            let pid: i32 = fs::read_to_string(&log).unwrap().trim().parse().unwrap();
            // waitpid confirms this process has no unreaped child at that PID.
            assert_eq!(
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
                -1
            );
        }
    }
}

#[test]
fn capture_uses_checkout_paths_filters_guest_overrides_and_invalidates_stale_success() {
    let temp = TempDir::new().unwrap();
    let canonical = temp.path().canonicalize().unwrap();
    let root = canonical.as_path();
    fs::create_dir_all(root.join("core")).unwrap();
    fs::write(root.join("core/Cargo.lock"), "fixture lock").unwrap();
    fs::write(root.join(".gitignore"), "target/\n").unwrap();
    for arguments in [
        vec!["init", "-q"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ],
    ] {
        assert!(
            Command::new("git")
                .args(arguments)
                .current_dir(root)
                .status()
                .unwrap()
                .success()
        );
    }
    let bin = root.join("target/debug/deps");
    fs::create_dir_all(&bin).unwrap();
    let binary = bin.join("indexer-smoke");
    executable(
        &binary,
        "test -f core/Cargo.lock\ntest -z \"${KONTOR_SMOKE_SENTINEL+x}\"\ntest \"$1\" = --exact\ntest \"$2\" = --test-threads=1\nshift 5\necho invocation >> target/invocations\nprintf 'test %s ... ok\\n' \"$@\"\nprintf 'test result: ok. %s passed; 0 failed; 0 ignored;\\n' \"$#\"",
    );
    let tools = root.join("target/tools");
    fs::create_dir(&tools).unwrap();
    executable(
        &tools.join("cargo"),
        &format!(
            "case \"$*\" in *'--locked --offline'*) ;; *) exit 1;; esac\ncase \"$*\" in *'no-dev'*) echo '{}' ;; *) echo '{}' ;; esac",
            expected_features("production").join(","),
            expected_features("qualification").join(",")
        ),
    );
    executable(
        &tools.join("rustc"),
        "printf 'rustc 1.99.1\\nhost: x86_64-unknown-linux-gnu\\n'",
    );
    let mut environment: Environment = env::vars().collect();
    environment.insert(
        "PATH".into(),
        format!("{}:{}", tools.display(), environment["PATH"]),
    );
    environment.insert(
        "KONTOR_SMOKE_SENTINEL".into(),
        "must not reach child".into(),
    );
    let directory = root.join("target/evidence");
    fixture(
        &directory,
        "Linux-X64/dev",
        "x86_64-unknown-linux-gnu",
        binary.to_str().unwrap(),
    );
    let args = || SmokeArgs {
        binary: PathBuf::from("target/debug/deps/indexer-smoke"),
        cell: "Linux-X64/dev".into(),
        output: PathBuf::from("target/evidence"),
    };
    let result = capture_with_environment(root, args(), &environment).unwrap();
    assert_eq!(result["tests"].as_object().unwrap().len(), TESTS.len());
    assert_eq!(
        fs::read_to_string(root.join("target/invocations")).unwrap(),
        "invocation\n"
    );
    executable(&binary, "echo failed; exit 1");
    assert!(capture_with_environment(root, args(), &environment).is_err());
    assert!(!directory.join("smoke.json").exists());
    assert_eq!(
        fs::read_to_string(directory.join("tests.log")).unwrap(),
        "failed\n"
    );
    executable(
        &binary,
        "echo changed >> core/Cargo.lock\nshift 5\nprintf 'test %s ... ok\\n' \"$@\"\nprintf 'test result: ok. %s passed; 0 failed; 0 ignored;\\n' \"$#\"",
    );
    assert!(capture_with_environment(root, args(), &environment).is_err());
    assert!(!directory.join("smoke.json").exists());
    assert!(directory.join("tests.log").is_file());
}

#[test]
fn grouped_evidence_requires_exactly_one_complete_successful_run() {
    let valid = group_log(TESTS);
    test_group::validate(&valid, TESTS).unwrap();
    for raw in [
        valid.replace("8 passed", "7 passed"),
        valid.replace("0 ignored", "1 ignored"),
        valid.replace("0 failed", "1 failed"),
        valid.replace(TESTS[0], TESTS[1]),
        valid.replace(TESTS[0], "unexpected"),
        valid.replace(&format!("test {} ... ok\n", TESTS[0]), ""),
        valid.clone() + &format!("test {} ... ok\n", TESTS[0]),
        valid.clone() + &valid,
        TESTS.iter().map(|name| test_log(name)).collect(),
    ] {
        assert!(test_group::validate(&raw, TESTS).is_err(), "{raw}");
    }
}
