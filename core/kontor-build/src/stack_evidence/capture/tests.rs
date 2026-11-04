use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::ptr;
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

use super::{
    CaptureStackArgs, DEFAULT_CASES, Driver, FORK_REVISION, OWNERSHIP_TESTS, acceptable,
    capture_with_environment,
};
use crate::stack_evidence::build::{expected_features, resolve_features};
use crate::stack_evidence::chains::tests::fixture as chains_fixture;
use crate::stack_evidence::comparison::{report, tests::case};
use crate::stack_evidence::tests::transcript;
use crate::toolchain::Environment;

fn executable(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
fn strip_log(value: &Value) -> Value {
    value
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| k.as_str() != "log")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}
fn setup() -> (TempDir, Environment) {
    let temp = tempdir().unwrap();
    let root = temp.path();
    fs::create_dir_all(root.join("core")).unwrap();
    fs::write(root.join("core/Cargo.lock"),format!("version = 4\n[[package]]\nname = \"wasmtime\"\nversion = \"51.0.0-kontor.2\"\nsource = \"git+https://example.invalid/wasmtime#{FORK_REVISION}\"\n")).unwrap();
    fs::write(root.join(".gitignore"), "target/\n").unwrap();
    for args in [
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
                .args(args)
                .current_dir(root)
                .status()
                .unwrap()
                .success()
        );
    }
    for path in [
        "target/debug/deps",
        "target/fixtures",
        "target/evidence",
        "target/tools",
    ] {
        fs::create_dir_all(root.join(path)).unwrap();
    }
    for kind in DEFAULT_CASES {
        let fixture = case(kind, "linux", "x86_64");
        for (role, field) in [
            ("worker", "observations"),
            ("control", "control_observations"),
        ] {
            let samples = fixture[field]
                .as_array()
                .unwrap()
                .iter()
                .map(strip_log)
                .collect::<Vec<_>>();
            fs::write(
                root.join(format!("target/fixtures/{kind}-{role}.log")),
                transcript(&samples, &fixture[format!("{role}_summary")]),
            )
            .unwrap();
        }
        let mut owned: String = fixture["owned_observations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| format!("KONTOR_OWNED_STACK_REPORT:{s}\n"))
            .collect();
        owned.push_str(&format!(
            "KONTOR_OWNED_STACK_SUMMARY:{}\n",
            fixture["owned_summary"]
        ));
        fs::write(
            root.join(format!("target/fixtures/{kind}-owned.log")),
            owned,
        )
        .unwrap();
    }
    let (chains, owned) = chains_fixture();
    for (name, prefix, data) in [
        ("chains.log", "CHAIN_PROBE_REPORT:", chains),
        ("owned-chains.log", "CHAIN_OWNED_PROBE_REPORT:", owned),
    ] {
        fs::write(
            root.join(format!("target/fixtures/{name}")),
            data.as_array()
                .unwrap()
                .iter()
                .map(|v| format!("{prefix}{v}\n"))
                .collect::<String>(),
        )
        .unwrap();
    }
    fs::write(
        root.join("target/fixtures/ownership.log"),
        OWNERSHIP_TESTS
            .iter()
            .map(|t| format!("test {t} ... ok\n"))
            .collect::<String>()
            + "test result: ok. 5 passed; 0 failed; 0 ignored;\n",
    )
    .unwrap();
    executable(
        &root.join("target/debug/deps/indexer-capture"),
        r#"
        test -f core/Cargo.lock
        test "$1" = --ignored
        test "$2" = --exact
        test "$4" = --nocapture
        test "${OTHER_SENTINEL}" = keep
        test -z "${KONTOR_STACK_SENTINEL+x}"
        case "$3" in
            *::owned_stack_control)
                role=owned
                test -z "${KONTOR_FOREIGN+x}"
                test -z "${KONTOR_STACK_MODE+x}"
                ;;
            *::qualification_probe)
                role="$KONTOR_STACK_MODE"
                test "$KONTOR_FOREIGN" = keep_worker
                test "$KONTOR_STACK_INITIAL_DEPTH" = 1024
                ;;
            *) exit 9;;
        esac
        printf '%s:%s:%s:%s:%s\n' "$KONTOR_STACK_KIND" "$role" "$$" "${KONTOR_STACK_CONTROL_DEPTHS-}" "${KONTOR_OWNED_DEPTHS-}" >> target/processes
        cat "target/fixtures/$KONTOR_STACK_KIND-$role.log"
    "#,
    );
    executable(
        &root.join("target/tools/cargo"),
        &format!(
            "case \"$*\" in *'--locked --offline'*) ;; *) exit 1;; esac\ncase \"$*\" in *'--target x86_64-unknown-linux-gnu'*) ;; *) exit 1;; esac\ncase \"$*\" in *'no-dev'*) echo '{}' ;; *) echo '{}' ;; esac",
            expected_features("production").join(","),
            expected_features("qualification").join(",")
        ),
    );
    executable(
        &root.join("target/tools/rustc"),
        "printf 'rustc 1.99.1\\nhost: x86_64-unknown-linux-gnu\\n'",
    );
    let binary = root.join("target/debug/deps/indexer-capture");
    let cargo = [
        json!({"reason":"compiler-artifact","target":{"name":"indexer","kind":["lib"]},"profile":{"test":true},"executable":binary}),
        json!({"reason":"compiler-artifact","target":{"name":"wasmtime","kind":["lib"]},"package_id":format!("git+https://github.com/wilfreddenton/wasmtime?rev={FORK_REVISION}#wasmtime@51.0.0-kontor.2"),"features":expected_features("qualification")}),
        json!({"reason":"build-finished","success":true}),
    ];
    fs::write(
        root.join("target/evidence/cargo.json"),
        cargo.iter().map(|v| format!("{v}\n")).collect::<String>(),
    )
    .unwrap();
    let mut environment: Environment = env::vars().collect();
    environment.insert(
        "PATH".into(),
        format!(
            "{}:{}",
            root.join("target/tools").display(),
            environment["PATH"]
        ),
    );
    for (key, value) in [
        ("KONTOR_STACK_SENTINEL", "strip"),
        ("KONTOR_STACK_CONTROL_DEPTHS", "wrong"),
        ("KONTOR_FOREIGN", "keep_worker"),
        ("OTHER_SENTINEL", "keep"),
    ] {
        environment.insert(key.into(), value.into());
    }
    (temp, environment)
}
fn args() -> CaptureStackArgs {
    CaptureStackArgs {
        binary: "target/debug/deps/indexer-capture".into(),
        cell: "Linux-X64/dev".into(),
        lockfile: "core/Cargo.lock".into(),
        output: "target/evidence".into(),
        cases: vec![],
        chain_log: Some("target/fixtures/chains.log".into()),
        owned_chain_log: Some("target/fixtures/owned-chains.log".into()),
        ownership_log: Some("target/fixtures/ownership.log".into()),
        max_depth: 32768,
        max_reentry_depth: 64,
        initial_depth: 1024,
        timeout: 10,
    }
}

#[test]
fn capture_runs_separate_processes_and_produces_valid_full_archive() {
    let (temp, environment) = setup();
    let root = temp.path();
    let result = capture_with_environment(root, args(), &environment).unwrap();
    assert_eq!(result["cases"].as_array().unwrap().len(), 10);
    report(
        &root.join("target/evidence/qualification.json"),
        "Linux-X64/dev",
        "linux",
        "x86_64",
    )
    .unwrap();
    let trace = fs::read_to_string(root.join("target/processes")).unwrap();
    let rows = trace.lines().collect::<Vec<_>>();
    assert_eq!(rows.len(), 30);
    let reentry = rows
        .iter()
        .filter(|s| s.starts_with("paid_reenter:"))
        .collect::<Vec<_>>();
    assert_eq!(reentry.len(), 3);
    let pids = reentry
        .iter()
        .map(|s| s.split(':').nth(2).unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(pids.len(), 3);
    assert!(reentry[0].ends_with("::"));
    assert!(reentry[1].ends_with(":63,64:"));
    assert!(reentry[2].ends_with("::63,64"));
    let mut selected = args();
    selected.cases = vec!["paid_recurse".into()];
    selected.chain_log = None;
    let result = capture_with_environment(root, selected, &environment).unwrap();
    assert_eq!(result["cases"].as_array().unwrap().len(), 1);
    assert!(result["chain_log"].is_null());
}

#[test]
fn failures_signals_and_timeouts_preserve_output_without_retry_or_live_child() {
    let (temp, environment) = setup();
    let root = temp.path();
    let binary = root.join("target/debug/deps/indexer-capture");
    let output = root.join("target/evidence");
    let driver = Driver {
        root,
        binary: &binary,
        output: &output,
        environment: &environment,
        timeout: Duration::from_millis(80),
    };
    for body in [
        "echo run >> target/attempts; printf partial; printf diagnostic >&2; exit 1",
        "echo run >> target/attempts; printf partial; printf diagnostic >&2; kill -TERM $$",
        "echo run >> target/attempts; echo $$ > target/pid; printf partial; printf diagnostic >&2; while :; do :; done",
    ] {
        executable(&binary, body);
        fs::write(root.join("target/attempts"), "").unwrap();
        assert!(driver.case("paid_reenter", 64, 1024).is_err());
        assert_eq!(
            fs::read_to_string(root.join("target/attempts")).unwrap(),
            "run\n"
        );
        assert_eq!(
            fs::read(output.join("paid_reenter-worker.log")).unwrap(),
            b"partialdiagnostic"
        );
        assert!(!output.join("paid_reenter-control.log").exists());
        assert!(!output.join("paid_reenter-owned.log").exists());
    }
    let pid = fs::read_to_string(root.join("target/pid"))
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap();
    assert_eq!(
        unsafe { libc::waitpid(pid, ptr::null_mut(), libc::WNOHANG) },
        -1
    );
}

#[test]
fn owned_summary_and_control_mismatch_stop_capture() {
    let (temp, environment) = setup();
    let root = temp.path();
    let binary = root.join("target/debug/deps/indexer-capture");
    let output = root.join("target/evidence");
    let driver = Driver {
        root,
        binary: &binary,
        output: &output,
        environment: &environment,
        timeout: Duration::from_secs(2),
    };
    let owned_path = root.join("target/fixtures/paid_reenter-owned.log");
    let original = fs::read_to_string(&owned_path).unwrap();
    for raw in [
        "test result: ok. 1 passed;\n".to_owned(),
        original.replace("\"owned\":true", "\"owned\":false"),
        original.clone() + original.lines().last().unwrap() + "\n",
    ] {
        fs::write(&owned_path, raw).unwrap();
        assert!(driver.case("paid_reenter", 64, 1024).is_err());
        assert!(output.join("paid_reenter-owned.log").is_file());
    }
    fs::write(&owned_path, original).unwrap();
    fs::write(root.join("target/processes"), "").unwrap();
    let control = root.join("target/fixtures/paid_reenter-control.log");
    let raw = fs::read_to_string(&control)
        .unwrap()
        .replace("\"user\":100", "\"user\":101");
    fs::write(control, raw).unwrap();
    assert!(driver.case("paid_reenter", 64, 1024).is_err());
    assert_eq!(
        fs::read_to_string(root.join("target/processes"))
            .unwrap()
            .lines()
            .count(),
        2
    );
}

#[test]
fn source_binary_and_lock_changes_invalidate_stale_success() {
    let (temp, environment) = setup();
    let root = temp.path();
    let path = root.join("target/evidence/qualification.json");
    let mut invalid = args();
    invalid.cell = "unknown/dev".into();
    fs::write(&path, "old success").unwrap();
    assert!(capture_with_environment(root, invalid, &environment).is_err());
    assert!(!path.exists());
    let original_lock = fs::read(root.join("core/Cargo.lock")).unwrap();
    fs::write(root.join("core/Cargo.lock"), "dirty lock").unwrap();
    fs::write(&path, "old success").unwrap();
    assert!(
        capture_with_environment(root, args(), &environment)
            .unwrap_err()
            .to_string()
            .contains("dirty")
    );
    assert!(!path.exists());
    fs::write(root.join("core/Cargo.lock"), original_lock).unwrap();
    let binary = root.join("target/debug/deps/indexer-capture");
    let original = fs::read_to_string(&binary).unwrap();
    for injection in [
        "echo changed >> core/Cargo.lock\n",
        "echo '#changed' >> \"$0\"\n",
    ] {
        fs::write(
            &binary,
            original.replacen("set -eu\n", &format!("set -eu\n{injection}"), 1),
        )
        .unwrap();
        fs::write(&path, "old success").unwrap();
        assert!(capture_with_environment(root, args(), &environment).is_err());
        assert!(!path.exists());
        Command::new("git")
            .args(["restore", "core/Cargo.lock"])
            .current_dir(root)
            .status()
            .unwrap();
    }
}

#[test]
fn feature_resolution_preserves_raw_log_and_rejects_duplicate_entries() {
    let (temp, environment) = setup();
    let root = temp.path();
    let directory = root.join("target/evidence");
    executable(&root.join("target/tools/cargo"), "echo pulley,async");
    let features =
        resolve_features(root, &environment, "x86_64-unknown-linux-gnu", &directory).unwrap();
    assert_eq!(features["production"], json!(["async", "pulley"]));
    assert_eq!(
        fs::read_to_string(directory.join("wasmtime-production-features.txt")).unwrap(),
        "pulley,async\n"
    );
    for raw in ["pulley,pulley", "pulley,", "", "pulley\\nasync"] {
        executable(
            &root.join("target/tools/cargo"),
            &format!("printf '{raw}\\n'"),
        );
        assert!(
            resolve_features(root, &environment, "x86_64-unknown-linux-gnu", &directory).is_err()
        );
    }
}

#[test]
fn selected_diagnostics_keep_exact_reentry_boundary_and_positive_limits() {
    acceptable(&[json!({"kind":"paid_recurse","boundary":"first_failure","last_success":3,"first_failure":4,"first_failure_outcome":"stack_overflow"})]).unwrap();
    let mut reentry = json!({"kind":"paid_reenter","boundary":"first_failure","last_success":62,"first_failure":63,"first_failure_outcome":"invocation_limit"});
    assert!(acceptable(&[reentry.clone()]).is_err());
    reentry["last_success"] = json!(63);
    reentry["first_failure"] = json!(64);
    acceptable(&[reentry]).unwrap();
    assert!(
        acceptable(&[json!({"kind":"paid_huge","observations":[{"outcome":"stack_overflow"}]})])
            .is_err()
    );
    let (temp, environment) = setup();
    for (initial, timeout) in [(0, 1), (1, 0)] {
        let mut invalid = args();
        invalid.initial_depth = initial;
        invalid.timeout = timeout;
        assert!(capture_with_environment(temp.path(), invalid, &environment).is_err());
    }
}
