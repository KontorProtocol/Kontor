use std::fs;
use std::iter::repeat_n;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

use super::{CompareStackArgs, FORK_REVISION, OWNERSHIP_TESTS, PLATFORMS, compare, compare_stack};
use crate::container::sha256;
use crate::stack_evidence::build::{FEATURE_LOGS, expected_features, feature_logs};
use crate::stack_evidence::chains::tests::fixture as chains_fixture;
use crate::stack_evidence::probes::{CASES, SEMANTICS, select};
use crate::stack_evidence::tests::{fixture as sweep_fixture, transcript};
use crate::toolchain::output as command_output;

fn strip_log(sample: &Value) -> Value {
    sample
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| k.as_str() != "log")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}
fn case(kind: &str, os: &str, arch: &str) -> Value {
    let mut case = json!({"kind":kind,"boundary":if kind=="paid_huge" {"bounded"} else {"first_failure"},
        "last_success":Value::Null,"first_failure":Value::Null,"first_failure_outcome":Value::Null,
        "worker_log":format!("{kind}-worker.log"),"control_log":format!("{kind}-control.log"),"owned_log":format!("{kind}-owned.log")});
    for role in ["worker", "control"] {
        let (mut samples, summary) = sweep_fixture(kind, role);
        for sample in &mut samples {
            let depth = sample["depth"].as_u64().unwrap();
            let ok = sample["outcome"] == "ok";
            let view = kind.starts_with("view_") || kind.starts_with("system_");
            sample["value"] = if ok {
                json!(
                    (if kind == "paid_huge" {
                        32640
                    } else if kind.ends_with("_wide") {
                        496 * depth
                    } else {
                        depth
                    })
                    .to_string()
                )
            } else {
                Value::Null
            };
            sample["receipt"] = if view {
                Value::Null
            } else {
                json!({"status":if ok {"Ok"} else if kind=="paid_reenter" {"Other"} else {"Trap"},"gas":10})
            };
            sample["last_depth"] = json!(if ok && !view {
                if kind == "paid_huge" { 1 } else { depth }
            } else {
                0
            });
            sample["child_markers"] = if kind == "paid_reenter" {
                if ok {
                    json!(
                        (0..depth)
                            .rev()
                            .chain(repeat_n(0, (64 - depth) as usize))
                            .collect::<Vec<_>>()
                    )
                } else {
                    json!(vec![0; 64])
                }
            } else {
                json!([])
            };
            sample["rolled_back"] = json!(!ok);
            for (field, value) in [
                ("gas_limit", 100000),
                ("paid_fuel_limit", 100000000),
                ("view_gas_limit", 100000),
                ("view_fuel_limit", 100000000),
                ("system_fuel_ceiling", 9223372036854775807_u64),
                ("gas_to_fuel_multiplier", 1000),
                ("max_wasm_stack", 524288),
                ("async_stack_size", 2097152),
            ] {
                sample[field] = json!(value);
            }
            sample["engine_target"] = json!("pulley64-unknown-unknown-elf");
            sample["component_sha256"] = json!("d".repeat(64));
            sample["target_os"] = json!(os);
            sample["target_arch"] = json!(arch);
            sample["log"] = json!(format!(
                "{kind}-{role}-{:04}.log",
                sample["sample_index"].as_u64().unwrap()
            ));
        }
        if kind != "paid_huge" {
            for field in ["last_success", "first_failure", "first_failure_outcome"] {
                case[field] = summary["boundaries"][field].clone();
            }
        }
        case[if role == "worker" {
            "observations"
        } else {
            "control_observations"
        }] = json!(samples);
        case[format!("{role}_summary")] = summary;
    }
    let mut owned = Vec::new();
    for (index, oracle) in case["control_observations"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let mut value = select(oracle, SEMANTICS);
        let api = kind.starts_with("view_");
        value["role"] = json!("owned");
        value["sample_index"] = json!(index);
        value["sample_id"] = json!(format!("owned:{kind}:{index:04}"));
        value["cache_mode"] = json!(if api {
            "fresh_api_pool_cache"
        } else {
            "warm_compiled_cache"
        });
        value["target_os"] = json!(os);
        value["target_arch"] = json!(arch);
        value["state_after_sha256"] = oracle["reset"]["post"]["persistent_digest_sha256"].clone();
        let peak = if kind == "paid_reenter" {
            (oracle["depth"].as_u64().unwrap() + 1).min(64)
        } else {
            1
        };
        value["ownership"] = json!({"kind": if api {"api"} else {"canonical"},
            "fuel_yield_interval": if api {json!(100000)} else {Value::Null}, "registered_peak": peak});
        owned.push(value);
    }
    case["owned_summary"] = json!({"kind":kind,"depths":owned.iter().map(|s|s["depth"].clone()).collect::<Vec<_>>(),"outcomes":owned.iter().map(|s|s["outcome"].clone()).collect::<Vec<_>>(),"owned":true});
    case["owned_observations"] = json!(owned);
    case
}
fn write_evidence(directory: &Path, report: &mut Value) {
    let mut logs = json!({});
    let mut write = |name: &str, raw: String| {
        fs::write(directory.join(name), raw).unwrap();
        logs[name] = json!(sha256(&directory.join(name)).unwrap());
    };
    for (graph, name) in FEATURE_LOGS {
        write(
            name,
            report["wasmtime_features"][graph]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>()
                .join(",")
                + "\n",
        );
    }
    let cargo = [
        json!({"reason":"compiler-artifact","target":{"name":"indexer","kind":["lib"]},"profile":{"test":true},"executable":report["binary"]}),
        json!({"reason":"compiler-artifact","target":{"name":"wasmtime","kind":["lib"]},"package_id":format!("git+https://github.com/wilfreddenton/wasmtime?rev={FORK_REVISION}#wasmtime@51.0.0-kontor.2"),"features":report["wasmtime_features"]["qualification"]}),
        json!({"reason":"build-finished","success":true}),
    ];
    write(
        "cargo.json",
        cargo.iter().map(|v| format!("{v}\n")).collect(),
    );
    for case in report["cases"].as_array().unwrap() {
        for (role, field) in [
            ("worker", "observations"),
            ("control", "control_observations"),
        ] {
            let samples = case[field].as_array().unwrap();
            for sample in samples {
                write(
                    sample["log"].as_str().unwrap(),
                    format!("KONTOR_STACK_REPORT:{}\n", strip_log(sample)),
                );
            }
            let raw_samples: Vec<_> = samples.iter().map(strip_log).collect();
            write(
                case[format!("{role}_log")].as_str().unwrap(),
                transcript(&raw_samples, &case[format!("{role}_summary")]),
            );
        }
        write(
            case["owned_log"].as_str().unwrap(),
            case["owned_observations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| format!("KONTOR_OWNED_STACK_REPORT:{s}\n"))
                .collect(),
        );
    }
    for (field, key, prefix) in [
        ("chain_log", "chains", "CHAIN_PROBE_REPORT:"),
        (
            "owned_chain_log",
            "owned_chains",
            "CHAIN_OWNED_PROBE_REPORT:",
        ),
    ] {
        write(
            report[field].as_str().unwrap(),
            report[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| format!("{prefix}{s}\n"))
                .collect(),
        );
    }
    write(report["ownership_log"].as_str().unwrap(),OWNERSHIP_TESTS.iter().map(|name|format!("test runtime::ownership::tests::{name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n")).collect());
    report["log_sha256"] = logs;
    save(directory, report);
}
fn save(directory: &Path, report: &Value) {
    fs::write(directory.join("qualification.json"), report.to_string()).unwrap();
}
fn load(directory: &Path) -> Value {
    serde_json::from_slice(&fs::read(directory.join("qualification.json")).unwrap()).unwrap()
}
fn fixture() -> TempDir {
    let root = tempdir().unwrap();
    for (runner, cell, os, arch) in PLATFORMS {
        for profile in ["dev", "release"] {
            let directory = root.path().join(format!("native-stack-{runner}-{profile}"));
            fs::create_dir(&directory).unwrap();
            let (mut chains, mut owned) = chains_fixture();
            for chain in chains
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .chain(owned.as_array_mut().unwrap())
            {
                chain["target_os"] = json!(os);
                chain["target_arch"] = json!(arch);
            }
            let mut report = json!({"schema_version":6,"cell":format!("{cell}/{profile}"),"source_sha":"a".repeat(40),"lockfile_sha256":"b".repeat(64),"binary_sha256":"c".repeat(64),
                "wasmtime_revision":FORK_REVISION,"wasmtime_features":{"production":expected_features("production"),"qualification":expected_features("qualification")},
                "feature_logs":feature_logs(),"cargo_log":"cargo.json","binary":format!("core/target/{}/deps/indexer-test",if profile=="dev" {"debug"} else {"release"}),"rustc_version_verbose":"rustc 1.99.1\n","host":"fixture",
                "cases":CASES.iter().map(|kind|case(kind,os,arch)).collect::<Vec<_>>(),"chains":chains,"owned_chains":owned,"chain_log":"chains.log","owned_chain_log":"owned-chains.log","ownership_log":"ownership.log"});
            write_evidence(&directory, &mut report);
        }
    }
    root
}
fn check(root: &Path) -> Result<Value> {
    compare(root, "success", None, None, None, "full")
}

#[test]
fn exact_profile_cells_sources_and_components_are_required() {
    let root = fixture();
    let result = check(root.path()).unwrap();
    assert_eq!(result["cells"].as_array().unwrap().len(), 6);
    for status in ["failure", "cancelled", "skipped"] {
        assert!(compare(root.path(), status, None, None, None, "full").is_err());
    }
    for policy in ["dev", "automatic", "", "release"] {
        assert!(compare(root.path(), "success", None, None, None, policy).is_err());
    }
    for (source, lock) in [(Some("wrong"), None), (None, Some("wrong"))] {
        assert!(compare(root.path(), "success", source, lock, None, "full").is_err());
    }
    for components in [
        json!({"stack_probe":"0".repeat(64)}),
        json!({"stack_probe":"d".repeat(64),"error_test":"0".repeat(64),"proxy":"f".repeat(64)}),
    ] {
        assert!(
            compare(
                root.path(),
                "success",
                None,
                None,
                Some(&components),
                "full"
            )
            .is_err()
        );
    }
    for (runner, _, _, _) in PLATFORMS {
        fs::remove_dir_all(root.path().join(format!("native-stack-{runner}-dev"))).unwrap();
    }
    assert_eq!(
        compare(
            root.path(),
            "success",
            Some(&"a".repeat(40)),
            Some(&"b".repeat(64)),
            None,
            "release"
        )
        .unwrap()["cells"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert!(check(root.path()).is_err());
    fs::remove_dir_all(root.path().join("native-stack-macos-15-release")).unwrap();
    assert!(compare(root.path(), "success", None, None, None, "release").is_err());
}

#[test]
fn matching_logs_do_not_hide_invalid_results_or_ownership() {
    let root = fixture();
    let directory = root.path().join("native-stack-ubuntu-24.04-dev");
    let baseline = load(&directory);
    for (pointer, value) in [
        ("/schema_version", json!(6.0)),
        ("/cell", json!("Linux-ARM64/dev")),
        ("/cases/0/first_failure", json!(5)),
        ("/cases/0/observations/0/target_arch", json!("aarch64")),
        ("/cases/0/observations/0/max_wasm_stack", json!(1)),
        ("/cases/0/observations/0/outcome", json!("process_signal")),
        ("/cases/0/observations/0/value", json!("wrong")),
        ("/cases/0/observations/0/last_depth", json!(1)),
        (
            "/cases/0/observations/0/reset/post/digest_matches",
            json!(false),
        ),
        ("/cases/0/observations/0/fuel/user", json!(101)),
        ("/cases/0/owned_observations/0/fuel/user", json!(101)),
        (
            "/cases/0/owned_observations/0/ownership/kind",
            json!("unowned"),
        ),
        (
            "/cases/0/owned_observations/0/ownership/fuel_yield_interval",
            json!(100000),
        ),
        ("/cases/0/owned_observations/0/sample_index", json!(true)),
        (
            "/cases/0/owned_observations/0/ownership/registered_peak",
            json!(0),
        ),
        (
            "/chains/0/trials/0/state_after_sha256",
            json!("2".repeat(64)),
        ),
        ("/chains/0/trials/0/balances/burned_after", json!("7")),
        ("/chains/0/trials/0/rollback_clean", json!(false)),
        ("/owned_chains/0/trials/0/ownership/kind", json!("unowned")),
    ] {
        let mut changed = baseline.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        write_evidence(&directory, &mut changed);
        assert!(check(root.path()).is_err(), "{pointer}");
    }
    write_evidence(&directory, &mut baseline.clone());
    check(root.path()).unwrap();
}

#[test]
fn cross_platform_and_complete_case_comparisons_remain_strict() {
    let root = fixture();
    let directory = root.path().join("native-stack-ubuntu-24.04-dev");
    let baseline = load(&directory);
    for key in ["cases", "chains", "owned_chains"] {
        let mut changed = baseline.clone();
        changed[key].as_array_mut().unwrap().pop();
        write_evidence(&directory, &mut changed);
        assert!(check(root.path()).is_err(), "{key}");
        let mut changed = baseline.clone();
        changed[key][1] = changed[key][0].clone();
        write_evidence(&directory, &mut changed);
        assert!(check(root.path()).is_err(), "duplicate {key}");
    }
    let mut changed = baseline.clone();
    for field in ["observations", "control_observations", "owned_observations"] {
        for sample in changed["cases"][0][field].as_array_mut().unwrap() {
            sample["fuel"]["user"] = json!(101);
        }
    }
    write_evidence(&directory, &mut changed);
    assert!(
        check(root.path())
            .unwrap_err()
            .to_string()
            .contains("cross-cell")
    );
    changed = baseline.clone();
    changed["chains"][0]["trials"][0]["fuel"]["system"] = json!(101);
    write_evidence(&directory, &mut changed);
    assert!(
        check(root.path())
            .unwrap_err()
            .to_string()
            .contains("cross-cell")
    );
    changed = baseline.clone();
    changed["chains"][0]["trials"][0]["state_before_sha256"] = json!("2".repeat(64));
    changed["chains"][0]["trials"][0]["state_after_sha256"] = json!("2".repeat(64));
    write_evidence(&directory, &mut changed);
    assert!(
        check(root.path())
            .unwrap_err()
            .to_string()
            .contains("cross-cell")
    );
}

#[test]
fn raw_evidence_and_lifecycle_markers_cannot_be_substituted() {
    let root = fixture();
    let directory = root.path().join("native-stack-ubuntu-24.04-dev");
    let baseline = load(&directory);
    for (name, raw, rehash) in [
        (
            baseline["cases"][0]["observations"][0]["log"]
                .as_str()
                .unwrap(),
            "truncated\n",
            false,
        ),
        (
            baseline["cases"][0]["owned_log"].as_str().unwrap(),
            "truncated\n",
            true,
        ),
        (
            "ownership.log",
            "test result: ok. 3 passed; 0 failed;\n",
            true,
        ),
        (
            "cargo.json",
            "{\"reason\":\"build-finished\",\"success\":false}\n",
            true,
        ),
        ("wasmtime-production-features.txt", "cache\n", true),
    ] {
        let mut changed = baseline.clone();
        write_evidence(&directory, &mut changed);
        fs::write(directory.join(name), raw).unwrap();
        if rehash {
            changed["log_sha256"][name] = json!(sha256(&directory.join(name)).unwrap());
            save(&directory, &changed);
        }
        assert!(check(root.path()).is_err(), "{name}");
    }
    let mut changed = baseline.clone();
    write_evidence(&directory, &mut changed);
    let name = changed["cases"][0]["observations"][0]["log"]
        .as_str()
        .unwrap();
    let raw = fs::read_to_string(directory.join(name)).unwrap() + "changed trailing diagnostic\n";
    fs::write(directory.join(name), raw).unwrap();
    assert!(check(root.path()).is_err());
    write_evidence(&directory, &mut changed);
    changed["log_sha256"]
        .as_object_mut()
        .unwrap()
        .remove("ownership.log");
    save(&directory, &changed);
    assert!(check(root.path()).is_err());
    write_evidence(&directory, &mut changed);
    fs::remove_file(directory.join("qualification.json")).unwrap();
    assert!(check(root.path()).is_err());
}

#[cfg(unix)]
#[test]
fn archive_paths_cannot_escape_through_symlinks() {
    let root = fixture();
    let outside = tempdir().unwrap();
    let directory = root.path().join("native-stack-ubuntu-24.04-dev");
    let report = load(&directory);
    let name = report["cases"][0]["observations"][0]["log"]
        .as_str()
        .unwrap();
    fs::rename(directory.join(name), outside.path().join(name)).unwrap();
    symlink(outside.path().join(name), directory.join(name)).unwrap();
    assert!(check(root.path()).is_err());
}

#[test]
fn command_binds_checkout_and_removes_stale_success_on_failure() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let evidence = fixture();
    let output = tempdir().unwrap();
    let output_path = output.path().join("comparison.json");
    let source = command_output(&root, Path::new("git"), &["rev-parse", "HEAD"], None)
        .unwrap()
        .trim()
        .to_owned();
    let lock = sha256(&root.join("core/Cargo.lock")).unwrap();
    let probe = sha256(&root.join("test-contracts/binaries/stack_probe.wasm.br")).unwrap();
    let chain_hashes = json!({"proxy":sha256(&root.join("test-contracts/binaries/proxy.wasm.br")).unwrap(),"error_test":sha256(&root.join("test-contracts/binaries/error_test.wasm.br")).unwrap()});
    for entry in fs::read_dir(evidence.path()).unwrap() {
        let directory = entry.unwrap().path();
        let mut report = load(&directory);
        report["source_sha"] = json!(source);
        report["lockfile_sha256"] = json!(lock);
        for case in report["cases"].as_array_mut().unwrap() {
            for field in ["observations", "control_observations", "owned_observations"] {
                for sample in case[field].as_array_mut().unwrap() {
                    sample["component_sha256"] = json!(probe);
                }
            }
        }
        for field in ["chains", "owned_chains"] {
            for chain in report[field].as_array_mut().unwrap() {
                chain["component_sha256"] = chain_hashes.clone();
            }
        }
        write_evidence(&directory, &mut report);
    }
    let args = |profiles: &str| CompareStackArgs {
        directory: evidence.path().to_owned(),
        output: output_path.clone(),
        upstream_status: "success".into(),
        profiles: profiles.into(),
        smoke_directory: None,
        lockfile: "core/Cargo.lock".into(),
    };
    let result = compare_stack(&root, args("full")).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&output_path).unwrap()).unwrap(),
        result
    );
    for (runner, _, _, _) in PLATFORMS {
        fs::remove_dir_all(evidence.path().join(format!("native-stack-{runner}-dev"))).unwrap();
    }
    assert!(
        compare_stack(&root, args("release"))
            .unwrap_err()
            .to_string()
            .contains("requires dev smoke")
    );
    assert!(!output_path.exists());
}
