use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use serde_json::{Value, json};
use tempfile::tempdir;

use super::{GUARD_MARKER, TARGET_MARKER, TERMINAL_MARKER, guard_control, thread_capacities};
use crate::container::sha256;
use crate::stack_evidence::resource_report::ThreadObservation;

fn runtime(os: &str, mode: &str, page: u64) -> Value {
    let requested = if mode == "reduced" {
        1_015_808
    } else {
        2_097_152
    };
    let threads: Vec<_> = ["tokio_worker", "tokio_worker", "blocking_pool", "block_on_caller"]
        .into_iter().enumerate().map(|(i, category)| {
            let base = (i as u64 + 1) * 4_194_304;
            let mac = os == "macos";
            let mapped = requested + if mac && page == 16_384 { 12_288 } else { 0 };
            let start = base + if mac { page } else { 0 };
            json!({
                "thread_category":category,"thread_id":format!("thread-{i}"),
                "process_id":100,"os_thread_id":1000+i,
                "identity_api":if mac {"macos_pthread_threadid_np"} else {"linux_gettid"},
                "page_size_bytes":page,"requested_bytes":if category=="tokio_worker" {json!(requested)} else {Value::Null},
                "mapped_bytes":mapped,"guard_bytes":page,"guard_start":base,"guard_end":base+page,
                "guard_verification":if mac {"macos_mach_vm_region_prot_none"} else {"linux_maps_prot_none"},
                "usable_bytes":mapped-if mac {0}else{page},"mapped_start":start,"mapped_end":start+mapped,
                "usable_start":base+page,"usable_end":start+mapped,
                "measurement_api":"pthread","guard_treatment":"verified interval","guard_verified":true,
            })
        }).collect();
    json!({"flavor":"multi_thread","worker_count":2,"worker_requested_bytes":requested,
        "thread_observations":threads,"blocking_pool_observed":true,"block_on_caller_observed":true})
}

#[test]
fn shared_observation_preserves_archived_shape_and_requires_nullable_request() {
    for os in ["linux", "macos"] {
        let fixture = runtime(os, "production", 4096);
        for record in fixture["thread_observations"].as_array().unwrap() {
            let observation: ThreadObservation = serde_json::from_value(record.clone()).unwrap();
            assert_eq!(serde_json::to_value(observation).unwrap(), *record);

            let mut missing = record.clone();
            missing.as_object_mut().unwrap().remove("requested_bytes");
            assert!(serde_json::from_value::<ThreadObservation>(missing).is_err());
            for invalid in [json!(true), json!(1.5), json!(-1), json!("4096")] {
                let mut malformed = record.clone();
                malformed["requested_bytes"] = invalid;
                assert!(serde_json::from_value::<ThreadObservation>(malformed).is_err());
            }
        }
    }
}

#[test]
fn measured_capacity_handles_both_platforms_and_rejects_range_identity_mutants() {
    for (os, page) in [("linux", 4096), ("macos", 4096), ("macos", 16_384)] {
        for mode in ["production", "reduced"] {
            let valid = runtime(os, mode, page);
            let groups = thread_capacities(&valid, mode, page, os, 100).unwrap();
            assert_eq!(groups["tokio_worker"].as_array().unwrap().len(), 2);
            assert_eq!(groups["tokio_worker"][0], valid["thread_observations"][0]);
            let mutations = [
                ("mapped_bytes", json!(0)),
                ("mapped_start", json!(u64::MAX)),
                ("mapped_end", json!(0)),
                ("usable_end", json!(0)),
                ("guard_end", json!(1)),
                ("guard_start", json!(u64::MAX)),
                ("guard_bytes", json!(0)),
                ("guard_verified", json!(false)),
                ("process_id", json!(101)),
                ("os_thread_id", json!(0)),
                ("thread_id", json!("")),
                ("page_size_bytes", json!(1)),
                ("measurement_api", json!("")),
                ("guard_treatment", json!("unknown")),
                ("guard_verification", json!("unverified")),
                ("requested_bytes", json!(1)),
                ("mapped_bytes", json!(true)),
                ("mapped_bytes", json!(1.0)),
                ("mapped_bytes", json!(-1)),
                ("extra", Value::Null),
            ];
            for (key, value) in mutations {
                let mut bad = valid.clone();
                bad["thread_observations"][0][key] = value;
                assert!(
                    thread_capacities(&bad, mode, page, os, 100).is_err(),
                    "{os}/{mode}/{key}"
                );
            }
            for key in ["thread_id", "os_thread_id"] {
                let mut bad = valid.clone();
                bad["thread_observations"][1][key] = bad["thread_observations"][0][key].clone();
                assert!(thread_capacities(&bad, mode, page, os, 100).is_err());
            }
            for key in ["blocking_pool_observed", "block_on_caller_observed"] {
                let mut bad = valid.clone();
                bad[key] = json!(false);
                assert!(thread_capacities(&bad, mode, page, os, 100).is_err());
            }
            let mut bad = valid.clone();
            bad["worker_count"] = json!(3);
            assert!(thread_capacities(&bad, mode, page, os, 100).is_err());
            assert!(thread_capacities(&valid, mode, 0, os, 100).is_err());
        }
    }
}

#[test]
fn macos_writable_pthread_offset_and_optional_nonworker_guards_are_preserved() {
    let mut valid = runtime("macos", "reduced", 16_384);
    let worker = &mut valid["thread_observations"][0];
    worker["usable_end"] = json!(worker["usable_end"].as_u64().unwrap() - 12_288);
    worker["usable_bytes"] = json!(worker["usable_bytes"].as_u64().unwrap() - 12_288);
    assert!(
        thread_capacities(&valid, "reduced", 16_384, "macos", 100)
            .unwrap_err()
            .to_string()
            .contains("pthread stack offset")
    );
    let mut valid = runtime("linux", "production", 4096);
    for index in [2, 3] {
        let thread = &mut valid["thread_observations"][index];
        for key in ["guard_bytes", "guard_start", "guard_end"] {
            thread[key] = json!(0);
        }
        thread["guard_verification"] = json!("pthread_reports_none");
    }
    thread_capacities(&valid, "production", 4096, "linux", 100).unwrap();
    valid["thread_observations"][0]["guard_verification"] = json!("linux_proc_self_mem_eio");
    thread_capacities(&valid, "production", 4096, "linux", 100).unwrap();
}

fn guard_fixture(directory: &Path, os: &str) -> (Value, Value, Vec<String>) {
    let manifest = json!({"guard_control_runner":{"test_name":"linux_guard","macos_test_name":"macos_guard","source_sha256":"source"},
        "artifacts":{"resource_worker_diagnostic":{"sha256":"source"}}});
    let name = if os == "linux" {
        "linux_guard"
    } else {
        "macos_guard"
    };
    let report = json!({"host":{"os":os},"binary_path":"/tmp/indexer-test","binary_sha256":"binary","source_sha":"source",
        "configurations":{"production":{"engine":{"page_size_bytes":4096},"process_log":{"path":"production.log"}},
            "reduced":{"engine":{"page_size_bytes":4096},"process_log":{"path":"reduced.log"}}},
        "guard_control":{"process":{"pid":103,"command":["/tmp/indexer-test","--exact",name,"--ignored","--nocapture"],
            "started_unix_ns":1000,"ended_unix_ns":1001,"exit_code":0,"signal":null,"timed_out":false,"complete":true,"test_harness_passed":true},
            "raw_log":{"path":"nested/guard.log","sha256":""}}});
    let mut lines = vec!["running 1 test".to_owned()];
    for (mode, pid, tid) in [("reduced", 104, 204), ("production", 105, 205)] {
        let target = json!({"mode":mode,"process_id":pid,"os_thread_id":tid,"page_size_bytes":4096,
            "guard_start":4096,"guard_end":8192,"address":6144,
            "guard_verification":if os=="linux" {"guard protected below pthread stack range"}else{"macos_mach_vm_region_prot_none"}});
        lines.push(format!("{GUARD_MARKER}{}",json!({"mode":mode,"signal":6,"target":target,"child_binary":"/tmp/indexer-test",
            "child_stdout":format!("running 1 test\n{TARGET_MARKER}{target}\n"),
            "child_stderr":format!("thread 'tokio-rt-worker' ({tid}) has overflowed its stack\nfatal runtime error: stack overflow, aborting\n")})));
    }
    lines.push(format!(
        "{TERMINAL_MARKER}{}",
        json!({"pid":103,"binary_path":"/tmp/indexer-test","binary_sha256":"binary",
        "embedded_source_sha":"source","modes":["reduced","production"],"complete":true})
    ));
    lines.push(format!("test {name} ... ok"));
    lines.push("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.14s".to_owned());
    fs::create_dir_all(directory.join("nested")).unwrap();
    (report, manifest, lines)
}

fn save(report: &mut Value, directory: &Path, lines: &[String]) {
    let path = directory.join("nested/guard.log");
    fs::write(&path, lines.join("\n") + "\n").unwrap();
    report["guard_control"]["raw_log"]["sha256"] = json!(sha256(&path).unwrap());
}

#[test]
fn raw_guard_faults_bind_both_children_to_process_source_and_fault_output() {
    for os in ["linux", "macos"] {
        let dir = tempdir().unwrap();
        let (mut report, manifest, lines) = guard_fixture(dir.path(), os);
        save(&mut report, dir.path(), &lines);
        guard_control(&report, &manifest, dir.path()).unwrap();
        for mutation in [
            "missing",
            "duplicate",
            "order",
            "source",
            "exit",
            "tid",
            "signal",
            "stderr",
            "target",
            "duplicate_key",
            "nested_duplicate",
            "unknown",
            "nonfinite",
        ] {
            let mut bad = report.clone();
            let mut raw = lines.clone();
            match mutation {
                "missing" => {
                    raw.remove(2);
                }
                "duplicate" => raw[2] = raw[1].clone(),
                "order" => raw.swap(2, 3),
                "source" => bad["source_sha"] = json!("other"),
                "exit" => bad["guard_control"]["process"]["exit_code"] = json!(1),
                "duplicate_key" => raw[1] = raw[1].replacen("{", "{\"signal\":6,", 1),
                "unknown" => raw[1] = raw[1].replacen("{", "{\"extra\":0,", 1),
                "nonfinite" => raw[1] = raw[1].replace("\"signal\":6", "\"signal\":NaN"),
                _ => {
                    let mut child: Value =
                        serde_json::from_str(raw[1].strip_prefix(GUARD_MARKER).unwrap()).unwrap();
                    match mutation {
                        "tid" => {
                            child["target"]["os_thread_id"] = json!(999);
                            child["child_stdout"] = json!(format!(
                                "running 1 test\n{TARGET_MARKER}{}\n",
                                child["target"]
                            ));
                        }
                        "signal" => child["signal"] = json!(11),
                        "stderr" => {
                            child["child_stderr"] = json!("fatal runtime error: unrelated abort")
                        }
                        "target" => child["target"]["address"] = json!(8192),
                        "nested_duplicate" => {
                            child["child_stdout"] = json!(format!(
                                "running 1 test\n{TARGET_MARKER}{}\n",
                                child["target"].to_string().replacen(
                                    "{",
                                    "{\"mode\":\"reduced\",",
                                    1
                                )
                            ))
                        }
                        _ => unreachable!(),
                    }
                    raw[1] = format!("{GUARD_MARKER}{child}");
                }
            }
            save(&mut bad, dir.path(), &raw);
            assert!(
                guard_control(&bad, &manifest, dir.path()).is_err(),
                "{os}/{mutation}"
            );
        }
    }
}

#[test]
fn raw_guard_archives_reject_substitution_aliases_escape_and_invalid_numbers() {
    let dir = tempdir().unwrap();
    let archive = dir.path().join("archive");
    let (mut report, manifest, lines) = guard_fixture(&archive, "linux");
    save(&mut report, &archive, &lines);
    let log = archive.join("nested/guard.log");
    fs::write(&log, "different").unwrap();
    assert!(guard_control(&report, &manifest, &archive).is_err());
    save(&mut report, &archive, &lines);
    let outside = dir.path().join("outside.log");
    fs::copy(&log, &outside).unwrap();
    symlink(&outside, archive.join("link.log")).unwrap();
    for path in [outside.to_str().unwrap(), "../outside.log", "link.log"] {
        let mut bad = report.clone();
        bad["guard_control"]["raw_log"]["path"] = json!(path);
        assert!(guard_control(&bad, &manifest, &archive).is_err());
    }
    let mut bad = report.clone();
    bad["configurations"]["production"]["process_log"]["path"] = json!("nested/guard.log");
    assert!(guard_control(&bad, &manifest, &archive).is_err());
    for (key, value) in [
        ("pid", json!(true)),
        ("pid", json!(1.0)),
        ("started_unix_ns", json!(u64::MAX)),
        ("ended_unix_ns", json!(0)),
        ("exit_code", json!(false)),
    ] {
        let mut bad = report.clone();
        bad["guard_control"]["process"][key] = value;
        assert!(guard_control(&bad, &manifest, &archive).is_err());
    }
}
