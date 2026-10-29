import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from resource_boundary_evidence import (TEST_NAME, expected_case_env,
                                        run_name, validate_bundle,
                                        validate_reviewed_discovery,
                                        validate_run)
from resource_boundary_manifest import (DISCOVERY_ROLE, MANIFEST,
                                        build_boundary_manifest)
from resource_evidence import sha256
from resource_manifest import ROOT, build_manifest


SOURCE_SHA = "1" * 40


def capacity(category, number, base, pid):
    guard = 4096 if category == "tokio_worker" else 0
    mapped = 2097152
    start = base + guard
    return {
        "thread_category": category,
        "thread_id": f"ThreadId({number})",
        "process_id": pid,
        "os_thread_id": number,
        "identity_api": "linux_gettid",
        "page_size_bytes": 4096,
        "requested_bytes": None,
        "mapped_bytes": mapped,
        "guard_bytes": guard,
        "guard_start": base if guard else 0,
        "guard_end": start if guard else 0,
        "guard_verification": ("linux_maps_prot_none" if guard
                               else "pthread_reports_none"),
        "usable_bytes": mapped,
        "mapped_start": start,
        "mapped_end": start + mapped,
        "usable_start": start,
        "usable_end": start + mapped,
        "measurement_api": "pthread_getattr_np",
        "guard_treatment": "separate_protected_page",
        "guard_verified": True,
    }


def teardown_events(mode):
    events = []
    identifier = 0
    for role, count in (("nested_chain", 1), ("post_observation", 5),
                        ("rollback_observation", 4),
                        ("target_native_auxiliary", 2 if mode == "paid" else 0)):
        for _ in range(count):
            for kind in ("reserved", "store_created", "table_destroyed",
                         "lease_released"):
                events.append({
                    "id": identifier, "role": role, "kind": kind,
                    "table_alive": False if kind == "table_destroyed" else None,
                })
            identifier += 1
    return events


def observation(case_id, index, depth, component_sha, mutations=None):
    leaf = case_id == "deepest_frame_host_call"
    wide = "_wide_" in case_id
    mode = "paid" if leaf else case_id.rsplit("_", 1)[1]
    outcome = "ok" if depth < 2 else "stack_overflow"
    charged = mode == "paid"
    balances = {
        "before": "100", "after": "99" if charged else "100",
        "restored": "100", "burned_before": "0",
        "burned_after": "1" if charged else "0",
        "supply_before": "100", "supply_after": "99" if charged else "100",
        "floor_before": "1",
        "floor_after": "0" if mode == "core" and outcome == "ok"
        and depth > 0 else "1",
        "floor_restored": "1",
    }
    result = {
        "role": DISCOVERY_ROLE, "sample_index": index,
        "sample_id": f"{DISCOVERY_ROLE}:{case_id}:{index:04}",
        "cache_mode": "warm_compiled_cache", "call_hook_installed": False,
        "fixture_contracts": 1,
        "kind": "paid_leaf_host" if leaf else (
            f"{mode}_wide" if wide else f"{mode}_recurse"),
        "depth": depth, "outcome": outcome,
        "error": None if outcome == "ok" else "typed Pulley stack overflow",
        "value": str((496 if wide else 1) * depth) if outcome == "ok" else None,
        "receipt": None if mode in ("view", "system") else {
            "status": "Ok" if outcome == "ok" else "Trap", "gas": 1,
        },
        "last_depth": (depth if mode in ("paid", "core")
                       and outcome == "ok" else 0),
        "child_markers": [], "rolled_back": outcome != "ok",
        "fuel": {"user": 100 if charged else 0,
                 "system": 0 if charged else 100, "deposit": 0},
        "gas_limit": 100000, "paid_fuel_limit": 100000000,
        "view_gas_limit": 100000, "view_fuel_limit": 100000000,
        "system_fuel_ceiling": 9223372036854775807,
        "gas_to_fuel_multiplier": 1000, "max_wasm_stack": 524288,
        "async_stack_size": 2097152,
        "engine_target": "pulley64-unknown-unknown-elf",
        "component_sha256": component_sha,
        "target_os": "linux", "target_arch": "aarch64",
        "teardown_events": teardown_events(mode), "teardown_probe_on": True,
        "error_class": None if outcome == "ok" else "deterministic",
        "typed_trap": None if outcome == "ok" else "StackOverflow",
        "host_io_suspended": leaf and outcome == "ok",
        "leaf_callback_seen": leaf and outcome == "ok",
        "live_store_peak": 1, "state_before_sha256": "b" * 64,
        "balance_transitions": balances,
        "reset": {
            "pre": {"live_invocations": 0, "stack_empty": True,
                    "savepoint_intact": True, "resource_count": 0,
                    "baseline_resource_count": 0,
                    "failure_rolled_back": True if outcome != "ok" else None},
            "post": {"persistent_digest_sha256": "b" * 64,
                     "baseline_digest_sha256": "b" * 64,
                     "digest_matches": True, "live_invocations": 0,
                     "stack_empty": True, "savepoint_restored": True,
                     "resource_count": 0, "balances_restored": True,
                     "floor_restored": True, "supply_restored": True},
        },
    }
    if mutations is not None:
        mutations(case_id, index, result)
    result["balance_transitions_sha256"] = hashlib.sha256(
        json.dumps(result["balance_transitions"], sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    return result


def calibration_depths():
    depths = [0, 1024]
    first_failure = 1024
    while first_failure > 2:
        first_failure //= 2
        depths.append(first_failure)
    depths.append(1)
    return depths


def trace_event(name, number=1, category="tokio_worker"):
    return {"name": name, "thread_id": f"ThreadId({number})",
            "os_thread_id": number, "category": category}


def make_run(directory, case_id, pid, binary_path, binary_sha,
             manifest_sha, component_sha, mutations=None,
             source_sha=SOURCE_SHA, trace_mutation=None):
    name = run_name(case_id, DISCOVERY_ROLE, "production")
    depths = calibration_depths()
    attempts = []
    timings = []
    events = [trace_event("fixture_preparation_entry"),
              trace_event("publication_entry"),
              trace_event("compiler_entry"), trace_event("compiler_exit"),
              trace_event("blocking_decode_entry", 3, "blocking_pool"),
              trace_event("blocking_decode_exit", 3, "blocking_pool"),
              trace_event("publication_exit"),
              trace_event("fixture_preparation_exit")]
    for index, depth in enumerate(depths):
        observed = observation(case_id, index, depth, component_sha, mutations)
        attempts.append({
            "case_id": case_id, "process_role": DISCOVERY_ROLE,
            "configuration": "production", "probe_on": True, "pid": pid,
            "sample_key": "calibration", "repeat_index": index,
            "depth": depth, "complete": True, "observation": observed,
        })
        timings.append({
            "role": DISCOVERY_ROLE, "kind": observed["kind"],
            "sample_index": index, "setup_ms": 1, "funding_ms": 1,
            "publication_ms": 1, "execution_ms": 1, "postcall_ms": 1,
            "total_sample_ms": 1,
        })
        events.extend(trace_event(event) for event in (
            "boundary_attempt_start", "sample_preparation_entry",
            "sample_preparation_exit", "operation_entry",
            "canonical_input_entry", "canonical_input_exit",
        ))
        if observed["outcome"] == "ok":
            events.extend(trace_event(event) for event in
                          ("canonical_output_entry", "canonical_output_exit"))
        events.extend(trace_event(event) for event in (
            "operation_exit", "postcall_observation_entry",
            "postcall_observation_exit", "teardown_entry", "teardown_exit",
            "boundary_attempt_end",
        ))
    runtime = {
        "scope": "paired_pulley_boundary_worker", "configuration": "production",
        "case_id": case_id, "process_role": DISCOVERY_ROLE, "pid": pid,
        "flavor": "multi_thread", "worker_count": 2,
        "worker_requested_bytes": None,
        "thread_observations": [
            capacity("tokio_worker", 1, 0x1000000, pid),
            capacity("tokio_worker", 2, 0x2000000, pid),
            capacity("blocking_pool", 3, 0x3000000, pid),
            capacity("block_on_caller", 4, 0x4000000, pid),
        ],
        "blocking_pool_observed": True, "block_on_caller_observed": True,
        "embedded_source_sha": source_sha, "binary_sha256": binary_sha,
    }
    trace = {"scope": runtime["scope"], "configuration": "production",
             "case_id": case_id, "process_role": DISCOVERY_ROLE,
             "events": events}
    if trace_mutation is not None:
        trace_mutation(case_id, trace["events"])
    summary = {
        "case_id": case_id, "process_role": DISCOVERY_ROLE,
        "configuration": "production", "probe_on": True, "pid": pid,
        "discovery": True, "last_success": 1, "first_failure": 2,
        "attempt_count": len(attempts), "component_sha256": component_sha,
        "engine_target": "pulley64-unknown-unknown-elf",
        "max_wasm_stack": 524288, "async_stack_size": 2097152,
        "cache_mode": "warm_compiled_cache", "complete": True,
    }
    terminal = {"case_id": case_id, "process_role": DISCOVERY_ROLE,
                "configuration": "production", "pid": pid,
                "attempt_count": len(attempts), "complete": True}
    lines = ["running 1 test"]
    for timing, attempt in zip(timings, attempts, strict=True):
        lines.extend(("KONTOR_STACK_TIMING:" + json.dumps(timing),
                      "BOUNDARY_PROBE_ATTEMPT:" + json.dumps(attempt)))
    lines.extend(("BOUNDARY_WORKER_RUNTIME=" + json.dumps(runtime),
                  "BOUNDARY_WORKER_TRACE=" + json.dumps(trace),
                  "BOUNDARY_PROBE_SUMMARY:" + json.dumps(summary),
                  "BOUNDARY_PROBE_TERMINAL:" + json.dumps(terminal),
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                  "1 filtered out; finished in 0.01s"))
    log = directory / f"{name}.log"
    log.write_text("\n".join(lines) + "\n")
    command = [binary_path, "--ignored", "--exact", TEST_NAME, "--nocapture"]
    return {
        "run_id": name, "case_id": case_id, "process_role": DISCOVERY_ROLE,
        "configuration": "production", "cell": "Linux-ARM64/dev",
        "argv": command, "case_env": expected_case_env(
            case_id, DISCOVERY_ROLE, "production"),
        "process": {"pid": pid, "command": command,
                    "started_unix_ns": pid * 1000,
                    "ended_unix_ns": pid * 1000 + 1,
                    "exit_code": 0, "signal": None, "timed_out": False,
                    "complete": True, "test_harness_passed": True},
        "raw_log": {"path": log.name, "sha256": sha256(log)},
        "binary_sha256_before": binary_sha,
        "binary_sha256_after": binary_sha,
        "source_sha": source_sha,
        "manifest_sha256": manifest_sha,
        "timeout_seconds": 600,
        "summary": summary, "runtime": runtime, "thread_trace": trace,
        "attempts": attempts, "timings": timings,
    }


class BoundaryCompositionTests(unittest.TestCase):
    def test_historical_archive_binds_all_nine_raw_runs_and_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "source"
            root.mkdir()

            def git(*args):
                return subprocess.run(["git", "-C", str(root), *args],
                                      check=True, capture_output=True,
                                      text=True).stdout.strip()

            def commit(message):
                git("add", ".")
                git("-c", "user.name=Test", "-c",
                    "user.email=test@example.invalid", "commit", "-qm", message)
                return git("rev-parse", "HEAD")

            git("init", "-q")
            source_dir = root / "tools/native-stack"
            source_dir.mkdir(parents=True)
            old_manifest = build_boundary_manifest()
            manifest_path = source_dir / "resource-boundary-manifest-v1.json"
            manifest_path.write_text(json.dumps(old_manifest, indent=2,
                                                sort_keys=True) + "\n")
            old_manifest_sha = sha256(manifest_path)
            old_v1_path = source_dir / "resource-manifest-v1.json"
            old_v1_path.write_text(json.dumps(build_manifest(), indent=2,
                                              sort_keys=True) + "\n")
            depths_path = source_dir / "resource-boundary-depths-v1.json"
            depths_path.write_text('{"cases":"pending"}\n')
            fixture = root / "test-contracts/binaries/stack_probe.wasm.br"
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes((ROOT / "test-contracts/binaries/stack_probe.wasm.br")
                                .read_bytes())
            runtime = root / "core/indexer/src/runtime/mod.rs"
            runtime.parent.mkdir(parents=True)
            runtime.write_text("stable frame source\n")
            discovery_sha = commit("discovery source")

            evidence = base / "evidence"
            evidence.mkdir()
            binary = evidence / "discovery-indexer-test"
            binary.write_bytes(b"historical selected test artifact")
            binary_sha = sha256(binary)
            original_binary = str(root / "core/target/indexer-test")
            component_sha = sha256(fixture)
            cases = [case["case_id"] for case in old_manifest["boundary_cases"]]
            cases.append(old_manifest["leaf_case"]["case_id"])
            runs = {
                run_name(case_id, DISCOVERY_ROLE, "production"):
                make_run(evidence, case_id, 100 + index,
                         original_binary, binary_sha, old_manifest_sha,
                         component_sha, source_sha=discovery_sha)
                for index, case_id in enumerate(cases)
            }
            control_dir = evidence / "control"
            control_dir.mkdir()

            def control_file(name, content):
                path = control_dir / name
                path.write_text(content)
                return {"path": name, "sha256": sha256(path)}

            profile = {"test": True, "opt_level": "0",
                       "debug_assertions": True}
            artifact = {
                "reason": "compiler-artifact", "package_id": "indexer-package",
                "target": {"name": "indexer", "kind": ["lib"]},
                "profile": profile, "executable": original_binary,
            }
            artifacts = control_file("cargo-artifacts.jsonl",
                                     json.dumps(artifact) + "\n" +
                                     json.dumps({"reason": "build-finished",
                                                 "success": True}) + "\n")
            metadata = control_file("cargo-metadata.json", json.dumps({
                "workspace_root": str(root / "core"),
                "packages": [{"name": "indexer", "id": "indexer-package"}],
            }) + "\n")
            guard_log = control_file("guard.log", "\n".join(
                "KONTOR_RESOURCE_GUARD_CONTROL=" + json.dumps({
                    "mode": mode, "target": {"page_size_bytes": 4096},
                }) for mode in ("reduced", "production")) + "\n")
            fiber = control_file("fiber.txt", "pinned fiber source\n")
            fiber_sources = {"crates/fiber/src/lib.rs": fiber["sha256"]}
            control = {
                "manifest_sha256": sha256(old_v1_path),
                "source_sha": discovery_sha,
                "binary_path": original_binary,
                "binary_sha256": binary_sha,
                "cargo_artifact": artifact,
                "cargo_artifacts": artifacts,
                "cargo_metadata": metadata,
                "guard_control": {"process": {}, "raw_log": guard_log},
                "wasmtime_source_files": {
                    "crates/fiber/src/lib.rs": fiber,
                },
            }
            control_path = control_dir / "resource-control-capture.json"
            control_path.write_text(json.dumps(control) + "\n")
            archive = {
                "schema_version": 1, "phase": "discovery",
                "qualification_status": "missing", "cell": "Linux-ARM64/dev",
                "manifest_sha256": old_manifest_sha,
                "source_sha": discovery_sha,
                "binary_path": original_binary,
                "binary_sha256": binary_sha, "timeout_seconds": 600,
                "control_capture": {"path": "control/" + control_path.name,
                                    "sha256": sha256(control_path)},
                "development_discovery": None, "reviewed_discovery": None,
                "discovery_binary": {"path": binary.name,
                                     "sha256": binary_sha},
                "runs": runs,
                "discovered_depths": {case_id: {
                    "last_success": 1, "first_failure": 2,
                } for case_id in cases},
                "remaining_case_bindings": sorted(
                    case["id"] for case in build_manifest()["cases"]
                    if case["family"] != "distinct_contract_chain"),
            }
            archive_path = evidence / "resource-boundary-capture.json"
            archive_path.write_text(json.dumps(archive) + "\n")
            final_manifest = copy.deepcopy(old_manifest)
            final_manifest["claim_status"] = "candidate_only"
            final_manifest["reviewed_discovery_sha256"] = sha256(archive_path)
            for case in final_manifest["boundary_cases"]:
                case.update(last_success=1, first_failure=2)
            final_manifest["leaf_case"].update(last_success=1,
                                               first_failure=2)
            manifest_path.write_text(json.dumps(final_manifest, indent=2,
                                                sort_keys=True) + "\n")
            depths_path.write_text('{"cases":"frozen"}\n')
            final_sha = commit("freeze reviewed depths")
            with patch("resource_boundary_evidence.ROOT", root), patch(
                    "resource_boundary_evidence.FIBER_SOURCE_FILES",
                    fiber_sources), patch(
                    "resource_boundary_evidence.check_guard_control") as guard_check:
                validate_reviewed_discovery(archive_path, sha256(archive_path),
                                            final_manifest, final_sha)
                guard_check.assert_called_once()
                wrong_pair = copy.deepcopy(final_manifest)
                wrong_pair["leaf_case"]["last_success"] = 2
                with self.assertRaises(ValueError):
                    validate_reviewed_discovery(archive_path,
                                                sha256(archive_path),
                                                wrong_pair, final_sha)
                binary.write_bytes(b"tampered artifact")
                with self.assertRaises(ValueError):
                    validate_reviewed_discovery(archive_path,
                                                sha256(archive_path),
                                                final_manifest, final_sha)
                binary.write_bytes(b"historical selected test artifact")
                bad_control = copy.deepcopy(control)
                bad_control["cargo_artifact"]["profile"]["opt_level"] = "3"
                control_path.write_text(json.dumps(bad_control) + "\n")
                archive["control_capture"]["sha256"] = sha256(control_path)
                archive_path.write_text(json.dumps(archive) + "\n")
                bad_manifest = copy.deepcopy(final_manifest)
                bad_manifest["reviewed_discovery_sha256"] = sha256(archive_path)
                with self.assertRaises(ValueError):
                    validate_reviewed_discovery(archive_path,
                                                sha256(archive_path),
                                                bad_manifest, final_sha)

    def test_all_nine_discovery_runs_validate_from_raw_transcripts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = build_boundary_manifest()
            manifest_sha = sha256(MANIFEST)
            component_sha = sha256(ROOT / "test-contracts/binaries/stack_probe.wasm.br")
            bundle = {"phase": "discovery", "cell": "Linux-ARM64/dev",
                      "source_sha": SOURCE_SHA,
                      "manifest_sha256": manifest_sha,
                      "binary_path": "/tmp/synthetic-indexer-test",
                      "binary_sha256": "a" * 64,
                      "timeout_seconds": 600}
            cases = [case["case_id"] for case in manifest["boundary_cases"]]
            cases.append(manifest["leaf_case"]["case_id"])
            for index, case_id in enumerate(cases):
                run = make_run(directory, case_id, 100 + index,
                               bundle["binary_path"], bundle["binary_sha256"],
                               manifest_sha, component_sha)
                signatures, counts = validate_run(run, bundle, manifest, directory)
                self.assertEqual(len(signatures), len(calibration_depths()))
                self.assertEqual(counts["compiler_entry"], 1)

    def test_full_pilot_discovery_composition_and_semantic_mutants(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest_sha = sha256(MANIFEST)
            component_sha = sha256(ROOT / "test-contracts/binaries/stack_probe.wasm.br")
            binary = directory / "discovery-indexer-test"
            binary.write_bytes(b"synthetic indexer test artifact")
            binary_sha = sha256(binary)
            original_binary_path = str(directory / "indexer-test")
            control_path = directory / "control.json"
            control_path.write_text("{}\n")
            cases = ("pulley_plain_paid", "pulley_wide_paid",
                     "deepest_frame_host_call")

            def bundle_with(mutations=None, trace_mutation=None):
                runs = {
                    run_name(case_id, DISCOVERY_ROLE, "production"):
                    make_run(directory, case_id, 100 + index,
                             original_binary_path, binary_sha, manifest_sha,
                             component_sha, mutations,
                             trace_mutation=trace_mutation)
                    for index, case_id in enumerate(cases)
                }
                remaining = sorted(case["id"] for case in build_manifest()["cases"]
                                   if case["family"] != "distinct_contract_chain")
                return {
                    "schema_version": 1, "phase": "pilot_discovery",
                    "qualification_status": "missing", "cell": "Linux-ARM64/dev",
                    "manifest_sha256": manifest_sha,
                    "source_sha": SOURCE_SHA,
                    "binary_path": original_binary_path,
                    "binary_sha256": binary_sha, "timeout_seconds": 600,
                    "control_capture": {"path": control_path.name,
                                        "sha256": sha256(control_path)},
                    "development_discovery": None,
                    "reviewed_discovery": None,
                    "discovery_binary": {"path": binary.name,
                                         "sha256": binary_sha},
                    "runs": runs,
                    "discovered_depths": {case_id: {
                        "last_success": 1, "first_failure": 2,
                    } for case_id in cases},
                    "remaining_case_bindings": remaining,
                }

            control = {
                "source_sha": SOURCE_SHA,
                "binary_sha256": binary_sha,
                "cargo_artifact": {"profile": {
                    "test": True, "opt_level": "0",
                    "debug_assertions": True,
                }},
                "guard_control": {"process": {
                    "pid": 999, "started_unix_ns": 999000,
                }},
            }
            with patch("resource_boundary_evidence.validate_control",
                       return_value=(control, Path(original_binary_path))), patch(
                           "resource_boundary_evidence.platform.machine",
                           return_value="aarch64"):
                self.assertEqual(len(validate_bundle(bundle_with(), directory)
                                     ["signatures"]), 3)
                for name, mutation in (
                    ("arch", lambda case, index, value:
                     value.update(target_arch="x86_64") if
                     case == "pulley_plain_paid" and index == 0 else None),
                    ("leaf", lambda case, index, value:
                     value.update(host_io_suspended=False) if
                     case == "deepest_frame_host_call" and index == 0 else None),
                    ("accounting", lambda case, index, value:
                     value["balance_transitions"].update(burned_after="0") if
                     case == "pulley_plain_paid" and index == 0 else None),
                    ("floor", lambda case, index, value:
                     value["balance_transitions"].update(floor_after="2") if
                     case == "pulley_plain_paid" and index == 0 else None),
                ):
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        validate_bundle(bundle_with(mutation), directory)
                def move_target_conversion(case_id, events):
                    if case_id != "pulley_plain_paid":
                        return
                    start = next(index for index, event in enumerate(events)
                                 if event["name"] == "boundary_attempt_start")
                    end = next(index for index, event in enumerate(events[start:],
                                                                    start)
                               if event["name"] == "boundary_attempt_end")
                    selected = [event for event in events[start:end]
                                if event["name"].startswith("canonical_")]
                    events[start:end] = [event for event in events[start:end]
                                         if not event["name"].startswith("canonical_")]
                    postcall = next(index for index, event in enumerate(events)
                                    if event["name"] ==
                                    "postcall_observation_entry")
                    events[postcall + 1:postcall + 1] = selected

                with self.assertRaises(ValueError):
                    validate_bundle(bundle_with(trace_mutation=
                                                move_target_conversion), directory)
                wrong_profile = bundle_with()
                control["cargo_artifact"]["profile"]["opt_level"] = "3"
                with self.assertRaises(ValueError):
                    validate_bundle(wrong_profile, directory)


if __name__ == "__main__":
    unittest.main()
