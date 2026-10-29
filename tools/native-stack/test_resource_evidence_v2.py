"""Exercise v2 process identity and per-Store teardown rejection paths."""

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

import resource_evidence_v2
from capture_resource_chain import (cross_mode_initial_states, measured_trace,
                                    observation_from_trial)
from resource_evidence import sha256
from resource_manifest import ROOT, build_manifest
from test_capture_resource_chain import trial_fixture
from resource_evidence_v2 import (expected_case_env, historical_semantics,
                                  marker_positions, validate_process_record,
                                  validate_teardown)
from resource_manifest_v2 import MANIFEST, SCHEMA, build_manifest_v2


def store_events(count, role="nested_chain", depth_gate=False, auxiliary=None):
    events = []
    roles = [role] * count
    for auxiliary_role, extra in sorted((auxiliary or {}).items()):
        roles.extend([auxiliary_role] * extra)
    for identifier, store_role in enumerate(roles):
        events.extend([
            {"id": identifier, "role": store_role, "kind": "reserved", "table_alive": None},
            {"id": identifier, "role": store_role, "kind": "store_created", "table_alive": None},
        ])
    if depth_gate:
        events.append({"id": None, "role": "nested_chain",
                       "kind": "depth_gate_rejected", "table_alive": None})
    for identifier, store_role in reversed(list(enumerate(roles))):
        events.extend([
            {"id": identifier, "role": store_role, "kind": "table_destroyed",
             "table_alive": False},
            {"id": identifier, "role": store_role, "kind": "lease_released",
             "table_alive": None},
        ])
    return events


def process_run():
    case_id = "chain_64_paid"
    role = "target_observed"
    configuration = "reduced"
    argv = ["/tmp/chain-test", "--ignored", "--exact",
            "runtime::call::tests::native_stack_resource::chain_worker_case",
            "--nocapture"]
    return {
        "run_id": f"{case_id}_{role}_{configuration}", "case_id": case_id,
        "process_role": role, "configuration": configuration,
        "process_attempt_index": 0, "argv": argv,
        "case_env": expected_case_env(case_id, role, configuration),
        "binary_sha256_before": "a" * 64, "binary_sha256_after": "a" * 64,
        "process": {"pid": 10, "command": argv, "started_unix_ns": 100,
                    "ended_unix_ns": 200, "exit_code": 0, "signal": None,
                    "timed_out": False, "complete": True,
                    "test_harness_passed": True},
    }


def thread_fixture(pid, category, index, usable, page):
    return {
        "thread_category": category, "thread_id": f"thread-{index}",
        "process_id": pid, "os_thread_id": pid * 10 + index,
        "identity_api": "linux_gettid", "page_size_bytes": page,
        "requested_bytes": usable, "mapped_bytes": usable + page,
        "guard_bytes": page, "guard_start": 0, "guard_end": page,
        "guard_verification": "linux_maps_prot_none", "usable_bytes": usable,
        "mapped_start": 0, "mapped_end": usable + page,
        "usable_start": page, "usable_end": usable + page,
        "measurement_api": "pthread_getattr_np", "guard_treatment": "excluded",
        "guard_verified": True,
    }


def bundle_fixture(directory):
    manifest = build_manifest_v2()
    manifest_v1 = build_manifest()
    schema_v1 = json.loads((ROOT / "tools/native-stack/resource-evidence-schema-v1.json").read_text())
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()
    binary_path = "/tmp/resource-v2-test-binary"
    binary_hash = "a" * 64
    control_dir = directory / "control"
    control_dir.mkdir()
    control_entries = {}
    for name in ("cargo-artifacts.json", "cargo-metadata.json", "guard.log"):
        path = control_dir / name
        path.write_text(name)
        control_entries[name] = {"path": name, "sha256": sha256(path)}
    control = {
        "source_sha": head, "binary_path": binary_path,
        "binary_sha256": binary_hash,
        "manifest_sha256": sha256(ROOT / "tools/native-stack/resource-manifest-v1.json"),
        "cargo_artifacts": control_entries["cargo-artifacts.json"],
        "cargo_metadata": control_entries["cargo-metadata.json"],
        "guard_control": {"process": {"pid": 1, "started_unix_ns": 1},
                          "raw_log": control_entries["guard.log"]},
        "wasmtime_source_files": {},
    }
    control_path = control_dir / "resource-control-capture.json"
    control_path.write_text(json.dumps(control))
    runs = {}
    historical_runs = {}
    page = 16_384
    pid = 100
    for binding in manifest["case_roles"]:
        case_id, role = binding["case_id"], binding["process_role"]
        stores, mode = int(case_id.split("_")[1]), case_id.split("_")[2]
        trap_control = role.startswith("trap_control")
        observed = role.endswith("observed")
        for configuration in ("reduced", "production"):
            pid += 1
            name = f"{case_id}_{role}_{configuration}"
            usable = 1_048_576 if configuration == "reduced" else 2_097_152
            trials = []
            observations = []
            for index, key in enumerate(binding["trials"]):
                outcome = ("trap" if key["sample_key"] == "trap_control" else
                           "invocation_limit" if stores == 65 else "ok")
                trial = trial_fixture(mode, stores, outcome, key["sample_key"])
                auxiliary = manifest["auxiliary_expected_counts"].get(
                    f"{case_id}/{role}/{configuration}/{index}")
                trial.update(repeat_index=index,
                             teardown_events=(store_events(min(stores, 64),
                                             depth_gate=stores == 65,
                                             auxiliary=auxiliary)
                                              if observed else None))
                trials.append(trial)
                observation = observation_from_trial(
                    trial, case_id, outcome, schema_v1, key["sample_key"])
                observation["resource_cleanup"]["invocation_table_released"] = (
                    True if observed else None)
                observations.append(observation)
            argv = [binary_path, "--ignored", "--exact",
                    "runtime::call::tests::native_stack_resource::chain_worker_case",
                    "--nocapture"]
            log = directory / f"{name}.log"
            threads = [thread_fixture(pid, "tokio_worker", index, usable, page)
                       for index in (1, 2)]
            threads.append(thread_fixture(pid, "blocking_pool", 3, usable, page))
            threads.append(thread_fixture(pid, "block_on_caller", 4, usable, page))
            runtime = {
                "scope": "paired_chain_worker", "mode": configuration,
                "stores": stores, "chain_mode": mode, "trap_control": trap_control,
                "pid": pid, "flavor": "multi_thread", "worker_count": 2,
                "worker_requested_bytes": usable,
                "thread_observations": threads,
                "blocking_pool_observed": True,
                "block_on_caller_observed": True,
            }
            names = ["chain_attempt_start", "chain_preparation_entry",
                     "chain_preparation_exit", "chain_operation_entry",
                     "chain_guest_task_entry", "canonical_input_entry",
                     "canonical_input_exit", "canonical_output_entry",
                     "canonical_output_exit", "chain_guest_task_exit",
                     "chain_operation_exit", "chain_postcall_entry",
                     "canonical_input_entry", "canonical_input_exit",
                     "chain_postcall_exit", "chain_teardown_entry",
                     "canonical_input_entry", "canonical_input_exit",
                     "chain_teardown_exit", "chain_attempt_end"]
            trace_events = []
            for key in binding["trials"]:
                trial_names = names if stores != 65 and key["sample_key"] != "trap_control" else [
                    entry for entry in names if entry not in
                    ("canonical_output_entry", "canonical_output_exit")]
                trace_events.extend({"name": entry, "thread_id": "thread-1",
                                     "os_thread_id": pid * 10 + 1,
                                     "category": "tokio_worker"}
                                    for entry in trial_names)
            trace = {"scope": "paired_chain_worker", "mode": configuration,
                     "stores": stores, "chain_mode": mode,
                     "trap_control": trap_control, "events": trace_events}
            attempts = measured_trace(trace, runtime, configuration, stores, pid,
                                      mode, trap_control,
                                      tuple(key["sample_key"] for key in binding["trials"]),
                                      page_size=page)
            report = {
                "case_id": case_id, "mode": mode, "stores": stores,
                "resource_mode": configuration,
                "teardown_probe_mode": "on" if observed else "off",
                "target_only": not trap_control, "call_hook_installed": False,
                "trials": trials,
                "component_sha256": {
                    "error_test": manifest_v1["artifacts"]["error_test"]["sha256"],
                    "proxy": manifest_v1["artifacts"]["proxy"]["sha256"],
                },
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack":
                    manifest_v1["configurations"][configuration]["pulley_stack_bytes"],
                "async_stack_size":
                    manifest_v1["configurations"][configuration]["fiber_requested_bytes"],
                "target_os": "linux", "target_arch": "aarch64",
            }
            raw_attempts = [{
                "case_id": case_id, "process_role": role,
                "configuration": configuration, "process_attempt_index": 0,
                "pid": pid, "sample_key": key["sample_key"],
                "repeat_index": key["repeat_index"], "complete": True,
            } for key in binding["trials"]]
            raw_terminal = {
                "case_id": case_id, "process_role": role,
                "configuration": configuration, "process_attempt_index": 0,
                "pid": pid, "trial_count": 3, "complete": True,
            }
            raw_lines = ["running 1 test"]
            raw_lines.extend("CHAIN_PROBE_ATTEMPT:" + json.dumps(item)
                             for item in raw_attempts)
            raw_lines.extend([
                "CHAIN_PROBE_REPORT:" + json.dumps(report),
                "CHAIN_PROBE_TERMINAL:" + json.dumps(raw_terminal),
                f"CHAIN_PROBE_COMPLETE mode={mode} stores={stores}",
                "KONTOR_CHAIN_WORKER_RUNTIME=" + json.dumps(runtime),
                "KONTOR_CHAIN_WORKER_TRACE=" + json.dumps(trace),
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 1.0s",
            ])
            log.write_text("\n".join(raw_lines) + "\n")
            role_counts = ([validate_teardown(trial["teardown_events"],
                                              min(stores, 64), int(stores == 65))
                            for trial in trials] if observed else [None, None, None])
            run = {
                "run_id": name, "case_id": case_id, "process_role": role,
                "cell": "Linux-ARM64/dev", "configuration": configuration,
                "process_attempt_index": 0, "argv": argv,
                "case_env": expected_case_env(case_id, role, configuration),
                "process": {"pid": pid, "command": argv, "started_unix_ns": pid * 100,
                            "ended_unix_ns": pid * 100 + 1, "exit_code": 0,
                            "signal": None, "timed_out": False, "complete": True,
                            "test_harness_passed": True},
                "timeout_seconds": 600,
                "raw_log": {"path": log.name, "sha256": sha256(log)},
                "binary_sha256_before": binary_hash,
                "binary_sha256_after": binary_hash,
                "source_sha": head,
                "manifest_sha256": sha256(MANIFEST),
                "report": report,
                "runtime": runtime,
                "thread_trace": trace,
                "worker_execution": {"whole_operation_spawned": True,
                                     "source_sha256": manifest_v1["worker_runner"]["sha256"],
                                     "attempts": attempts},
                "observations": observations,
                "markers": marker_positions(log, report, role, configuration, pid),
                "role_counts": role_counts,
                "engine": {"target": "pulley64-unknown-unknown-elf",
                           "pulley_stack_bytes": report["max_wasm_stack"],
                           "fiber_requested_bytes": report["async_stack_size"],
                           "page_size_bytes": page,
                           "fiber_effective_writable_bytes": report["async_stack_size"],
                           "derivation_rule": "round_up_requested_bytes_to_host_page"},
            }
            runs[name] = run
            old_name = f"{case_id}_{'trap_control_' if trap_control else ''}{configuration}"
            old_observations = copy.deepcopy(observations)
            for observation in old_observations:
                observation["resource_cleanup"]["invocation_table_released"] = None
            historical_runs[old_name] = {"observations": old_observations}
    historical = {"source_sha": resource_evidence_v2.HISTORICAL_SOURCE,
                  "manifest_sha256":
                      "8ac4acad47f0d5caa2acc490475e2751f8090268309d60b229c62ffa5e39ad46",
                  "runs": historical_runs}
    historical_path = directory / "phase10-resource-chain-capture.json"
    historical_path.write_text(json.dumps(historical))
    captured = {f"{case_id}_{configuration}": {
        "observations": runs[f"{case_id}_target_observed_{configuration}"]["observations"]}
        for case_id in (item["case_id"] for item in manifest["case_roles"]
                        if item["process_role"] == "target_observed")
        for configuration in ("reduced", "production")}
    bundle = {
        "schema_version": 2, "status": "candidate_actual_binding",
        "qualification_status": "missing", "cell": "Linux-ARM64/dev",
        "source_sha": head, "manifest_sha256": sha256(MANIFEST),
        "binary_path": binary_path, "binary_sha256": binary_hash,
        "timeout_seconds": 600,
        "control_capture": {"path": "control/resource-control-capture.json",
                            "sha256": sha256(control_path)},
        "historical_reference": {"path": historical_path.name,
                                 "sha256": sha256(historical_path)},
        "runs": runs, "remaining_case_bindings": manifest["remaining_case_ids"],
        "auxiliary_count_status": manifest["auxiliary_count_status"],
        "auxiliary_expected_counts": manifest["auxiliary_expected_counts"],
        "cross_mode_initial_states": cross_mode_initial_states(captured, {}),
    }
    (directory / "resource-chain-v2-capture.json").write_text(json.dumps(bundle))
    return bundle, control


class EvidenceV2Tests(unittest.TestCase):
    def test_complete_bundle_closure_and_guard_revalidation(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            bundle, control = bundle_fixture(directory)
            measured = bundle["runs"]["chain_33_paid_target_observed_reduced"]
            resource_evidence_v2.validate_engine_measurement(measured)
            archived_page = copy.deepcopy(measured)
            archived_page["engine"]["page_size_bytes"] = 65_536
            for thread in archived_page["runtime"]["thread_observations"]:
                thread["page_size_bytes"] = 65_536
            resource_evidence_v2.validate_engine_measurement(archived_page)
            wrong_page = copy.deepcopy(measured)
            wrong_page["engine"]["page_size_bytes"] *= 2
            with self.assertRaisesRegex(ValueError, "fiber capacity"):
                resource_evidence_v2.validate_engine_measurement(wrong_page)
            with (patch.object(resource_evidence_v2, "HISTORICAL_BUNDLE_SHA256",
                               bundle["historical_reference"]["sha256"]),
                  patch.object(resource_evidence_v2, "validate_control",
                               return_value=(control, Path(bundle["binary_path"]))) as guard):
                signatures = resource_evidence_v2.validate_bundle(
                    bundle, directory, allow_pilot=True)
                self.assertEqual(len(signatures), 60)
                guard.assert_called_once()
                self.assertEqual(guard.call_args.kwargs["page_size"], 16_384)
                self.assertEqual(len(resource_evidence_v2.validate_bundle(
                    bundle, directory)), 60)
                changed = copy.deepcopy(bundle)
                changed_run = changed["runs"]["chain_64_paid_target_probe_off_control_reduced"]
                duplicate = changed["runs"][
                    "chain_64_paid_target_observed_reduced"]["process"]
                changed_run["process"]["pid"] = duplicate["pid"]
                changed_run["process"]["started_unix_ns"] = duplicate["started_unix_ns"]
                with self.assertRaisesRegex(ValueError, "duplicate child process identity"):
                    resource_evidence_v2.validate_bundle(changed, directory, allow_pilot=True)
                changed = copy.deepcopy(bundle)
                changed["runs"]["chain_33_paid_target_observed_reduced"][
                    "raw_log"]["sha256"] = "f" * 64
                with self.assertRaisesRegex(ValueError, "raw log hash mismatch"):
                    resource_evidence_v2.validate_bundle(changed, directory, allow_pilot=True)
                changed = copy.deepcopy(bundle)
                changed["runs"]["chain_33_paid_target_observed_reduced"][
                    "binary_sha256_after"] = "f" * 64
                with self.assertRaisesRegex(ValueError, "test binary changed"):
                    resource_evidence_v2.validate_bundle(changed, directory, allow_pilot=True)
                changed = copy.deepcopy(bundle)
                changed_run = changed["runs"]["chain_33_paid_target_observed_production"]
                changed_run["runtime"]["thread_observations"][0]["usable_bytes"] = 100
                with patch.object(resource_evidence_v2, "run_semantics",
                                  side_effect=lambda run, *_: run["observations"]):
                    with self.assertRaisesRegex(ValueError, "usable-capacity ratio"):
                        resource_evidence_v2.validate_bundle(changed, directory,
                                                             allow_pilot=True)
            with (patch.object(resource_evidence_v2, "HISTORICAL_BUNDLE_SHA256",
                               bundle["historical_reference"]["sha256"]),
                  patch.object(resource_evidence_v2, "validate_control",
                               side_effect=ValueError("guard transcript invalid"))):
                with self.assertRaisesRegex(ValueError, "guard transcript invalid"):
                    resource_evidence_v2.validate_bundle(bundle, directory, allow_pilot=True)

    def test_manifest_has_all_role_and_trial_bindings(self):
        manifest = build_manifest_v2()
        self.assertEqual(json.loads(MANIFEST.read_text()), manifest)
        self.assertEqual(len(manifest["case_roles"]), 30)
        self.assertEqual(len(manifest["remaining_case_ids"]), 29)
        self.assertEqual(manifest["auxiliary_count_status"], "frozen")
        self.assertEqual(len(manifest["auxiliary_expected_counts"]), 90)
        with patch("resource_manifest_v2.AUXILIARY_EXPECTED_COUNTS", {}):
            with self.assertRaisesRegex(ValueError, "cover each observed trial"):
                build_manifest_v2()
        for key, counts in manifest["auxiliary_expected_counts"].items():
            case_id = key.split("/", 1)[0]
            mode = case_id.split("_")[2]
            self.assertEqual(counts, {
                "pre_observation": 4, "post_observation": 5,
                "rollback_observation": 5,
                "target_native_auxiliary": 2 if mode == "paid" else 0,
            })
        self.assertEqual(sum(len(item["trials"]) for item in manifest["case_roles"]), 90)
        self.assertTrue(all(item["nested_chain_created"] in (33, 63, 64)
                            for item in manifest["case_roles"]))

    def test_teardown_closes_per_id_even_when_nested(self):
        result = validate_teardown(store_events(64, depth_gate=True), 64, 1)
        self.assertEqual(result["created"]["nested_chain"], 64)
        self.assertEqual(result["alive_after_teardown_count"], 0)

    def test_teardown_rejects_retained_missing_reordered_and_unknown(self):
        base = store_events(2)
        invalid = []
        retained = copy.deepcopy(base)
        retained[4]["table_alive"] = True
        invalid.append(retained)
        invalid.append(base[:-1])
        duplicate = copy.deepcopy(base)
        duplicate.append(copy.deepcopy(base[-1]))
        invalid.append(duplicate)
        reordered = copy.deepcopy(base)
        reordered[4], reordered[5] = reordered[5], reordered[4]
        invalid.append(reordered)
        unassigned = copy.deepcopy(base)
        unassigned[0]["role"] = "unassigned"
        invalid.append(unassigned)
        no_store = copy.deepcopy(base)
        no_store[1]["kind"] = "lease_released"
        invalid.append(no_store)
        failed_initialization = copy.deepcopy(base)
        failed_initialization.insert(2, {"id": 0, "role": "nested_chain",
                                         "kind": "store_initialization_failed",
                                         "table_alive": None})
        invalid.append(failed_initialization)
        for events in invalid:
            with self.subTest(events=events):
                with self.assertRaises(ValueError):
                    validate_teardown(events, 2, 0)

    def test_process_rejects_failure_drift_and_unexpected_env(self):
        base = process_run()
        validate_process_record(base)
        mutations = (
            ("process", "timed_out", True),
            ("process", "signal", 9),
            ("process", "exit_code", 1),
            ("process", "started_unix_ns", 300),
            ("binary_sha256_after", None, "b" * 64),
            ("process_attempt_index", None, 1),
        )
        for outer, inner, value in mutations:
            changed = copy.deepcopy(base)
            if inner is None:
                changed[outer] = value
            else:
                changed[outer][inner] = value
            with self.subTest(field=(outer, inner)):
                with self.assertRaises(ValueError):
                    validate_process_record(changed)
        changed = copy.deepcopy(base)
        changed["case_env"]["KONTOR_CHAIN_DEPTH"] = "100"
        with self.assertRaisesRegex(ValueError, "environment"):
            validate_process_record(changed)

    def test_marker_order_and_duplicates(self):
        report = {"case_id": "chain_64_paid", "mode": "paid", "stores": 64,
                  "trials": [{"sample_key": "target", "repeat_index": i}
                             for i in range(3)]}
        attempts = ["CHAIN_PROBE_ATTEMPT:" + json.dumps({
            "case_id": "chain_64_paid", "process_role": "target_observed",
            "configuration": "reduced", "process_attempt_index": 0,
            "pid": 10, "sample_key": "target", "repeat_index": i,
            "complete": True,
        }) for i in range(3)]
        terminal = "CHAIN_PROBE_TERMINAL:" + json.dumps({
            "case_id": "chain_64_paid", "process_role": "target_observed",
            "configuration": "reduced", "process_attempt_index": 0,
            "pid": 10, "trial_count": 3, "complete": True,
        })
        lines = [*attempts, "CHAIN_PROBE_REPORT:{}", terminal,
                 "CHAIN_PROBE_COMPLETE mode=paid stores=64",
                 "KONTOR_CHAIN_WORKER_RUNTIME={}", "KONTOR_CHAIN_WORKER_TRACE={}",
                 "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 1.0s"]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "child.log"
            path.write_text("\n".join(lines))
            self.assertEqual(marker_positions(path, report, "target_observed", "reduced", 10)
                             ["trial_keys"][1]["repeat_index"], 1)
            for bad in (lines + [lines[0]], [*lines[:4], *lines[5:]],
                        [lines[3], *lines[:3], *lines[4:]],
                        [lines[1], lines[0], *lines[2:]]):
                path.write_text("\n".join(bad))
                with self.assertRaises(ValueError):
                    marker_positions(path, report, "target_observed", "reduced", 10)
            path.write_text("\n".join(lines))
            with self.assertRaisesRegex(ValueError, "role"):
                marker_positions(path, report, "trap_control_observed", "reduced", 10)

    def test_schema_rejects_unknown_nested_fields_and_v1(self):
        schema = json.loads(SCHEMA.read_text())
        Draft202012Validator.check_schema(schema)
        self.assertFalse(Draft202012Validator(schema).is_valid({"schema_version": 1}))
        validator = Draft202012Validator({"$ref": "#/$defs/v2_teardown_event",
                                          "$defs": schema["$defs"]})
        event = store_events(1)[0]
        self.assertTrue(validator.is_valid(event))
        self.assertFalse(validator.is_valid({**event, "unexpected": True}))

    def test_historical_comparison_excludes_only_provenance_sensitive_full_db(self):
        observation = {"state": {"before_sha256": "a", "after_sha256": "a",
                                 "balances_sha256": "x", "marker": "m"},
                       "resource_cleanup": {"invocation_table_released": True},
                       "fuel": {"user": 1}}
        changed = copy.deepcopy(observation)
        changed["state"].update(before_sha256="b", after_sha256="b")
        self.assertEqual(historical_semantics([observation]),
                         historical_semantics([changed]))
        changed["fuel"]["user"] = 2
        self.assertNotEqual(historical_semantics([observation]),
                            historical_semantics([changed]))


if __name__ == "__main__":
    unittest.main()
