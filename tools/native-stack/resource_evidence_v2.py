#!/usr/bin/env python3
"""Validate candidate v2 per-process chain and Store teardown evidence."""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

sys.dont_write_bytecode = True

from capture_resource_chain import (CROSS_MODE_FIXTURE_REASONS, STACK_MODES,
                                    WORKER_TEST, cross_mode_initial_states,
                                    parse_worker)
from capture_resource_diagnostic import validate_control
from resource_evidence import (file_evidence, load_json_strict, no_duplicate_keys,
                               no_nonfinite_constants, require, sha256)
from resource_manifest import MANIFEST as V1_MANIFEST
from resource_manifest import ROOT, build_manifest
from resource_manifest_v2 import MANIFEST, ROLES, SCHEMA, build_manifest_v2


HISTORICAL_SOURCE = "b760345fab4f36ca85f35e1ff53e42b156f6e66a"
HISTORICAL_BUNDLE_SHA256 = "9d325af8461ca482104886c8add17c6a790405411c0454ce90b1b840bb9f0534"
TEARDOWN_ROLES = {
    "nested_chain", "target_native_auxiliary", "pre_observation",
    "post_observation", "rollback_observation",
}
AUXILIARY_ROLES = TEARDOWN_ROLES - {"nested_chain"}
EVENT_KEYS = {"id", "role", "kind", "table_alive"}
CASE_ENV_KEYS = {
    "KONTOR_RESOURCE_MODE", "KONTOR_CHAIN_MODE", "KONTOR_CHAIN_STORES",
    "KONTOR_CHAIN_TRAP_CONTROL", "KONTOR_RESOURCE_TEARDOWN_PROBE",
}


def run_name(case_id, role, configuration):
    return f"{case_id}_{role}_{configuration}"


def role_properties(role):
    require(role in ROLES, f"unknown process role: {role}")
    return role.startswith("trap_control"), role.endswith("observed")


def expected_case_env(case_id, role, configuration):
    identity = re.fullmatch(r"chain_(33|63|64|65)_(paid|view|core)", case_id)
    require(identity is not None, f"unknown chain case: {case_id}")
    trap_control, observed = role_properties(role)
    return {
        "KONTOR_RESOURCE_MODE": configuration,
        "KONTOR_CHAIN_MODE": identity.group(2),
        "KONTOR_CHAIN_STORES": identity.group(1),
        "KONTOR_CHAIN_TRAP_CONTROL": "1" if trap_control else "0",
        "KONTOR_RESOURCE_TEARDOWN_PROBE": "on" if observed else "off",
    }


def expected_trial_keys(role):
    trap_control, _ = role_properties(role)
    samples = ("target", "trap_control", "target") if trap_control else ("target",) * 3
    return [{"sample_key": sample, "repeat_index": index}
            for index, sample in enumerate(samples)]


def validate_teardown(events, expected_nested, expect_depth_gate):
    require(isinstance(events, list) and events, "teardown events are missing")
    states = {}
    roles = {}
    counts = Counter()
    rejections = Counter()
    for event in events:
        require(isinstance(event, dict) and set(event) == EVENT_KEYS,
                "teardown event has unknown fields")
        role, kind, identifier, alive = (event[key] for key in
                                         ("role", "kind", "id", "table_alive"))
        require(role in TEARDOWN_ROLES, "teardown event has unknown role")
        if kind in {"depth_gate_rejected", "physical_capacity_rejected", "reserve_rejected"}:
            require(identifier is None and alive is None,
                    "teardown rejection has a Store identity")
            rejections[kind, role] += 1
            continue
        require(kind != "store_initialization_failed",
                "post-reserve Store initialization failed")
        require(type(identifier) is int and identifier >= 0,
                "teardown Store identity is invalid")
        require(kind in {"reserved", "store_created", "table_destroyed", "lease_released"},
                "unknown teardown event kind")
        if kind == "reserved":
            require(identifier not in states and alive is None,
                    "duplicate teardown reservation")
            states[identifier] = "reserved"
            roles[identifier] = role
        else:
            require(roles.get(identifier) == role,
                    "teardown Store role changed")
            expected = {"store_created": "reserved", "table_destroyed": "store_created",
                        "lease_released": "table_destroyed"}[kind]
            if kind == "lease_released" and states.get(identifier) == "reserved":
                raise ValueError("post-reserve Store construction failed")
            require(states.get(identifier) == expected,
                    "teardown Store events are missing or reordered")
            require((type(alive) is bool and alive is False) if kind == "table_destroyed"
                    else alive is None, "Store table survived teardown or event is malformed")
            states[identifier] = kind
            if kind == "store_created":
                counts[role] += 1
    require(states and set(states) == set(range(len(states)))
            and all(state == "lease_released" for state in states.values()),
            "teardown Store identities are incomplete")
    require(counts["nested_chain"] == expected_nested,
            "nested chain Store count differs from frozen depth")
    require(rejections["depth_gate_rejected", "nested_chain"] == expect_depth_gate
            and sum(rejections.values()) == expect_depth_gate,
            "unexpected invocation depth or physical capacity rejection")
    return {"created": {role: counts[role] for role in sorted(TEARDOWN_ROLES)},
            "depth_gate_rejected": expect_depth_gate,
            "alive_after_teardown_count": 0,
            "all_ids_closed": True}


def marker_positions(path, report, role, configuration, pid, process_attempt_index=0):
    lines = path.read_text().splitlines()
    def parse_marked(marker):
        positions = [(index, json.loads(line.split(marker, 1)[1],
                                        object_pairs_hook=no_duplicate_keys,
                                        parse_constant=no_nonfinite_constants))
                     for index, line in enumerate(lines) if marker in line]
        return positions

    attempts = parse_marked("CHAIN_PROBE_ATTEMPT:")
    terminal = parse_marked("CHAIN_PROBE_TERMINAL:")
    require(len(attempts) == 3 and len(terminal) == 1,
            "missing or duplicate raw role-bound attempt or terminal marker")
    expected_keys = expected_trial_keys(role)
    for (position, event), key in zip(attempts, expected_keys, strict=True):
        require(event == {
            "case_id": report["case_id"], "process_role": role,
            "configuration": configuration,
            "process_attempt_index": process_attempt_index, "pid": pid,
            "sample_key": key["sample_key"],
            "repeat_index": key["repeat_index"], "complete": True,
        }, f"raw attempt at line {position} differs from process role or trial")
    require(terminal[0][1] == {
        "case_id": report["case_id"], "process_role": role,
        "configuration": configuration,
        "process_attempt_index": process_attempt_index, "pid": pid,
        "trial_count": len(attempts), "complete": True,
    }, "raw terminal differs from child identity or attempt count")
    prefixes = {
        "report_position": "CHAIN_PROBE_REPORT:",
        "runtime_position": "KONTOR_CHAIN_WORKER_RUNTIME=",
        "trace_position": "KONTOR_CHAIN_WORKER_TRACE=",
    }
    result = {}
    for key, marker in prefixes.items():
        positions = [index for index, line in enumerate(lines) if marker in line]
        require(len(positions) == 1, f"duplicate or missing {key}")
        result[key] = positions[0]
    complete = [index for index, line in enumerate(lines)
                if line.strip() == f"CHAIN_PROBE_COMPLETE mode={report['mode']} stores={report['stores']}"]
    harness = [index for index, line in enumerate(lines)
               if line.startswith("test result:")]
    require(len(complete) == len(harness) == 1,
            "duplicate or missing child terminal marker")
    result["complete_position"] = complete[0]
    result["harness_position"] = harness[0]
    result["attempt_positions"] = [position for position, _ in attempts]
    result["terminal_position"] = terminal[0][0]
    require(result["attempt_positions"] == sorted(result["attempt_positions"])
            and result["attempt_positions"][-1] < result["report_position"]
            < result["terminal_position"] < result["complete_position"]
            < result["runtime_position"] < result["trace_position"]
            < result["harness_position"], "child markers are out of order")
    result["trial_keys"] = [{"sample_key": event["sample_key"],
                             "repeat_index": event["repeat_index"]}
                            for _, event in attempts]
    require(result["trial_keys"] == [
        {"sample_key": trial["sample_key"], "repeat_index": trial["repeat_index"]}
        for trial in report["trials"]],
        "raw trial markers differ from final report")
    require(len(result["trial_keys"]) == len({(item["sample_key"], item["repeat_index"])
                                               for item in result["trial_keys"]}),
            "duplicate child trial marker")
    return result


def validate_process_record(run):
    case_id, role, configuration = (run[key] for key in
                                    ("case_id", "process_role", "configuration"))
    require(set(run["case_env"]) == CASE_ENV_KEYS
            and run["case_env"] == expected_case_env(case_id, role, configuration),
            "case-driving environment differs from allowlist")
    require(run["run_id"] == run_name(case_id, role, configuration)
            and run["process_attempt_index"] == 0,
            "process run identity differs from expected case")
    process = run["process"]
    argv = [run["argv"][0], "--ignored", "--exact", WORKER_TEST, "--nocapture"]
    require(run["argv"] == argv and process["command"] == argv
            and type(process["pid"]) is int and process["pid"] > 0
            and process["started_unix_ns"] > 0
            and process["ended_unix_ns"] > process["started_unix_ns"]
            and process["exit_code"] == 0 and process["signal"] is None
            and process["timed_out"] is False and process["complete"] is True
            and process["test_harness_passed"] is True,
            "child process failed, timed out, or changed command")
    require(run["binary_sha256_before"] == run["binary_sha256_after"],
            "test binary changed during child run")


def validate_engine_measurement(run):
    require(run["engine"]["target"] == run["report"]["engine_target"]
            and run["engine"]["pulley_stack_bytes"] == run["report"]["max_wasm_stack"]
            and run["engine"]["fiber_requested_bytes"] ==
                run["report"]["async_stack_size"]
            and run["engine"]["derivation_rule"] ==
                "round_up_requested_bytes_to_host_page",
            "child engine identity differs")
    page = run["engine"]["page_size_bytes"]
    require(type(page) is int and page > 0 and page & (page - 1) == 0
            and page == os.sysconf("SC_PAGE_SIZE")
            and all(thread["page_size_bytes"] == page for thread in
                    run["runtime"]["thread_observations"])
            and run["engine"]["fiber_effective_writable_bytes"] ==
                (run["engine"]["fiber_requested_bytes"] + page - 1) // page * page,
            "child fiber capacity derivation differs")


def run_semantics(run, v1_manifest, v2_manifest, directory):
    case_id, role, configuration = (run[key] for key in
                                    ("case_id", "process_role", "configuration"))
    trap_control, observed = role_properties(role)
    identity = re.fullmatch(r"chain_(33|63|64|65)_(paid|view|core)", case_id)
    require(identity is not None and (not trap_control or identity.group(1) == "64"),
            "unknown target or trap-control case")
    stores, chain_mode = int(identity.group(1)), identity.group(2)
    validate_process_record(run)
    process = run["process"]
    file_evidence(directory, run["raw_log"])
    raw_path = directory / run["raw_log"]["path"]
    schema_v1 = load_json_strict(V1_MANIFEST.with_name("resource-evidence-schema-v1.json"))
    parsed = parse_worker(raw_path, configuration, stores, process["pid"],
                          v1_manifest, schema_v1, chain_mode, trap_control)
    require(run["report"] == parsed["report"]
            and run["runtime"] == parsed["runtime"]
            and run["thread_trace"] == parsed["thread_trace"]
            and run["worker_execution"] == parsed["worker_execution"],
            "run differs from complete raw child transcript")
    require(run["report"]["teardown_probe_mode"] == ("on" if observed else "off")
            and run["report"]["target_os"] == "linux"
            and run["report"]["target_arch"] == "aarch64"
            and run["markers"] == marker_positions(raw_path, run["report"], role,
                                                    configuration, process["pid"],
                                                    run["process_attempt_index"])
            and run["markers"]["trial_keys"] == expected_trial_keys(role),
            "run role or ordered trial markers differ")
    counts = []
    observations = parsed["observations"]
    for index, (trial, observation) in enumerate(zip(run["report"]["trials"],
                                                    observations, strict=True)):
        if observed:
            teardown = validate_teardown(trial["teardown_events"], min(stores, 64),
                                         int(stores == 65))
            observation["resource_cleanup"]["invocation_table_released"] = True
            counts.append(teardown)
            if v2_manifest["auxiliary_count_status"] == "frozen":
                key = f"{case_id}/{role}/{configuration}/{index}"
                expected = v2_manifest["auxiliary_expected_counts"].get(key)
                require(expected is not None
                        and {auxiliary: teardown["created"][auxiliary]
                             for auxiliary in sorted(AUXILIARY_ROLES)} == expected,
                        "auxiliary Store count differs from reviewed fixture")
        else:
            require(trial["teardown_events"] is None,
                    "probe-off control emitted teardown events")
            counts.append(None)
    require(run["observations"] == observations and run["role_counts"] == counts,
            "observations or teardown counts differ from raw process")
    validate_engine_measurement(run)
    return observations


def normalized_for_probe_parity(observations):
    normalized = json.loads(json.dumps(observations))
    for observation in normalized:
        observation["resource_cleanup"]["invocation_table_released"] = None
    return normalized


def historical_semantics(observations):
    normalized = normalized_for_probe_parity(observations)
    for observation in normalized:
        observation["state"].pop("before_sha256")
        observation["state"].pop("after_sha256")
    return normalized


def validate_bundle(bundle, directory, allow_pilot=False):
    require(bundle.get("schema_version") == 2, "v2 validator rejects v1 evidence")
    schema = load_json_strict(SCHEMA)
    Draft202012Validator.check_schema(schema)
    error = next(Draft202012Validator(schema).iter_errors(bundle), None)
    require(error is None, f"v2 schema violation: {error}")
    v1_manifest = build_manifest()
    v2_manifest = build_manifest_v2()
    require(load_json_strict(V1_MANIFEST) == v1_manifest
            and load_json_strict(MANIFEST) == v2_manifest
            and bundle["manifest_sha256"] == sha256(MANIFEST),
            "v2 source or manifest closure changed")
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()
    require(bundle["source_sha"] == head,
            "v2 bundle source differs from checkout")
    require(bundle["qualification_status"] == "missing"
            and bundle["cell"] == "Linux-ARM64/dev"
            and bundle["auxiliary_count_status"] == v2_manifest["auxiliary_count_status"]
            and bundle["auxiliary_expected_counts"] ==
                v2_manifest["auxiliary_expected_counts"]
            and bundle["remaining_case_bindings"] == v2_manifest["remaining_case_ids"],
            "candidate bundle overclaims qualification or changes frozen counts")
    require(bundle["historical_reference"]["sha256"] == HISTORICAL_BUNDLE_SHA256,
            "historical phase10 bundle identity differs")
    file_evidence(directory, bundle["historical_reference"])
    historical = load_json_strict(directory / bundle["historical_reference"]["path"])
    require(historical["source_sha"] == HISTORICAL_SOURCE
            and historical["manifest_sha256"] ==
                "8ac4acad47f0d5caa2acc490475e2751f8090268309d60b229c62ffa5e39ad46",
            "historical phase10 source or manifest differs")
    if not allow_pilot:
        require(bundle["auxiliary_count_status"] == "frozen",
                "auxiliary Store counts are not frozen")
    file_evidence(directory, bundle["control_capture"])
    control, binary = validate_control(
        directory / bundle["control_capture"]["path"],
        bundle["control_capture"]["sha256"], v1_manifest)
    require(control["source_sha"] == bundle["source_sha"]
            and control["binary_path"] == bundle["binary_path"]
            and control["binary_sha256"] == bundle["binary_sha256"]
            and str(binary) == bundle["binary_path"]
            and control["manifest_sha256"] == sha256(V1_MANIFEST),
            "guard/source control differs from v2 run")
    control_entries = [control["cargo_artifacts"], control["cargo_metadata"],
                       control["guard_control"]["raw_log"],
                       *control["wasmtime_source_files"].values()]
    control_directory = directory / "control"
    for entry in control_entries:
        file_evidence(control_directory, entry)
    require({str(path.relative_to(control_directory)) for path in
             control_directory.rglob("*") if path.is_file()} ==
            {"resource-control-capture.json"} |
            {entry["path"] for entry in control_entries},
            "control archive has orphan or missing files")
    expected = {(item["case_id"], item["process_role"], configuration)
                for item in v2_manifest["case_roles"] for configuration in STACK_MODES}
    runs = bundle["runs"]
    require(set(runs) == {run_name(*item) for item in expected},
            "missing or extra child process role")
    identities = {(control["guard_control"]["process"]["pid"],
                   control["guard_control"]["process"]["started_unix_ns"])}
    signatures = {}
    for case_id, role, configuration in sorted(expected):
        run = runs[run_name(case_id, role, configuration)]
        require((run["case_id"], run["process_role"], run["configuration"]) ==
                (case_id, role, configuration)
                and run["cell"] == bundle["cell"]
                and run["source_sha"] == bundle["source_sha"]
                and run["manifest_sha256"] == bundle["manifest_sha256"]
                and run["binary_sha256_before"] == bundle["binary_sha256"]
                and run["timeout_seconds"] == bundle["timeout_seconds"]
                and run["argv"][0] == bundle["binary_path"],
                "child case, cell, source, or binary identity differs")
        identity = (run["process"]["pid"], run["process"]["started_unix_ns"])
        require(identity not in identities, "duplicate child process identity")
        identities.add(identity)
        signatures[case_id, role, configuration] = run_semantics(
            run, v1_manifest, v2_manifest, directory)
    for case_id in (item["id"] for item in v1_manifest["cases"]
                    if item["family"] == "distinct_contract_chain"):
        for role in ROLES:
            if (case_id, role, "reduced") not in signatures:
                continue
            reduced_workers = [thread["usable_bytes"] for thread in
                               runs[run_name(case_id, role, "reduced")]["runtime"]
                               ["thread_observations"]
                               if thread["thread_category"] == "tokio_worker"]
            production_workers = [thread["usable_bytes"] for thread in
                                  runs[run_name(case_id, role, "production")]["runtime"]
                                  ["thread_observations"]
                                  if thread["thread_category"] == "tokio_worker"]
            require(reduced_workers and production_workers
                    and min(production_workers) >= 2 * max(reduced_workers),
                    "actual worker usable-capacity ratio is below two")
            require(signatures[case_id, role, "reduced"] ==
                    signatures[case_id, role, "production"],
                    "full observations differ across worker stack configurations")
        for configuration in STACK_MODES:
            for observed_role, off_role in (("target_observed", "target_probe_off_control"),
                                            ("trap_control_observed", "trap_control_probe_off_control")):
                if (case_id, observed_role, configuration) not in signatures:
                    continue
                require(normalized_for_probe_parity(signatures[case_id, observed_role,
                                                               configuration]) ==
                        normalized_for_probe_parity(signatures[case_id, off_role,
                                                               configuration]),
                        "probe-on/off semantic or full SQLite parity differs")
            if case_id.startswith("chain_64_"):
                target = signatures[case_id, "target_observed", configuration][0]
                controls = signatures[case_id, "trap_control_observed", configuration]
                require(controls[0] == target == controls[2]
                        and controls[1]["outcome"] == "trap"
                        and controls[1]["trap"] == "UnreachableCodeReached",
                        "trap control differs from target or typed trap")
            for role in ROLES:
                key = (case_id, role, configuration)
                if key not in signatures:
                    continue
                historical_key = (f"{case_id}_"
                                  f"{'trap_control_' if role.startswith('trap_control') else ''}"
                                  f"{configuration}")
                require(historical_semantics(signatures[key]) == historical_semantics(
                    historical["runs"][historical_key]["observations"]),
                    "final-source fuel, balance, receipt, outcome, or peak differs from phase10")
    require(len(identities) == len(runs) + 1, "process identities are incomplete")
    expected_logs = {run["raw_log"]["path"] for run in runs.values()}
    require(len(expected_logs) == len(runs)
            and expected_logs == {path.name for path in directory.glob("*.log")},
            "orphan, duplicated, or missing child log")
    require({path.name for path in directory.iterdir() if path.is_file()} ==
            expected_logs | {bundle["historical_reference"]["path"],
                             "resource-chain-v2-capture.json"},
            "evidence archive has orphan or missing root files")
    captured = {
        f"{case_id}_{configuration}": {
            "observations": signatures[case_id, "target_observed", configuration]}
        for case_id in (item["id"] for item in v1_manifest["cases"]
                        if item["family"] == "distinct_contract_chain")
        for configuration in STACK_MODES
    }
    require(bundle["cross_mode_initial_states"] == cross_mode_initial_states(
        captured, CROSS_MODE_FIXTURE_REASONS),
        "cross-mode initial state fixture evidence differs")
    return signatures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--pilot", action="store_true")
    args = parser.parse_args()
    bundle = load_json_strict(args.bundle)
    validate_bundle(bundle, args.bundle.parent, allow_pilot=args.pilot)
    print("v2 candidate evidence validated; full resource qualification remains missing")


if __name__ == "__main__":
    main()
