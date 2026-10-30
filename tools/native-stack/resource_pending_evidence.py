#!/usr/bin/env python3
"""Validate pending production-host I/O with distinct suspended and resumed evidence."""

import argparse
import hashlib
import json
import re
from decimal import Decimal
from pathlib import Path

from capture_resource_diagnostic import validate_control
from resource_boundary_evidence import (normalized_boundary_amount,
                                        validate_balance_transitions,
                                        validate_cell_identity, validate_trace)
from resource_evidence import (file_evidence, load_json_strict, no_duplicate_keys,
                               no_nonfinite_constants, require, sha256)
from resource_evidence_v2 import validate_teardown
from resource_finite_evidence import CONFIGURATIONS, ROLES, WORKER_TEST
from resource_manifest import MANIFEST, build_manifest


CASE_ID = "pending_host_io"
HOST_IMPORT = "kontor:built-in/crypto.sha256"
INPUT = b"native-stack-pending"
EXPECTED_VALUE = list(hashlib.sha256(INPUT).digest())
OBSERVATION_KEYS = {
    "async_stack_size", "balance_transitions", "balance_transitions_sha256",
    "cache_mode", "call_hook_installed", "child_markers", "component_sha256",
    "depth", "engine_target", "error", "error_class", "fixture_contracts",
    "fuel", "gas_limit", "gas_to_fuel_multiplier", "kind", "last_depth",
    "live_deposit_gas", "live_deposit_gas_sha256", "live_store_peak",
    "max_wasm_stack", "outcome", "paid_fuel_limit", "receipt", "reset",
    "role", "rolled_back", "sample_id", "sample_index", "state_before_sha256",
    "system_fuel_ceiling", "target_arch", "target_os", "teardown_events",
    "teardown_probe_on", "typed_trap", "value", "view_fuel_limit", "view_gas_limit",
}
MARKERS = {
    "attempts": "PENDING_HOST_IO_ATTEMPT:",
    "controls": "PENDING_HOST_IO_CONTROL:",
    "summary": "PENDING_HOST_IO_SUMMARY:",
    "runtime": "FINITE_STACK_RUNTIME=",
    "trace": "FINITE_STACK_TRACE=",
    "terminal": "FINITE_STACK_TERMINAL=",
}


def run_name(role, configuration):
    require(role in ROLES and configuration in CONFIGURATIONS,
            "unknown pending host I/O run")
    return f"{CASE_ID}-{role}-{configuration}"


def expected_case_env(role, configuration):
    run_name(role, configuration)
    return {
        "KONTOR_FINITE_STACK_CASE": CASE_ID,
        "KONTOR_FINITE_STACK_ROLE": role,
        "KONTOR_RESOURCE_MODE": configuration,
        "KONTOR_RESOURCE_TEARDOWN_PROBE": "on" if role == "target_observed" else "off",
    }


def parse_worker_log(path):
    lines = path.read_text().splitlines()
    require(sum(line.strip() == "running 1 test" for line in lines) == 1,
            "pending host transcript lacks one selected test")
    harness = [index for index, line in enumerate(lines) if re.fullmatch(
        r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s",
        line)]
    require(len(harness) == 1, "pending host test harness did not pass")
    records = {}
    positions = {}
    for key, marker in MARKERS.items():
        matched = [(index, json.loads(line.split(marker, 1)[1],
                                      object_pairs_hook=no_duplicate_keys,
                                      parse_constant=no_nonfinite_constants))
                   for index, line in enumerate(lines) if marker in line]
        expected_count = 4 if key == "attempts" else 2 if key == "controls" else 1
        require(len(matched) == expected_count,
                f"pending host transcript lacks {key}")
        positions[key] = [index for index, _ in matched]
        records[key] = ([value for _, value in matched]
                        if key in {"attempts", "controls"} else matched[0][1])
    a, c = positions["attempts"], positions["controls"]
    timings = [index for index, line in enumerate(lines) if "KONTOR_STACK_TIMING:" in line]
    require(len(timings) == 4
            and a[0] < timings[0] < a[1] < timings[1] < c[0]
            < a[2] < timings[2] < a[3] < timings[3] < c[1]
            < positions["summary"][0]
            < positions["runtime"][0] < positions["trace"][0]
            < positions["terminal"][0] < harness[0],
            "pending host markers, timings, or harness result are out of order")
    return records


def validate_observation(attempt, role, configuration, sample_index,
                         repeat_index, sample_key, manifest, cell):
    observation = attempt["observation"]
    require(isinstance(observation, dict) and set(observation) == OBSERVATION_KEYS
            and observation["role"] == role
            and observation["sample_index"] == sample_index
            and observation["sample_id"] == f"{role}:view_crypto:{sample_index:04}"
            and observation["kind"] == "view_crypto"
            and observation["depth"] == 0
            and observation["fixture_contracts"] == 1
            and observation["cache_mode"] == "warm_compiled_cache"
            and observation["child_markers"] == []
            and observation["component_sha256"] ==
                manifest["artifacts"]["crypto_component"]["sha256"]
            and observation["target_os"] ==
                ("macos" if cell.startswith("macOS-") else "linux")
            and observation["target_arch"] ==
                ("x86_64" if cell.startswith("Linux-X64/") else "aarch64")
            and observation["engine_target"] == "pulley64-unknown-unknown-elf"
            and observation["max_wasm_stack"] == 524288
            and observation["async_stack_size"] ==
                (1048576 if configuration == "reduced" else 2097152)
            and observation["gas_limit"] == 100000
            and observation["paid_fuel_limit"] == 100000000
            and observation["view_fuel_limit"] == 100000000
            and observation["view_gas_limit"] == 100000
            and observation["gas_to_fuel_multiplier"] == 1000
            and observation["live_store_peak"] == 1
            and observation["call_hook_installed"] is False,
            "pending host guest, engine, or execution path changed")
    require(observation["outcome"] == "ok"
            and observation["error"] is None
            and observation["error_class"] is None
            and observation["typed_trap"] is None
            and json.loads(observation["value"]) == EXPECTED_VALUE
            and observation["receipt"] is None
            and observation["last_depth"] == 0
            and observation["rolled_back"] is False,
            "pending host output, result class, or view receipt differs")
    fuel = observation["fuel"]
    require(set(fuel) == {"user", "system", "deposit"}
            and all(type(value) is int and value >= 0 for value in fuel.values())
            and fuel["system"] > 0 and fuel["user"] == fuel["deposit"] == 0,
            "pending host system fuel differs")
    reset = observation["reset"]
    pre, post = reset["pre"], reset["post"]
    digest = observation["state_before_sha256"]
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
            and digest == post["persistent_digest_sha256"] ==
                post["baseline_digest_sha256"]
            and pre["live_invocations"] == post["live_invocations"] == 0
            and pre["stack_empty"] is pre["savepoint_intact"] is True
            and post["stack_empty"] is post["savepoint_restored"] is True
            and post["digest_matches"] is True
            and all(post[key] is True for key in
                    ("balances_restored", "floor_restored", "supply_restored"))
            and pre["resource_count"] == pre["baseline_resource_count"] ==
                post["resource_count"]
            and pre["failure_rolled_back"] is None,
            "pending host full persistent state or resources did not reset")
    balances = observation["balance_transitions"]
    live_gas = observation["live_deposit_gas"]
    validate_balance_transitions(balances, "view", "ok", 0,
                                 observation["balance_transitions_sha256"])
    encoded = json.dumps(live_gas, sort_keys=True, separators=(",", ":")).encode()
    require(set(live_gas) == {"before", "after", "restored"}
            and observation["live_deposit_gas_sha256"] ==
                hashlib.sha256(encoded).hexdigest()
            and all(type(value) is int and value >= 0 for value in live_gas.values())
            and live_gas["before"] == live_gas["after"] == live_gas["restored"] == 8
            and all(Decimal(normalized_boundary_amount(balances[key])) ==
                    Decimal(8) / Decimal(10**9) for key in
                    ("floor_before", "floor_after", "floor_restored")),
            "pending host storage collateral changed or lacks full accounting")
    require(observation["teardown_probe_on"] is (role == "target_observed"),
            "pending host teardown probe role differs")
    if role == "target_observed":
        counts = validate_teardown(observation["teardown_events"], 1, 0)["created"]
        require(counts["nested_chain"] == 1
                and counts["target_native_auxiliary"] == 0
                and counts["post_observation"] == 4
                and counts["rollback_observation"] == 4,
                "pending host Store lifecycle changed")
    else:
        require(observation["teardown_events"] is None,
                "pending host probe-off role emitted teardown events")
    return {
        "sample_key": sample_key, "repeat_index": repeat_index,
        "outcome": observation["outcome"], "value": observation["value"],
        "fuel": fuel, "receipt": observation["receipt"],
        "state_before_sha256": digest,
        "state_after_sha256": post["persistent_digest_sha256"],
        "balances": balances, "live_deposit_gas": live_gas,
    }


def validate_phase_attempts(attempts, role, configuration, pid):
    require([(item["sample_key"], item["repeat_index"]) for item in attempts] ==
            [("suspended", 0), ("resumed", 0), ("suspended", 1), ("resumed", 1)]
            and all(set(item) == {"case_id", "configuration", "process_role",
                                      "sample_key", "repeat_index", "pid", "host_import",
                                      "host_entered", "host_poll_pending_count",
                                      "guest_task_pending", "other_task_progressed",
                                      "observation"}
                    and item["case_id"] == CASE_ID
                    and item["configuration"] == configuration
                    and item["process_role"] == role
                    and item["pid"] == pid
                    and item["host_import"] == HOST_IMPORT
                    and item["host_entered"] is True
                    and item["other_task_progressed"] is True for item in attempts)
            and all(type(item["host_poll_pending_count"]) is int for item in attempts)
            and [item["host_poll_pending_count"] for item in attempts] == [1, 1, 2, 2]
            and all(attempts[index]["guest_task_pending"] is True
                    and attempts[index]["observation"] is None for index in (0, 2))
            and all(attempts[index]["guest_task_pending"] is False for index in (1, 3)),
            "pending host suspension and resumption phase markers differ")


def validate_control_parity(resumed_signature, control_signature):
    require({key: value for key, value in resumed_signature.items()
             if key != "sample_key"} ==
            {key: value for key, value in control_signature.items()
             if key != "sample_key"},
            "pending and unshadowed production host semantics differ")


def validate_run(run, bundle, manifest, directory):
    role, configuration = run["process_role"], run["configuration"]
    name = run_name(role, configuration)
    command = [bundle["binary_path"], "--ignored", "--exact", WORKER_TEST, "--nocapture"]
    process = run["process"]
    require(run["run_id"] == name and run["case_id"] == CASE_ID
            and run["cell"] == bundle["cell"]
            and run["case_env"] == expected_case_env(role, configuration)
            and run["source_sha"] == bundle["source_sha"]
            and run["binary_sha256_before"] == run["binary_sha256_after"] ==
                bundle["binary_sha256"]
            and run["argv"] == process["command"] == command
            and type(process["pid"]) is int and process["pid"] > 0
            and process["exit_code"] == 0 and process["signal"] is None
            and process["timed_out"] is False and process["complete"] is True
            and process["test_harness_passed"] is True
            and process["started_unix_ns"] < process["ended_unix_ns"],
            "pending host child identity, command, or process completion differs")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in
                ("attempts", "controls", "summary", "runtime", "trace", "terminal")),
            "pending host records differ from raw process transcript")
    attempts = parsed["attempts"]
    controls = parsed["controls"]
    validate_phase_attempts(attempts, role, configuration, process["pid"])
    require(all(set(item) == {"case_id", "configuration", "process_role",
                                      "sample_key", "repeat_index", "pid", "host_import",
                                      "linker", "observation"}
                and item["case_id"] == CASE_ID
                and item["configuration"] == configuration
                and item["process_role"] == role
                and item["sample_key"] == "unshadowed_control"
                and item["repeat_index"] == index
                and item["pid"] == process["pid"]
                and item["host_import"] == HOST_IMPORT
                and item["linker"] == "production"
                for index, item in enumerate(controls)),
            "pending host unshadowed control identity differs")
    summary, runtime, terminal = (parsed[key] for key in
                                  ("summary", "runtime", "terminal"))
    require(summary == {"case_id": CASE_ID, "configuration": configuration,
                        "process_role": role, "sample_count": 4,
                        "host_calls": 2, "host_poll_pending_count": 2,
                        "control_count": 2, "complete": True}
            and terminal == {"case_id": CASE_ID, "configuration": configuration,
                             "process_role": role, "pid": process["pid"],
                             "sample_count": 4, "complete": True}
            and runtime["scope"] == "paired_finite_stack_worker"
            and all(runtime[key] == expected for key, expected in
                    (("case_id", CASE_ID), ("configuration", configuration),
                     ("process_role", role), ("pid", process["pid"]),
                     ("embedded_source_sha", bundle["source_sha"]),
                     ("binary_sha256", bundle["binary_sha256"]))),
            "pending host summary, runtime, or terminal identity differs")
    os_name = "macos" if bundle["cell"].startswith("macOS-") else "linux"
    resumed = [attempts[1], attempts[3]]
    operation_order = [resumed[0], controls[0], resumed[1], controls[1]]
    validate_trace(parsed["trace"], runtime, operation_order, os_name,
                   ("finite_stack_attempt_start", "finite_stack_attempt_end"))
    signatures = []
    for index, (resumed_item, control_item) in enumerate(zip(resumed, controls, strict=True)):
        resumed_signature = validate_observation(
            resumed_item, role, configuration, index * 2, index, "resumed",
            manifest, bundle["cell"])
        control_signature = validate_observation(
            control_item, role, configuration, index * 2 + 1, index,
            "unshadowed_control", manifest, bundle["cell"])
        validate_control_parity(resumed_signature, control_signature)
        signatures.append(resumed_signature)
    return signatures


def validate_bundle(bundle, directory, archive_binary=None):
    manifest = build_manifest()
    require(set(bundle) == {"schema_version", "qualification_status", "cell",
                            "manifest_sha256", "source_sha", "binary_path",
                            "binary_sha256", "control_capture", "runs"}
            and bundle["schema_version"] == 1
            and load_json_strict(MANIFEST) == manifest
            and bundle["manifest_sha256"] == sha256(MANIFEST)
            and bundle["qualification_status"] == "missing",
            "pending host source or claim status differs")
    file_evidence(directory, bundle["control_capture"])
    control, binary = validate_control(
        directory / bundle["control_capture"]["path"],
        bundle["control_capture"]["sha256"], manifest,
        archive_binary=archive_binary, expected_cell=bundle["cell"])
    validate_cell_identity(bundle["cell"], control["cargo_artifact"],
                           check_host=archive_binary is None)
    require(control["source_sha"] == bundle["source_sha"]
            and control["binary_sha256"] == bundle["binary_sha256"]
            and str(binary) == bundle["binary_path"],
            "pending host control source or binary differs")
    expected = {(role, configuration) for role in ROLES
                for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "pending host process registry has missing or extra children")
    process_ids = [(run["process"]["pid"], run["process"]["started_unix_ns"])
                   for run in bundle["runs"].values()]
    process_ids.append((control["guard_control"]["process"]["pid"],
                        control["guard_control"]["process"]["started_unix_ns"]))
    require(len(process_ids) == len(set(process_ids))
            and {run["raw_log"]["path"] for run in bundle["runs"].values()} ==
                {path.name for path in directory.glob("*.log")},
            "pending host child identities or raw logs overlap")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle,
                                    manifest, directory) for key in sorted(expected)}
    reference = signatures["target_observed", "production"]
    require(all({key: value for key, value in item.items() if key != "repeat_index"} ==
                {key: value for key, value in reference[0].items() if key != "repeat_index"}
                for item in reference),
            "pending host repeats changed semantics")
    for role in ROLES:
        for configuration in CONFIGURATIONS:
            require(signatures[role, configuration] == reference,
                    "pending host role or stack configuration changed semantics")
        reduced = [item["usable_bytes"] for item in
                   bundle["runs"][run_name(role, "reduced")]["runtime"]["thread_observations"]
                   if item["thread_category"] == "tokio_worker"]
        production = [item["usable_bytes"] for item in
                      bundle["runs"][run_name(role, "production")]["runtime"]["thread_observations"]
                      if item["thread_category"] == "tokio_worker"]
        require(reduced and production and min(production) >= 2 * max(reduced),
                "pending host measured worker-capacity ratio is below two")
    return signatures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    bundle = load_json_strict(args.capture)
    validate_bundle(bundle, args.capture.parent)
    print(json.dumps({"status": "validated", "runs": len(bundle["runs"])},
                     sort_keys=True))


if __name__ == "__main__":
    main()
