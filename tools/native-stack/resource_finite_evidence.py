#!/usr/bin/env python3
"""Validate real paid finite-stack child transcripts and source closure."""

import argparse
import json
import re
from pathlib import Path

from capture_resource_diagnostic import validate_control
from resource_boundary_evidence import (validate_balance_transitions,
                                        validate_cell_identity, validate_live_deposit_gas,
                                        validate_trace)
from resource_evidence import (file_evidence, load_json_strict, no_duplicate_keys,
                               no_nonfinite_constants, require, sha256)
from resource_evidence_v2 import validate_teardown
from resource_manifest import MANIFEST, build_manifest


CASES = {"large_frame_paid": 3, "max_gas_paid": 2}
ROLES = ("target_observed", "probe_off_control")
CONFIGURATIONS = ("reduced", "production")
WORKER_TEST = "runtime::call::tests::native_stack_resource::finite_stack_worker_case"
MARKERS = {
    "attempts": "FINITE_STACK_ATTEMPT:",
    "summary": "FINITE_STACK_SUMMARY:",
    "runtime": "FINITE_STACK_RUNTIME=",
    "trace": "FINITE_STACK_TRACE=",
    "terminal": "FINITE_STACK_TERMINAL=",
}


def run_name(case_id, role, configuration):
    require(case_id in CASES and role in ROLES and configuration in CONFIGURATIONS,
            "unknown finite-stack run")
    return f"{case_id}-{role}-{configuration}"


def expected_case_env(case_id, role, configuration):
    run_name(case_id, role, configuration)
    return {
        "KONTOR_FINITE_STACK_CASE": case_id,
        "KONTOR_FINITE_STACK_ROLE": role,
        "KONTOR_RESOURCE_MODE": configuration,
        "KONTOR_RESOURCE_TEARDOWN_PROBE": "on" if role == "target_observed" else "off",
    }


def parse_worker_log(path):
    lines = path.read_text().splitlines()
    require(sum(line.strip() == "running 1 test" for line in lines) == 1,
            "finite stack transcript lacks one selected test")
    harness = [index for index, line in enumerate(lines) if re.fullmatch(
        r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s",
        line)]
    require(len(harness) == 1, "finite stack test harness did not pass")
    records = {}
    positions = {}
    for key, marker in MARKERS.items():
        matched = [(index, json.loads(line.split(marker, 1)[1],
                                      object_pairs_hook=no_duplicate_keys,
                                      parse_constant=no_nonfinite_constants))
                   for index, line in enumerate(lines) if marker in line]
        require(bool(matched) if key == "attempts" else len(matched) == 1,
                f"finite stack transcript lacks {key}")
        positions[key] = [index for index, _ in matched]
        records[key] = [value for _, value in matched] if key == "attempts" else matched[0][1]
    require(positions["attempts"] == sorted(positions["attempts"])
            and positions["attempts"][-1] < positions["summary"][0]
            < positions["runtime"][0] < positions["trace"][0]
            < positions["terminal"][0] < harness[0],
            "finite stack markers or harness result are out of order")
    require(sum("KONTOR_STACK_TIMING:" in line for line in lines) ==
            len(records["attempts"]), "finite stack per-repeat timings are missing")
    return records


def validate_observation(attempt, case_id, role, configuration, index, manifest, cell):
    value = attempt["observation"]
    require(set(attempt) == {"case_id", "configuration", "process_role", "sample_key",
                             "repeat_index", "pid", "observation"}
            and attempt["case_id"] == case_id
            and attempt["configuration"] == configuration
            and attempt["process_role"] == role
            and attempt["sample_key"] == "target"
            and attempt["repeat_index"] == index,
            "finite stack attempt identity or order changed")
    require(value["role"] == role and value["sample_index"] == index
            and value["kind"] == "paid_huge" and value["depth"] == 0
            and value["fixture_contracts"] == 1
            and value["component_sha256"] == manifest["artifacts"]["stack_probe"]["sha256"]
            and value["target_os"] ==
                ("macos" if cell.startswith("macOS-") else "linux")
            and value["target_arch"] ==
                ("x86_64" if cell.startswith("Linux-X64/") else "aarch64")
            and value["engine_target"] == "pulley64-unknown-unknown-elf"
            and value["max_wasm_stack"] == 524288
            and value["async_stack_size"] ==
            (1048576 if configuration == "reduced" else 2097152)
            and value["gas_limit"] == 100000
            and value["paid_fuel_limit"] == 100000000
            and value["call_hook_installed"] is False,
            "finite stack guest, engine, or paid limit differs from fixture")
    require(value["outcome"] == "ok" and value["error"] is None
            and value["error_class"] is None and value["typed_trap"] is None
            and value["value"] == "32640" and value["last_depth"] == 1
            and value["rolled_back"] is False,
            "finite stack value, marker, or outcome differs")
    receipt = value["receipt"]
    fuel = value["fuel"]
    require(set(receipt) == {"status", "gas"} and receipt["status"] == "Ok"
            and type(receipt["gas"]) is int and receipt["gas"] > 0
            and set(fuel) == {"user", "system", "deposit"}
            and all(type(amount) is int and amount >= 0 for amount in fuel.values())
            and fuel["user"] > 0,
            "finite stack paid receipt or fuel is incomplete")
    reset = value["reset"]
    pre, post = reset["pre"], reset["post"]
    before = value["state_before_sha256"]
    require(all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item)
                for item in (before, post["persistent_digest_sha256"],
                             post["baseline_digest_sha256"]))
            and before == post["persistent_digest_sha256"] ==
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
            "finite stack full persistent state or resource reset failed")
    validate_balance_transitions(value["balance_transitions"], "paid", "ok", 1,
                                 value["balance_transitions_sha256"])
    validate_live_deposit_gas(value["live_deposit_gas"],
                              value["live_deposit_gas_sha256"],
                              value["balance_transitions"], "paid", "ok", 1)
    require(value["teardown_probe_on"] is (role == "target_observed"),
            "finite stack teardown probe role changed")
    if role == "target_observed":
        counts = validate_teardown(value["teardown_events"], 1, 0)["created"]
        require(counts["nested_chain"] == 1
                and counts["target_native_auxiliary"] == 2
                and counts["post_observation"] == 5
                and counts["rollback_observation"] == 4,
                "finite stack Store lifecycle count differs")
    else:
        require(value["teardown_events"] is None,
                "probe-off finite stack child emitted teardown events")
    return {
        "sample_key": "target", "repeat_index": index,
        "outcome": value["outcome"], "value": value["value"],
        "fuel": fuel, "receipt": receipt,
        "state_before_sha256": before,
        "state_after_sha256": post["persistent_digest_sha256"],
        "balances": value["balance_transitions"],
        "live_deposit_gas": value["live_deposit_gas"],
        "last_depth": value["last_depth"],
    }


def validate_run(run, bundle, manifest, directory):
    case_id, role, configuration = (run[key] for key in
                                    ("case_id", "process_role", "configuration"))
    name = run_name(case_id, role, configuration)
    require(run["run_id"] == name and run["cell"] == bundle["cell"]
            and run["case_env"] == expected_case_env(case_id, role, configuration)
            and run["source_sha"] == bundle["source_sha"]
            and run["binary_sha256_before"] == run["binary_sha256_after"] ==
                bundle["binary_sha256"],
            "finite stack child identity or binary changed")
    process = run["process"]
    command = [bundle["binary_path"], "--ignored", "--exact", WORKER_TEST, "--nocapture"]
    require(run["argv"] == process["command"] == command
            and type(process["pid"]) is int and process["pid"] > 0
            and process["exit_code"] == 0 and process["signal"] is None
            and process["timed_out"] is False and process["complete"] is True
            and process["test_harness_passed"] is True
            and process["started_unix_ns"] < process["ended_unix_ns"],
            "finite stack child failed, timed out, or used wrong command")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in
                ("attempts", "summary", "runtime", "trace", "terminal")),
            "finite stack child records differ from raw transcript")
    attempts = parsed["attempts"]
    summary, runtime, terminal = (parsed[key] for key in
                                  ("summary", "runtime", "terminal"))
    require(len(attempts) == CASES[case_id]
            and summary == {"case_id": case_id, "configuration": configuration,
                            "process_role": role, "sample_count": len(attempts),
                            "outcomes": ["ok"] * len(attempts), "complete": True}
            and terminal == {"case_id": case_id, "configuration": configuration,
                             "process_role": role, "pid": process["pid"],
                             "sample_count": len(attempts), "complete": True}
            and runtime["scope"] == "paired_finite_stack_worker"
            and all(runtime[key] == expected for key, expected in
                    (("case_id", case_id), ("configuration", configuration),
                     ("process_role", role), ("pid", process["pid"]),
                     ("embedded_source_sha", bundle["source_sha"]),
                     ("binary_sha256", bundle["binary_sha256"]))),
            "finite stack summary, terminal, or runtime identity differs")
    os_name = "macos" if bundle["cell"].startswith("macOS-") else "linux"
    validate_trace(parsed["trace"], runtime, attempts, os_name,
                   ("finite_stack_attempt_start", "finite_stack_attempt_end"))
    signatures = []
    for index, attempt in enumerate(attempts):
        require(attempt["pid"] == process["pid"],
                "finite stack attempt escaped child process")
        signatures.append(validate_observation(
            attempt, case_id, role, configuration, index, manifest, bundle["cell"]))
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
            "finite stack source or claim status differs")
    file_evidence(directory, bundle["control_capture"])
    control_path = directory / bundle["control_capture"]["path"]
    control, binary = validate_control(
        control_path, bundle["control_capture"]["sha256"], manifest,
        archive_binary=archive_binary, expected_cell=bundle["cell"])
    validate_cell_identity(bundle["cell"], control["cargo_artifact"],
                           check_host=archive_binary is None)
    require(control["source_sha"] == bundle["source_sha"]
            and control["binary_sha256"] == bundle["binary_sha256"]
            and str(binary) == bundle["binary_path"],
            "finite stack control source or binary differs")
    expected = {(case_id, role, configuration) for case_id in CASES
                for role in ROLES for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "finite stack process registry has missing or extra children")
    process_ids = [(run["process"]["pid"], run["process"]["started_unix_ns"])
                   for run in bundle["runs"].values()]
    process_ids.append((control["guard_control"]["process"]["pid"],
                        control["guard_control"]["process"]["started_unix_ns"]))
    require(len(process_ids) == len(set(process_ids)),
            "finite stack child process identities overlap")
    require({run["raw_log"]["path"] for run in bundle["runs"].values()} ==
            {path.name for path in directory.glob("*.log")},
            "finite stack raw process logs are missing or extra")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle, manifest,
                                    directory) for key in sorted(expected)}
    for case_id in CASES:
        reference = signatures[case_id, "target_observed", "production"]
        require(all({key: value for key, value in item.items()
                     if key != "repeat_index"} ==
                    {key: value for key, value in reference[0].items()
                     if key != "repeat_index"}
                    for item in reference),
                f"{case_id}: repeated paid semantics changed")
        for role in ROLES:
            for configuration in CONFIGURATIONS:
                require(signatures[case_id, role, configuration] == reference,
                        f"{case_id}: role or stack configuration changed semantics")
            reduced = [thread["usable_bytes"] for thread in
                       bundle["runs"][run_name(case_id, role, "reduced")]
                       ["runtime"]["thread_observations"]
                       if thread["thread_category"] == "tokio_worker"]
            production = [thread["usable_bytes"] for thread in
                          bundle["runs"][run_name(case_id, role, "production")]
                          ["runtime"]["thread_observations"]
                          if thread["thread_category"] == "tokio_worker"]
            require(reduced and production and min(production) >= 2 * max(reduced),
                    f"{case_id}: measured worker-capacity ratio is below two")
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
