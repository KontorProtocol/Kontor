#!/usr/bin/env python3
"""Validate generated initialization on measured native worker stacks."""

import argparse
import json
import re
from pathlib import Path

from capture_resource_diagnostic import validate_control
from resource_boundary_evidence import validate_cell_identity
from resource_evidence import (file_evidence, load_json_strict, require, sha256,
                               thread_capacities)
from resource_finite_evidence import (CONFIGURATIONS, ROLES, WORKER_TEST,
                                      parse_worker_log)
from resource_manifest import MANIFEST, build_manifest


CASE_ID = "generated_initialization"
SAMPLES = ("active_data_success", "active_element_success", "active_data_oob",
           "active_element_oob", "fuel_failure")
EXPECTED = {"active_data_success": ("ok", None),
            "active_element_success": ("ok", None),
            "active_data_oob": ("deterministic_error", "MemoryOutOfBounds"),
            "active_element_oob": ("deterministic_error", "TableOutOfBounds"),
            "fuel_failure": ("out_of_fuel", "OutOfFuel")}
OBSERVATION_KEYS = {
    "sample_key", "outcome", "typed_trap", "module_sha256", "fuel_limit",
    "fuel_used", "host_callback_count", "state_before_sha256",
    "state_after_sha256", "store_closed", "teardown_probe_on",
    "store_close_count", "engine_target", "max_wasm_stack", "async_stack_size",
}


def run_name(case_id, role, configuration):
    require(case_id == CASE_ID and role in ROLES and configuration in CONFIGURATIONS,
            "unknown generated initialization run")
    return f"{case_id}-{role}-{configuration}"


def expected_case_env(case_id, role, configuration):
    run_name(case_id, role, configuration)
    return {"KONTOR_FINITE_STACK_CASE": case_id,
            "KONTOR_FINITE_STACK_ROLE": role,
            "KONTOR_RESOURCE_MODE": configuration,
            "KONTOR_RESOURCE_TEARDOWN_PROBE":
                "on" if role == "target_observed" else "off"}


def validate_observation(attempt, sample, repeat_index, role, configuration, pid):
    value = attempt["observation"]
    require(set(attempt) == {"case_id", "configuration", "process_role",
                             "sample_key", "repeat_index", "pid", "observation"}
            and attempt["case_id"] == CASE_ID
            and attempt["configuration"] == configuration
            and attempt["process_role"] == role
            and attempt["sample_key"] == sample
            and attempt["repeat_index"] == repeat_index
            and attempt["pid"] == pid,
            "generated initialization attempt identity changed")
    expected_outcome, expected_trap = EXPECTED[sample]
    fuel_limit = 0 if sample == "fuel_failure" else 1_000_000
    require(isinstance(value, dict) and set(value) == OBSERVATION_KEYS
            and value["sample_key"] == sample
            and value["outcome"] == expected_outcome
            and value["typed_trap"] == expected_trap
            and isinstance(value["module_sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["module_sha256"])
            and value["fuel_limit"] == fuel_limit
            and type(value["fuel_used"]) is int
            and 0 <= value["fuel_used"] <= fuel_limit
            and value["host_callback_count"] == 0
            and value["store_closed"] is True
            and value["teardown_probe_on"] is (role == "target_observed")
            and value["store_close_count"] == (1 if role == "target_observed" else 0)
            and value["engine_target"] == "pulley64-unknown-unknown-elf"
            and value["max_wasm_stack"] == 524_288
            and value["async_stack_size"] ==
                (1_048_576 if configuration == "reduced" else 2_097_152),
            "generated initialization result, trap, fuel, or Store lifecycle changed")
    before = value["state_before_sha256"]
    require(isinstance(before, str) and re.fullmatch(r"[0-9a-f]{64}", before)
            and value["state_after_sha256"] == before,
            "generated initialization changed full persistent state")
    return {"sample_key": sample, "repeat_index": repeat_index,
            "outcome": value["outcome"], "typed_trap": value["typed_trap"],
            "module_sha256": value["module_sha256"],
            "fuel_used": value["fuel_used"], "state_sha256": before}


def validate_trace(trace, runtime, attempts, os_name):
    require(set(trace) == {"scope", "configuration", "case_id", "process_role",
                           "events"}
            and all(trace[key] == runtime[key] for key in
                    ("scope", "configuration", "case_id", "process_role")),
            "generated initialization thread trace identity changed")
    observations = runtime["thread_observations"]
    threads = thread_capacities(
        {key: value for key, value in runtime.items()
         if key not in {"scope", "configuration", "case_id", "process_role",
                        "pid", "embedded_source_sha", "binary_sha256"}},
        runtime["configuration"], observations[0]["page_size_bytes"],
        os_name, runtime["pid"])
    workers = {item["thread_id"]: item["os_thread_id"]
               for item in threads["tokio_worker"]}
    names = []
    for event in trace["events"]:
        require(set(event) == {"name", "thread_id", "os_thread_id", "category"}
                and event["name"] in {"compiler_entry", "compiler_exit",
                                      "finite_stack_attempt_start",
                                      "finite_stack_attempt_end"}
                and event["category"] == "tokio_worker"
                and workers.get(event["thread_id"]) == event["os_thread_id"],
                "generated initialization escaped a measured worker")
        names.append(event["name"])
    starts = [index for index, name in enumerate(names)
              if name == "finite_stack_attempt_start"]
    ends = [index for index, name in enumerate(names)
            if name == "finite_stack_attempt_end"]
    require(len(starts) == len(ends) == len(attempts)
            and all(start < end and (index == 0 or ends[index - 1] < start)
                    for index, (start, end) in enumerate(zip(starts, ends, strict=True)))
            and names.count("compiler_entry") == names.count("compiler_exit"),
            "generated initialization worker attempt intervals are incomplete")


def validate_run(run, bundle, manifest, directory):
    role, configuration = run["process_role"], run["configuration"]
    name = run_name(CASE_ID, role, configuration)
    process = run["process"]
    command = [bundle["binary_path"], "--ignored", "--exact", WORKER_TEST,
               "--nocapture"]
    require(run["run_id"] == name and run["case_id"] == CASE_ID
            and run["cell"] == bundle["cell"]
            and run["case_env"] == expected_case_env(CASE_ID, role, configuration)
            and run["source_sha"] == bundle["source_sha"]
            and run["binary_sha256_before"] == run["binary_sha256_after"] ==
                bundle["binary_sha256"]
            and run["argv"] == process["command"] == command
            and type(process["pid"]) is int and process["pid"] > 0
            and process["exit_code"] == 0 and process["signal"] is None
            and process["timed_out"] is False and process["complete"] is True
            and process["test_harness_passed"] is True
            and process["started_unix_ns"] < process["ended_unix_ns"],
            "generated initialization process identity or completion changed")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in
                ("attempts", "summary", "runtime", "trace", "terminal")),
            "generated initialization differs from raw transcript")
    attempts = parsed["attempts"]
    expected_order = [(sample, repeat) for sample in SAMPLES for repeat in range(2)]
    require([(item["sample_key"], item["repeat_index"]) for item in attempts] ==
            expected_order,
            "generated initialization sample order or repetitions changed")
    summary, runtime, terminal = (parsed[key] for key in
                                  ("summary", "runtime", "terminal"))
    require(summary == {"case_id": CASE_ID, "configuration": configuration,
                        "process_role": role, "sample_count": len(expected_order),
                        "outcomes": [EXPECTED[sample][0] for sample, _ in expected_order],
                        "complete": True}
            and terminal == {"case_id": CASE_ID, "configuration": configuration,
                             "process_role": role, "pid": process["pid"],
                             "sample_count": len(expected_order), "complete": True}
            and runtime["scope"] == "paired_finite_stack_worker"
            and all(runtime[key] == expected for key, expected in
                    (("case_id", CASE_ID), ("configuration", configuration),
                     ("process_role", role), ("pid", process["pid"]),
                     ("embedded_source_sha", bundle["source_sha"]),
                     ("binary_sha256", bundle["binary_sha256"]))),
            "generated initialization summary or runtime identity changed")
    os_name = "macos" if bundle["cell"].startswith("macOS-") else "linux"
    validate_trace(parsed["trace"], runtime, attempts, os_name)
    return [validate_observation(item, sample, repeat, role, configuration,
                                 process["pid"])
            for item, (sample, repeat) in zip(attempts, expected_order, strict=True)]


def validate_bundle(bundle, directory):
    manifest = build_manifest()
    require(set(bundle) == {"schema_version", "qualification_status", "cell",
                            "manifest_sha256", "source_sha", "binary_path",
                            "binary_sha256", "control_capture", "runs"}
            and bundle["schema_version"] == 1
            and bundle["qualification_status"] == "missing"
            and load_json_strict(MANIFEST) == manifest
            and bundle["manifest_sha256"] == sha256(MANIFEST),
            "generated initialization source or claim status changed")
    file_evidence(directory, bundle["control_capture"])
    control_path = directory / bundle["control_capture"]["path"]
    control, binary = validate_control(
        control_path, bundle["control_capture"]["sha256"], manifest)
    validate_cell_identity(bundle["cell"], control["cargo_artifact"])
    require(control["source_sha"] == bundle["source_sha"]
            and control["binary_sha256"] == bundle["binary_sha256"]
            and str(binary) == bundle["binary_path"],
            "generated initialization control source or binary changed")
    expected = {(CASE_ID, role, configuration) for role in ROLES
                for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "generated initialization process registry is incomplete")
    ids = [(run["process"]["pid"], run["process"]["started_unix_ns"])
           for run in bundle["runs"].values()]
    ids.append((control["guard_control"]["process"]["pid"],
                control["guard_control"]["process"]["started_unix_ns"]))
    require(len(ids) == len(set(ids)),
            "generated initialization process identities overlap")
    require({run["raw_log"]["path"] for run in bundle["runs"].values()} ==
            {path.name for path in directory.glob("*.log")},
            "generated initialization raw logs are missing or extra")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle,
                                    manifest, directory) for key in sorted(expected)}
    reference = signatures[CASE_ID, "target_observed", "production"]
    for sample_index in range(0, len(reference), 2):
        require({key: value for key, value in reference[sample_index].items()
                 if key != "repeat_index"} ==
                {key: value for key, value in reference[sample_index + 1].items()
                 if key != "repeat_index"},
                "generated initialization repeated semantics changed")
    for role in ROLES:
        for configuration in CONFIGURATIONS:
            require(signatures[CASE_ID, role, configuration] == reference,
                    "generated initialization role or stack configuration changed semantics")
        reduced = [thread["usable_bytes"] for thread in
                   bundle["runs"][run_name(CASE_ID, role, "reduced")]
                   ["runtime"]["thread_observations"]
                   if thread["thread_category"] == "tokio_worker"]
        production = [thread["usable_bytes"] for thread in
                      bundle["runs"][run_name(CASE_ID, role, "production")]
                      ["runtime"]["thread_observations"]
                      if thread["thread_category"] == "tokio_worker"]
        require(reduced and production and min(production) >= 2 * max(reduced),
                "generated initialization worker capacity ratio is below two")
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
