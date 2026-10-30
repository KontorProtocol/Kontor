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
from resource_evidence_v2 import validate_teardown
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
    "sample_key", "outcome", "typed_trap", "result_value", "module_sha256",
    "component_address",
    "execution_path", "published", "input_precharge_fuel", "view_fuel_limit",
    "fuel_control",
    "user_fuel", "system_fuel", "deposit_fuel",
    "state_before_sha256", "state_after_sha256", "receipts_before",
    "receipts_after", "resources_before", "resources_after", "stack_empty",
    "savepoint_empty", "live_invocations", "teardown_probe_on",
    "teardown_events", "engine_target", "max_wasm_stack", "async_stack_size",
}
FUEL_CONTROL_KEYS = {
    "component_address", "module_sha256", "result_value", "view_fuel_limit",
    "system_fuel", "state_before_sha256",
    "state_after_sha256", "receipts_before", "receipts_after",
    "resources_before", "resources_after", "live_invocations",
    "teardown_probe_on", "teardown_events",
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
    publish_failure = sample in {"active_data_oob", "active_element_oob"}
    expression = "init()" if publish_failure else 'view-run("")'
    precharge = 10 * (len(expression) + len(f"generated-{sample.replace('_', '-')}"))
    address = f"generated-{sample.replace('_', '-')}:1:{SAMPLES.index(sample)}"
    require(isinstance(value, dict) and set(value) == OBSERVATION_KEYS
            and value["sample_key"] == sample
            and value["outcome"] == expected_outcome
            and value["typed_trap"] == expected_trap
            and ((isinstance(value["result_value"], str)
                  and sample.endswith("success"))
                 or (value["result_value"] is None
                     and not sample.endswith("success")))
            and isinstance(value["module_sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["module_sha256"])
            and value["component_address"] == address
            and value["execution_path"] ==
                ("Runtime::publish/init" if publish_failure else "Runtime::execute")
            and value["published"] is (not publish_failure)
            and type(value["input_precharge_fuel"]) is int
            and value["input_precharge_fuel"] == precharge
            and (value["view_fuel_limit"] is None if publish_failure else
                 (type(value["view_fuel_limit"]) is int and
                  value["view_fuel_limit"] ==
                    (1_000 if sample == "fuel_failure" else 100_000_000)))
            and all(type(value[key]) is int and value[key] >= 0 for key in
                    ("user_fuel", "system_fuel", "deposit_fuel"))
            and value["user_fuel"] == value["deposit_fuel"] == 0
            and (value["system_fuel"] == value["input_precharge_fuel"]
                 if publish_failure else value["system_fuel"] >
                 value["input_precharge_fuel"])
            and (sample != "fuel_failure" or
                 value["system_fuel"] == value["view_fuel_limit"])
            and type(value["receipts_before"]) is int
            and value["receipts_after"] == value["receipts_before"]
            and type(value["resources_before"]) is int
            and value["resources_after"] == value["resources_before"]
            and value["stack_empty"] is True
            and value["savepoint_empty"] is True
            and value["live_invocations"] == 0
            and value["teardown_probe_on"] is (role == "target_observed")
            and value["engine_target"] == "pulley64-unknown-unknown-elf"
            and value["max_wasm_stack"] == 524_288
            and value["async_stack_size"] ==
                (1_048_576 if configuration == "reduced" else 2_097_152),
            "generated initialization result, trap, fuel, or Store lifecycle changed")
    before = value["state_before_sha256"]
    require(isinstance(before, str) and re.fullmatch(r"[0-9a-f]{64}", before)
            and value["state_after_sha256"] == before,
            "generated initialization changed full persistent state")
    control = value["fuel_control"]
    if sample == "fuel_failure":
        require(isinstance(control, dict) and set(control) == FUEL_CONTROL_KEYS
                and control["component_address"] == address
                and control["module_sha256"] == value["module_sha256"]
                and control["result_value"] == ""
                and control["view_fuel_limit"] == 100_000_000
                and type(control["system_fuel"]) is int
                and 1_000 < control["system_fuel"] < control["view_fuel_limit"]
                and control["state_before_sha256"] ==
                    control["state_after_sha256"] == before
                and control["receipts_before"] ==
                    control["receipts_after"] == value["receipts_before"]
                and control["resources_before"] ==
                    control["resources_after"] == value["resources_before"]
                and control["live_invocations"] == 0
                and control["teardown_probe_on"] is (role == "target_observed"),
                "same-component sufficient-fuel control is incomplete")
        if role == "target_observed":
            validate_teardown(control["teardown_events"], 1, 0)
        else:
            require(control["teardown_events"] is None,
                    "probe-off fuel control recorded teardown events")
    else:
        require(control is None, "unexpected initialization fuel control")
    if role == "target_observed":
        teardown = validate_teardown(value["teardown_events"], 1, 0)
        require(teardown["created"]["nested_chain"] == 1,
                "generated initialization did not close one call Store")
    else:
        require(value["teardown_events"] is None,
                "generated initialization probe-off role recorded Store events")
    return {"sample_key": sample, "repeat_index": repeat_index,
            "outcome": value["outcome"], "typed_trap": value["typed_trap"],
            "result_value": value["result_value"],
            "module_sha256": value["module_sha256"],
            "component_address": address,
            "input_precharge_fuel": value["input_precharge_fuel"],
            "view_fuel_limit": value["view_fuel_limit"],
            "user_fuel": value["user_fuel"],
            "system_fuel": value["system_fuel"],
            "deposit_fuel": value["deposit_fuel"],
            "control_fuel": control["system_fuel"] if control else None,
            "receipts": value["receipts_before"],
            "resources": value["resources_before"],
            "state_sha256": before}


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
    blocking = {item["thread_id"]: item["os_thread_id"]
                for item in threads["blocking_pool"]}
    names = []
    for event in trace["events"]:
        require(set(event) == {"name", "thread_id", "os_thread_id", "category"}
                and event["name"] in {"compiler_entry", "compiler_exit",
                                      "finite_stack_attempt_start",
                                      "finite_stack_attempt_end",
                                      "publication_entry", "publication_exit",
                                      "fuel_control_entry", "fuel_control_exit",
                                      "canonical_input_entry", "canonical_input_exit",
                                      "canonical_output_entry", "canonical_output_exit",
                                      "blocking_decode_entry", "blocking_decode_exit"},
                "generated initialization has an unknown thread event")
        if event["category"] == "tokio_worker":
            require(workers.get(event["thread_id"]) == event["os_thread_id"]
                    and not event["name"].startswith("blocking_decode_"),
                    "generated initialization escaped a measured worker")
        else:
            require(event["category"] == "blocking_pool"
                    and blocking.get(event["thread_id"]) == event["os_thread_id"]
                    and event["name"].startswith("blocking_decode_"),
                    "generated initialization blocking decode lacks measured stack")
        names.append(event["name"])
    starts = [index for index, name in enumerate(names)
              if name == "finite_stack_attempt_start"]
    ends = [index for index, name in enumerate(names)
            if name == "finite_stack_attempt_end"]
    require(len(starts) == len(ends) == len(attempts)
            and all(start < end and (index == 0 or ends[index - 1] < start)
                    for index, (start, end) in enumerate(zip(starts, ends, strict=True)))
            and names.count("compiler_entry") > 0
            and names.count("blocking_decode_entry") > 0
            and names.count("publication_entry") ==
                names.count("publication_exit") == 3
            and names.count("fuel_control_entry") ==
                names.count("fuel_control_exit") == 1,
            "generated initialization worker attempt intervals are incomplete")
    publications = [index for index, name in enumerate(names)
                    if name == "publication_entry"]
    publication_ends = [index for index, name in enumerate(names)
                        if name == "publication_exit"]
    require(all(start < end < starts[attempt_index]
                and (attempt_index == 0 or ends[attempt_index - 1] < start)
                for start, end, attempt_index in
                zip(publications, publication_ends, (0, 2, 8), strict=True)),
            "generated initialization publication order changed")
    control_start = names.index("fuel_control_entry")
    control_end = names.index("fuel_control_exit")
    control_events = names[control_start:control_end + 1]
    require(publication_ends[2] < control_start < control_end < starts[8]
            and control_events.count("canonical_input_entry") == 1
            and control_events.count("canonical_output_entry") == 1,
            "sufficient-fuel control did not execute the published component")
    for index, (attempt, start, end) in enumerate(zip(attempts, starts, ends, strict=True)):
        operation = names[start:end + 1]
        if attempt["observation"]["outcome"] == "ok":
            require(operation.count("canonical_input_entry") == 1
                    and operation.count("canonical_output_entry") == 1
                    and operation.count("compiler_entry") == 0
                    and operation.count("blocking_decode_entry") == 0,
                    "generated initialization success omitted canonical call conversion")
        elif attempt["sample_key"] in {"active_data_oob", "active_element_oob"}:
            require(operation.count("compiler_entry") == 1
                    and operation.count("blocking_decode_entry") == 1
                    and operation.count("canonical_input_entry") == 0,
                    "generated initialization publish trap escaped component startup")
        else:
            # A published, cached component has cleared the measured input
            # precharge. With no canonical input event, the fuel trap is in
            # instantiate_async's metered active-segment startup.
            require(index in (8, 9)
                    and all(operation.count(name) == 0 for name in
                            ("compiler_entry", "blocking_decode_entry",
                             "canonical_input_entry", "canonical_output_entry"))
                    and attempt["observation"]["view_fuel_limit"] >
                        attempt["observation"]["input_precharge_fuel"],
                    "generated initialization fuel trap did not reach startup")
    for entry, exit_name in (
        ("compiler_entry", "compiler_exit"),
        ("blocking_decode_entry", "blocking_decode_exit"),
        ("canonical_input_entry", "canonical_input_exit"),
        ("canonical_output_entry", "canonical_output_exit"),
    ):
        in_flight = {}
        for event in trace["events"]:
            thread = event["thread_id"]
            if event["name"] == entry:
                require(thread not in in_flight,
                        f"overlapping generated initialization {entry}")
                in_flight[thread] = event["os_thread_id"]
            elif event["name"] == exit_name:
                require(in_flight.pop(thread, None) == event["os_thread_id"],
                        f"unpaired generated initialization {exit_name}")
        require(not in_flight,
                f"unclosed generated initialization {entry}")


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


def validate_bundle(bundle, directory, archive_binary=None):
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
        control_path, bundle["control_capture"]["sha256"], manifest,
        archive_binary=archive_binary, expected_cell=bundle["cell"])
    validate_cell_identity(bundle["cell"], control["cargo_artifact"],
                           check_host=archive_binary is None)
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
