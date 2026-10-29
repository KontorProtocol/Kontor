#!/usr/bin/env python3
"""Validate bounded WAVE parse and print work through foreign.call."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from capture_resource_diagnostic import validate_control
from resource_boundary_evidence import validate_cell_identity
from resource_evidence import (file_evidence, load_json_strict, require, sha256,
                               thread_capacities)
from resource_evidence_v2 import validate_teardown
from resource_finite_evidence import (CONFIGURATIONS, ROLES, WORKER_TEST,
                                      parse_worker_log)
from resource_manifest import MANIFEST, build_manifest


CASE_ID = "foreign_wave_parse_print"
SAMPLES = ("depth_64", "depth_65_rejected", "literal_16384",
           "literal_16385_rejected", "print_depth_64", "print_depth_65_rejected")
EXPECTED = {
    "depth_64": ("ok", None, "1"),
    "depth_65_rejected": ("deterministic_error", "expression_depth", None),
    "literal_16384": ("ok", None, "5"),
    "literal_16385_rejected": ("deterministic_error", "string_literal_bytes", None),
    "print_depth_64": ("ok", None, None),
    "print_depth_65_rejected": ("deterministic_error", "result_value_depth", None),
}
OBSERVATION_KEYS = {
    "sample_key", "outcome", "error_kind", "typed_trap", "result_value",
    "inner_expression_sha256", "inner_expression_bytes", "caller_module_sha256",
    "target_module_sha256", "caller_address", "target_address", "execution_path",
    "system_fuel", "user_fuel", "deposit_fuel", "state_before_sha256",
    "state_after_sha256", "receipts_before", "receipts_after",
    "resources_before", "resources_after", "stack_empty", "savepoint_empty",
    "live_invocations", "teardown_probe_on", "teardown_events",
    "engine_target", "max_wasm_stack", "async_stack_size",
}
PHASES = (
    ("compiler_entry", "compiler_exit"),
    ("blocking_decode_entry", "blocking_decode_exit"),
    ("canonical_input_entry", "canonical_input_exit"),
    ("canonical_output_entry", "canonical_output_exit"),
)


def expression(sample):
    if sample == "depth_64":
        return "view-depth(" + "{child:" * 63 + "1" + "}" * 63 + ")"
    if sample == "depth_65_rejected":
        return "view-depth(" + "{child:" * 64 + "1" + "}" * 64 + ")"
    if sample == "literal_16384":
        return 'view-literal("' + "x" * 16_384 + '")'
    if sample == "literal_16385_rejected":
        return 'view-literal("' + "x" * 16_385 + '")'
    if sample == "print_depth_64":
        return "print-depth64()"
    if sample == "print_depth_65_rejected":
        return "print-depth65()"
    raise ValueError(f"unknown foreign WAVE sample {sample}")


def run_name(case_id, role, configuration):
    require(case_id == CASE_ID and role in ROLES and configuration in CONFIGURATIONS,
            "unknown foreign WAVE run")
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
    expected_outcome, expected_error, expected_result = EXPECTED[sample]
    expr = expression(sample)
    require(set(attempt) == {"case_id", "configuration", "process_role",
                             "sample_key", "repeat_index", "pid", "observation"}
            and (attempt["case_id"], attempt["configuration"],
                 attempt["process_role"], attempt["sample_key"],
                 attempt["repeat_index"], attempt["pid"]) ==
                (CASE_ID, configuration, role, sample, repeat_index, pid),
            "foreign WAVE attempt identity changed")
    require(isinstance(value, dict) and set(value) == OBSERVATION_KEYS
            and value["sample_key"] == sample
            and value["outcome"] == expected_outcome
            and value["error_kind"] == expected_error
            and value["typed_trap"] is None
            and (value["result_value"] == expected_result if sample !=
                 "print_depth_64" else
                 isinstance(value["result_value"], str) and
                 value["result_value"].isdigit() and
                 400 <= int(value["result_value"]) < 1024)
            and value["inner_expression_bytes"] == len(expr.encode())
            and value["inner_expression_sha256"] ==
                hashlib.sha256(expr.encode()).hexdigest()
            and all(isinstance(value[key], str) and
                    re.fullmatch(r"[0-9a-f]{64}", value[key]) for key in
                    ("caller_module_sha256", "target_module_sha256"))
            and value["caller_address"] == "wave-caller:1:1"
            and value["target_address"] == "wave-target:1:0"
            and value["execution_path"] ==
                "Runtime::execute/foreign.call/Runtime::invoke"
            and all(type(value[key]) is int and value[key] >= 0 for key in
                    ("system_fuel", "user_fuel", "deposit_fuel"))
            and value["system_fuel"] > 0
            and value["user_fuel"] == value["deposit_fuel"] == 0
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
            "foreign WAVE output, source expression, or Store state changed")
    before = value["state_before_sha256"]
    require(isinstance(before, str) and re.fullmatch(r"[0-9a-f]{64}", before)
            and value["state_after_sha256"] == before,
            "foreign WAVE changed full persistent state")
    if role == "target_observed":
        teardown = validate_teardown(value["teardown_events"], 2, 0)
        require(teardown["created"]["nested_chain"] == 2,
                "foreign WAVE did not close caller and target Stores")
    else:
        require(value["teardown_events"] is None,
                "probe-off foreign WAVE child emitted teardown events")
    return {"sample_key": sample, "repeat_index": repeat_index,
            "outcome": expected_outcome, "error_kind": expected_error,
            "result_value": value["result_value"],
            "inner_expression_sha256": value["inner_expression_sha256"],
            "inner_expression_bytes": value["inner_expression_bytes"],
            "caller_module_sha256": value["caller_module_sha256"],
            "target_module_sha256": value["target_module_sha256"],
            "system_fuel": value["system_fuel"],
            "state_sha256": before, "receipts": value["receipts_before"],
            "resources": value["resources_before"]}


def validate_trace(trace, runtime, attempts, os_name):
    require(set(trace) == {"scope", "configuration", "case_id", "process_role",
                           "events"}
            and all(trace[key] == runtime[key] for key in
                    ("scope", "configuration", "case_id", "process_role")),
            "foreign WAVE trace identity changed")
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
    allowed = {name for pair in PHASES for name in pair} | {
        "publication_entry", "publication_exit", "finite_stack_attempt_start",
        "finite_stack_attempt_end"}
    events = trace["events"]
    require(isinstance(events, list) and events,
            "foreign WAVE trace is empty")
    for event in events:
        require(set(event) == {"name", "thread_id", "os_thread_id", "category"}
                and event["name"] in allowed,
                "foreign WAVE emitted an unknown trace event")
        if event["category"] == "tokio_worker":
            require(workers.get(event["thread_id"]) == event["os_thread_id"]
                    and not event["name"].startswith("blocking_decode_"),
                    "foreign WAVE escaped measured workers")
        else:
            require(event["category"] == "blocking_pool"
                    and blocking.get(event["thread_id"]) == event["os_thread_id"]
                    and event["name"].startswith("blocking_decode_"),
                    "foreign WAVE blocking decode lacks a measured stack")
    names = [event["name"] for event in events]
    starts = [index for index, name in enumerate(names)
              if name == "finite_stack_attempt_start"]
    ends = [index for index, name in enumerate(names)
            if name == "finite_stack_attempt_end"]
    publications = [index for index, name in enumerate(names)
                    if name == "publication_entry"]
    publication_ends = [index for index, name in enumerate(names)
                        if name == "publication_exit"]
    require(len(starts) == len(ends) == len(attempts)
            and all(start < end and (index == 0 or ends[index - 1] < start)
                    for index, (start, end) in enumerate(zip(starts, ends, strict=True)))
            and len(publications) == len(publication_ends) == 2
            and publications[0] < publication_ends[0] < publications[1]
                < publication_ends[1] < starts[0]
            and names.count("compiler_entry") >= 2
            and names.count("blocking_decode_entry") >= 2,
            "foreign WAVE publication or attempt intervals changed")
    for attempt, start, end in zip(attempts, starts, ends, strict=True):
        segment = names[start:end + 1]
        sample = attempt["sample_key"]
        if sample in {"depth_65_rejected", "literal_16385_rejected"}:
            expected_input, expected_output = 1, 0
        elif sample == "print_depth_65_rejected":
            expected_input, expected_output = 2, 1
        else:
            expected_input, expected_output = 2, 2
        require(segment.count("publication_entry") == 0
                and segment.count("compiler_entry") == 0
                and segment.count("canonical_input_entry") == expected_input
                and segment.count("canonical_output_entry") == expected_output,
                f"foreign WAVE {sample} did not reach its expected inner boundary")
    for entry, exit_name in PHASES:
        in_flight = {}
        for event in events:
            thread = event["thread_id"]
            if event["name"] == entry:
                require(thread not in in_flight,
                        f"overlapping foreign WAVE {entry}")
                in_flight[thread] = event["os_thread_id"]
            elif event["name"] == exit_name:
                require(in_flight.pop(thread, None) == event["os_thread_id"],
                        f"unpaired foreign WAVE {exit_name}")
        require(not in_flight, f"unclosed foreign WAVE {entry}")


def validate_run(run, bundle, directory):
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
            "foreign WAVE process identity or completion changed")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in
                ("attempts", "summary", "runtime", "trace", "terminal")),
            "foreign WAVE records differ from raw transcript")
    attempts = parsed["attempts"]
    expected_order = [(sample, repeat) for sample in SAMPLES for repeat in range(2)]
    require([(item["sample_key"], item["repeat_index"]) for item in attempts] ==
            expected_order,
            "foreign WAVE sample order or repetitions changed")
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
            "foreign WAVE summary or runtime identity changed")
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
            "foreign WAVE source or claim status changed")
    file_evidence(directory, bundle["control_capture"])
    control_path = directory / bundle["control_capture"]["path"]
    control, binary = validate_control(
        control_path, bundle["control_capture"]["sha256"], manifest)
    validate_cell_identity(bundle["cell"], control["cargo_artifact"])
    require(control["source_sha"] == bundle["source_sha"]
            and control["binary_sha256"] == bundle["binary_sha256"]
            and str(binary) == bundle["binary_path"],
            "foreign WAVE control source or binary changed")
    expected = {(CASE_ID, role, configuration) for role in ROLES
                for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "foreign WAVE process registry is incomplete")
    identities = [(run["process"]["pid"], run["process"]["started_unix_ns"])
                  for run in bundle["runs"].values()]
    identities.append((control["guard_control"]["process"]["pid"],
                       control["guard_control"]["process"]["started_unix_ns"]))
    require(len(identities) == len(set(identities)),
            "foreign WAVE process identities overlap")
    require({run["raw_log"]["path"] for run in bundle["runs"].values()} ==
            {path.name for path in directory.glob("*.log")},
            "foreign WAVE raw logs are missing or extra")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle,
                                    directory) for key in sorted(expected)}
    reference = signatures[CASE_ID, "target_observed", "production"]
    for index in range(0, len(reference), 2):
        require({key: value for key, value in reference[index].items()
                 if key != "repeat_index"} ==
                {key: value for key, value in reference[index + 1].items()
                 if key != "repeat_index"},
                "foreign WAVE repeated semantics changed")
    for role in ROLES:
        for configuration in CONFIGURATIONS:
            require(signatures[CASE_ID, role, configuration] == reference,
                    "foreign WAVE role or stack configuration changed semantics")
        reduced = [thread["usable_bytes"] for thread in
                   bundle["runs"][run_name(CASE_ID, role, "reduced")]
                   ["runtime"]["thread_observations"]
                   if thread["thread_category"] == "tokio_worker"]
        production = [thread["usable_bytes"] for thread in
                      bundle["runs"][run_name(CASE_ID, role, "production")]
                      ["runtime"]["thread_observations"]
                      if thread["thread_category"] == "tokio_worker"]
        require(reduced and production and min(production) >= 2 * max(reduced),
                "foreign WAVE worker capacity ratio is below two")
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
