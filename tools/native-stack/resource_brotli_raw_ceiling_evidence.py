#!/usr/bin/env python3
"""Validate exact raw Brotli admission and deterministic publication rollback."""

import argparse
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


CASE_ID = "brotli_raw_ceiling"
RAW_CEILING = 67_108_864
SAMPLES = ("at_ceiling", "one_byte_over_rejected")
RAW_SHA256 = {
    "at_ceiling": "cbefc9776b80115b4e8abf8416ff28bd043a69222bb165b2ab46198dd1e89b66",
    "one_byte_over_rejected":
        "acb46cdfad0ba099d23ee13156c0affbe7466ba2259cc9df4e3fc865498ca43a",
}
OBSERVATION_KEYS = {
    "sample_key", "outcome", "error_kind", "result_value", "raw_bytes",
    "raw_sha256", "compressed_bytes", "compressed_sha256",
    "publication_path", "state_before_sha256", "state_after_sha256",
    "state_restored_sha256", "receipts_before", "receipts_after",
    "receipts_restored", "resources_before", "resources_after",
    "system_fuel", "user_fuel", "deposit_fuel", "stack_empty",
    "savepoint_empty", "live_invocations", "teardown_probe_on",
    "teardown_events", "engine_target", "max_wasm_stack",
    "async_stack_size",
}
TRACE_EVENTS = {
    "fixture_preparation_entry", "fixture_preparation_exit",
    "finite_stack_attempt_start", "finite_stack_attempt_end",
    "publication_entry", "publication_exit", "compiler_entry", "compiler_exit",
    "blocking_decode_entry", "blocking_decode_exit",
    "canonical_input_entry", "canonical_input_exit",
    "canonical_output_entry", "canonical_output_exit",
}


def run_name(case_id, role, configuration):
    require(case_id == CASE_ID and role in ROLES and configuration in CONFIGURATIONS,
            "unknown Brotli ceiling run")
    return f"{case_id}-{role}-{configuration}"


def expected_case_env(case_id, role, configuration):
    run_name(case_id, role, configuration)
    return {"KONTOR_FINITE_STACK_CASE": case_id,
            "KONTOR_FINITE_STACK_ROLE": role,
            "KONTOR_RESOURCE_MODE": configuration,
            "KONTOR_RESOURCE_TEARDOWN_PROBE":
                "on" if role == "target_observed" else "off"}


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)


def validate_observation(attempt, sample, repeat_index, role, configuration, pid):
    require(set(attempt) == {"case_id", "configuration", "process_role",
                             "sample_key", "repeat_index", "pid", "observation"}
            and (attempt["case_id"], attempt["configuration"],
                 attempt["process_role"], attempt["sample_key"],
                 attempt["repeat_index"], attempt["pid"]) ==
                (CASE_ID, configuration, role, sample, repeat_index, pid),
            "Brotli ceiling attempt identity changed")
    value = attempt["observation"]
    accepted = sample == "at_ceiling"
    raw_bytes = RAW_CEILING + (not accepted)
    require(isinstance(value, dict) and set(value) == OBSERVATION_KEYS
            and value["sample_key"] == sample
            and value["outcome"] == ("ok" if accepted else "deterministic_error")
            and value["error_kind"] == (None if accepted else "raw_ceiling_exceeded")
            and ((isinstance(value["result_value"], str)
                  and value["result_value"])
                 if accepted else value["result_value"] is None)
            and type(value["raw_bytes"]) is int
            and value["raw_bytes"] == raw_bytes
            and value["raw_sha256"] == RAW_SHA256[sample]
            and type(value["compressed_bytes"]) is int
            and 0 < value["compressed_bytes"] < raw_bytes
            and digest(value["compressed_sha256"])
            and value["publication_path"] ==
                "Runtime::publish/Storage::decode_component_bytes/spawn_blocking"
            and all(digest(value[key]) for key in
                    ("state_before_sha256", "state_after_sha256",
                     "state_restored_sha256"))
            and value["state_restored_sha256"] == value["state_before_sha256"]
            and (value["state_after_sha256"] != value["state_before_sha256"]) is accepted
            and all(type(value[key]) is int and value[key] >= 0 for key in
                    ("receipts_before", "receipts_after", "receipts_restored",
                     "resources_before", "resources_after", "system_fuel",
                     "user_fuel", "deposit_fuel", "live_invocations"))
            and (value["receipts_after"] > value["receipts_before"]) is accepted
            and value["receipts_restored"] == value["receipts_before"]
            and value["resources_after"] == value["resources_before"]
            and value["user_fuel"] == value["deposit_fuel"] == 0
            and value["live_invocations"] == 0
            and value["stack_empty"] is True
            and value["savepoint_empty"] is True
            and value["teardown_probe_on"] is (role == "target_observed")
            and value["engine_target"] == "pulley64-unknown-unknown-elf"
            and value["max_wasm_stack"] == 524_288
            and value["async_stack_size"] ==
                (1_048_576 if configuration == "reduced" else 2_097_152),
            "Brotli ceiling size, result, or state changed")
    if role == "target_observed":
        if accepted:
            teardown = validate_teardown(value["teardown_events"], 1, 0)
            require(teardown["created"]["nested_chain"] == 1,
                    "accepted Brotli publish did not close its init Store")
        else:
            require(value["teardown_events"] == [],
                    "Brotli size rejection created a Store")
    else:
        require(value["teardown_events"] is None,
                "probe-off Brotli child emitted teardown events")
    return {key: value[key] for key in (
        "sample_key", "outcome", "error_kind", "result_value", "raw_bytes",
        "raw_sha256", "compressed_bytes", "compressed_sha256",
        "state_before_sha256", "state_after_sha256", "state_restored_sha256",
        "receipts_before", "receipts_after", "receipts_restored",
        "resources_before", "resources_after", "system_fuel", "user_fuel",
        "deposit_fuel")}


def validate_trace(trace, runtime, attempts, os_name):
    require(set(trace) == {"scope", "configuration", "case_id", "process_role",
                           "events"}
            and all(trace[key] == runtime[key] for key in
                    ("scope", "configuration", "case_id", "process_role")),
            "Brotli trace identity changed")
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
                and event["name"] in TRACE_EVENTS,
                "Brotli trace has an unknown event")
        if event["category"] == "tokio_worker":
            require(workers.get(event["thread_id"]) == event["os_thread_id"]
                    and not event["name"].startswith("blocking_decode_"),
                    "Brotli publication escaped a measured Tokio worker")
        else:
            require(event["category"] == "blocking_pool"
                    and blocking.get(event["thread_id"]) == event["os_thread_id"]
                    and event["name"].startswith("blocking_decode_"),
                    "Brotli decode lacks measured blocking-thread capacity")
        names.append(event["name"])
    starts = [index for index, name in enumerate(names)
              if name == "finite_stack_attempt_start"]
    ends = [index for index, name in enumerate(names)
            if name == "finite_stack_attempt_end"]
    require(len(starts) == len(ends) == len(attempts) == 4
            and names.count("fixture_preparation_entry") ==
                names.count("fixture_preparation_exit") == 1
            and names.index("fixture_preparation_entry") <
                names.index("fixture_preparation_exit") < starts[0]
            and all(start < end and (index == 0 or ends[index - 1] < start)
                    for index, (start, end) in enumerate(zip(starts, ends, strict=True))),
            "Brotli setup or attempt intervals changed")
    for attempt, start, end in zip(attempts, starts, ends, strict=True):
        segment = trace["events"][start:end + 1]
        segment_names = [item["name"] for item in segment]
        accepted = attempt["sample_key"] == "at_ceiling"
        require(segment_names.count("publication_entry") ==
                segment_names.count("publication_exit") == 1
                and segment_names.count("blocking_decode_entry") ==
                segment_names.count("blocking_decode_exit") == 1
                and segment_names.count("compiler_entry") ==
                segment_names.count("compiler_exit") == int(accepted)
                and segment_names.index("publication_entry") <
                segment_names.index("blocking_decode_entry") <
                segment_names.index("blocking_decode_exit") <
                segment_names.index("publication_exit")
                and (not accepted or segment_names.index("blocking_decode_exit") <
                     segment_names.index("compiler_entry") <
                     segment_names.index("compiler_exit") <
                     segment_names.index("publication_exit")),
                "Brotli size check or compiler phases changed")
        decode = [item for item in segment if item["name"].startswith("blocking_decode_")]
        require(decode[0]["thread_id"] == decode[1]["thread_id"]
                and decode[0]["os_thread_id"] == decode[1]["os_thread_id"],
                "Brotli decode entry and exit used different blocking threads")


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
            "Brotli process identity or completion changed")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in
                ("attempts", "summary", "runtime", "trace", "terminal")),
            "Brotli records differ from raw transcript")
    attempts = parsed["attempts"]
    expected_order = [(sample, repeat) for sample in SAMPLES for repeat in range(2)]
    require([(item["sample_key"], item["repeat_index"]) for item in attempts] ==
            expected_order, "Brotli samples or repetitions changed")
    summary, runtime, terminal = (parsed[key] for key in
                                  ("summary", "runtime", "terminal"))
    require(summary == {"case_id": CASE_ID, "configuration": configuration,
                        "process_role": role, "sample_count": 4,
                        "outcomes": ["ok", "ok", "deterministic_error",
                                     "deterministic_error"], "complete": True}
            and terminal == {"case_id": CASE_ID, "configuration": configuration,
                             "process_role": role, "pid": process["pid"],
                             "sample_count": 4, "complete": True}
            and runtime["scope"] == "paired_finite_stack_worker"
            and all(runtime[key] == expected for key, expected in (
                ("case_id", CASE_ID), ("configuration", configuration),
                ("process_role", role), ("pid", process["pid"]),
                ("embedded_source_sha", bundle["source_sha"]),
                ("binary_sha256", bundle["binary_sha256"]))),
            "Brotli summary or runtime identity changed")
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
            "Brotli source or claim status changed")
    file_evidence(directory, bundle["control_capture"])
    control, binary = validate_control(
        directory / bundle["control_capture"]["path"],
        bundle["control_capture"]["sha256"], manifest)
    validate_cell_identity(bundle["cell"], control["cargo_artifact"])
    require(control["source_sha"] == bundle["source_sha"]
            and control["binary_sha256"] == bundle["binary_sha256"]
            and str(binary) == bundle["binary_path"],
            "Brotli control source or binary changed")
    expected = {(CASE_ID, role, configuration) for role in ROLES
                for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "Brotli process registry is incomplete")
    identities = [(run["process"]["pid"], run["process"]["started_unix_ns"])
                  for run in bundle["runs"].values()]
    identities.append((control["guard_control"]["process"]["pid"],
                       control["guard_control"]["process"]["started_unix_ns"]))
    require(len(identities) == len(set(identities)),
            "Brotli process identities overlap")
    require({run["raw_log"]["path"] for run in bundle["runs"].values()} ==
            {path.name for path in directory.glob("*.log")},
            "Brotli raw logs are missing or extra")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle,
                                    directory) for key in sorted(expected)}
    reference = signatures[CASE_ID, "target_observed", "production"]
    for index in range(0, len(reference), 2):
        require(reference[index] == reference[index + 1],
                "Brotli repeated semantics changed")
    for role in ROLES:
        for configuration in CONFIGURATIONS:
            require(signatures[CASE_ID, role, configuration] == reference,
                    "Brotli role or stack configuration changed semantics")
        reduced = [thread["usable_bytes"] for thread in
                   bundle["runs"][run_name(CASE_ID, role, "reduced")]
                   ["runtime"]["thread_observations"]
                   if thread["thread_category"] == "tokio_worker"]
        production = [thread["usable_bytes"] for thread in
                      bundle["runs"][run_name(CASE_ID, role, "production")]
                      ["runtime"]["thread_observations"]
                      if thread["thread_category"] == "tokio_worker"]
        require(reduced and production and min(production) >= 2 * max(reduced),
                "Brotli worker capacity ratio is below two")
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
