#!/usr/bin/env python3
"""Validate cold publication admission, rejection, rollback, and stack traces."""

import argparse
import json
import re
from pathlib import Path

from capture_resource_diagnostic import bundle_page_size, validate_control
from resource_boundary_evidence import validate_cell_identity
from resource_evidence import (file_evidence, load_json_strict, require, sha256,
                               thread_capacities)
from resource_evidence_v2 import validate_teardown
from resource_finite_evidence import (CONFIGURATIONS, ROLES, WORKER_TEST,
                                      parse_worker_log)
from resource_manifest import MANIFEST, build_manifest


FUNCTION_LIMIT = 7_654_321
BR_FIXTURE_MAX = FUNCTION_LIMIT - 13
CASE_SAMPLES = {
    "cold_publish_large_function": ("accepted", "over_limit_rejected"),
    "cold_publish_control_nesting": ("accepted",),
    "cold_publish_br_table": ("accepted", "over_limit_rejected"),
}
CASE_IDS = tuple(CASE_SAMPLES)
RAW_MODULES = {
    ("cold_publish_large_function", "accepted"):
        (7_885_448, "0d771e5dd82aa6208e875e56a79c1eec655e9898ea04dc87026575d785f4fedb"),
    ("cold_publish_large_function", "over_limit_rejected"):
        (7_885_449, "80cf04fb061d2329f4fdfa0aee4dbb045fb3ccdf5e480569e1c18d013912082a"),
    ("cold_publish_control_nesting", "accepted"):
        (231_895, "09fc9c8f84f6ada884261642f643f43150788e9589e11db92888b55b3bba6807"),
    ("cold_publish_br_table", "accepted"):
        (7_885_448, "620adb05f14c8b3d988e5fa4032c796c9a0c3a5714e2d6915d3635bfc0fcb145"),
    ("cold_publish_br_table", "over_limit_rejected"):
        (7_885_449, "58dc4487424b2fc8c2188703eb59cc6d8ed06cbb0be12ae37f245e72c2409b19"),
}
OBSERVATION_KEYS = {
    "sample_key", "outcome", "error_kind", "error_text", "result_value",
    "function_body_bytes", "function_body_limit_bytes", "br_table_entries",
    "br_table_source_limit_entries", "br_table_fixture_max_entries",
    "control_depth", "raw_module_bytes", "raw_module_sha256",
    "compressed_bytes", "compressed_sha256", "serialized_instruction_bytes",
    "publication_path", "state_before_sha256", "state_after_sha256",
    "state_restored_sha256", "receipts_before", "receipts_after",
    "measured_receipts", "receipts_restored", "resources_before",
    "resources_after", "system_fuel", "user_fuel", "deposit_fuel",
    "stack_empty", "savepoint_empty", "live_invocations",
    "teardown_probe_on", "teardown_events", "engine_target",
    "max_wasm_stack", "async_stack_size",
}
RECEIPT_KEYS = {
    "contract", "function", "status", "gas", "size", "value",
    "signer_id", "payer_signer_id", "height", "tx_id", "input_index",
    "op_index", "result_index",
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
    require(case_id in CASE_SAMPLES and role in ROLES
            and configuration in CONFIGURATIONS, "unknown cold publication run")
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


def expected_address(case_id, sample):
    index = CASE_SAMPLES[case_id].index(sample)
    name = f"cold-{case_id.replace('_', '-')}-{index}"
    return name, f'{{name: "{name}", height: 1, tx-index: {index}}}'


def expected_shape(case_id, sample):
    over = sample == "over_limit_rejected"
    if case_id == "cold_publish_large_function":
        return FUNCTION_LIMIT + int(over), None, None
    if case_id == "cold_publish_br_table":
        count = BR_FIXTURE_MAX + int(over)
        return count + 13, count, None
    return 3 * 256 + 3, None, 256


def validate_observation(attempt, case_id, sample, repeat_index, role,
                         configuration, pid):
    require(set(attempt) == {"case_id", "configuration", "process_role",
                             "sample_key", "repeat_index", "pid", "observation"}
            and (attempt["case_id"], attempt["configuration"],
                 attempt["process_role"], attempt["sample_key"],
                 attempt["repeat_index"], attempt["pid"]) ==
                (case_id, configuration, role, sample, repeat_index, pid),
            "cold publication attempt identity changed")
    value = attempt["observation"]
    accepted = sample == "accepted"
    body_bytes, entries, depth = expected_shape(case_id, sample)
    raw_bytes, raw_sha256 = RAW_MODULES[case_id, sample]
    name, address = expected_address(case_id, sample)
    require(isinstance(value, dict) and set(value) == OBSERVATION_KEYS
            and value["sample_key"] == sample
            and value["outcome"] == ("ok" if accepted else "deterministic_error")
            and value["error_kind"] ==
                (None if accepted else "function_body_size_exceeded")
            and (value["error_text"] is None if accepted else
                 isinstance(value["error_text"], str) and
                 "function body size count exceeds limit of 7654321"
                 in value["error_text"])
            and value["result_value"] == (address if accepted else None)
            and type(value["function_body_bytes"]) is int
            and value["function_body_bytes"] == body_bytes
            and value["function_body_limit_bytes"] == FUNCTION_LIMIT
            and value["br_table_entries"] == entries
            and value["br_table_source_limit_entries"] ==
                (FUNCTION_LIMIT if entries is not None else None)
            and value["br_table_fixture_max_entries"] ==
                (BR_FIXTURE_MAX if entries is not None else None)
            and value["control_depth"] == depth
            and type(value["raw_module_bytes"]) is int
            and value["raw_module_bytes"] == raw_bytes
            and value["raw_module_sha256"] == raw_sha256
            and type(value["compressed_bytes"]) is int
            and 0 < value["compressed_bytes"] < value["raw_module_bytes"]
            and digest(value["compressed_sha256"])
            and type(value["serialized_instruction_bytes"]) is int
            and value["compressed_bytes"] <
                value["serialized_instruction_bytes"] <= 387 * 1024
            and value["publication_path"] ==
                "Runtime::publish/Storage::decode_component_bytes/"
                "ComponentEncoder/Component::from_binary"
            and all(digest(value[key]) for key in
                    ("state_before_sha256", "state_after_sha256",
                     "state_restored_sha256"))
            and value["state_restored_sha256"] == value["state_before_sha256"]
            and (value["state_after_sha256"] != value["state_before_sha256"])
                is accepted
            and all(type(value[key]) is int and value[key] >= 0 for key in
                    ("receipts_before", "receipts_after", "receipts_restored",
                     "resources_before", "resources_after", "system_fuel",
                     "user_fuel", "deposit_fuel", "live_invocations"))
            and value["receipts_after"] == value["receipts_before"] + int(accepted)
            and value["receipts_restored"] == value["receipts_before"]
            and value["resources_after"] == value["resources_before"]
            and (value["system_fuel"] > 0) is accepted
            and value["user_fuel"] == value["deposit_fuel"] == 0
            and value["live_invocations"] == 0
            and value["stack_empty"] is True
            and value["savepoint_empty"] is True
            and value["teardown_probe_on"] is (role == "target_observed")
            and value["engine_target"] == "pulley64-unknown-unknown-elf"
            and value["max_wasm_stack"] == 524_288
            and value["async_stack_size"] ==
                (1_048_576 if configuration == "reduced" else 2_097_152),
            "cold publication fixture, result, or state changed")
    receipts = value["measured_receipts"]
    require(isinstance(receipts, list) and len(receipts) == int(accepted),
            "cold publication receipt count changed")
    if accepted:
        receipt = receipts[0]
        require(isinstance(receipt, dict) and set(receipt) == RECEIPT_KEYS
                and receipt["contract"] == name
                and receipt["function"] == "init"
                and receipt["status"] == "Ok"
                and type(receipt["gas"]) is int and receipt["gas"] > 0
                and type(receipt["size"]) is int
                and receipt["size"] == len(address.encode())
                and receipt["value"] == address
                and type(receipt["signer_id"]) is int
                and receipt["signer_id"] == 1
                and type(receipt["payer_signer_id"]) is int
                and receipt["payer_signer_id"] == 1
                and receipt["height"] == 1
                and receipt["tx_id"] is None
                and receipt["input_index"] == receipt["op_index"] ==
                    receipt["result_index"] == 0,
                "cold publication init receipt content or order changed")
    if role == "target_observed":
        if accepted:
            teardown = validate_teardown(value["teardown_events"], 1, 0)
            require(teardown["created"]["nested_chain"] == 1,
                    "cold publication did not close its init Store")
        else:
            require(value["teardown_events"] == [],
                    "cold publication rejection created a Store")
    else:
        require(value["teardown_events"] is None,
                "probe-off cold publication emitted teardown events")
    return {key: value[key] for key in (
        "sample_key", "outcome", "error_kind", "error_text", "result_value",
        "function_body_bytes", "br_table_entries", "control_depth",
        "raw_module_bytes", "raw_module_sha256", "compressed_bytes",
        "compressed_sha256", "serialized_instruction_bytes",
        "state_before_sha256", "state_after_sha256", "state_restored_sha256",
        "receipts_before", "receipts_after", "receipts_restored",
        "measured_receipts", "resources_before", "resources_after",
        "system_fuel", "user_fuel", "deposit_fuel")}


def validate_trace(trace, runtime, attempts, os_name):
    require(set(trace) == {"scope", "configuration", "case_id", "process_role",
                           "events"}
            and all(trace[key] == runtime[key] for key in
                    ("scope", "configuration", "case_id", "process_role")),
            "cold publication trace identity changed")
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
                "cold publication trace has an unknown event")
        if event["category"] == "tokio_worker":
            require(workers.get(event["thread_id"]) == event["os_thread_id"]
                    and not event["name"].startswith("blocking_decode_"),
                    "cold publication escaped a measured Tokio worker")
        else:
            require(event["category"] == "blocking_pool"
                    and blocking.get(event["thread_id"]) == event["os_thread_id"]
                    and event["name"].startswith("blocking_decode_"),
                    "cold publication lacks blocking-thread capacity")
        names.append(event["name"])
    starts = [i for i, name in enumerate(names)
              if name == "finite_stack_attempt_start"]
    ends = [i for i, name in enumerate(names)
            if name == "finite_stack_attempt_end"]
    require(len(starts) == len(ends) == len(attempts)
            and names.count("fixture_preparation_entry") ==
                names.count("fixture_preparation_exit") == 1
            and names.index("fixture_preparation_entry") <
                names.index("fixture_preparation_exit") < starts[0]
            and all(start < end and (i == 0 or ends[i - 1] < start)
                    for i, (start, end) in enumerate(zip(starts, ends, strict=True))),
            "cold publication setup or attempt intervals changed")
    setup_start = names.index("fixture_preparation_entry")
    setup_end = names.index("fixture_preparation_exit")
    intervals = [(setup_start, setup_end)] + list(zip(starts, ends, strict=True))
    boundaries = {"fixture_preparation_entry", "fixture_preparation_exit",
                  "finite_stack_attempt_start", "finite_stack_attempt_end"}
    require(all(name in boundaries or any(start < index < end
                    for start, end in intervals)
                for index, name in enumerate(names)),
            "cold publication phase escaped setup or an attempt")
    for attempt, start, end in zip(attempts, starts, ends, strict=True):
        segment = trace["events"][start:end + 1]
        sequence = [event["name"] for event in segment]
        accepted = attempt["sample_key"] == "accepted"
        canonical = [name for name in sequence if name.startswith("canonical_")]
        require(sequence.count("publication_entry") ==
                sequence.count("publication_exit") == 1
                and sequence.count("blocking_decode_entry") ==
                    sequence.count("blocking_decode_exit") == 1
                and sequence.count("compiler_entry") ==
                    sequence.count("compiler_exit") == int(accepted)
                and canonical == (["canonical_input_entry", "canonical_input_exit",
                                   "canonical_output_entry", "canonical_output_exit"]
                                  if accepted else [])
                and sequence.index("publication_entry") <
                    sequence.index("blocking_decode_entry") <
                    sequence.index("blocking_decode_exit") <
                    sequence.index("publication_exit")
                and (not accepted or sequence.index("blocking_decode_exit") <
                     sequence.index("compiler_entry") <
                     sequence.index("compiler_exit") <
                     sequence.index("canonical_input_entry") <
                     sequence.index("canonical_input_exit") <
                     sequence.index("canonical_output_entry") <
                     sequence.index("canonical_output_exit") <
                     sequence.index("publication_exit")),
                "cold publication validation or compiler phases changed")
        decode = [event for event in segment
                  if event["name"].startswith("blocking_decode_")]
        require(decode[0]["thread_id"] == decode[1]["thread_id"]
                and decode[0]["os_thread_id"] == decode[1]["os_thread_id"],
                "cold publication decode migrated blocking threads")
        if accepted:
            for entry, exit_name in (("compiler_entry", "compiler_exit"),
                                     ("canonical_input_entry", "canonical_input_exit")):
                first = segment[sequence.index(entry)]
                last = segment[sequence.index(exit_name)]
                require(first["thread_id"] == last["thread_id"]
                        and first["os_thread_id"] == last["os_thread_id"],
                        "cold publication synchronous phase migrated workers")


def validate_run(run, bundle, directory):
    case_id, role, configuration = (run[key] for key in
                                    ("case_id", "process_role", "configuration"))
    name = run_name(case_id, role, configuration)
    process = run["process"]
    command = [bundle["binary_path"], "--ignored", "--exact", WORKER_TEST,
               "--nocapture"]
    require(run["run_id"] == name and run["cell"] == bundle["cell"]
            and run["case_env"] == expected_case_env(case_id, role, configuration)
            and run["source_sha"] == bundle["source_sha"]
            and run["binary_sha256_before"] == run["binary_sha256_after"] ==
                bundle["binary_sha256"]
            and run["argv"] == process["command"] == command
            and type(process["pid"]) is int and process["pid"] > 0
            and process["exit_code"] == 0 and process["signal"] is None
            and process["timed_out"] is False and process["complete"] is True
            and process["test_harness_passed"] is True
            and process["started_unix_ns"] < process["ended_unix_ns"],
            "cold publication process identity or completion changed")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in
                ("attempts", "summary", "runtime", "trace", "terminal")),
            "cold publication records differ from raw transcript")
    samples = CASE_SAMPLES[case_id]
    expected_order = [(sample, repeat) for sample in samples for repeat in range(2)]
    attempts = parsed["attempts"]
    require([(item["sample_key"], item["repeat_index"]) for item in attempts] ==
            expected_order, "cold publication samples or repeats changed")
    summary, runtime, terminal = (parsed[key] for key in
                                  ("summary", "runtime", "terminal"))
    outcomes = ["ok" if sample == "accepted" else "deterministic_error"
                for sample, _ in expected_order]
    require(summary == {"case_id": case_id, "configuration": configuration,
                        "process_role": role, "sample_count": len(attempts),
                        "outcomes": outcomes, "complete": True}
            and terminal == {"case_id": case_id, "configuration": configuration,
                             "process_role": role, "pid": process["pid"],
                             "sample_count": len(attempts), "complete": True}
            and runtime["scope"] == "paired_finite_stack_worker"
            and all(runtime[key] == expected for key, expected in (
                ("case_id", case_id), ("configuration", configuration),
                ("process_role", role), ("pid", process["pid"]),
                ("embedded_source_sha", bundle["source_sha"]),
                ("binary_sha256", bundle["binary_sha256"]))),
            "cold publication summary or runtime identity changed")
    os_name = "macos" if bundle["cell"].startswith("macOS-") else "linux"
    validate_trace(parsed["trace"], runtime, attempts, os_name)
    return [validate_observation(attempt, case_id, sample, repeat, role,
                                 configuration, process["pid"])
            for attempt, (sample, repeat) in zip(attempts, expected_order,
                                                 strict=True)]


def validate_bundle(bundle, directory, archive_binary=None):
    manifest = build_manifest()
    require(set(bundle) == {"schema_version", "qualification_status", "cell",
                            "manifest_sha256", "source_sha", "binary_path",
                            "binary_sha256", "control_capture", "runs"}
            and bundle["schema_version"] == 1
            and bundle["qualification_status"] == "missing"
            and load_json_strict(MANIFEST) == manifest
            and bundle["manifest_sha256"] == sha256(MANIFEST),
            "cold publication source or claim status changed")
    file_evidence(directory, bundle["control_capture"])
    control, binary = validate_control(
        directory / bundle["control_capture"]["path"],
        bundle["control_capture"]["sha256"], manifest,
        page_size=bundle_page_size(bundle) if archive_binary is not None else None,
        archive_binary=archive_binary, expected_cell=bundle["cell"])
    validate_cell_identity(bundle["cell"], control["cargo_artifact"],
                           check_host=archive_binary is None)
    require(control["source_sha"] == bundle["source_sha"]
            and control["binary_sha256"] == bundle["binary_sha256"]
            and str(binary) == bundle["binary_path"],
            "cold publication control source or binary changed")
    expected = {(case_id, role, configuration) for case_id in CASE_IDS
                for role in ROLES for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "cold publication process registry is incomplete")
    identities = [(run["process"]["pid"], run["process"]["started_unix_ns"])
                  for run in bundle["runs"].values()]
    identities.append((control["guard_control"]["process"]["pid"],
                       control["guard_control"]["process"]["started_unix_ns"]))
    require(len(identities) == len(set(identities)),
            "cold publication process identities overlap")
    require({run["raw_log"]["path"] for run in bundle["runs"].values()} ==
            {path.name for path in directory.glob("*.log")},
            "cold publication raw logs are missing or extra")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle,
                                    directory) for key in sorted(expected)}
    for case_id in CASE_IDS:
        reference = signatures[case_id, "target_observed", "production"]
        for index in range(0, len(reference), 2):
            require(reference[index] == reference[index + 1],
                    "cold publication repeated semantics changed")
        for role in ROLES:
            for configuration in CONFIGURATIONS:
                require(signatures[case_id, role, configuration] == reference,
                        "cold publication role or stack configuration changed semantics")
            reduced = [thread["usable_bytes"] for thread in
                       bundle["runs"][run_name(case_id, role, "reduced")]
                       ["runtime"]["thread_observations"]
                       if thread["thread_category"] == "tokio_worker"]
            production = [thread["usable_bytes"] for thread in
                          bundle["runs"][run_name(case_id, role, "production")]
                          ["runtime"]["thread_observations"]
                          if thread["thread_category"] == "tokio_worker"]
            require(reduced and production and min(production) >= 2 * max(reduced),
                    "cold publication worker capacity ratio is below two")
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
