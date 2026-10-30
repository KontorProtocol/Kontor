#!/usr/bin/env python3
"""Validate full large-value guest pages through compact exact row hashes."""

import argparse
import hashlib
import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path

from capture_resource_diagnostic import validate_control
from resource_boundary_evidence import validate_cell_identity
from resource_evidence import (file_evidence, load_json_strict, require, sha256,
                               thread_capacities)
from resource_evidence_v2 import validate_teardown
from resource_finite_evidence import (CONFIGURATIONS, ROLES, WORKER_TEST,
                                      parse_worker_log)
from resource_manifest import MANIFEST, ROOT, build_manifest


CASE_ID = "sqlite_large_values"
ROWS = 101
LARGE_INDEX = 50
SMALL_VALUE_BYTES = 16
VALUE_BYTES = (16_384, 1_048_576)
PAGE_SIZES = (1, 7, 100)
SAMPLES = tuple(f"value_{value_bytes}_page_{page_size}"
                for value_bytes in VALUE_BYTES for page_size in PAGE_SIZES)
COMPONENT_SHA256 = sha256(ROOT / "test-contracts/binaries/counter.wasm.br")
OBSERVATION_KEYS = {
    "sample_key", "outcome", "page_size", "value_bytes", "row_count",
    "items", "cursor", "next", "large_key", "setup_provenance",
    "paid_rejection", "component_sha256", "publication_path",
    "address", "execution_path", "system_fuel", "user_fuel", "deposit_fuel",
    "state_before_sha256", "state_after_sha256", "receipts_before",
    "receipts_after", "resources_before", "resources_after", "stack_empty",
    "savepoint_empty", "live_invocations", "teardown_probe_on",
    "teardown_events", "engine_target", "max_wasm_stack", "async_stack_size",
}
PHASES = (
    ("compiler_entry", "compiler_exit"),
    ("blocking_decode_entry", "blocking_decode_exit"),
    ("canonical_input_entry", "canonical_input_exit"),
    ("canonical_output_entry", "canonical_output_exit"),
)


def expected_page(sample):
    parts = sample.split("_")
    require(len(parts) == 4 and parts[0] == "value" and parts[2] == "page"
            and parts[1].isdigit() and parts[3].isdigit()
            and int(parts[1]) in VALUE_BYTES and int(parts[3]) in PAGE_SIZES,
            "unknown large-value sample")
    value_bytes, size = int(parts[1]), int(parts[3])
    start = {1: 50, 7: 47, 100: 0}[size]
    end = min(start + size, ROWS)
    rows = []
    for index in range(start, end):
        length = value_bytes if index == LARGE_INDEX else SMALL_VALUE_BYTES
        rows.append({"key": f"k{index:03}", "value_bytes": length,
                     "value_sha256": hashlib.sha256(b"a" * length).hexdigest()})
    cursor = f"k{start - 1:03}" if start else None
    continuation = f"k{end - 1:03}" if end < ROWS else None
    return rows, cursor, continuation, size, value_bytes


def run_name(case_id, role, configuration):
    require(case_id == CASE_ID and role in ROLES and configuration in CONFIGURATIONS,
            "unknown large-value run")
    return f"{case_id}-{role}-{configuration}"


def expected_case_env(case_id, role, configuration):
    run_name(case_id, role, configuration)
    return {"KONTOR_FINITE_STACK_CASE": case_id,
            "KONTOR_FINITE_STACK_ROLE": role,
            "KONTOR_RESOURCE_MODE": configuration,
            "KONTOR_RESOURCE_TEARDOWN_PROBE":
                "on" if role == "target_observed" else "off"}


def validate_paid_rejection(rejection):
    require(isinstance(rejection, dict)
            and set(rejection) == {
                "outcome", "error", "key", "row_absent",
                "state_before_sha256", "state_after_sha256",
                "state_restored_sha256", "receipts_before", "receipts_after",
                "receipts_restored", "receipt_status", "receipt_gas",
                "user_fuel", "gas_to_fuel_multiplier", "fee",
                "payer_before", "payer_after", "burner_before", "burner_after",
                "supply_before", "supply_after", "core_before", "core_after"},
            "paid large-value rejection fields changed")
    require(rejection["outcome"] == "deterministic_error"
            and rejection["error"] ==
                "storage deposit exceeds the op's gas budget"
            and rejection["key"] == "k999"
            and rejection["row_absent"] is True
            and rejection["receipt_status"] == "Other",
            "paid large-value rejection outcome changed")
    before = rejection["state_before_sha256"]
    after = rejection["state_after_sha256"]
    restored = rejection["state_restored_sha256"]
    require(all(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                for digest in (before, after, restored))
            and before != after and restored == before,
            "paid large-value rejection leaked persistent state")
    receipts_before = rejection["receipts_before"]
    require(type(receipts_before) is int and receipts_before >= 0
            and type(rejection["receipts_after"]) is int
            and rejection["receipts_after"] == receipts_before + 1
            and type(rejection["receipts_restored"]) is int
            and rejection["receipts_restored"] == receipts_before,
            "paid large-value rejection receipt count changed")
    gas = rejection["receipt_gas"]
    user_fuel = rejection["user_fuel"]
    multiplier = rejection["gas_to_fuel_multiplier"]
    require(all(type(value) is int for value in (gas, user_fuel, multiplier))
            and user_fuel > 0 and multiplier > 0
            and gas == max(1, (user_fuel + multiplier - 1) // multiplier)
            and gas <= 100_000,
            "paid large-value rejection gas accounting changed")
    numeric_keys = ("fee", "payer_before", "payer_after", "burner_before",
                    "burner_after", "supply_before", "supply_after",
                    "core_before", "core_after")
    try:
        amounts = {key: Decimal(rejection[key]) for key in numeric_keys
                   if isinstance(rejection[key], str)}
    except InvalidOperation as error:
        raise ValueError("paid large-value rejection has invalid amounts") from error
    require(len(amounts) == len(numeric_keys)
            and all(amount.is_finite() for amount in amounts.values())
            and amounts["fee"] == Decimal(gas) * Decimal("1e-9")
            and amounts["payer_before"] - amounts["payer_after"] == amounts["fee"]
            and amounts["burner_after"] - amounts["burner_before"] == amounts["fee"]
            and amounts["supply_before"] - amounts["supply_after"] == amounts["fee"]
            and amounts["core_before"] == amounts["core_after"],
            "paid large-value rejection fee or balance delta changed")


def validate_observation(attempt, sample, repeat_index, role, configuration, pid):
    value = attempt["observation"]
    rows, cursor, continuation, size, value_bytes = expected_page(sample)
    require(set(attempt) == {"case_id", "configuration", "process_role",
                             "sample_key", "repeat_index", "pid", "observation"}
            and (attempt["case_id"], attempt["configuration"],
                 attempt["process_role"], attempt["sample_key"],
                 attempt["repeat_index"], attempt["pid"]) ==
                (CASE_ID, configuration, role, sample, repeat_index, pid),
            "large-value attempt identity changed")
    require(isinstance(value, dict) and set(value) == OBSERVATION_KEYS
            and value["sample_key"] == sample and value["outcome"] == "ok"
            and value["items"] == rows and value["cursor"] == cursor
            and value["next"] == continuation
            and type(value["page_size"]) is int and value["page_size"] == size
            and type(value["value_bytes"]) is int
            and value["value_bytes"] == value_bytes
            and type(value["row_count"]) is int and value["row_count"] == ROWS
            and value["large_key"] == "k050"
            and value["setup_provenance"] ==
                ("paid" if value_bytes == 16_384 else "core_after_paid_rejection")
            and value["address"] == "counter:1:0"
            and value["component_sha256"] == COMPONENT_SHA256
            and value["publication_path"] ==
                "Runtime::publish/native_provenance"
            and value["execution_path"] == "Runtime::execute/Runtime::invoke"
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
            "large-value page contents, cursor, or Store state changed")
    rejection = value["paid_rejection"]
    if value_bytes == 16_384:
        require(rejection is None,
                "small value fixture unexpectedly used a paid rejection")
    else:
        validate_paid_rejection(rejection)
    before = value["state_before_sha256"]
    require(isinstance(before, str) and re.fullmatch(r"[0-9a-f]{64}", before)
            and value["state_after_sha256"] == before,
            "large-value view changed full persistent state")
    if role == "target_observed":
        teardown = validate_teardown(value["teardown_events"], 1, 0)
        require(teardown["created"]["nested_chain"] == 1,
                "large-value page did not close its invocation Store")
    else:
        require(value["teardown_events"] is None,
                "probe-off large-value child emitted teardown events")
    return {"sample_key": sample, "repeat_index": repeat_index,
            "outcome": "ok", "items": rows, "cursor": cursor,
            "next": continuation, "value_bytes": value_bytes,
            "setup_provenance": value["setup_provenance"],
            "paid_rejection": rejection,
            "page_size": size, "row_count": ROWS,
            "system_fuel": value["system_fuel"],
            "state_sha256": before, "receipts": value["receipts_before"],
            "resources": value["resources_before"]}


def validate_trace(trace, runtime, attempts, os_name):
    require(set(trace) == {"scope", "configuration", "case_id", "process_role",
                           "events"}
            and all(trace[key] == runtime[key] for key in
                    ("scope", "configuration", "case_id", "process_role")),
            "large-value trace identity changed")
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
        "fixture_preparation_entry", "fixture_preparation_exit",
        "publication_entry", "publication_exit",
        "finite_stack_attempt_start", "finite_stack_attempt_end"}
    events = trace["events"]
    require(isinstance(events, list) and events,
            "large-value trace is empty")
    for event in events:
        require(set(event) == {"name", "thread_id", "os_thread_id", "category"}
                and event["name"] in allowed,
                "large-value emitted an unknown trace event")
        if event["category"] == "tokio_worker":
            require(workers.get(event["thread_id"]) == event["os_thread_id"]
                    and not event["name"].startswith("blocking_decode_"),
                    "large-value escaped measured workers")
        else:
            require(event["category"] == "blocking_pool"
                    and blocking.get(event["thread_id"]) == event["os_thread_id"]
                    and event["name"].startswith("blocking_decode_"),
                    "large-value blocking decode lacks a measured stack")
    names = [event["name"] for event in events]
    starts = [index for index, name in enumerate(names)
              if name == "finite_stack_attempt_start"]
    ends = [index for index, name in enumerate(names)
            if name == "finite_stack_attempt_end"]
    setup_starts = [index for index, name in enumerate(names)
                    if name == "fixture_preparation_entry"]
    setup_ends = [index for index, name in enumerate(names)
                  if name == "fixture_preparation_exit"]
    require(len(starts) == len(ends) == len(attempts)
            and all(start < end and (index == 0 or ends[index - 1] < start)
                    for index, (start, end) in enumerate(zip(starts, ends, strict=True)))
            and len(setup_starts) == len(setup_ends) == 2
            and setup_starts[0] < setup_ends[0] < starts[0]
            and ends[5] < setup_starts[1] < setup_ends[1] < starts[6]
            and names.count("publication_entry") ==
                names.count("publication_exit") == 1
            and setup_starts[0] < names.index("publication_entry")
            < names.index("publication_exit") < setup_ends[0]
            and names.count("compiler_entry") >= 1
            and names.count("blocking_decode_entry") >= 1,
            "large-value setup or attempt intervals changed")
    for attempt, start, end in zip(attempts, starts, ends, strict=True):
        segment = names[start:end + 1]
        conversion = [name for name in segment if name.startswith("canonical_")]
        require(segment.count("fixture_preparation_entry") == 0
                and segment.count("compiler_entry") == 0
                and segment.count("publication_entry") == 0
                and conversion == ["canonical_input_entry", "canonical_input_exit",
                                   "canonical_output_entry", "canonical_output_exit"],
                f"large-value {attempt['sample_key']} did not reach its query boundary")
    for entry, exit_name in PHASES:
        if entry == "canonical_output_entry":
            # Encoding awaits, so its scope can resume on another Tokio worker.
            depth = 0
            for event in events:
                if event["name"] == entry:
                    depth += 1
                elif event["name"] == exit_name:
                    require(depth > 0, "unpaired large-value canonical output exit")
                    depth -= 1
            require(depth == 0, "unclosed large-value canonical output entry")
            continue
        in_flight = {}
        for event in events:
            thread = event["thread_id"]
            if event["name"] == entry:
                require(thread not in in_flight,
                        f"overlapping large-value {entry}")
                in_flight[thread] = event["os_thread_id"]
            elif event["name"] == exit_name:
                require(in_flight.pop(thread, None) == event["os_thread_id"],
                        f"unpaired large-value {exit_name}")
        require(not in_flight, f"unclosed large-value {entry}")


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
            "large-value process identity or completion changed")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in
                ("attempts", "summary", "runtime", "trace", "terminal")),
            "large-value records differ from raw transcript")
    attempts = parsed["attempts"]
    expected_order = [(sample, repeat) for sample in SAMPLES for repeat in range(2)]
    require([(item["sample_key"], item["repeat_index"]) for item in attempts] ==
            expected_order,
            "large-value sample order or repetitions changed")
    summary, runtime, terminal = (parsed[key] for key in
                                  ("summary", "runtime", "terminal"))
    require(summary == {"case_id": CASE_ID, "configuration": configuration,
                        "process_role": role, "sample_count": len(expected_order),
                        "outcomes": ["ok"] * len(expected_order), "complete": True}
            and terminal == {"case_id": CASE_ID, "configuration": configuration,
                             "process_role": role, "pid": process["pid"],
                             "sample_count": len(expected_order), "complete": True}
            and runtime["scope"] == "paired_finite_stack_worker"
            and all(runtime[key] == expected for key, expected in
                    (("case_id", CASE_ID), ("configuration", configuration),
                     ("process_role", role), ("pid", process["pid"]),
                     ("embedded_source_sha", bundle["source_sha"]),
                     ("binary_sha256", bundle["binary_sha256"]))),
            "large-value summary or runtime identity changed")
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
            "large-value source or claim status changed")
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
            "large-value control source or binary changed")
    expected = {(CASE_ID, role, configuration) for role in ROLES
                for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "large-value process registry is incomplete")
    identities = [(run["process"]["pid"], run["process"]["started_unix_ns"])
                  for run in bundle["runs"].values()]
    identities.append((control["guard_control"]["process"]["pid"],
                       control["guard_control"]["process"]["started_unix_ns"]))
    require(len(identities) == len(set(identities)),
            "large-value process identities overlap")
    require({run["raw_log"]["path"] for run in bundle["runs"].values()} ==
            {path.name for path in directory.glob("*.log")},
            "large-value raw logs are missing or extra")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle,
                                    directory) for key in sorted(expected)}
    reference = signatures[CASE_ID, "target_observed", "production"]
    for index in range(0, len(reference), 2):
        require({key: value for key, value in reference[index].items()
                 if key != "repeat_index"} ==
                {key: value for key, value in reference[index + 1].items()
                 if key != "repeat_index"},
                "large-value repeated semantics changed")
    for role in ROLES:
        for configuration in CONFIGURATIONS:
            require(signatures[CASE_ID, role, configuration] == reference,
                    "large-value role or stack configuration changed semantics")
        reduced = [thread["usable_bytes"] for thread in
                   bundle["runs"][run_name(CASE_ID, role, "reduced")]
                   ["runtime"]["thread_observations"]
                   if thread["thread_category"] == "tokio_worker"]
        production = [thread["usable_bytes"] for thread in
                      bundle["runs"][run_name(CASE_ID, role, "production")]
                      ["runtime"]["thread_observations"]
                      if thread["thread_category"] == "tokio_worker"]
        require(reduced and production and min(production) >= 2 * max(reduced),
                "large-value worker capacity ratio is below two")
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
