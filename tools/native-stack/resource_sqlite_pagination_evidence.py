#!/usr/bin/env python3
"""Validate exact native token and NFT page contents and Store closure."""

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


CASE_ID = "sqlite_pagination"
ROWS = 1_024
PAGE_SIZES = (1, 7, 100)
POSITIONS = ("first", "middle", "final")
SAMPLES = tuple(f"{source}_{size}_{position}"
                for source in ("token", "nft") for size in PAGE_SIZES
                for position in POSITIONS)
TOKEN_ROWS = sorted(
    [{"acc": "7", "amt": "1000000000"}] +
    [{"acc": str(identity), "amt": "1"}
     for identity in range(10_000, 10_000 + ROWS - 1)],
    key=lambda row: row["acc"])
NFT_ROWS = [
    {"nft_id": f"nft-{index:04}", "agreement_id": f"file-{index:04}",
     "owner": "7", "creator": "7"}
    for index in range(ROWS)
]
OBSERVATION_KEYS = {
    "sample_key", "outcome", "page", "cursor", "page_size", "row_count",
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
    source, size, position = sample.split("_")
    require(source in {"token", "nft"} and int(size) in PAGE_SIZES
            and position in POSITIONS, "unknown pagination sample")
    size = int(size)
    start = {"first": 0, "middle": ROWS // 2,
             "final": ROWS - (size + 1) // 2}[position]
    end = min(start + size, ROWS)
    rows = TOKEN_ROWS if source == "token" else NFT_ROWS
    key = "acc" if source == "token" else "nft_id"
    cursor = rows[start - 1][key] if start else None
    continuation = rows[end - 1][key] if end < ROWS else None
    return {"items": rows[start:end], "next": continuation}, cursor, size


def run_name(case_id, role, configuration):
    require(case_id == CASE_ID and role in ROLES and configuration in CONFIGURATIONS,
            "unknown pagination run")
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
    page, cursor, size = expected_page(sample)
    source = sample.split("_", 1)[0]
    require(set(attempt) == {"case_id", "configuration", "process_role",
                             "sample_key", "repeat_index", "pid", "observation"}
            and (attempt["case_id"], attempt["configuration"],
                 attempt["process_role"], attempt["sample_key"],
                 attempt["repeat_index"], attempt["pid"]) ==
                (CASE_ID, configuration, role, sample, repeat_index, pid),
            "pagination attempt identity changed")
    require(isinstance(value, dict) and set(value) == OBSERVATION_KEYS
            and value["sample_key"] == sample and value["outcome"] == "ok"
            and value["page"] == page and value["cursor"] == cursor
            and type(value["page_size"]) is int and value["page_size"] == size
            and type(value["row_count"]) is int and value["row_count"] == ROWS
            and value["address"] == f"{source}:0:0"
            and value["execution_path"] == "Runtime::execute_api/Runtime::invoke"
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
            "pagination page contents, continuation, or Store state changed")
    before = value["state_before_sha256"]
    require(isinstance(before, str) and re.fullmatch(r"[0-9a-f]{64}", before)
            and value["state_after_sha256"] == before,
            "pagination changed full persistent state")
    if role == "target_observed":
        teardown = validate_teardown(value["teardown_events"], 1, 0)
        require(teardown["created"]["nested_chain"] == 1,
                "pagination did not close its invocation Store")
    else:
        require(value["teardown_events"] is None,
                "probe-off pagination child emitted teardown events")
    return {"sample_key": sample, "repeat_index": repeat_index,
            "outcome": "ok", "page": page, "cursor": cursor,
            "page_size": size, "row_count": ROWS,
            "system_fuel": value["system_fuel"],
            "state_sha256": before, "receipts": value["receipts_before"],
            "resources": value["resources_before"]}


def validate_trace(trace, runtime, attempts, os_name):
    require(set(trace) == {"scope", "configuration", "case_id", "process_role",
                           "events"}
            and all(trace[key] == runtime[key] for key in
                    ("scope", "configuration", "case_id", "process_role")),
            "pagination trace identity changed")
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
        "finite_stack_attempt_start", "finite_stack_attempt_end"}
    events = trace["events"]
    require(isinstance(events, list) and events,
            "pagination trace is empty")
    for event in events:
        require(set(event) == {"name", "thread_id", "os_thread_id", "category"}
                and event["name"] in allowed,
                "pagination emitted an unknown trace event")
        if event["category"] == "tokio_worker":
            require(workers.get(event["thread_id"]) == event["os_thread_id"]
                    and not event["name"].startswith("blocking_decode_"),
                    "pagination escaped measured workers")
        else:
            require(event["category"] == "blocking_pool"
                    and blocking.get(event["thread_id"]) == event["os_thread_id"]
                    and event["name"].startswith("blocking_decode_"),
                    "pagination blocking decode lacks a measured stack")
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
            and ends[17] < setup_starts[1] < setup_ends[1] < starts[18]
            and names.count("compiler_entry") >= 1
            and names.count("blocking_decode_entry") >= 1,
            "pagination setup or attempt intervals changed")
    for attempt, start, end in zip(attempts, starts, ends, strict=True):
        segment = names[start:end + 1]
        conversion = [name for name in segment if name.startswith("canonical_")]
        require(segment.count("fixture_preparation_entry") == 0
                and segment.count("compiler_entry") == 0
                and conversion == ["canonical_input_entry", "canonical_input_exit",
                                   "canonical_output_entry", "canonical_output_exit"],
                f"pagination {attempt['sample_key']} did not reach its query boundary")
    for entry, exit_name in PHASES:
        if entry == "canonical_output_entry":
            # Encoding awaits, so its scope can resume on another Tokio worker.
            depth = 0
            for event in events:
                if event["name"] == entry:
                    depth += 1
                elif event["name"] == exit_name:
                    require(depth > 0, "unpaired pagination canonical output exit")
                    depth -= 1
            require(depth == 0, "unclosed pagination canonical output entry")
            continue
        in_flight = {}
        for event in events:
            thread = event["thread_id"]
            if event["name"] == entry:
                require(thread not in in_flight,
                        f"overlapping pagination {entry}")
                in_flight[thread] = event["os_thread_id"]
            elif event["name"] == exit_name:
                require(in_flight.pop(thread, None) == event["os_thread_id"],
                        f"unpaired pagination {exit_name}")
        require(not in_flight, f"unclosed pagination {entry}")


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
            "pagination process identity or completion changed")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in
                ("attempts", "summary", "runtime", "trace", "terminal")),
            "pagination records differ from raw transcript")
    attempts = parsed["attempts"]
    expected_order = [(sample, repeat) for sample in SAMPLES for repeat in range(2)]
    require([(item["sample_key"], item["repeat_index"]) for item in attempts] ==
            expected_order,
            "pagination sample order or repetitions changed")
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
            "pagination summary or runtime identity changed")
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
            "pagination source or claim status changed")
    file_evidence(directory, bundle["control_capture"])
    control_path = directory / bundle["control_capture"]["path"]
    control, binary = validate_control(
        control_path, bundle["control_capture"]["sha256"], manifest,
        page_size=bundle_page_size(bundle) if archive_binary is not None else None,
        archive_binary=archive_binary, expected_cell=bundle["cell"])
    validate_cell_identity(bundle["cell"], control["cargo_artifact"],
                           check_host=archive_binary is None)
    require(control["source_sha"] == bundle["source_sha"]
            and control["binary_sha256"] == bundle["binary_sha256"]
            and str(binary) == bundle["binary_path"],
            "pagination control source or binary changed")
    expected = {(CASE_ID, role, configuration) for role in ROLES
                for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "pagination process registry is incomplete")
    identities = [(run["process"]["pid"], run["process"]["started_unix_ns"])
                  for run in bundle["runs"].values()]
    identities.append((control["guard_control"]["process"]["pid"],
                       control["guard_control"]["process"]["started_unix_ns"]))
    require(len(identities) == len(set(identities)),
            "pagination process identities overlap")
    require({run["raw_log"]["path"] for run in bundle["runs"].values()} ==
            {path.name for path in directory.glob("*.log")},
            "pagination raw logs are missing or extra")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle,
                                    directory) for key in sorted(expected)}
    reference = signatures[CASE_ID, "target_observed", "production"]
    for index in range(0, len(reference), 2):
        require({key: value for key, value in reference[index].items()
                 if key != "repeat_index"} ==
                {key: value for key, value in reference[index + 1].items()
                 if key != "repeat_index"},
                "pagination repeated semantics changed")
    for role in ROLES:
        for configuration in CONFIGURATIONS:
            require(signatures[CASE_ID, role, configuration] == reference,
                    "pagination role or stack configuration changed semantics")
        reduced = [thread["usable_bytes"] for thread in
                   bundle["runs"][run_name(CASE_ID, role, "reduced")]
                   ["runtime"]["thread_observations"]
                   if thread["thread_category"] == "tokio_worker"]
        production = [thread["usable_bytes"] for thread in
                      bundle["runs"][run_name(CASE_ID, role, "production")]
                      ["runtime"]["thread_observations"]
                      if thread["thread_category"] == "tokio_worker"]
        require(reduced and production and min(production) >= 2 * max(reduced),
                "pagination worker capacity ratio is below two")
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
