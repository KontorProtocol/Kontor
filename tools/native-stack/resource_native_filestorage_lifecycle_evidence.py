#!/usr/bin/env python3
"""Validate deterministic native filestorage lifecycle calls on measured stacks."""

import argparse
import json
import re
from decimal import Decimal
from pathlib import Path

from capture_resource_diagnostic import validate_control
from resource_boundary_evidence import validate_cell_identity
from resource_evidence import (file_evidence, load_json_strict, require, sha256,
                               thread_capacities)
from resource_evidence_v2 import validate_teardown
from resource_finite_evidence import (CONFIGURATIONS, ROLES, WORKER_TEST,
                                      parse_worker_log)
from resource_manifest import MANIFEST, build_manifest


CASE_ID = "native_filestorage_lifecycle"
SAMPLES = ("expiry", "penalty", "cleanup")
WORK_LIMIT = 32
OBSERVATION_KEYS = {
    "sample_key", "outcome", "processed", "challenge_count", "file_count",
    "challenge_ids", "agreements", "requirements",
    "active_agreements_before", "active_agreements_after",
    "statuses_before", "statuses_after",
    "stake_before", "stake_after", "supply_before", "supply_after",
    "penalty_total", "reservation_before", "reservation_after",
    "pending_before", "pending_after", "obligations_before",
    "obligations_after", "memberships_before", "memberships_after",
    "system_fuel", "user_fuel", "deposit_fuel", "state_before_sha256",
    "state_after_sha256", "state_restored_sha256", "receipts_before",
    "receipts_after", "measured_receipts", "receipts_restored",
    "resources_before", "resources_after", "stack_empty",
    "savepoint_restored", "savepoint_empty", "live_invocations",
    "teardown_probe_on", "teardown_events", "engine_target",
    "max_wasm_stack", "async_stack_size",
}
RECEIPT_KEYS = {
    "contract", "function", "status", "gas", "size", "value",
    "signer_id", "payer_signer_id", "height", "tx_id", "input_index",
    "op_index", "result_index",
}
DECIMAL_RECORD = (
    r"\{r0: ([0-9]+), r1: ([0-9]+), r2: ([0-9]+), "
    r"r3: ([0-9]+), sign: plus\}")
TOKEN_RESULT = re.compile(
    r"ok\(\{src: signer-id\(4\), amt: " + DECIMAL_RECORD + r"\}\)")
STAKING_RESULT = re.compile(
    r"ok\(\{burned: " + DECIMAL_RECORD +
    r", remaining: " + DECIMAL_RECORD + r"\}\)")


def decimal(value, label):
    require(isinstance(value, str), f"filestorage {label} is not a string")
    try:
        result = Decimal(value)
    except Exception as error:
        raise ValueError(f"filestorage {label} is malformed") from error
    require(result.is_finite() and result >= 0 and result.as_tuple().exponent >= -18,
            f"filestorage {label} is out of range")
    return result


def run_name(case_id, role, configuration):
    require(case_id == CASE_ID and role in ROLES and configuration in CONFIGURATIONS,
            "unknown filestorage run")
    return f"{case_id}-{role}-{configuration}"


def expected_case_env(case_id, role, configuration):
    run_name(case_id, role, configuration)
    return {"KONTOR_FINITE_STACK_CASE": case_id,
            "KONTOR_FINITE_STACK_ROLE": role,
            "KONTOR_RESOURCE_MODE": configuration,
            "KONTOR_RESOURCE_TEARDOWN_PROBE":
                "on" if role == "target_observed" else "off"}


def validate_receipts(receipts, sample):
    expected_function = ("expire-challenges" if sample == "expiry"
                         else "settle-expired-challenges")
    root = ("filestorage", expected_function)
    expected = ([(("token", "burn"), ("staking", "slash"))] * WORK_LIMIT
                if sample == "penalty" else [])
    expected = [entry for pair in expected for entry in pair] + [root]
    root_value = ("32" if sample == "expiry" else
                  "ok(32)" if sample == "penalty" else "ok(9)")
    require(isinstance(receipts, list) and len(receipts) == len(expected),
            "filestorage measured receipt count changed")
    for index, (receipt, (contract, function)) in enumerate(zip(
            receipts, expected, strict=True)):
        expected_signer = 4 if contract == "token" else 1
        expected_payer = 1 if contract == "filestorage" else None
        require(isinstance(receipt, dict) and set(receipt) == RECEIPT_KEYS
                and receipt["contract"] == contract
                and receipt["function"] == function
                and receipt["status"] == "Ok"
                and type(receipt["gas"]) is int and receipt["gas"] > 0
                and isinstance(receipt["value"], str) and receipt["value"]
                and (receipt["value"] == root_value
                     if contract == "filestorage" else
                     (TOKEN_RESULT if contract == "token" else STAKING_RESULT)
                     .fullmatch(receipt["value"]) is not None)
                and type(receipt["size"]) is int
                and receipt["size"] == len(receipt["value"].encode())
                and type(receipt["signer_id"]) is int
                and receipt["signer_id"] == expected_signer
                and ((type(receipt["payer_signer_id"]) is int
                      and receipt["payer_signer_id"] == expected_payer)
                     if contract == "filestorage" else
                     receipt["payer_signer_id"] is None)
                and type(receipt["height"]) is int
                and receipt["height"] == 2016
                and all(receipt[key] is None for key in
                        ("tx_id", "input_index", "op_index"))
                and type(receipt["result_index"]) is int
                and receipt["result_index"] == index,
                "filestorage receipt content or order changed")


def record_decimal(parts):
    limbs = [int(part) for part in parts]
    require(len(limbs) == 4 and all(0 <= limb < 2**64 for limb in limbs),
            "filestorage receipt decimal limb changed")
    return Decimal(sum(limb << (64 * index)
                       for index, limb in enumerate(limbs))) / Decimal(10**18)


def validate_penalty_receipt_values(receipts, challenge_ids, requirements):
    ordered = sorted(zip(challenge_ids, requirements, strict=True))
    remaining = Decimal(9000)
    for index, (_, required) in enumerate(ordered):
        burn, slash = receipts[2 * index:2 * index + 2]
        token = TOKEN_RESULT.fullmatch(burn["value"])
        staking = STAKING_RESULT.fullmatch(slash["value"])
        require(token is not None and staking is not None,
                "filestorage nested penalty result shape changed")
        amount = required * 30
        remaining -= amount
        require(record_decimal(token.groups()) == amount
                and record_decimal(staking.groups()[:4]) == amount
                and record_decimal(staking.groups()[4:]) == remaining,
                "filestorage penalty receipt amount or challenge order changed")


def validate_observation(attempt, sample, repeat_index, role, configuration, pid):
    require(sample in SAMPLES and isinstance(attempt, dict)
            and set(attempt) == {"case_id", "configuration", "process_role",
                                 "sample_key", "repeat_index", "pid",
                                 "observation"}
            and (attempt["case_id"], attempt["configuration"],
                 attempt["process_role"], attempt["sample_key"],
                 attempt["repeat_index"], attempt["pid"]) ==
                (CASE_ID, configuration, role, sample, repeat_index, pid),
            "filestorage attempt identity changed")
    value = attempt["observation"]
    require(isinstance(value, dict) and set(value) == OBSERVATION_KEYS
            and value["sample_key"] == sample and value["outcome"] == "ok",
            "filestorage observation shape changed")
    cleanup = sample == "cleanup"
    count = 3 if cleanup else WORK_LIMIT
    files = 40 if cleanup else WORK_LIMIT
    require(all(type(value[key]) is int and value[key] >= 0 for key in (
                "processed", "challenge_count", "file_count",
                "memberships_before", "memberships_after",
                "system_fuel", "user_fuel", "deposit_fuel",
                "receipts_before", "receipts_after", "receipts_restored",
                "resources_before", "resources_after", "live_invocations"))
            and value["processed"] == (9 if cleanup else WORK_LIMIT)
            and value["challenge_count"] == count
            and value["file_count"] == files
            and value["memberships_before"] == (8 if cleanup else files)
            and value["memberships_after"] == (0 if cleanup else files)
            and value["system_fuel"] > 0
            and value["user_fuel"] == value["deposit_fuel"] == 0
            and value["receipts_after"] ==
                value["receipts_before"] + len(value["measured_receipts"])
            and value["receipts_restored"] == value["receipts_before"]
            and value["resources_after"] == value["resources_before"]
            and value["live_invocations"] == 0
            and value["stack_empty"] is True
            and value["savepoint_restored"] is True
            and value["savepoint_empty"] is True
            and value["teardown_probe_on"] is (role == "target_observed")
            and value["engine_target"] == "pulley64-unknown-unknown-elf"
            and value["max_wasm_stack"] == 524_288
            and value["async_stack_size"] ==
                (1_048_576 if configuration == "reduced" else 2_097_152),
            "filestorage operation, budget, fuel, or Store state changed")
    before, after, restored = (value[key] for key in (
        "state_before_sha256", "state_after_sha256",
        "state_restored_sha256"))
    require(all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item)
                for item in (before, after, restored))
            and before != after and restored == before,
            "filestorage persistent state did not change and restore")
    ids = value["challenge_ids"]
    agreements = value["agreements"]
    requirements = value["requirements"]
    active_before = value["active_agreements_before"]
    active_after = value["active_agreements_after"]
    first = value["statuses_before"]
    last = value["statuses_after"]
    require(isinstance(ids, list) and len(ids) == count
            and all(isinstance(item, str) and item for item in ids)
            and len(ids) == len(set(ids))
            and isinstance(agreements, list) and len(agreements) == files
            and all(isinstance(item, str) and item for item in agreements)
            and len(set(agreements)) == files
            and isinstance(requirements, list) and len(requirements) == files
            and isinstance(active_before, list)
            and isinstance(active_after, list)
            and active_before ==
                ([agreement for agreement in agreements
                  if agreement not in set(sorted(agreements)[:WORK_LIMIT])]
                 if cleanup else agreements)
            and active_after == ([] if cleanup else agreements)
            and isinstance(first, list) and isinstance(last, list)
            and first == ["Settled" if cleanup else
                          "Active" if sample == "expiry" else "Expired"] * count
            and last == ["Expired" if sample == "expiry" else "Settled"] * count,
            "filestorage challenges or frozen workload changed")
    required = [decimal(item, "required collateral") for item in requirements]
    require(all(item > 0 for item in required),
            "filestorage collateral requirement vanished")
    collateral_by_agreement = dict(zip(agreements, required, strict=True))
    active_collateral = sum(
        (collateral_by_agreement[item] for item in active_before), Decimal(0))
    amounts = {key: decimal(value[key], key) for key in (
        "stake_before", "stake_after", "supply_before", "supply_after",
        "penalty_total", "reservation_before", "reservation_after")}
    expected_penalty = sum(required, Decimal(0)) * 30 if sample == "penalty" else Decimal(0)
    require(amounts["penalty_total"] == expected_penalty
            and amounts["stake_before"] == (Decimal(0) if cleanup else Decimal(9000))
            and amounts["stake_after"] ==
                amounts["stake_before"] - expected_penalty
            and amounts["supply_after"] ==
                amounts["supply_before"] - expected_penalty
            and amounts["reservation_before"] == active_collateral
            and amounts["reservation_after"] ==
                (Decimal(0) if cleanup else amounts["reservation_before"])
            and value["pending_before"] is cleanup
            and value["pending_after"] is False
            and value["obligations_before"] is True
            and value["obligations_after"] is (not cleanup),
            "filestorage collateral, supply, reservation, or obligation changed")
    validate_receipts(value["measured_receipts"], sample)
    if sample == "penalty":
        validate_penalty_receipt_values(
            value["measured_receipts"], ids, required)
    if role == "target_observed":
        nested = sum(receipt["contract"] != "token"
                     for receipt in value["measured_receipts"])
        auxiliary = sum(receipt["contract"] == "token"
                        for receipt in value["measured_receipts"])
        teardown = validate_teardown(value["teardown_events"], nested, 0)
        require(teardown["created"]["target_native_auxiliary"] ==
                    auxiliary
                and teardown["alive_after_teardown_count"] == 0,
                "filestorage native Store count or cleanup changed")
    else:
        require(value["teardown_events"] is None,
                "filestorage probe-off child emitted teardown events")
    return {key: item for key, item in value.items()
            if key not in {"teardown_probe_on", "teardown_events",
                           "async_stack_size", "max_wasm_stack", "engine_target",
                           "resources_before", "resources_after",
                           "stack_empty", "savepoint_restored", "savepoint_empty",
                           "live_invocations", "state_restored_sha256",
                           "receipts_restored"}}


def validate_operation_phases(events, expected_count):
    names = [event["name"] for event in events]
    require(names[0] == "operation_entry" and names[-1] == "operation_exit",
            "filestorage operation markers are incomplete")
    input_open = {}
    input_count = output_count = completed_input = output_depth = 0
    for event in events[1:-1]:
        name, thread, os_thread = (event[key] for key in
                                   ("name", "thread_id", "os_thread_id"))
        if name == "canonical_input_entry":
            require(thread not in input_open,
                    "filestorage canonical input overlapped on one worker")
            input_open[thread] = os_thread
            input_count += 1
        elif name == "canonical_input_exit":
            require(input_open.pop(thread, None) == os_thread,
                    "filestorage canonical input exit lacks its worker entry")
            completed_input += 1
        elif name == "canonical_output_entry":
            require(output_count < completed_input,
                    "filestorage canonical output preceded its input")
            output_count += 1
            output_depth += 1
        elif name == "canonical_output_exit":
            require(output_depth > 0,
                    "filestorage canonical output exit lacks an entry")
            output_depth -= 1
    require(input_count == completed_input == output_count == expected_count
            and not input_open and output_depth == 0,
            "filestorage canonical call count or phases changed")


def validate_trace(trace, runtime, attempts, os_name):
    require(set(trace) == {"scope", "configuration", "case_id", "process_role",
                           "events"}
            and all(trace[key] == runtime[key] for key in
                    ("scope", "configuration", "case_id", "process_role")),
            "filestorage trace identity changed")
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
    allowed = {"fixture_preparation_entry", "fixture_preparation_exit",
               "finite_stack_attempt_start", "finite_stack_attempt_end",
               "operation_entry", "operation_exit",
               "postcall_observation_entry", "postcall_observation_exit",
               "compiler_entry", "compiler_exit", "blocking_decode_entry",
               "blocking_decode_exit", "canonical_input_entry",
               "canonical_input_exit", "canonical_output_entry",
               "canonical_output_exit"}
    names = []
    for event in trace["events"]:
        require(set(event) == {"name", "thread_id", "os_thread_id", "category"}
                and event["name"] in allowed,
                "filestorage emitted an unknown trace event")
        if event["category"] == "tokio_worker":
            require(workers.get(event["thread_id"]) == event["os_thread_id"]
                    and not event["name"].startswith("blocking_decode_"),
                    "filestorage escaped measured Tokio workers")
        else:
            require(event["category"] == "blocking_pool"
                    and blocking.get(event["thread_id"]) == event["os_thread_id"]
                    and event["name"].startswith("blocking_decode_"),
                    "filestorage blocking decode lacks measured capacity")
        names.append(event["name"])
    starts = [i for i, name in enumerate(names)
              if name == "finite_stack_attempt_start"]
    ends = [i for i, name in enumerate(names)
            if name == "finite_stack_attempt_end"]
    setups = [i for i, name in enumerate(names)
              if name == "fixture_preparation_entry"]
    setup_ends = [i for i, name in enumerate(names)
                  if name == "fixture_preparation_exit"]
    require(len(starts) == len(ends) == len(attempts) == 6
            and len(setups) == len(setup_ends) == len(SAMPLES)
            and all(ends[index] < starts[index + 1]
                    for index in range(len(starts) - 1))
            and all(start < end < starts[2 * index]
                    and (index == 0 or ends[2 * index - 1] < start)
                    for index, (start, end) in
                    enumerate(zip(setups, setup_ends, strict=True))),
            "filestorage setup or attempt intervals changed")
    for index, (start, end) in enumerate(zip(starts, ends, strict=True)):
        segment = trace["events"][start:end + 1]
        segment_names = [event["name"] for event in segment]
        require(start < end
                and all(segment_names.count(marker) == 1 for marker in (
                    "operation_entry", "operation_exit",
                    "postcall_observation_entry", "postcall_observation_exit"))
                and "fixture_preparation_entry" not in segment_names,
                "filestorage attempt markers are missing or overlap setup")
        operation_start = segment_names.index("operation_entry")
        operation_end = segment_names.index("operation_exit")
        observer_start = segment_names.index("postcall_observation_entry")
        observer_end = segment_names.index("postcall_observation_exit")
        require(0 < operation_start < operation_end < observer_start
                < observer_end < len(segment_names) - 1,
                "filestorage operation and observer intervals overlap")
        validate_operation_phases(
            segment[operation_start:operation_end + 1],
            len(attempts[index]["observation"]["measured_receipts"]))


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
            "filestorage process identity or completion changed")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in (
                "attempts", "summary", "runtime", "trace", "terminal")),
            "filestorage records differ from raw transcript")
    attempts = parsed["attempts"]
    expected_order = [(sample, repeat) for sample in SAMPLES for repeat in range(2)]
    require([(item["sample_key"], item["repeat_index"]) for item in attempts] ==
            expected_order,
            "filestorage sample order or repetitions changed")
    summary, runtime, terminal = (parsed[key] for key in
                                  ("summary", "runtime", "terminal"))
    require(summary == {"case_id": CASE_ID, "configuration": configuration,
                        "process_role": role, "sample_count": 6,
                        "outcomes": ["ok"] * 6, "complete": True}
            and terminal == {"case_id": CASE_ID, "configuration": configuration,
                             "process_role": role, "pid": process["pid"],
                             "sample_count": 6, "complete": True}
            and runtime["scope"] == "paired_finite_stack_worker"
            and all(runtime[key] == expected for key, expected in (
                ("case_id", CASE_ID), ("configuration", configuration),
                ("process_role", role), ("pid", process["pid"]),
                ("embedded_source_sha", bundle["source_sha"]),
                ("binary_sha256", bundle["binary_sha256"]))),
            "filestorage summary or runtime identity changed")
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
            "filestorage source or claim status changed")
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
            "filestorage control source or binary changed")
    expected = {(CASE_ID, role, configuration) for role in ROLES
                for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "filestorage process registry is incomplete")
    identities = [(run["process"]["pid"], run["process"]["started_unix_ns"])
                  for run in bundle["runs"].values()]
    identities.append((control["guard_control"]["process"]["pid"],
                       control["guard_control"]["process"]["started_unix_ns"]))
    require(len(identities) == len(set(identities)),
            "filestorage process identities overlap")
    require({run["raw_log"]["path"] for run in bundle["runs"].values()} ==
            {path.name for path in directory.glob("*.log")},
            "filestorage raw logs are missing or extra")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle,
                                    directory) for key in sorted(expected)}
    reference = signatures[CASE_ID, "target_observed", "production"]
    for index in range(0, len(reference), 2):
        require(reference[index] == reference[index + 1],
                "filestorage repeated semantics changed")
    for role in ROLES:
        for configuration in CONFIGURATIONS:
            require(signatures[CASE_ID, role, configuration] == reference,
                    "filestorage role or stack configuration changed semantics")
        reduced = [thread["usable_bytes"] for thread in
                   bundle["runs"][run_name(CASE_ID, role, "reduced")]
                   ["runtime"]["thread_observations"]
                   if thread["thread_category"] == "tokio_worker"]
        production = [thread["usable_bytes"] for thread in
                      bundle["runs"][run_name(CASE_ID, role, "production")]
                      ["runtime"]["thread_observations"]
                      if thread["thread_category"] == "tokio_worker"]
        require(reduced and production and min(production) >= 2 * max(reduced),
                "filestorage worker capacity ratio is below two")
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
