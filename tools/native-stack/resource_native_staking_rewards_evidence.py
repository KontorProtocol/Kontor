#!/usr/bin/env python3
"""Validate deterministic native staking rewards on measured worker stacks."""

import argparse
import hashlib
import json
import re
from decimal import Decimal, ROUND_HALF_UP, localcontext
from pathlib import Path

from capture_resource_diagnostic import validate_control
from resource_boundary_evidence import validate_cell_identity
from resource_evidence import (file_evidence, load_json_strict, require, sha256,
                               thread_capacities)
from resource_evidence_v2 import validate_teardown
from resource_finite_evidence import (CONFIGURATIONS, ROLES, WORKER_TEST,
                                      parse_worker_log)
from resource_manifest import MANIFEST, build_manifest


CASE_ID = "native_staking_rewards"
POPULATIONS = (0, 4, 32, 128)
SAMPLES = tuple(f"population_{count}" for count in POPULATIONS)
KEY_FINGERPRINTS = {
    0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    4: "55296181c904b022ad7d53c13d9a4561b778ffdb73d2027589c4eae7b7516e4c",
    32: "a169677bd10142975a498d0a79b025baf256f133df53454adec071f734bd9c09",
    128: "4d2e74ef4a17070bdc824f677aa0143308695ba7392f5ef90bd6be70544df2ca",
}
OBSERVATION_KEYS = {
    "sample_key", "outcome", "population", "eligible", "amount", "paid",
    "credited", "accounts", "validator_metadata_before",
    "validator_metadata_after", "supply_pre_mint", "supply_before", "supply_after",
    "storage_emission_budget_before", "storage_emission_budget_after",
    "escrow_before", "escrow_after", "pool_before", "pool_after",
    "total_stake_before", "total_stake_after", "last_reward_height",
    "system_fuel", "user_fuel", "deposit_fuel", "state_before_sha256",
    "state_after_sha256", "state_restored_sha256", "receipts_before",
    "receipts_after", "measured_receipts", "receipts_restored",
    "resources_before", "resources_after",
    "stack_empty", "savepoint_restored", "savepoint_empty", "live_invocations",
    "teardown_probe_on", "teardown_events", "engine_target", "max_wasm_stack",
    "async_stack_size",
}


def q(value):
    with localcontext() as ctx:
        ctx.prec = 100
        return value.quantize(Decimal("1e-18"), rounding=ROUND_HALF_UP)


def amount(value, key):
    require(isinstance(value, str), f"staking {key} is not a decimal string")
    try:
        result = Decimal(value)
    except Exception as error:
        raise ValueError(f"staking {key} is malformed") from error
    require(result.is_finite() and result == q(result),
            f"staking {key} exceeds canonical decimal scale")
    return result


def expected_emission(supply, eligible):
    if not eligible:
        return Decimal(0)
    return q(q(q(q(supply * 5) / 100) / 52560) / 10)


def expected_storage_budget(supply):
    scheduled = q(q(q(supply * 5) / 100) / 52560)
    ordering = q(scheduled / 10)
    return q(scheduled - ordering)


def validate_receipts(receipts, population):
    expected = ([('staking', 'distribute-ordering-reward')] if population == 0
                else [('token', 'transfer-ordering-reward'),
                      ('staking', 'distribute-ordering-reward')])
    require(isinstance(receipts, list) and len(receipts) == len(expected),
            "staking reward measured receipt count changed")
    keys = {"contract", "function", "status", "gas", "size", "value",
            "signer_id", "payer_signer_id", "height", "tx_id",
            "input_index", "op_index", "result_index"}
    for index, (receipt, (contract, function)) in enumerate(zip(
            receipts, expected, strict=True)):
        require(isinstance(receipt, dict) and set(receipt) == keys
                and receipt["contract"] == contract
                and receipt["function"] == function
                and receipt["status"] == "Ok"
                and type(receipt["gas"]) is int and receipt["gas"] > 0
                and isinstance(receipt["value"], str) and receipt["value"]
                and type(receipt["size"]) is int
                and receipt["size"] == len(receipt["value"].encode())
                and type(receipt["signer_id"]) is int
                and receipt["signer_id"] == 1
                and receipt["payer_signer_id"] is None
                and type(receipt["height"]) is int
                and receipt["height"] == 1
                and all(receipt[field] is None for field in
                        ("tx_id", "input_index", "op_index"))
                and type(receipt["result_index"]) is int
                and receipt["result_index"] == index,
                "staking reward measured receipt content changed")


def run_name(case_id, role, configuration):
    require(case_id == CASE_ID and role in ROLES and configuration in CONFIGURATIONS,
            "unknown staking reward run")
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
    population = int(sample.removeprefix("population_"))
    require(sample in SAMPLES and set(attempt) == {
        "case_id", "configuration", "process_role", "sample_key",
        "repeat_index", "pid", "observation"}
        and (attempt["case_id"], attempt["configuration"],
             attempt["process_role"], attempt["sample_key"],
             attempt["repeat_index"], attempt["pid"]) ==
            (CASE_ID, configuration, role, sample, repeat_index, pid),
        "staking reward attempt identity changed")
    require(isinstance(value, dict) and set(value) == OBSERVATION_KEYS
            and value["sample_key"] == sample and value["outcome"] == "ok"
            and type(value["population"]) is int
            and value["population"] == population
            and value["eligible"] is (population > 0)
            and value["last_reward_height"] == 1
            and all(type(value[key]) is int and value[key] >= 0 for key in
                    ("system_fuel", "user_fuel", "deposit_fuel",
                     "receipts_before", "receipts_after", "receipts_restored",
                     "resources_before", "resources_after", "live_invocations"))
            and value["system_fuel"] > 0
            and value["user_fuel"] == value["deposit_fuel"] == 0
            and value["receipts_after"] == value["receipts_before"] +
                (1 if population == 0 else 2)
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
            "staking reward outcome, receipt, fuel, or Store state changed")
    before, after, restored = (value[key] for key in
                               ("state_before_sha256", "state_after_sha256",
                                "state_restored_sha256"))
    require(all(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                for digest in (before, after, restored))
            and before != after and restored == before,
            "staking reward full persistent state did not restore")
    amounts = {key: amount(value[key], key) for key in (
        "amount", "paid", "credited", "supply_pre_mint", "supply_before",
        "supply_after", "escrow_before", "escrow_after", "pool_before",
        "pool_after", "total_stake_before", "total_stake_after")}
    expected = expected_emission(amounts["supply_pre_mint"], population > 0)
    budget_before = amount(value["storage_emission_budget_before"],
                           "storage_emission_budget_before")
    budget_after = amount(value["storage_emission_budget_after"],
                          "storage_emission_budget_after")
    require(amounts["supply_pre_mint"] == Decimal(population * 1000)
            and amounts["amount"] == amounts["paid"] == amounts["credited"] == expected
            and budget_before == budget_after ==
                expected_storage_budget(amounts["supply_pre_mint"])
            and amounts["supply_before"] == amounts["supply_pre_mint"] + expected
            and amounts["supply_after"] == amounts["supply_before"]
            and amounts["escrow_before"] == amounts["total_stake_before"] ==
                Decimal(population * 1000)
            and amounts["escrow_after"] - amounts["escrow_before"] == expected
            and amounts["total_stake_after"] - amounts["total_stake_before"] == expected
            and amounts["pool_before"] == expected
            and amounts["pool_after"] == 0,
            "staking reward emission or conservation changed")
    validate_receipts(value["measured_receipts"], population)
    accounts = value["accounts"]
    require(isinstance(accounts, list) and len(accounts) == population,
            "staking reward account population changed")
    metadata_before = value["validator_metadata_before"]
    metadata_after = value["validator_metadata_after"]
    require(isinstance(metadata_before, list) and isinstance(metadata_after, list)
            and len(metadata_before) == len(metadata_after) == population,
            "staking reward validator metadata population changed")
    fingerprint_parts = []
    credited = Decimal(0)
    prior_holder = None
    for index, entry in enumerate(accounts):
        require(isinstance(entry, dict) and set(entry) == {
            "holder", "ed25519_pubkey", "stake_before", "stake_after"},
            "staking reward account fields changed")
        holder, edkey = entry["holder"], entry["ed25519_pubkey"]
        require(isinstance(holder, str) and re.fullmatch(r"[0-9a-f]{64}", holder)
                and isinstance(edkey, str) and re.fullmatch(r"[0-9a-f]{64}", edkey)
                and (prior_holder is None or prior_holder < holder),
                "staking reward holder ordering or metadata changed")
        prior_holder = holder
        fingerprint_parts.append(holder + ":" + edkey)
        stake_before = amount(entry["stake_before"], "stake_before")
        stake_after = amount(entry["stake_after"], "stake_after")
        remaining = expected - credited
        share = (remaining if index + 1 == population else
                 min(q(q(expected * stake_before) / Decimal(population * 1000)),
                     remaining))
        require(stake_before == Decimal(1000)
                and stake_after == stake_before + share,
                "staking reward share or final-holder remainder changed")
        for metadata, expected_stake in ((metadata_before[index], stake_before),
                                         (metadata_after[index], stake_after)):
            require(isinstance(metadata, dict) and set(metadata) == {
                "holder", "ed25519_pubkey", "validator_stake", "bonded_stake",
                "status", "activation_height", "deactivation_height",
                "withdrawal_height"}
                and metadata["holder"] == holder
                and metadata["ed25519_pubkey"] == edkey
                and amount(metadata["validator_stake"], "validator_stake") ==
                    expected_stake
                and amount(metadata["bonded_stake"], "bonded_stake") ==
                    expected_stake
                and metadata["status"] == "Active"
                and type(metadata["activation_height"]) is int
                and metadata["activation_height"] == 0
                and type(metadata["deactivation_height"]) is int
                and metadata["deactivation_height"] == 0
                and metadata["withdrawal_height"] is None,
                "staking reward validator status or transition metadata changed")
        credited += share
    fingerprint = hashlib.sha256("\n".join(fingerprint_parts).encode()).hexdigest()
    require(fingerprint == KEY_FINGERPRINTS[population] and credited == expected,
            "staking reward fixed holder metadata or credited total changed")
    if role == "target_observed":
        teardown = validate_teardown(value["teardown_events"], 1, 0)
        require(teardown["created"]["target_native_auxiliary"] ==
                    (0 if population == 0 else 1)
                and teardown["alive_after_teardown_count"] == 0,
                "staking reward Store remained live")
    else:
        require(value["teardown_events"] is None,
                "probe-off staking reward emitted teardown events")
    return {"sample_key": sample, "repeat_index": repeat_index,
            "accounts": accounts,
            "validator_metadata_before": metadata_before,
            "validator_metadata_after": metadata_after,
            "measured_receipts": value["measured_receipts"],
            "storage_emission_budget_before":
                value["storage_emission_budget_before"],
            "storage_emission_budget_after":
                value["storage_emission_budget_after"],
            "amount": value["amount"],
            "paid": value["paid"], "credited": value["credited"],
            "supply_pre_mint": value["supply_pre_mint"],
            "supply_before": value["supply_before"],
            "supply_after": value["supply_after"],
            "escrow_before": value["escrow_before"],
            "escrow_after": value["escrow_after"],
            "pool_before": value["pool_before"],
            "pool_after": value["pool_after"],
            "total_stake_before": value["total_stake_before"],
            "total_stake_after": value["total_stake_after"],
            "system_fuel": value["system_fuel"],
            "receipts_before": value["receipts_before"],
            "receipts_after": value["receipts_after"],
            "state_before_sha256": before, "state_after_sha256": after}


def validate_operation_phases(events):
    names = [event["name"] for event in events]
    require(names[0] == "operation_entry" and names[-1] == "operation_exit",
            "staking reward operation markers are incomplete")
    input_open = {}
    input_count = output_count = completed_input = output_depth = 0
    for event in events[1:-1]:
        name, thread, os_thread = (event[key] for key in
                                   ("name", "thread_id", "os_thread_id"))
        if name == "canonical_input_entry":
            require(thread not in input_open,
                    "staking reward canonical input overlapped on one worker")
            input_open[thread] = os_thread
            input_count += 1
        elif name == "canonical_input_exit":
            require(input_open.pop(thread, None) == os_thread,
                    "staking reward canonical input exit lacks its worker entry")
            completed_input += 1
        elif name == "canonical_output_entry":
            require(output_count < completed_input,
                    "staking reward canonical output preceded its input")
            output_count += 1
            output_depth += 1
        elif name == "canonical_output_exit":
            require(output_depth > 0,
                    "staking reward canonical output exit lacks an entry")
            output_depth -= 1
    require(input_count == completed_input == output_count > 0
            and not input_open and output_depth == 0,
            "staking reward canonical phases are missing or unbalanced")


def validate_trace(trace, runtime, attempts, os_name):
    require(set(trace) == {"scope", "configuration", "case_id", "process_role",
                           "events"}
            and all(trace[key] == runtime[key] for key in
                    ("scope", "configuration", "case_id", "process_role")),
            "staking reward trace identity changed")
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
                "staking reward emitted an unknown trace event")
        if event["category"] == "tokio_worker":
            require(workers.get(event["thread_id"]) == event["os_thread_id"]
                    and not event["name"].startswith("blocking_decode_"),
                    "staking reward escaped measured Tokio workers")
        else:
            require(event["category"] == "blocking_pool"
                    and blocking.get(event["thread_id"]) == event["os_thread_id"]
                    and event["name"].startswith("blocking_decode_"),
                    "staking reward blocking decode lacks measured capacity")
        names.append(event["name"])
    starts = [i for i, name in enumerate(names)
              if name == "finite_stack_attempt_start"]
    ends = [i for i, name in enumerate(names)
            if name == "finite_stack_attempt_end"]
    setups = [i for i, name in enumerate(names)
              if name == "fixture_preparation_entry"]
    setup_ends = [i for i, name in enumerate(names)
                  if name == "fixture_preparation_exit"]
    require(len(starts) == len(ends) == len(attempts) == 8
            and len(setups) == len(setup_ends) == 4
            and all(start < end and (i == 0 or ends[i-1] < start)
                    for i, (start, end) in enumerate(zip(starts, ends, strict=True)))
            and all(start < end < starts[2*i]
                    and (i == 0 or ends[2*i-1] < start)
                    for i, (start, end) in
                    enumerate(zip(setups, setup_ends, strict=True))),
            "staking reward setup or attempt intervals changed")
    for start, end in zip(starts, ends, strict=True):
        segment = trace["events"][start:end+1]
        segment_names = [event["name"] for event in segment]
        require("fixture_preparation_entry" not in segment_names
                and all(segment_names.count(marker) == 1 for marker in
                        ("operation_entry", "operation_exit",
                         "postcall_observation_entry", "postcall_observation_exit")),
                "staking reward operation or observer markers are missing")
        operation_start = segment_names.index("operation_entry")
        operation_end = segment_names.index("operation_exit")
        observer_start = segment_names.index("postcall_observation_entry")
        observer_end = segment_names.index("postcall_observation_exit")
        require(0 < operation_start < operation_end < observer_start
                < observer_end < len(segment_names) - 1,
                "staking reward operation and observer intervals overlap")
        validate_operation_phases(segment[operation_start:operation_end+1])


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
            "staking reward process identity or completion changed")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in
                ("attempts", "summary", "runtime", "trace", "terminal")),
            "staking reward records differ from raw transcript")
    attempts = parsed["attempts"]
    expected_order = [(sample, repeat) for sample in SAMPLES for repeat in range(2)]
    require([(item["sample_key"], item["repeat_index"]) for item in attempts] ==
            expected_order,
            "staking reward sample order or repetitions changed")
    summary, runtime, terminal = (parsed[key] for key in
                                  ("summary", "runtime", "terminal"))
    require(summary == {"case_id": CASE_ID, "configuration": configuration,
                        "process_role": role, "sample_count": 8,
                        "outcomes": ["ok"] * 8, "complete": True}
            and terminal == {"case_id": CASE_ID, "configuration": configuration,
                             "process_role": role, "pid": process["pid"],
                             "sample_count": 8, "complete": True}
            and runtime["scope"] == "paired_finite_stack_worker"
            and all(runtime[key] == expected for key, expected in
                    (("case_id", CASE_ID), ("configuration", configuration),
                     ("process_role", role), ("pid", process["pid"]),
                     ("embedded_source_sha", bundle["source_sha"]),
                     ("binary_sha256", bundle["binary_sha256"]))),
            "staking reward summary or runtime identity changed")
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
            "staking reward source or claim status changed")
    file_evidence(directory, bundle["control_capture"])
    control_path = directory / bundle["control_capture"]["path"]
    control, binary = validate_control(
        control_path, bundle["control_capture"]["sha256"], manifest)
    validate_cell_identity(bundle["cell"], control["cargo_artifact"])
    require(control["source_sha"] == bundle["source_sha"]
            and control["binary_sha256"] == bundle["binary_sha256"]
            and str(binary) == bundle["binary_path"],
            "staking reward control source or binary changed")
    expected = {(CASE_ID, role, configuration) for role in ROLES
                for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "staking reward process registry is incomplete")
    identities = [(run["process"]["pid"], run["process"]["started_unix_ns"])
                  for run in bundle["runs"].values()]
    identities.append((control["guard_control"]["process"]["pid"],
                       control["guard_control"]["process"]["started_unix_ns"]))
    require(len(identities) == len(set(identities)),
            "staking reward process identities overlap")
    require({run["raw_log"]["path"] for run in bundle["runs"].values()} ==
            {path.name for path in directory.glob("*.log")},
            "staking reward raw logs are missing or extra")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle,
                                    directory) for key in sorted(expected)}
    reference = signatures[CASE_ID, "target_observed", "production"]
    for index in range(0, len(reference), 2):
        require({key: value for key, value in reference[index].items()
                 if key != "repeat_index"} ==
                {key: value for key, value in reference[index + 1].items()
                 if key != "repeat_index"},
                "staking reward repeated semantics changed")
    for role in ROLES:
        for configuration in CONFIGURATIONS:
            require(signatures[CASE_ID, role, configuration] == reference,
                    "staking reward role or stack configuration changed semantics")
        reduced = [thread["usable_bytes"] for thread in
                   bundle["runs"][run_name(CASE_ID, role, "reduced")]
                   ["runtime"]["thread_observations"]
                   if thread["thread_category"] == "tokio_worker"]
        production = [thread["usable_bytes"] for thread in
                      bundle["runs"][run_name(CASE_ID, role, "production")]
                      ["runtime"]["thread_observations"]
                      if thread["thread_category"] == "tokio_worker"]
        require(reduced and production and min(production) >= 2 * max(reduced),
                "staking reward worker capacity ratio is below two")
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
