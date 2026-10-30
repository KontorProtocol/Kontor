#!/usr/bin/env python3
"""Validate publishable canonical ABI calls on measured Tokio worker stacks."""

import argparse
import hashlib
import json
import re
from decimal import Decimal
from pathlib import Path

from capture_resource_diagnostic import bundle_page_size, validate_control
from resource_boundary_evidence import (normalized_boundary_amount,
                                        validate_balance_transitions,
                                        validate_cell_identity, validate_trace)
from resource_evidence import (file_evidence, load_json_strict, no_duplicate_keys,
                               no_nonfinite_constants, require, sha256)
from resource_evidence_v2 import validate_teardown
from resource_finite_evidence import CONFIGURATIONS, ROLES, WORKER_TEST
from resource_manifest import MANIFEST, build_manifest
from resource_pending_evidence import OBSERVATION_KEYS


CASES = {
    "canonical_lift_lower": (
        ("success", "view_canonical_echo", "ok", None),
        ("failure", "view_canonical_realloc_import", "other_trap",
         "CannotLeaveComponent"),
    ),
    "canonical_realloc": (
        ("success_lowering", "view_canonical_echo", "ok", None),
        ("realloc_trap", "view_canonical_realloc_trap", "other_trap",
         "UnreachableCodeReached"),
        ("forbidden_import", "view_canonical_realloc_import", "other_trap",
         "CannotLeaveComponent"),
    ),
    "canonical_post_return": (
        ("light", "paid_canonical_post_light", "other_trap",
         "CannotLeaveComponent"),
        ("heavy", "paid_canonical_post_heavy", "other_trap",
         "CannotLeaveComponent"),
    ),
}
MARKERS = {
    "attempts": "CANONICAL_STACK_ATTEMPT:",
    "summary": "CANONICAL_STACK_SUMMARY:",
    "runtime": "FINITE_STACK_RUNTIME=",
    "trace": "FINITE_STACK_TRACE=",
    "terminal": "FINITE_STACK_TERMINAL=",
}
EXPECTED_ECHO = json.dumps("x" * 16_384)


def run_name(case_id, role, configuration):
    require(case_id in CASES and role in ROLES and configuration in CONFIGURATIONS,
            "unknown canonical stack run")
    return f"{case_id}-{role}-{configuration}"


def expected_case_env(case_id, role, configuration):
    run_name(case_id, role, configuration)
    return {
        "KONTOR_FINITE_STACK_CASE": case_id,
        "KONTOR_FINITE_STACK_ROLE": role,
        "KONTOR_RESOURCE_MODE": configuration,
        "KONTOR_RESOURCE_TEARDOWN_PROBE":
            "on" if role == "target_observed" else "off",
    }


def parse_worker_log(path):
    lines = path.read_text().splitlines()
    require(sum(line.strip() == "running 1 test" for line in lines) == 1,
            "canonical transcript lacks one selected test")
    harness = [index for index, line in enumerate(lines) if re.fullmatch(
        r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s",
        line)]
    require(len(harness) == 1, "canonical worker test harness did not pass")
    records, positions = {}, {}
    for key, marker in MARKERS.items():
        matched = [(index, json.loads(line.split(marker, 1)[1],
                                      object_pairs_hook=no_duplicate_keys,
                                      parse_constant=no_nonfinite_constants))
                   for index, line in enumerate(lines) if marker in line]
        require(matched and (key == "attempts" or len(matched) == 1),
                f"canonical transcript lacks {key}")
        positions[key] = [index for index, _ in matched]
        records[key] = ([value for _, value in matched]
                        if key == "attempts" else matched[0][1])
    case_id = records["summary"].get("case_id")
    require(case_id in CASES and len(records["attempts"]) == 2 * len(CASES[case_id]),
            "canonical transcript has wrong case or attempt count")
    timings = [index for index, line in enumerate(lines)
               if "KONTOR_STACK_TIMING:" in line]
    attempts = positions["attempts"]
    require(len(timings) == len(attempts)
            and all((attempts[index - 1] if index else 0) < timing < attempt
                    for index, (timing, attempt) in
                    enumerate(zip(timings, attempts, strict=True)))
            and attempts[-1] < positions["summary"][0]
            < positions["runtime"][0] < positions["trace"][0]
            < positions["terminal"][0] < harness[0],
            "canonical attempts, timings, or harness result are out of order")
    return records


def validate_paid_accounting(fuel, receipt, balances, balance_digest,
                             gas_limit, multiplier):
    require(fuel["deposit"] == 0 and multiplier == 1000,
            "canonical paid fixture used deposit fuel or changed gas scale")
    expected_gas = max(1, (fuel["user"] + multiplier - 1) // multiplier)
    require(receipt["gas"] == expected_gas and receipt["gas"] <= gas_limit,
            "canonical paid receipt gas differs from measured user fuel")
    validate_balance_transitions(balances, "paid", "other_trap", 0,
                                 balance_digest)
    amounts = {key: Decimal(normalized_boundary_amount(value))
               for key, value in balances.items()}
    expected_fee = Decimal(expected_gas) / Decimal(10**9)
    require(amounts["before"] - amounts["after"] == expected_fee
            and amounts["burned_after"] - amounts["burned_before"] == expected_fee
            and amounts["supply_before"] - amounts["supply_after"] == expected_fee,
            "canonical paid debit, burn, or supply differs from priced gas")
    return expected_fee


def validate_post_return_delta(light, heavy):
    require(heavy["fuel"]["user"] >= light["fuel"]["user"] + 16_384
            and heavy["receipt"]["gas"] > light["receipt"]["gas"]
            and Decimal(heavy["execution_fee"]) >
                Decimal(light["execution_fee"]),
            "canonical heavy post-return work or fee was not charged")


def validate_observation(attempt, case_id, role, configuration, cell):
    sample_key, repeat_index = attempt["sample_key"], attempt["repeat_index"]
    spec = next((item for item in CASES[case_id] if item[0] == sample_key), None)
    require(spec is not None and repeat_index in (0, 1),
            "canonical sample key or repeat index differs")
    _, kind, outcome, trap = spec
    value = attempt["observation"]
    require(isinstance(value, dict) and set(value) == OBSERVATION_KEYS
            and value["role"] == role
            and value["sample_index"] == repeat_index
            and value["sample_id"] == f"{role}:{kind}:{repeat_index:04}"
            and value["kind"] == kind
            and value["depth"] == 0 and value["fixture_contracts"] == 1
            and value["cache_mode"] == "warm_compiled_cache"
            and value["child_markers"] == []
            and isinstance(value["component_sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["component_sha256"])
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
            and value["view_gas_limit"] == 100000
            and value["view_fuel_limit"] == 100000000
            and value["gas_to_fuel_multiplier"] == 1000
            and value["live_store_peak"] == 1
            and value["call_hook_installed"] is False,
            "canonical guest, engine, or execution path changed")
    require(value["outcome"] == outcome and value["typed_trap"] == trap
            and value["last_depth"] == 0
            and value["rolled_back"] is (outcome != "ok")
            and (value["value"] == EXPECTED_ECHO if outcome == "ok"
                 else value["value"] is None)
            and (value["error"] is None if outcome == "ok"
                 else isinstance(value["error"], str))
            and value["error_class"] ==
                (None if outcome == "ok" else "deterministic"),
            "canonical result, trap, or string lifting differs")
    fuel, receipt = value["fuel"], value["receipt"]
    paid = kind.startswith("paid_")
    require(set(fuel) == {"user", "system", "deposit"}
            and all(type(amount) is int and amount >= 0
                    for amount in fuel.values())
            and (fuel["user"] > 0 if paid else
                 fuel["system"] > 0 and fuel["user"] == fuel["deposit"] == 0),
            "canonical view or paid fuel differs")
    if paid:
        require(isinstance(receipt, dict) and set(receipt) == {"status", "gas"}
                and receipt["status"] == "Trap"
                and type(receipt["gas"]) is int
                and 0 < receipt["gas"] <= value["gas_limit"],
                "canonical paid trap receipt differs")
    else:
        require(receipt is None, "canonical view emitted a receipt")
    reset = value["reset"]
    pre, post = reset["pre"], reset["post"]
    digest = value["state_before_sha256"]
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
            and digest == post["persistent_digest_sha256"] ==
                post["baseline_digest_sha256"]
            and pre["live_invocations"] == post["live_invocations"] == 0
            and pre["stack_empty"] is pre["savepoint_intact"] is True
            and post["stack_empty"] is post["savepoint_restored"] is True
            and post["digest_matches"] is True
            and all(post[key] is True for key in
                    ("balances_restored", "floor_restored", "supply_restored"))
            and pre["resource_count"] == pre["baseline_resource_count"] ==
                post["resource_count"]
            and pre["failure_rolled_back"] is
                (None if outcome == "ok" else True),
            "canonical full persistent state or resources did not reset")
    balances, live_gas = value["balance_transitions"], value["live_deposit_gas"]
    if paid:
        fee = validate_paid_accounting(
            fuel, receipt, balances, value["balance_transitions_sha256"],
            value["gas_limit"], value["gas_to_fuel_multiplier"])
    else:
        validate_balance_transitions(balances, "view", outcome, 0,
                                     value["balance_transitions_sha256"])
        fee = Decimal(0)
    encoded = json.dumps(live_gas, sort_keys=True, separators=(",", ":")).encode()
    require(set(live_gas) == {"before", "after", "restored"}
            and all(type(amount) is int and amount == 0
                    for amount in live_gas.values())
            and live_gas["before"] == live_gas["after"] == live_gas["restored"]
            and value["live_deposit_gas_sha256"] == hashlib.sha256(encoded).hexdigest()
            and all(Decimal(normalized_boundary_amount(balances[key])) ==
                    Decimal(live_gas["before"]) / Decimal(10**9)
                    for key in ("floor_before", "floor_after", "floor_restored")),
            "canonical storage collateral or deposit changed")
    require(value["teardown_probe_on"] is (role == "target_observed"),
            "canonical teardown role changed")
    if role == "target_observed":
        counts = validate_teardown(value["teardown_events"], 1, 0)["created"]
        require(counts["target_native_auxiliary"] == (2 if paid else 0)
                and counts["post_observation"] == 4
                and counts["rollback_observation"] == 4,
                "canonical Store lifecycle changed")
    else:
        require(value["teardown_events"] is None,
                "canonical probe-off role emitted teardown events")
    return {
        "sample_key": sample_key, "repeat_index": repeat_index,
        "kind": kind, "component_sha256": value["component_sha256"],
        "outcome": outcome, "trap": trap, "value": value["value"],
        "fuel": fuel, "receipt": receipt, "state_before_sha256": digest,
        "execution_fee": str(fee),
        "state_after_sha256": post["persistent_digest_sha256"],
        "balances": balances, "live_deposit_gas": live_gas,
    }


def validate_run(run, bundle, manifest, directory):
    case_id, role, configuration = (run[key] for key in
                                    ("case_id", "process_role", "configuration"))
    require(case_id in CASES, "unknown canonical case")
    process = run["process"]
    command = [bundle["binary_path"], "--ignored", "--exact", WORKER_TEST,
               "--nocapture"]
    require(run["run_id"] == run_name(case_id, role, configuration)
            and run["cell"] == bundle["cell"]
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
            "canonical child identity, command, or process completion differs")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in MARKERS),
            "canonical records differ from raw process transcript")
    attempts = parsed["attempts"]
    expected_samples = [(key, index) for key, *_ in CASES[case_id]
                        for index in (0, 1)]
    require([(attempt["sample_key"], attempt["repeat_index"])
             for attempt in attempts] == expected_samples
            and all(set(attempt) == {"case_id", "configuration", "process_role",
                                         "sample_key", "repeat_index", "pid",
                                         "observation"}
                    and attempt["case_id"] == case_id
                    and attempt["configuration"] == configuration
                    and attempt["process_role"] == role
                    and attempt["pid"] == process["pid"]
                    for attempt in attempts),
            "canonical sample order or process identity differs")
    summary, runtime, terminal = (parsed[key] for key in
                                  ("summary", "runtime", "terminal"))
    require(summary == {"case_id": case_id, "configuration": configuration,
                        "process_role": role, "sample_count": len(attempts),
                        "sample_keys": [key for key, *_ in CASES[case_id]],
                        "outcomes": [outcome for _, _, outcome, _ in CASES[case_id]
                                     for _ in (0, 1)], "complete": True}
            and terminal == {"case_id": case_id, "configuration": configuration,
                             "process_role": role, "pid": process["pid"],
                             "sample_count": len(attempts), "complete": True}
            and runtime["scope"] == "paired_finite_stack_worker"
            and all(runtime[key] == expected for key, expected in
                    (("case_id", case_id), ("configuration", configuration),
                     ("process_role", role), ("pid", process["pid"]),
                     ("embedded_source_sha", bundle["source_sha"]),
                     ("binary_sha256", bundle["binary_sha256"]))),
            "canonical summary, runtime, or terminal identity differs")
    trace = parsed["trace"]
    events = trace["events"]
    starts = [index for index, event in enumerate(events)
              if event["name"] == "fixture_preparation_entry"]
    require(len(starts) == len(CASES[case_id]),
            "canonical fixture publication count changed")
    os_name = "macos" if bundle["cell"].startswith("macOS-") else "linux"
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(events)
        require((index == 0 and start == 0) or index > 0,
                "canonical trace has events before first fixture")
        segment = {**trace, "events": events[start:end]}
        validate_trace(segment, runtime, attempts[index * 2:index * 2 + 2],
                       os_name, ("finite_stack_attempt_start",
                                 "finite_stack_attempt_end"))
    signatures = [validate_observation(attempt, case_id, role, configuration,
                                       bundle["cell"]) for attempt in attempts]
    if case_id == "canonical_post_return":
        validate_post_return_delta(signatures[0], signatures[2])
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
            "canonical source or claim status differs")
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
            "canonical control source or binary differs")
    expected = {(case_id, role, configuration) for case_id in CASES
                for role in ROLES for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "canonical process registry has missing or extra children")
    process_ids = [(run["process"]["pid"], run["process"]["started_unix_ns"])
                   for run in bundle["runs"].values()]
    process_ids.append((control["guard_control"]["process"]["pid"],
                        control["guard_control"]["process"]["started_unix_ns"]))
    require(len(process_ids) == len(set(process_ids)),
            "canonical child process identities overlap")
    require({run["raw_log"]["path"] for run in bundle["runs"].values()} ==
            {path.name for path in directory.glob("*.log")},
            "canonical raw process logs are missing or extra")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle,
                                    manifest, directory) for key in sorted(expected)}
    for case_id in CASES:
        reference = signatures[case_id, "target_observed", "production"]
        for first, second in zip(reference[::2], reference[1::2], strict=True):
            require({key: value for key, value in first.items()
                     if key != "repeat_index"} ==
                    {key: value for key, value in second.items()
                     if key != "repeat_index"},
                    f"{case_id}: repeated canonical semantics changed")
        for role in ROLES:
            for configuration in CONFIGURATIONS:
                require(signatures[case_id, role, configuration] == reference,
                        f"{case_id}: role or worker stack changed canonical semantics")
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
