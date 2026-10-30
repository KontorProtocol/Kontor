#!/usr/bin/env python3
"""Validate pending production-host I/O with distinct suspended and resumed evidence."""

import argparse
import hashlib
import json
import re
from decimal import Decimal
from pathlib import Path

from capture_resource_diagnostic import bundle_page_size, validate_control
from capture_resource_chain import (check_repeated_observations,
                                    observation_from_trial)
from resource_boundary_evidence import (normalized_boundary_amount,
                                        validate_balance_transitions,
                                        validate_cell_identity, validate_trace)
from resource_evidence import (file_evidence, load_json_strict, no_duplicate_keys,
                               no_nonfinite_constants, require, sha256)
from resource_evidence_v2 import validate_teardown
from resource_finite_evidence import CONFIGURATIONS, ROLES, WORKER_TEST
from resource_manifest import MANIFEST, ROOT, build_manifest


CASE_ID = "pending_host_io"
HOST_IMPORT = "kontor:built-in/crypto.sha256"
INPUT = b"native-stack-pending"
EXPECTED_VALUE = list(hashlib.sha256(INPUT).digest())
OBSERVATION_KEYS = {
    "async_stack_size", "balance_transitions", "balance_transitions_sha256",
    "cache_mode", "call_hook_installed", "child_markers", "component_sha256",
    "depth", "engine_target", "error", "error_class", "fixture_contracts",
    "fuel", "gas_limit", "gas_to_fuel_multiplier", "kind", "last_depth",
    "live_deposit_gas", "live_deposit_gas_sha256", "live_store_peak",
    "max_wasm_stack", "outcome", "paid_fuel_limit", "receipt", "reset",
    "role", "rolled_back", "sample_id", "sample_index", "state_before_sha256",
    "system_fuel_ceiling", "target_arch", "target_os", "teardown_events",
    "teardown_probe_on", "typed_trap", "value", "view_fuel_limit", "view_gas_limit",
}
MARKERS = {
    "attempts": "PENDING_HOST_IO_ATTEMPT:",
    "controls": "PENDING_HOST_IO_CONTROL:",
    "summary": "PENDING_HOST_IO_SUMMARY:",
    "runtime": "FINITE_STACK_RUNTIME=",
    "trace": "FINITE_STACK_TRACE=",
    "terminal": "FINITE_STACK_TERMINAL=",
}
MEMORY_MARKERS = {
    "memory_baseline": "SUSPENDED_64_BASELINE:",
    "memory_peak": "SUSPENDED_64_PEAK:",
    "memory_completion": "SUSPENDED_64_COMPLETION:",
}
MEMORY_PLAN = ROOT / "tools/native-stack/resource-suspended-64-plan-v1.json"


def run_name(role, configuration):
    require(role in ROLES and configuration in CONFIGURATIONS,
            "unknown pending host I/O run")
    return f"{CASE_ID}-{role}-{configuration}"


def expected_case_env(role, configuration):
    run_name(role, configuration)
    return {
        "KONTOR_FINITE_STACK_CASE": CASE_ID,
        "KONTOR_FINITE_STACK_ROLE": role,
        "KONTOR_RESOURCE_MODE": configuration,
        "KONTOR_RESOURCE_TEARDOWN_PROBE": "on" if role == "target_observed" else "off",
    }


def parse_worker_log(path):
    lines = path.read_text().splitlines()
    require(sum(line.strip() == "running 1 test" for line in lines) == 1,
            "pending host transcript lacks one selected test")
    harness = [index for index, line in enumerate(lines) if re.fullmatch(
        r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s",
        line)]
    require(len(harness) == 1, "pending host test harness did not pass")
    records = {}
    positions = {}
    for key, marker in MARKERS.items():
        matched = [(index, json.loads(line.split(marker, 1)[1],
                                      object_pairs_hook=no_duplicate_keys,
                                      parse_constant=no_nonfinite_constants))
                   for index, line in enumerate(lines) if marker in line]
        expected_count = 4 if key == "attempts" else 2 if key == "controls" else 1
        require(len(matched) == expected_count,
                f"pending host transcript lacks {key}")
        positions[key] = [index for index, _ in matched]
        records[key] = ([value for _, value in matched]
                        if key in {"attempts", "controls"} else matched[0][1])
    for key, marker in MEMORY_MARKERS.items():
        matched = [(index, json.loads(line.split(marker, 1)[1],
                                      object_pairs_hook=no_duplicate_keys,
                                      parse_constant=no_nonfinite_constants))
                   for index, line in enumerate(lines) if marker in line]
        require(len(matched) <= 1, f"pending host transcript duplicated {key}")
        positions[key] = [index for index, _ in matched]
        records[key] = matched[0][1] if matched else None
    a, c = positions["attempts"], positions["controls"]
    if any(positions[key] for key in MEMORY_MARKERS):
        require(all(positions[key] for key in MEMORY_MARKERS)
                and positions["memory_baseline"][0]
                < positions["memory_peak"][0]
                < positions["memory_completion"][0] < a[0],
                "suspended-64 memory phases are missing or out of order")
        chain_reports = [(index, json.loads(line.split("CHAIN_PROBE_REPORT:", 1)[1],
                                           object_pairs_hook=no_duplicate_keys,
                                           parse_constant=no_nonfinite_constants))
                         for index, line in enumerate(lines)
                         if "CHAIN_PROBE_REPORT:" in line]
        require(len(chain_reports) == 1
                and positions["memory_peak"][0] < chain_reports[0][0]
                < positions["memory_completion"][0]
                and chain_reports[0][1] == records["memory_completion"]["report"],
                "suspended-64 chain report is missing or differs from completion")
    timings = [index for index, line in enumerate(lines) if "KONTOR_STACK_TIMING:" in line]
    require(len(timings) == 4
            and a[0] < timings[0] < a[1] < timings[1] < c[0]
            < a[2] < timings[2] < a[3] < timings[3] < c[1]
            < positions["summary"][0]
            < positions["runtime"][0] < positions["trace"][0]
            < positions["terminal"][0] < harness[0],
            "pending host markers, timings, or harness result are out of order")
    return records


def validate_observation(attempt, role, configuration, sample_index,
                         repeat_index, sample_key, manifest, cell):
    observation = attempt["observation"]
    require(isinstance(observation, dict) and set(observation) == OBSERVATION_KEYS
            and observation["role"] == role
            and observation["sample_index"] == sample_index
            and observation["sample_id"] == f"{role}:view_crypto:{sample_index:04}"
            and observation["kind"] == "view_crypto"
            and observation["depth"] == 0
            and observation["fixture_contracts"] == 1
            and observation["cache_mode"] == "warm_compiled_cache"
            and observation["child_markers"] == []
            and observation["component_sha256"] ==
                manifest["artifacts"]["crypto_component"]["sha256"]
            and observation["target_os"] ==
                ("macos" if cell.startswith("macOS-") else "linux")
            and observation["target_arch"] ==
                ("x86_64" if cell.startswith("Linux-X64/") else "aarch64")
            and observation["engine_target"] == "pulley64-unknown-unknown-elf"
            and observation["max_wasm_stack"] == 524288
            and observation["async_stack_size"] ==
                (1048576 if configuration == "reduced" else 2097152)
            and observation["gas_limit"] == 100000
            and observation["paid_fuel_limit"] == 100000000
            and observation["view_fuel_limit"] == 100000000
            and observation["view_gas_limit"] == 100000
            and observation["gas_to_fuel_multiplier"] == 1000
            and observation["live_store_peak"] == 1
            and observation["call_hook_installed"] is False,
            "pending host guest, engine, or execution path changed")
    require(observation["outcome"] == "ok"
            and observation["error"] is None
            and observation["error_class"] is None
            and observation["typed_trap"] is None
            and json.loads(observation["value"]) == EXPECTED_VALUE
            and observation["receipt"] is None
            and observation["last_depth"] == 0
            and observation["rolled_back"] is False,
            "pending host output, result class, or view receipt differs")
    fuel = observation["fuel"]
    require(set(fuel) == {"user", "system", "deposit"}
            and all(type(value) is int and value >= 0 for value in fuel.values())
            and fuel["system"] > 0 and fuel["user"] == fuel["deposit"] == 0,
            "pending host system fuel differs")
    reset = observation["reset"]
    pre, post = reset["pre"], reset["post"]
    digest = observation["state_before_sha256"]
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
            and pre["failure_rolled_back"] is None,
            "pending host full persistent state or resources did not reset")
    balances = observation["balance_transitions"]
    live_gas = observation["live_deposit_gas"]
    validate_balance_transitions(balances, "view", "ok", 0,
                                 observation["balance_transitions_sha256"])
    encoded = json.dumps(live_gas, sort_keys=True, separators=(",", ":")).encode()
    require(set(live_gas) == {"before", "after", "restored"}
            and observation["live_deposit_gas_sha256"] ==
                hashlib.sha256(encoded).hexdigest()
            and all(type(value) is int and value >= 0 for value in live_gas.values())
            and live_gas["before"] == live_gas["after"] == live_gas["restored"] == 8
            and all(Decimal(normalized_boundary_amount(balances[key])) ==
                    Decimal(8) / Decimal(10**9) for key in
                    ("floor_before", "floor_after", "floor_restored")),
            "pending host storage collateral changed or lacks full accounting")
    require(observation["teardown_probe_on"] is (role == "target_observed"),
            "pending host teardown probe role differs")
    if role == "target_observed":
        counts = validate_teardown(observation["teardown_events"], 1, 0)["created"]
        require(counts["nested_chain"] == 1
                and counts["target_native_auxiliary"] == 0
                and counts["post_observation"] == 4
                and counts["rollback_observation"] == 4,
                "pending host Store lifecycle changed")
    else:
        require(observation["teardown_events"] is None,
                "pending host probe-off role emitted teardown events")
    return {
        "sample_key": sample_key, "repeat_index": repeat_index,
        "outcome": observation["outcome"], "value": observation["value"],
        "fuel": fuel, "receipt": observation["receipt"],
        "state_before_sha256": digest,
        "state_after_sha256": post["persistent_digest_sha256"],
        "balances": balances, "live_deposit_gas": live_gas,
    }


def validate_phase_attempts(attempts, role, configuration, pid):
    require([(item["sample_key"], item["repeat_index"]) for item in attempts] ==
            [("suspended", 0), ("resumed", 0), ("suspended", 1), ("resumed", 1)]
            and all(set(item) == {"case_id", "configuration", "process_role",
                                      "sample_key", "repeat_index", "pid", "host_import",
                                      "host_entered", "host_poll_pending_count",
                                      "guest_task_pending", "other_task_progressed",
                                      "observation"}
                    and item["case_id"] == CASE_ID
                    and item["configuration"] == configuration
                    and item["process_role"] == role
                    and item["pid"] == pid
                    and item["host_import"] == HOST_IMPORT
                    and item["host_entered"] is True
                    and item["other_task_progressed"] is True for item in attempts)
            and all(type(item["host_poll_pending_count"]) is int for item in attempts)
            and [item["host_poll_pending_count"] for item in attempts] == [1, 1, 2, 2]
            and all(attempts[index]["guest_task_pending"] is True
                    and attempts[index]["observation"] is None for index in (0, 2))
            and all(attempts[index]["guest_task_pending"] is False for index in (1, 3)),
            "pending host suspension and resumption phase markers differ")


def validate_control_parity(resumed_signature, control_signature):
    require({key: value for key, value in resumed_signature.items()
             if key != "sample_key"} ==
            {key: value for key, value in control_signature.items()
             if key != "sample_key"},
            "pending and unshadowed production host semantics differ")


def validate_run(run, bundle, manifest, directory):
    role, configuration = run["process_role"], run["configuration"]
    name = run_name(role, configuration)
    command = [bundle["binary_path"], "--ignored", "--exact", WORKER_TEST, "--nocapture"]
    process = run["process"]
    require(run["run_id"] == name and run["case_id"] == CASE_ID
            and run["cell"] == bundle["cell"]
            and run["case_env"] == expected_case_env(role, configuration)
            and run["source_sha"] == bundle["source_sha"]
            and run["binary_sha256_before"] == run["binary_sha256_after"] ==
                bundle["binary_sha256"]
            and run["argv"] == process["command"] == command
            and type(process["pid"]) is int and process["pid"] > 0
            and process["exit_code"] == 0 and process["signal"] is None
            and process["timed_out"] is False and process["complete"] is True
            and process["test_harness_passed"] is True
            and process["started_unix_ns"] < process["ended_unix_ns"],
            "pending host child identity, command, or process completion differs")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in
                ("attempts", "controls", "summary", "runtime", "trace", "terminal",
                 *MEMORY_MARKERS)),
            "pending host records differ from raw process transcript")
    memory_present = [parsed[key] is not None for key in MEMORY_MARKERS]
    require(all(memory_present) if role == "target_observed" and
            configuration == "production" else not any(memory_present),
            "suspended-64 profile is missing or ran outside production target")
    attempts = parsed["attempts"]
    controls = parsed["controls"]
    validate_phase_attempts(attempts, role, configuration, process["pid"])
    require(all(set(item) == {"case_id", "configuration", "process_role",
                                      "sample_key", "repeat_index", "pid", "host_import",
                                      "linker", "observation"}
                and item["case_id"] == CASE_ID
                and item["configuration"] == configuration
                and item["process_role"] == role
                and item["sample_key"] == "unshadowed_control"
                and item["repeat_index"] == index
                and item["pid"] == process["pid"]
                and item["host_import"] == HOST_IMPORT
                and item["linker"] == "production"
                for index, item in enumerate(controls)),
            "pending host unshadowed control identity differs")
    summary, runtime, terminal = (parsed[key] for key in
                                  ("summary", "runtime", "terminal"))
    require(summary == {"case_id": CASE_ID, "configuration": configuration,
                        "process_role": role, "sample_count": 4,
                        "host_calls": 2, "host_poll_pending_count": 2,
                        "control_count": 2, "complete": True}
            and terminal == {"case_id": CASE_ID, "configuration": configuration,
                             "process_role": role, "pid": process["pid"],
                             "sample_count": 4, "complete": True}
            and runtime["scope"] == "paired_finite_stack_worker"
            and all(runtime[key] == expected for key, expected in
                    (("case_id", CASE_ID), ("configuration", configuration),
                     ("process_role", role), ("pid", process["pid"]),
                     ("embedded_source_sha", bundle["source_sha"]),
                     ("binary_sha256", bundle["binary_sha256"]))),
            "pending host summary, runtime, or terminal identity differs")
    os_name = "macos" if bundle["cell"].startswith("macOS-") else "linux"
    resumed = [attempts[1], attempts[3]]
    operation_order = [resumed[0], controls[0], resumed[1], controls[1]]
    validate_trace(parsed["trace"], runtime, operation_order, os_name,
                   ("finite_stack_attempt_start", "finite_stack_attempt_end"))
    signatures = []
    for index, (resumed_item, control_item) in enumerate(zip(resumed, controls, strict=True)):
        resumed_signature = validate_observation(
            resumed_item, role, configuration, index * 2, index, "resumed",
            manifest, bundle["cell"])
        control_signature = validate_observation(
            control_item, role, configuration, index * 2 + 1, index,
            "unshadowed_control", manifest, bundle["cell"])
        validate_control_parity(resumed_signature, control_signature)
        signatures.append(resumed_signature)
    return signatures


def validate_suspended_64(run, manifest, cell):
    plan = load_json_strict(MEMORY_PLAN)
    require(sha256(MEMORY_PLAN) ==
            manifest["artifacts"]["suspended_64_plan"]["sha256"]
            and plan["schema_version"] == 1
            and plan["claim_status"] == "frozen_source_unmeasured"
            and plan["profile_id"] == "suspended_64"
            and plan["simultaneous_stores"] == 64
            and plan["view_roots"] == 0
            and plan["reactor_roots"] == 1
            and plan["nested_invocation_depth"] == 64
            and plan["configuration"] == "production"
            and plan["process_role"] == "target_observed"
            and plan["deliberate_guest_memory_pressure_bytes"] == 0
            and plan["cache_state"] == "warm_compiled_cache"
            and plan["required_service"] == {
                "host_calls_pending_at_peak": 1,
                "other_tokio_task_progressed": True,
                "successful_root_resumptions": 3,
                "closed_store_lifecycles_per_resumption": 64,
            },
            "suspended-64 source plan differs from frozen capacity policy")
    reference = next(item for item in manifest["memory_profiles"]
                     if item["id"] == "suspended_64")
    require(reference["simultaneous_stores"] == 64
            and reference["production_capacity_only"] is True
            and reference["reactor_roots"] == 1
            and reference["view_roots"] == 0,
            "suspended-64 memory profile differs from case manifest")
    baseline = run["memory_baseline"]
    peak_record = run["memory_peak"]
    completion = run["memory_completion"]
    require(isinstance(baseline, dict) and isinstance(peak_record, dict)
            and isinstance(completion, dict)
            and set(peak_record) == {"memory", "pending_host_calls", "reactor_roots",
                                 "view_roots", "live_stores",
                                 "reservations", "other_task_progressed",
                                 "deliberate_guest_memory_pressure_bytes", "cache_state",
                                 "configuration", "profile_id"}
            and peak_record["pending_host_calls"] == 1
            and peak_record["reactor_roots"] == 1
            and peak_record["view_roots"] == 0
            and peak_record["live_stores"] == peak_record["reservations"] == 64
            and peak_record["other_task_progressed"] is True
            and peak_record["deliberate_guest_memory_pressure_bytes"] ==
                plan["deliberate_guest_memory_pressure_bytes"]
            and peak_record["cache_state"] == plan["cache_state"]
            and peak_record["configuration"] == "production"
            and peak_record["profile_id"] == "suspended_64"
            and set(completion) == {"memory", "report",
                                    "completed_store_lifecycles",
                                    "pending_host_calls_after", "live_stores_after"}
            and completion["completed_store_lifecycles"] == 64
            and completion["pending_host_calls_after"] ==
                completion["live_stores_after"] == 0,
            "suspended-64 overlap, cache, or completion differs")
    os_name = "macos" if cell.startswith("macOS-") else "linux"
    sources = ({
        "mapped_reservation": "/proc/self/status:VmSize",
        "resident": "/proc/self/status:VmRSS",
        "private": "/proc/self/smaps_rollup:Private_Clean+Private_Dirty",
    } if os_name == "linux" else {
        "mapped_reservation": "task_vm_info.virtual_size",
        "resident": "task_vm_info.resident_size",
        "private": "task_vm_info.internal",
        "accounted_scope": "task_vm_info.phys_footprint",
    })
    snapshots = (baseline, peak_record["memory"], completion["memory"])
    for snapshot in snapshots:
        require(isinstance(snapshot, dict)
                and set(snapshot) == {"os", "pid", "cpu_count",
                                      "physical_memory_bytes", "enforcement",
                                      "mapped_reservation", "resident",
                                      "private", "accounted_scope"}
                and snapshot["os"] == os_name
                and snapshot["pid"] == run["process"]["pid"]
                and type(snapshot["cpu_count"]) is int
                and snapshot["cpu_count"] > 0
                and type(snapshot["physical_memory_bytes"]) is int
                and snapshot["physical_memory_bytes"] > 0
                and isinstance(snapshot["enforcement"], dict)
                and set(snapshot["enforcement"]) ==
                    {"memory_field", "memory_source"},
                "suspended-64 host or process memory identity differs")
        for metric in ("mapped_reservation", "resident", "private",
                       "accounted_scope"):
            value = snapshot[metric]
            require(isinstance(value, dict)
                    and set(value) == ({"bytes", "source", "scope"}
                                       if metric == "accounted_scope"
                                       else {"bytes", "source"})
                    and type(value["bytes"]) is int and value["bytes"] >= 0
                    and isinstance(value["source"], str) and value["source"],
                    f"suspended-64 {metric} measurement is invalid")
            if metric in sources:
                require(value["source"] == sources[metric],
                        f"suspended-64 {metric} OS source differs")
        if os_name == "linux":
            charge_source = snapshot["accounted_scope"]["source"]
            limit_source = snapshot["enforcement"]["memory_source"]
            require(charge_source.startswith("/sys/fs/cgroup/")
                    and ".." not in Path(charge_source).parts
                    and ((charge_source.endswith("/memory.current")
                          and limit_source == charge_source.removesuffix("current") + "max")
                         or (charge_source.endswith("/memory.usage_in_bytes")
                             and limit_source == charge_source.removesuffix(
                                 "usage_in_bytes") + "limit_in_bytes"))
                and snapshot["accounted_scope"]["scope"] ==
                    "cgroup_total_including_other_processes_and_cache"
                and re.fullmatch(r"max|[0-9]+",
                                 snapshot["enforcement"]["memory_field"]),
                "suspended-64 Linux cgroup memory accounting is invalid")
        else:
            require(snapshot["enforcement"] ==
                    {"memory_field": "none", "memory_source": "none"}
                    and snapshot["accounted_scope"]["scope"] ==
                    "process_task_phys_footprint",
                    "suspended-64 macOS enforcement label differs")
    require(all(snapshot["cpu_count"] == baseline["cpu_count"]
                and snapshot["physical_memory_bytes"] ==
                    baseline["physical_memory_bytes"]
                and snapshot["enforcement"] == baseline["enforcement"]
                for snapshot in snapshots),
            "suspended-64 host hardware or enforcement changed during run")
    peak = peak_record["memory"]
    private_growth = max(0, peak["private"]["bytes"] - baseline["private"]["bytes"])
    require(private_growth <= plan["per_root_private_growth_allowance_bytes"]
            + plan["shared_private_growth_allowance_bytes"]
            and peak["mapped_reservation"]["bytes"] <=
                plan["mapped_reservation_allowance_bytes"]
            and peak["resident"]["bytes"] <= plan["resident_allowance_bytes"]
            and peak["accounted_scope"]["bytes"] <=
                plan["accounted_scope_allowance_bytes"],
            "suspended-64 private, mapped, resident, or charged allowance exceeded")
    workers = [item for item in run["runtime"]["thread_observations"]
               if item["thread_category"] == "tokio_worker"]
    require(len(workers) == 2 and all(item["usable_bytes"] > 0 for item in workers),
            "suspended-64 production worker capacity was not measured")
    report = completion["report"]
    require(isinstance(report, dict)
            and report["case_id"] == "chain_64_paid"
            and report["mode"] == "paid"
            and report["resource_mode"] == "production"
            and report["teardown_probe_mode"] == "on"
            and report["target_only"] is True
            and report["call_hook_installed"] is False
            and report["stores"] == 64
            and report["engine_target"] == "pulley64-unknown-unknown-elf"
            and report["max_wasm_stack"] == 524288
            and report["async_stack_size"] == 2097152
            and report["target_os"] == os_name
            and report["target_arch"] ==
                ("x86_64" if cell.startswith("Linux-X64/") else "aarch64")
            and report["component_sha256"] == {
                "error_test": manifest["artifacts"]["error_test"]["sha256"],
                "proxy": manifest["artifacts"]["proxy"]["sha256"],
            }, "suspended-64 paid root or production engine differs")
    trials = report["trials"]
    require(isinstance(trials, list) and len(trials) == 3
            and [trial["repeat_index"] for trial in trials] == [0, 1, 2],
            "suspended-64 repeated root reports are incomplete")
    schema = load_json_strict(
        ROOT / "tools/native-stack/resource-evidence-schema-v1.json")
    signatures = []
    for trial in trials:
        signatures.append(observation_from_trial(
            trial, "chain_64_paid", "ok", schema))
        validate_teardown(trial["teardown_events"], 64, 0)
    check_repeated_observations(signatures, False, "suspended_64")
    return {"profile_id": "suspended_64", "simultaneous_stores": 64,
            "reactor_roots": 1, "observation": signatures[0]}


def validate_bundle(bundle, directory, archive_binary=None):
    manifest = build_manifest()
    require(set(bundle) == {"schema_version", "qualification_status", "cell",
                            "manifest_sha256", "source_sha", "binary_path",
                            "binary_sha256", "control_capture", "runs"}
            and bundle["schema_version"] == 1
            and load_json_strict(MANIFEST) == manifest
            and bundle["manifest_sha256"] == sha256(MANIFEST)
            and bundle["qualification_status"] == "missing",
            "pending host source or claim status differs")
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
            "pending host control source or binary differs")
    expected = {(role, configuration) for role in ROLES
                for configuration in CONFIGURATIONS}
    require(set(bundle["runs"]) == {run_name(*key) for key in expected},
            "pending host process registry has missing or extra children")
    process_ids = [(run["process"]["pid"], run["process"]["started_unix_ns"])
                   for run in bundle["runs"].values()]
    process_ids.append((control["guard_control"]["process"]["pid"],
                        control["guard_control"]["process"]["started_unix_ns"]))
    require(len(process_ids) == len(set(process_ids))
            and {run["raw_log"]["path"] for run in bundle["runs"].values()} ==
                {path.name for path in directory.glob("*.log")},
            "pending host child identities or raw logs overlap")
    signatures = {key: validate_run(bundle["runs"][run_name(*key)], bundle,
                                    manifest, directory) for key in sorted(expected)}
    reference = signatures["target_observed", "production"]
    require(all({key: value for key, value in item.items() if key != "repeat_index"} ==
                {key: value for key, value in reference[0].items() if key != "repeat_index"}
                for item in reference),
            "pending host repeats changed semantics")
    for role in ROLES:
        for configuration in CONFIGURATIONS:
            require(signatures[role, configuration] == reference,
                    "pending host role or stack configuration changed semantics")
        reduced = [item["usable_bytes"] for item in
                   bundle["runs"][run_name(role, "reduced")]["runtime"]["thread_observations"]
                   if item["thread_category"] == "tokio_worker"]
        production = [item["usable_bytes"] for item in
                      bundle["runs"][run_name(role, "production")]["runtime"]["thread_observations"]
                      if item["thread_category"] == "tokio_worker"]
        require(reduced and production and min(production) >= 2 * max(reduced),
                "pending host measured worker-capacity ratio is below two")
    memory_run = bundle["runs"][run_name("target_observed", "production")]
    signatures["suspended_64", "production"] = validate_suspended_64(
        memory_run, manifest, bundle["cell"])
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
