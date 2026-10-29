#!/usr/bin/env python3
"""Capture all paired distinct-contract chain cases and measured trap controls."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path

from jsonschema import Draft202012Validator

sys.dont_write_bytecode = True

from capture_resource_control import run_bounded_process
from capture_resource_diagnostic import one_marker, validate_control
from resource_evidence import (canonical_decimal_amount as canonical_decimal,
                               file_evidence, load_json_strict, require, sha256,
                               thread_capacities)
from resource_manifest import MANIFEST, ROOT, build_manifest


WORKER_TEST = "runtime::call::tests::native_stack_resource::chain_worker_case"
CHAIN_MODES = ("paid", "view", "core")
STACK_MODES = ("reduced", "production")
CHAIN_STORES = (33, 63, 64, 65)
CROSS_MODE_FIXTURE_REASONS = {}
BALANCE_KEYS = {
    "before", "after", "restored", "burned_before", "burned_after",
    "supply_before", "supply_after", "floor_before", "floor_after",
    "floor_restored",
}
PHASE_PAIRS = (
    ("preparation", "chain_preparation_entry", "chain_preparation_exit"),
    ("operation", "chain_operation_entry", "chain_operation_exit"),
    ("teardown", "chain_teardown_entry", "chain_teardown_exit"),
)
CONVERSION_NAMES = {
    "canonical_input_entry", "canonical_input_exit",
    "canonical_output_entry", "canonical_output_exit",
}
EVENT_NAMES = {
    "chain_attempt_start", "chain_attempt_end", "chain_guest_task_entry",
    "chain_guest_task_exit", "chain_postcall_entry", "chain_postcall_exit",
    "compiler_entry", "compiler_exit", "blocking_decode_entry", "blocking_decode_exit",
    *CONVERSION_NAMES,
    *(name for _, entry, exit in PHASE_PAIRS for name in (entry, exit)),
}


def harness_position(lines, label):
    require(sum(line.strip() == "running 1 test" for line in lines) == 1,
            f"{label}: expected one selected Rust test")
    positions = [index for index, line in enumerate(lines)
                 if re.fullmatch(
                     r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s",
                     line)]
    require(len(positions) == 1, f"{label}: Rust test harness did not pass")
    return positions[0]


def measured_trace(trace, runtime, mode, stores, process_id, chain_mode="paid",
                   trap_control=False, sample_keys=("target", "target", "target"),
                   page_size=None):
    require(isinstance(runtime, dict) and set(runtime) == {
        "scope", "mode", "stores", "chain_mode", "trap_control", "pid",
        "flavor", "worker_count",
        "worker_requested_bytes", "thread_observations",
        "blocking_pool_observed", "block_on_caller_observed",
    } and runtime["scope"] == "paired_chain_worker"
            and runtime["mode"] == mode and runtime["stores"] == stores
            and runtime["chain_mode"] == chain_mode
            and runtime["trap_control"] is trap_control
            and runtime["pid"] == process_id,
            "chain runtime identity differs from child process")
    capacities = {key: value for key, value in runtime.items()
                  if key not in {"scope", "mode", "stores", "chain_mode",
                                 "trap_control", "pid"}}
    by_category = thread_capacities(capacities, mode,
                                    page_size if page_size is not None else os.sysconf("SC_PAGE_SIZE"),
                                    "linux", process_id)
    workers = {item["thread_id"]: item["os_thread_id"]
               for item in by_category["tokio_worker"]}
    blocking = {item["thread_id"]: item["os_thread_id"]
                for item in by_category["blocking_pool"]}
    require(isinstance(trace, dict) and set(trace) == {
        "scope", "mode", "stores", "chain_mode", "trap_control", "events",
    } and trace["scope"] == "paired_chain_worker"
            and trace["mode"] == mode and trace["stores"] == stores
            and trace["chain_mode"] == chain_mode
            and trace["trap_control"] is trap_control
            and isinstance(trace["events"], list),
            "chain trace identity differs from runtime")
    require(tuple(sample_keys) == (("target", "trap_control", "target")
                                    if trap_control else ("target",) * 3),
            "chain attempt sample order differs")
    events = trace["events"]
    for event in events:
        require(isinstance(event, dict) and set(event) == {
            "name", "thread_id", "os_thread_id", "category",
        } and event["name"] in EVENT_NAMES and isinstance(event["thread_id"], str)
                and type(event["os_thread_id"]) is int and event["os_thread_id"] > 0,
                "chain trace contains an unknown event")
        category = event["category"]
        thread = event["thread_id"]
        tid = event["os_thread_id"]
        if category == "tokio_worker":
            require(workers.get(thread) == tid,
                    "chain trace worker differs from measured kernel identity")
        else:
            require(category == "blocking_pool" and blocking.get(thread) == tid
                    and event["name"].startswith("blocking_decode_"),
                    "chain blocking trace lacks measured thread capacity")
    starts = [index for index, event in enumerate(events)
              if event["name"] == "chain_attempt_start"]
    ends = [index for index, event in enumerate(events)
            if event["name"] == "chain_attempt_end"]
    require(len(starts) == len(ends) == 3
            and all(starts[index] < ends[index]
                    and (index == 0 or ends[index - 1] < starts[index])
                    for index in range(3)),
            "chain trace lacks three ordered attempt intervals")
    attempts = []
    for repeat_index, (start, end) in enumerate(zip(starts, ends, strict=True)):
        segment = events[start:end + 1]
        names = [event["name"] for event in segment]
        require(names[0] == "chain_attempt_start" and names[-1] == "chain_attempt_end",
                "chain attempt markers are malformed")
        phase_threads = {}
        positions = []
        for phase, entry, exit in PHASE_PAIRS:
            require(names.count(entry) == names.count(exit) == 1,
                    f"chain {repeat_index}: {phase} phase is incomplete")
            begin, finish = names.index(entry), names.index(exit)
            require(begin < finish, f"chain {repeat_index}: {phase} phase is reversed")
            positions.extend((begin, finish))
            phase_threads[phase] = sorted({event["thread_id"] for event in
                                           segment[begin:finish + 1]
                                           if event["category"] == "tokio_worker"})
        post_entry = names.index("chain_postcall_entry") if names.count("chain_postcall_entry") == 1 else -1
        post_exit = names.index("chain_postcall_exit") if names.count("chain_postcall_exit") == 1 else -1
        require(0 <= post_entry < post_exit and
                positions[1] < positions[2] < positions[3] < post_entry < post_exit
                < positions[4] < positions[5],
                f"chain {repeat_index}: work phases are out of order")
        require(names.count("chain_guest_task_entry") ==
                names.count("chain_guest_task_exit") == 1
                and positions[2] < names.index("chain_guest_task_entry")
                < names.index("chain_guest_task_exit") < positions[3],
                f"chain {repeat_index}: guest task escaped operation phase")
        phase_intervals = ((positions[0], positions[1]),
                           (positions[2], positions[3]),
                           (post_entry, post_exit),
                           (positions[4], positions[5]))
        require(all(any(begin < index < finish for begin, finish in phase_intervals)
                    for index, event in enumerate(segment)
                    if event["name"] in CONVERSION_NAMES),
                f"chain {repeat_index}: conversion escaped named worker phases")
        open_conversions = {}
        for event in segment:
            name = event["name"]
            if name not in CONVERSION_NAMES:
                continue
            kind, boundary = name.rsplit("_", 1)
            key = kind, event["thread_id"]
            if boundary == "entry":
                require(key not in open_conversions,
                        f"chain {repeat_index}: overlapping canonical conversion")
                open_conversions[key] = event["os_thread_id"]
            else:
                require(open_conversions.pop(key, None) == event["os_thread_id"],
                        f"chain {repeat_index}: unmatched canonical conversion")
        require(not open_conversions,
                f"chain {repeat_index}: unclosed canonical conversion")
        conversion_positions = [index for index, event in enumerate(segment)
                                if positions[2] < index < positions[3]
                                and event["name"] in CONVERSION_NAMES]
        conversions = [segment[index]["thread_id"] for index in conversion_positions]
        conversion_names = [segment[index]["name"] for index in conversion_positions]
        require(conversions and all(thread in workers for thread in conversions)
                and conversion_names.count("canonical_input_entry") ==
                    conversion_names.count("canonical_input_exit") > 0
                and conversion_names.count("canonical_output_entry") ==
                    conversion_names.count("canonical_output_exit")
                and (stores == 65 or sample_keys[repeat_index] == "trap_control"
                     or conversion_names.count("canonical_output_entry") > 0),
                f"chain {repeat_index}: canonical conversion was not observed on workers")
        phase_threads["conversion"] = sorted(set(conversions))
        require(all(phase_threads.values()),
                f"chain {repeat_index}: a phase lacks worker evidence")
        attempts.append({
            "sample_key": sample_keys[repeat_index], "repeat_index": repeat_index,
            "phase_threads": phase_threads,
            "blocking_thread_ids": sorted({event["thread_id"] for event in segment
                                           if event["category"] == "blocking_pool"}),
            "cache_state": "warm",
        })
    require(all(event["name"] not in {"chain_attempt_start", "chain_attempt_end"}
                for event in events[:starts[0]] + events[ends[-1] + 1:]),
            "chain trace contains unpaired attempt markers")
    return attempts


def balance_amounts(values, case_id):
    require(isinstance(values, dict) and set(values) == BALANCE_KEYS
            and all(isinstance(value, str) for value in values.values()),
            f"{case_id}: balance transitions are incomplete")
    try:
        return {key: Fraction(Decimal(canonical_decimal(value, case_id)))
                for key, value in values.items()}
    except (InvalidOperation, OverflowError, TypeError, ValueError) as error:
        raise ValueError(f"{case_id}: invalid balance amount") from error


def normalized_balance_transitions(values, case_id):
    balance_amounts(values, case_id)
    return {key: canonical_decimal(value, case_id) for key, value in values.items()}


def observation_from_trial(trial, case_id, expected_outcome, schema, sample_key="target"):
    identity = re.fullmatch(r"chain_(33|63|64|65)_(paid|view|core)", case_id)
    require(identity is not None and expected_outcome in {
        "ok", "trap", "invocation_limit",
    }, f"{case_id}: unknown chain case or outcome")
    stores, mode = int(identity.group(1)), identity.group(2)
    expected_error = None if expected_outcome == "ok" else "deterministic"
    expected_trap = "UnreachableCodeReached" if expected_outcome == "trap" else None
    require(isinstance(trial, dict) and trial.get("sample_key") == sample_key
            and trial.get("outcome") == expected_outcome
            and trial.get("error_class") == expected_error
            and trial.get("trap") == expected_trap
            and trial.get("live_stores_before") == trial.get("live_stores_after") == 0
            and trial.get("live_store_peak") == min(stores, 64)
            and trial.get("rolled_back") is True
            and trial.get("savepoint_restored") is True
            and trial.get("stack_empty") is True
            and trial.get("rollback_clean") is True
            and trial.get("resource_count") == trial.get("baseline_resource_count"),
            f"{case_id}: chain trial peak, typed outcome, or cleanup differs")
    before = trial["state_before_sha256"]
    after = trial["state_after_sha256"]
    require(before == after and re.fullmatch(r"[0-9a-f]{64}", before),
            f"{case_id}: persistent state changed after rollback")
    balances = trial["balances_snapshot"]
    require(isinstance(balances, dict) and set(balances) ==
            {"actor", "burner", "floor", "supply"}
            and all(isinstance(value, str) for value in balances.values()),
            f"{case_id}: balance snapshot is incomplete")
    encoded = json.dumps(balances, sort_keys=True, separators=(",", ":")).encode()
    require(hashlib.sha256(encoded).hexdigest() == trial["balances_sha256"],
            f"{case_id}: balance snapshot digest differs")
    amounts = balance_amounts(trial.get("balances"), case_id)
    try:
        baseline = {key: Fraction(Decimal(value)) for key, value in balances.items()}
    except (InvalidOperation, OverflowError, TypeError, ValueError) as error:
        raise ValueError(f"{case_id}: invalid balance amount") from error
    require(amounts["before"] == baseline["actor"]
            and amounts["burned_before"] == baseline["burner"]
            and amounts["floor_before"] == baseline["floor"]
            and amounts["supply_before"] == baseline["supply"]
            and amounts["restored"] == amounts["before"]
            and amounts["floor_restored"] == amounts["floor_before"],
            f"{case_id}: balance baseline or rollback differs")
    debit = amounts["before"] - amounts["after"]
    burned = amounts["burned_after"] - amounts["burned_before"]
    supply_delta = amounts["supply_before"] - amounts["supply_after"]
    require(debit == burned == supply_delta
            and (debit > 0 if mode == "paid" else debit == 0)
            and (amounts["floor_after"] < amounts["floor_before"]
                 if mode == "core" and expected_outcome == "ok"
                 else amounts["floor_after"] == amounts["floor_before"]),
            f"{case_id}: paid, view, or Core balance transition differs")
    fuel = trial.get("fuel")
    require(isinstance(fuel, dict) and set(fuel) == {"user", "system", "deposit"}
            and all(type(value) is int and value >= 0 for value in fuel.values())
            and (fuel["user"] > 0 if mode == "paid" else fuel["system"] > 0),
            f"{case_id}: fuel allocation differs")
    receipt = trial["receipt"]
    if mode == "view":
        require(receipt is None and trial["receipt_count"] == 0,
                f"{case_id}: view created receipts")
    else:
        require(isinstance(receipt, dict) and set(receipt) ==
                {"contract_id", "status", "gas", "value"}
                and type(receipt["contract_id"]) is int and receipt["contract_id"] > 0
                and type(receipt["gas"]) is int and receipt["gas"] > 0
                and receipt["status"] == ("Ok" if expected_outcome == "ok" else "Other")
                and receipt["value"] == trial["value"]
                and trial["receipt_count"] == (
                    stores if expected_outcome == "ok" else 1),
                f"{case_id}: root receipt is missing or misclassified")
    require((expected_outcome != "trap") == (sample_key == "target")
            and trial["value"] == ("42" if expected_outcome == "ok" else None)
            and trial["storage_state"] == (
                "[2, 0, 0, 0]" if expected_outcome == "ok" and mode != "view"
                else "[0, 0, 0, 0]")
            and trial["host_io_suspended"] is (expected_outcome != "invocation_limit")
            and trial["leaf_callback_seen"] is (expected_outcome != "invocation_limit"),
            f"{case_id}: root-inclusive call or rejection differs")
    observation = {
        "case_id": case_id, "sample_key": sample_key, "outcome": expected_outcome,
        "error_class": expected_error,
        "trap": expected_trap, "value": trial["value"], "fuel": fuel,
        "receipts": [] if receipt is None else [receipt],
        "state": {"before_sha256": before, "after_sha256": after,
                  "marker": trial["storage_state"],
                  "balances_sha256": trial["balances_sha256"],
                  "balance_transitions": normalized_balance_transitions(
                      trial["balances"], case_id)},
        "rollback": True,
        "live_stores": {"before": 0, "during": trial["live_store_peak"], "after": 0},
        "reservations": {"before": 0, "during": trial["live_store_peak"], "after": 0},
        "resource_cleanup": {
            "table_before": trial["baseline_resource_count"],
            "table_after": trial["resource_count"],
            "savepoint_restored": trial["savepoint_restored"],
            "stack_empty": trial["stack_empty"],
            "invocation_table_released": None,
        },
        "fresh_store": True, "suspended": trial["host_io_suspended"],
        "reused": False, "observed_depth": None,
    }
    validator = Draft202012Validator({"$ref": "#/$defs/observation", "$defs": schema["$defs"]})
    error = next(validator.iter_errors(observation), None)
    require(error is None, f"{case_id}: observation schema failed: {error}")
    return observation


def check_repeated_observations(observations, trap_control, label):
    require(len(observations) == 3 and observations[0] == observations[2]
            and (trap_control or observations[0] == observations[1]),
            f"{label}: repeated observations diverge")


def parse_worker(path, mode, stores, pid, manifest, schema, chain_mode="paid",
                 trap_control=False, page_size=None):
    case_id = f"chain_{stores}_{chain_mode}"
    label = f"{case_id}/{mode}" + (" trap control" if trap_control else "")
    lines = path.read_text().splitlines()
    harness = harness_position(lines, label)
    report_pos, report = one_marker(lines, "CHAIN_PROBE_REPORT:")
    runtime_pos, runtime = one_marker(lines, "KONTOR_CHAIN_WORKER_RUNTIME=")
    trace_pos, trace = one_marker(lines, "KONTOR_CHAIN_WORKER_TRACE=")
    completed = [index for index, line in enumerate(lines)
                 if line.strip() == f"CHAIN_PROBE_COMPLETE mode={chain_mode} stores={stores}"]
    require(len(completed) == 1 and report_pos < completed[0] < runtime_pos < trace_pos < harness,
            f"{label}: child terminal markers are missing or out of order")
    expected = next(case for case in manifest["cases"] if case["id"] == case_id)
    require(isinstance(report, dict) and report.get("case_id") == case_id
            and report.get("mode") == chain_mode and report.get("stores") == stores
            and report.get("resource_mode") == mode
            and report.get("target_only") is (not trap_control)
            and report.get("call_hook_installed") is False
            and report.get("engine_target") == "pulley64-unknown-unknown-elf"
            and report.get("max_wasm_stack") == manifest["configurations"][mode]["pulley_stack_bytes"]
            and report.get("async_stack_size") == manifest["configurations"][mode]["fiber_requested_bytes"]
            and report.get("component_sha256") == {
                "error_test": manifest["artifacts"]["error_test"]["sha256"],
                "proxy": manifest["artifacts"]["proxy"]["sha256"],
            }, f"{label}: chain fixture or engine settings differ")
    trials = report.get("trials")
    sample_keys = (("target", "trap_control", "target") if trap_control
                   else ("target",) * 3)
    outcomes = (("ok", "trap", "ok") if trap_control
                else (expected["expected_outcomes"]["target"],) * 3)
    require(isinstance(trials, list) and len(trials) == 3
            and all(isinstance(trial, dict) for trial in trials)
            and [trial.get("repeat_index") for trial in trials] == [0, 1, 2]
            and [trial.get("sample_key") for trial in trials] == list(sample_keys)
            and [trial.get("outcome") for trial in trials] == list(outcomes),
            f"{label}: three ordered trials are missing")
    attempts = measured_trace(trace, runtime, mode, stores, pid, chain_mode,
                              trap_control, sample_keys, page_size)
    observations = [observation_from_trial(
        trial, case_id, outcome, schema, sample_key,
    ) for trial, outcome, sample_key in zip(trials, outcomes, sample_keys, strict=True)]
    check_repeated_observations(observations, trap_control, label)
    return {
        "id": case_id, "parameters": expected["parameters"],
        "trap_control": trap_control, "report": report,
        "observations": observations,
        "worker_execution": {"whole_operation_spawned": True,
                             "source_sha256": manifest["worker_runner"]["sha256"],
                             "attempts": attempts},
        "runtime": runtime, "thread_trace": trace,
    }


def verify_final_closure(control, binary, control_dir, control_copy, control_sha256):
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain"],
        check=True, capture_output=True, text=True,
    ).stdout
    require(head == control["source_sha"] and not dirty,
            "chain source revision changed during capture")
    require(sha256(MANIFEST) == control["manifest_sha256"]
            and load_json_strict(MANIFEST) == build_manifest(),
            "chain resource manifest changed during capture")
    require(sha256(binary) == control["binary_sha256"],
            "chain test binary changed during capture")
    require(sha256(control_copy) == control_sha256,
            "chain control capture changed in archive")
    for entry in (control["cargo_artifacts"], control["cargo_metadata"],
                  control["build_attestation"], control["build_log"],
                  control["guard_control"]["raw_log"],
                  *control["fastnum_files"].values(),
                  *control["wasmtime_source_files"].values()):
        file_evidence(control_dir, entry)


def check_run_consistency(captured, case_id, mode, trap_control, detail):
    name = f"{case_id}_{'trap_control_' if trap_control else ''}{mode}"
    if mode == "production":
        reduced_name = f"{case_id}_{'trap_control_' if trap_control else ''}reduced"
        require(detail["observations"] == captured[reduced_name]["observations"],
                f"{name}: full observations differ across worker stack modes")
    if trap_control:
        target = captured[f"{case_id}_{mode}"]
        require(detail["observations"][0] == target["observations"][0]
                and detail["observations"][2] == target["observations"][0],
                f"{name}: 64-Store target and control prestate or success differs")


def cross_mode_initial_states(captured, fixture_reasons):
    summaries = {}
    for stores in CHAIN_STORES:
        digests = {}
        for chain_mode in CHAIN_MODES:
            observation = captured[f"chain_{stores}_{chain_mode}_reduced"]["observations"][0]
            digests[chain_mode] = observation["state"]["before_sha256"]
        references = {}
        for chain_mode in CHAIN_MODES:
            equal = digests[chain_mode] == digests["paid"]
            reason = fixture_reasons.get((stores, chain_mode))
            require(equal or (isinstance(reason, str) and reason.strip()
                              and "\n" not in reason and "\r" not in reason),
                    f"chain_{stores}_{chain_mode}: cross-mode initial state needs a fixture reason")
            references[chain_mode] = {"matches_paid": equal,
                                      "fixture_reason": None if equal else reason}
        summaries[str(stores)] = {"digests": digests, "comparisons": references}
    return summaries


def capture(control_path, control_sha256, evidence_dir, timeout_seconds):
    require(sys.platform == "linux", "paired chain worker capture is Linux-only")
    manifest = build_manifest()
    require(load_json_strict(MANIFEST) == manifest, "resource manifest changed")
    control, binary = validate_control(control_path, control_sha256, manifest)
    schema = load_json_strict(MANIFEST.with_name("resource-evidence-schema-v1.json"))
    if evidence_dir.exists() and any(evidence_dir.iterdir()):
        raise ValueError("chain evidence output directory is not empty")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    control_dir = evidence_dir / "control"
    control_dir.mkdir()
    control_entries = [control["cargo_artifacts"], control["cargo_metadata"],
                       control["build_attestation"], control["build_log"],
                       control["guard_control"]["raw_log"],
                       *control["fastnum_files"].values(),
                       *control["wasmtime_source_files"].values()]
    for entry in control_entries:
        source = control_path.parent / entry["path"]
        target = control_dir / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as original, target.open("xb") as destination:
            shutil.copyfileobj(original, destination)
        file_evidence(control_dir, entry)
    control_copy = control_dir / "resource-control-capture.json"
    with control_path.open("rb") as original, control_copy.open("xb") as destination:
        shutil.copyfileobj(original, destination)
    require(sha256(control_copy) == control_sha256, "control capture changed in archive")
    captured = {}
    failure_path = evidence_dir / "resource-chain-failure.json"
    runs = [(stores, chain_mode, mode, False)
            for chain_mode in CHAIN_MODES for stores in CHAIN_STORES
            for mode in STACK_MODES]
    runs.extend((64, chain_mode, mode, True)
                for chain_mode in CHAIN_MODES for mode in STACK_MODES)
    for stores, chain_mode, mode, trap_control in runs:
        command = [str(binary), "--ignored", "--exact", WORKER_TEST, "--nocapture"]
        environment = os.environ.copy()
        environment["KONTOR_RESOURCE_MODE"] = mode
        environment["KONTOR_CHAIN_MODE"] = chain_mode
        environment["KONTOR_CHAIN_STORES"] = str(stores)
        environment["KONTOR_CHAIN_TRAP_CONTROL"] = "1" if trap_control else "0"
        child, started, ended, output, timed_out = run_bounded_process(
            command, timeout_seconds, environment,
        )
        case_id = f"chain_{stores}_{chain_mode}"
        name = f"{case_id}_{'trap_control_' if trap_control else ''}{mode}"
        raw_path = evidence_dir / f"{name}.log"
        with raw_path.open("xb") as destination:
            destination.write(output)
        process = {
            "pid": child.pid, "command": command,
            "started_unix_ns": started, "ended_unix_ns": ended,
            "exit_code": child.returncode if child.returncode >= 0 else None,
            "signal": -child.returncode if child.returncode < 0 else None,
            "timed_out": timed_out, "complete": not timed_out and child.returncode == 0,
            "test_harness_passed": not timed_out and child.returncode == 0,
        }
        raw = {"path": raw_path.name, "sha256": sha256(raw_path)}
        try:
            require(not timed_out and child.returncode == 0,
                    f"{name}: Rust child failed or timed out")
            detail = parse_worker(raw_path, mode, stores, child.pid, manifest,
                                  schema, chain_mode, trap_control)
            require(sha256(binary) == control["binary_sha256"],
                    f"{name}: test binary changed during capture")
            check_run_consistency(captured, case_id, mode, trap_control, detail)
            captured[name] = {"process": process, "raw_log": raw, **detail}
        except Exception as error:
            with failure_path.open("x") as destination:
                json.dump({"error": str(error), "failed_run": name, "process": process,
                           "raw_log": raw, "completed_runs": captured},
                          destination, indent=2, sort_keys=True)
                destination.write("\n")
            raise
    try:
        signatures = {
            f"chain_{stores}_{chain_mode}":
                captured[f"chain_{stores}_{chain_mode}_reduced"]["observations"][0]
            for chain_mode in CHAIN_MODES for stores in CHAIN_STORES}
        trap_signatures = {
            chain_mode:
                captured[f"chain_64_{chain_mode}_trap_control_reduced"]["observations"][1]
            for chain_mode in CHAIN_MODES}
        initial_states = cross_mode_initial_states(captured, CROSS_MODE_FIXTURE_REASONS)
        identities = [(item["process"]["pid"], item["process"]["started_unix_ns"])
                      for item in captured.values()]
        identities.append((control["guard_control"]["process"]["pid"],
                           control["guard_control"]["process"]["started_unix_ns"]))
        require(len(set(identities)) == len(identities),
                "guard, chain targets, or trap control reused a process record")
        verify_final_closure(control, binary, control_dir, control_copy,
                             control_sha256)
    except Exception as error:
        with failure_path.open("x") as destination:
            json.dump({"error": str(error), "completed_runs": captured},
                      destination, indent=2, sort_keys=True)
            destination.write("\n")
        raise
    bundle = {
        "status": "candidate_actual_binding",
        "qualification_status": "missing",
        "timeout_seconds": timeout_seconds,
        "source_sha": control["source_sha"],
        "binary_path": str(binary),
        "binary_sha256": control["binary_sha256"],
        "manifest_sha256": control["manifest_sha256"],
        "control_capture": {"path": "control/resource-control-capture.json",
                            "sha256": control_sha256},
        "runs": captured,
        "paired_signatures": signatures,
        "paired_trap_signatures": trap_signatures,
        "cross_mode_initial_states": initial_states,
        "remaining_case_bindings": [case["id"] for case in manifest["cases"]
                                    if case["id"] not in signatures],
        "unmet_requirements": {
            "macos_guard": "missing", "production_memory_profiles": "missing",
            "workload_plan": manifest["workload_plan"]["status"],
            "attestation": manifest["attestation_status"],
        },
    }
    destination = evidence_dir / "resource-chain-capture.json"
    with destination.open("x") as output:
        json.dump(bundle, output, indent=2, sort_keys=True)
        output.write("\n")
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-capture", type=Path, required=True)
    parser.add_argument("--control-sha256", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 1200:
        parser.error("timeout must be between 1 and 1200 seconds")
    path = capture(args.control_capture, args.control_sha256,
                   args.evidence_dir, args.timeout_seconds)
    print(json.dumps({"capture_path": str(path), "sha256": sha256(path)}, sort_keys=True))


if __name__ == "__main__":
    main()
