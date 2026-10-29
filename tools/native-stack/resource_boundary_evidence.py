#!/usr/bin/env python3
"""Validate the bounded, per-process Pulley boundary family evidence."""

import argparse
import hashlib
import json
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

from jsonschema import Draft202012Validator

sys.dont_write_bytecode = True

from capture_resource_chain import harness_position
from capture_resource_diagnostic import validate_control
from resource_evidence import (file_evidence, load_json_strict, no_duplicate_keys,
                               no_nonfinite_constants, require, sha256,
                               thread_capacities)
from resource_evidence_v2 import validate_teardown
from resource_boundary_manifest import (CONFIGURATIONS, DISCOVERY_CELL,
                                        DISCOVERY_ROLE, FINAL_ROLES, MANIFEST,
                                        SCHEMA, build_boundary_manifest)
from resource_manifest import ROOT, build_manifest


TEST_NAME = "runtime::call::tests::native_stack_resource::pulley_boundary_worker_case"
ATTEMPT_MARKER = "BOUNDARY_PROBE_ATTEMPT:"
SUMMARY_MARKER = "BOUNDARY_PROBE_SUMMARY:"
TERMINAL_MARKER = "BOUNDARY_PROBE_TERMINAL:"
RUNTIME_MARKER = "BOUNDARY_WORKER_RUNTIME="
TRACE_MARKER = "BOUNDARY_WORKER_TRACE="
TIMING_MARKER = "KONTOR_STACK_TIMING:"
OBSERVATION_KEYS = {
    "role", "sample_index", "sample_id", "cache_mode", "call_hook_installed",
    "fixture_contracts", "kind", "depth", "outcome", "error", "value",
    "receipt", "last_depth", "child_markers", "rolled_back", "fuel",
    "gas_limit", "paid_fuel_limit", "view_gas_limit", "view_fuel_limit",
    "system_fuel_ceiling", "gas_to_fuel_multiplier", "max_wasm_stack",
    "async_stack_size", "engine_target", "component_sha256", "target_os",
    "target_arch", "reset", "state_before_sha256", "teardown_events",
    "teardown_probe_on", "error_class", "typed_trap", "host_io_suspended",
    "leaf_callback_seen", "balance_transitions", "balance_transitions_sha256",
    "live_store_peak",
}
ATTEMPT_KEYS = {
    "case_id", "process_role", "configuration", "probe_on", "pid",
    "sample_key", "repeat_index", "depth", "complete", "observation",
}
SUMMARY_KEYS = {
    "case_id", "process_role", "configuration", "probe_on", "pid",
    "discovery", "last_success", "first_failure", "attempt_count",
    "component_sha256", "engine_target", "max_wasm_stack",
    "async_stack_size", "cache_mode", "complete",
}
RUNTIME_KEYS = {
    "scope", "configuration", "case_id", "process_role", "pid", "flavor",
    "worker_count", "worker_requested_bytes", "thread_observations",
    "blocking_pool_observed", "block_on_caller_observed",
    "embedded_source_sha", "binary_sha256",
}
TRACE_KEYS = {"scope", "configuration", "case_id", "process_role", "events"}
TRACE_EVENT_KEYS = {"name", "thread_id", "os_thread_id", "category"}
PHASES = (
    ("sample_preparation_entry", "sample_preparation_exit"),
    ("operation_entry", "operation_exit"),
    ("postcall_observation_entry", "postcall_observation_exit"),
    ("teardown_entry", "teardown_exit"),
)
EXTRA_EVENTS = {
    "fixture_preparation_entry", "fixture_preparation_exit",
    "publication_entry", "publication_exit", "compiler_entry", "compiler_exit",
    "blocking_decode_entry", "blocking_decode_exit",
    "canonical_input_entry", "canonical_input_exit",
    "canonical_output_entry", "canonical_output_exit",
}


def run_name(case_id, role, configuration):
    return f"{case_id}_{role}_{configuration}"


def expected_case_env(case_id, role, configuration, depths=None):
    require(role in (*FINAL_ROLES, DISCOVERY_ROLE), "unknown boundary role")
    require(configuration in CONFIGURATIONS, "unknown boundary configuration")
    require(role != DISCOVERY_ROLE or configuration == "production",
            "discovery must use production workers")
    expected = {
        "KONTOR_RESOURCE_MODE": configuration,
        "KONTOR_BOUNDARY_CASE": case_id,
        "KONTOR_BOUNDARY_ROLE": role,
        "KONTOR_RESOURCE_TEARDOWN_PROBE":
            "off" if role == "probe_off_control" else "on",
    }
    if role != DISCOVERY_ROLE:
        require(depths is not None, "replay lacks reviewed depths")
        expected["KONTOR_BOUNDARY_LAST_SUCCESS"] = str(depths[0])
        expected["KONTOR_BOUNDARY_FIRST_FAILURE"] = str(depths[1])
    return expected


def parse_worker_log(path):
    lines = path.read_text().splitlines()

    def marked(prefix):
        return [(index, json.loads(line.split(prefix, 1)[1],
                                   object_pairs_hook=no_duplicate_keys,
                                   parse_constant=no_nonfinite_constants))
                for index, line in enumerate(lines) if prefix in line]

    attempts = marked(ATTEMPT_MARKER)
    summary = marked(SUMMARY_MARKER)
    terminal = marked(TERMINAL_MARKER)
    runtime = marked(RUNTIME_MARKER)
    trace = marked(TRACE_MARKER)
    timings = marked(TIMING_MARKER)
    require(attempts and len(summary) == len(terminal) == len(runtime) == len(trace) == 1,
            "boundary transcript lacks one summary, terminal, runtime, or trace")
    require(len(timings) == len(attempts),
            "boundary timing count differs from raw attempts")
    harness = harness_position(lines, "boundary child")
    positions = [index for index, _ in attempts]
    require(positions == sorted(set(positions))
            and all((positions[index - 1] if index else -1)
                    < timings[index][0] < positions[index]
                    for index in range(len(positions)))
            and positions[-1] < runtime[0][0] < trace[0][0]
            < summary[0][0] < terminal[0][0] < harness,
            "boundary trial, summary, and terminal markers are reordered")
    require(sum("BOUNDARY_" in line for line in lines)
            == len(attempts) + 4,
            "boundary transcript has an unrecognized or duplicate marker")
    return {
        "attempts": [value for _, value in attempts],
        "summary": summary[0][1],
        "terminal": terminal[0][1],
        "runtime": runtime[0][1],
        "thread_trace": trace[0][1],
        "timings": [value for _, value in timings],
    }


def validate_discovery_sequence(attempts, summary):
    require(len(attempts) <= 21 and attempts[0]["depth"] == 0
            and attempts[0]["observation"]["outcome"] == "ok",
            "discovery did not start at a successful zero depth")
    position = 1
    last_success = 0
    depth = 1024
    while True:
        require(position < len(attempts) and attempts[position]["depth"] == depth,
                "discovery exponential search is missing or reordered")
        outcome = attempts[position]["observation"]["outcome"]
        position += 1
        if outcome != "ok":
            require(outcome == "stack_overflow", "discovery found a non-stack failure")
            first_failure = depth
            break
        last_success = depth
        require(depth < 32768, "discovery never found a bounded failure")
        depth = min(depth * 2, 32768)
    while first_failure - last_success > 1:
        midpoint = last_success + (first_failure - last_success) // 2
        require(position < len(attempts)
                and attempts[position]["depth"] == midpoint,
                "discovery bisection is missing or reordered")
        outcome = attempts[position]["observation"]["outcome"]
        position += 1
        if outcome == "ok":
            last_success = midpoint
        else:
            require(outcome == "stack_overflow",
                    "discovery bisection found a non-stack failure")
            first_failure = midpoint
    require(position == len(attempts)
            and (summary["last_success"], summary["first_failure"])
            == (last_success, first_failure),
            "discovery summary differs from complete search transcript")


def validate_replay_order(attempts, depths, leaf=False):
    if leaf:
        expected = [("target", depths[0], index, "ok")
                    for index in range(2)]
    else:
        expected = [
            ("last_success", depths[0], 0, "ok"),
            ("first_failure", depths[1], 0, "stack_overflow"),
            ("first_failure", depths[1], 1, "stack_overflow"),
            ("last_success", depths[0], 1, "ok"),
            ("last_success", depths[0], 2, "ok"),
            ("first_failure", depths[1], 2, "stack_overflow"),
        ]
    require(len(attempts) == len(expected)
            and all((attempt["sample_key"], attempt["depth"],
                     attempt["repeat_index"],
                     attempt["observation"]["outcome"]) == item
                    for attempt, item in zip(attempts, expected, strict=True)),
            "boundary replay omitted or reordered frozen depth samples")


def validate_trace(trace, runtime, attempts):
    require(set(trace) == TRACE_KEYS
            and trace["scope"] == runtime["scope"]
            and all(trace[key] == runtime[key] for key in
                    ("configuration", "case_id", "process_role")),
            "boundary trace identity differs from runtime")
    observations = runtime["thread_observations"]
    page = observations[0]["page_size_bytes"]
    threads = thread_capacities(
        {key: value for key, value in runtime.items()
         if key not in {"scope", "configuration", "case_id",
                        "process_role", "pid", "embedded_source_sha",
                        "binary_sha256"}},
        runtime["configuration"], page, "linux", runtime["pid"])
    workers = {item["thread_id"]: item["os_thread_id"]
               for item in threads["tokio_worker"]}
    blocking = {item["thread_id"]: item["os_thread_id"]
                for item in threads["blocking_pool"]}
    events = trace["events"]
    require(isinstance(events, list) and events,
            "boundary thread trace is empty")
    allowed = {name for pair in PHASES for name in pair} | EXTRA_EVENTS | {
        "boundary_attempt_start", "boundary_attempt_end",
    }
    for event in events:
        require(isinstance(event, dict) and set(event) == TRACE_EVENT_KEYS
                and event["name"] in allowed,
                "boundary trace has an unknown event")
        thread, tid = event["thread_id"], event["os_thread_id"]
        if event["category"] == "tokio_worker":
            require(workers.get(thread) == tid,
                    "boundary phase escaped measured workers")
        else:
            require(event["category"] == "blocking_pool"
                    and blocking.get(thread) == tid
                    and event["name"].startswith("blocking_decode_"),
                    "boundary blocking event lacks measured stack")
    names = [event["name"] for event in events]
    starts = [index for index, name in enumerate(names)
              if name == "boundary_attempt_start"]
    ends = [index for index, name in enumerate(names)
            if name == "boundary_attempt_end"]
    require(len(starts) == len(ends) == len(attempts)
            and all(start < end
                    and (index == 0 or ends[index - 1] < start)
                    for index, (start, end) in enumerate(zip(starts, ends, strict=True))),
            "boundary attempt intervals are incomplete or overlap")
    require(names.count("fixture_preparation_entry") ==
            names.count("fixture_preparation_exit") == 1
            and names.count("publication_entry") ==
            names.count("publication_exit") == 1
            and names.index("fixture_preparation_entry")
            < names.index("publication_entry")
            < names.index("publication_exit")
            < names.index("fixture_preparation_exit")
            < starts[0],
            "boundary fixture preparation or publication escaped worker phases")
    for start, end in zip(starts, ends, strict=True):
        segment = names[start:end + 1]
        ordered = []
        for entry, exit_name in PHASES:
            require(segment.count(entry) == segment.count(exit_name) == 1
                    and segment.index(entry) < segment.index(exit_name),
                    "boundary attempt lacks a complete worker phase")
            ordered.extend((segment.index(entry), segment.index(exit_name)))
        require(ordered == sorted(ordered)
                and segment.count("canonical_input_entry")
                == segment.count("canonical_input_exit") >= 1,
                "boundary operation or canonical input conversion is incomplete")
    compile_counts = {}
    for entry, exit_name in (
        ("compiler_entry", "compiler_exit"),
        ("blocking_decode_entry", "blocking_decode_exit"),
        ("canonical_input_entry", "canonical_input_exit"),
        ("canonical_output_entry", "canonical_output_exit"),
    ):
        require(names.count(entry) == names.count(exit_name),
                f"unpaired boundary {entry}/{exit_name}")
        in_flight = {}
        for event in events:
            if event["name"] == entry:
                require(event["thread_id"] not in in_flight,
                        f"overlapping boundary {entry} on one thread")
                in_flight[event["thread_id"]] = event
            elif event["name"] == exit_name:
                require(event["thread_id"] in in_flight,
                        f"boundary {exit_name} has no matching entry")
                previous = in_flight.pop(event["thread_id"])
                require(previous["os_thread_id"] == event["os_thread_id"],
                        f"boundary {entry}/{exit_name} thread identity changed")
        require(not in_flight, f"unclosed boundary {entry} event")
        compile_counts[entry] = names.count(entry)
    require(compile_counts["compiler_entry"] >= 1
            and compile_counts["blocking_decode_entry"] >= 1,
            "boundary fixture lacked compilation or blocking decode evidence")
    return compile_counts


def validate_observation(attempt, summary, manifest, index):
    require(isinstance(attempt, dict) and set(attempt) == ATTEMPT_KEYS
            and attempt["complete"] is True,
            "boundary attempt has missing or unknown fields")
    observation = attempt["observation"]
    require(isinstance(observation, dict)
            and set(observation) == OBSERVATION_KEYS,
            "boundary observation has missing or unknown fields")
    role = attempt["process_role"]
    case_id = attempt["case_id"]
    configuration = attempt["configuration"]
    mode = "paid" if case_id == "deepest_frame_host_call" else case_id.rsplit("_", 1)[1]
    shape = "leaf" if case_id == "deepest_frame_host_call" else case_id.split("_")[1]
    kind = (("paid_leaf_host" if shape == "leaf" else
             f"{mode}_{'recurse' if shape == 'plain' else 'wide'}"))
    require(observation["role"] == role
            and observation["sample_index"] == index
            and observation["kind"] == kind
            and observation["depth"] == attempt["depth"]
            and observation["teardown_probe_on"] is attempt["probe_on"]
            and observation["cache_mode"] == summary["cache_mode"]
            and observation["call_hook_installed"] is False
            and observation["fixture_contracts"] == 1
            and observation["component_sha256"] == summary["component_sha256"]
            and observation["engine_target"] == summary["engine_target"]
            and observation["max_wasm_stack"] == summary["max_wasm_stack"]
            and observation["async_stack_size"] == summary["async_stack_size"]
            and observation["target_os"] == "linux"
            and observation["child_markers"] == [],
            "boundary observation differs from selected real fixture")
    require(observation["live_store_peak"] == 1,
            "boundary guest Store did not reach one live reservation")
    require(observation["engine_target"] == "pulley64-unknown-unknown-elf"
            and observation["max_wasm_stack"] == 524288
            and observation["async_stack_size"] ==
            (1048576 if configuration == "reduced" else 2097152),
            "boundary Engine stack settings differ from manifest")
    outcome = observation["outcome"]
    require(outcome in ("ok", "stack_overflow")
            and observation["error_class"] ==
            (None if outcome == "ok" else "deterministic")
            and observation["typed_trap"] ==
            (None if outcome == "ok" else "StackOverflow")
            and (observation["error"] is None if outcome == "ok"
                 else isinstance(observation["error"], str)
                 and bool(observation["error"])),
            "boundary outcome or typed trap is wrong")
    depth = attempt["depth"]
    expected_value = (496 * depth if shape == "wide" else depth)
    require((observation["value"] == str(expected_value)
             and observation["last_depth"] ==
             (0 if mode in ("view", "system") else depth)
             and observation["rolled_back"] is False)
            if outcome == "ok"
            else (observation["value"] is None
                  and observation["last_depth"] == 0
                  and observation["rolled_back"] is True),
            "boundary value, marker, or rollback differs")
    fuel = observation["fuel"]
    require(isinstance(fuel, dict) and set(fuel) == {"user", "system", "deposit"}
            and all(type(value) is int and value >= 0 for value in fuel.values())
            and fuel["user" if mode == "paid" else "system"] > 0,
            "boundary fuel allocation is incomplete")
    receipt = observation["receipt"]
    if mode in ("view", "system"):
        require(receipt is None, "boundary view persisted a receipt")
    else:
        require(isinstance(receipt, dict) and set(receipt) == {"status", "gas"}
                and receipt["status"] == ("Ok" if outcome == "ok" else "Trap")
                and type(receipt["gas"]) is int and receipt["gas"] > 0,
                "boundary paid/Core receipt is missing or wrong")
    reset = observation["reset"]
    require(isinstance(reset, dict) and set(reset) == {"pre", "post"}
            and set(reset["pre"]) == {
                "live_invocations", "stack_empty", "savepoint_intact",
                "resource_count", "baseline_resource_count",
                "failure_rolled_back",
            }
            and set(reset["post"]) == {
                "persistent_digest_sha256", "baseline_digest_sha256",
                "digest_matches", "live_invocations", "stack_empty",
                "savepoint_restored", "resource_count", "balances_restored",
                "floor_restored", "supply_restored",
            },
            "boundary reset fields are incomplete")
    before = observation["state_before_sha256"]
    after = reset["post"]["persistent_digest_sha256"]
    baseline = reset["post"]["baseline_digest_sha256"]
    require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                for value in (before, after, baseline))
            and before == after == baseline
            and reset["pre"]["live_invocations"] == 0
            and reset["post"]["live_invocations"] == 0
            and reset["pre"]["stack_empty"] is True
            and reset["pre"]["savepoint_intact"] is True
            and reset["post"]["stack_empty"] is True
            and reset["post"]["savepoint_restored"] is True
            and reset["post"]["digest_matches"] is True
            and all(reset["post"][key] is True for key in
                    ("balances_restored", "floor_restored", "supply_restored"))
            and reset["pre"]["resource_count"] ==
            reset["pre"]["baseline_resource_count"] ==
            reset["post"]["resource_count"]
            and reset["pre"]["failure_rolled_back"] ==
            (None if outcome == "ok" else True),
            "boundary full rows/schema or resource reset failed")
    balances = observation["balance_transitions"]
    require(isinstance(balances, dict) and set(balances) == {
        "before", "after", "restored", "burned_before", "burned_after",
        "supply_before", "supply_after", "floor_before", "floor_after",
        "floor_restored",
    }, "boundary balance transition fields are incomplete")
    try:
        amounts = {key: Decimal(value) for key, value in balances.items()}
    except (InvalidOperation, TypeError, ValueError) as error:
        raise ValueError("boundary balance amount is invalid") from error
    require(all(amount.is_finite() and amount >= 0 for amount in amounts.values())
            and amounts["restored"] == amounts["before"]
            and amounts["floor_restored"] == amounts["floor_before"],
            "boundary balances or floor did not restore")
    encoded = json.dumps(balances, sort_keys=True,
                         separators=(",", ":")).encode()
    require(observation["balance_transitions_sha256"] ==
            hashlib.sha256(encoded).hexdigest(),
            "boundary balance transition digest differs")
    expected_leaf = case_id == "deepest_frame_host_call"
    require(observation["host_io_suspended"] is expected_leaf
            and observation["leaf_callback_seen"] is expected_leaf,
            "leaf host import was not proven pending and resumed")
    if attempt["probe_on"]:
        counts = validate_teardown(observation["teardown_events"], 1, 0)
        expected_auxiliary = manifest["auxiliary_expected_counts_by_mode"][mode]
        require(all(counts["created"][role] == expected
                    for role, expected in expected_auxiliary.items()),
                "boundary auxiliary Store count differs from reviewed source")
    else:
        require(observation["teardown_events"] is None,
                "probe-off boundary child emitted teardown events")


def semantic_signature(attempt):
    value = attempt["observation"]
    return {
        "sample_key": attempt["sample_key"],
        "depth": attempt["depth"],
        "outcome": value["outcome"],
        "error_class": value["error_class"],
        "typed_trap": value["typed_trap"],
        "value": value["value"],
        "receipt": value["receipt"],
        "last_depth": value["last_depth"],
        "rolled_back": value["rolled_back"],
        "fuel": value["fuel"],
        "live_store_peak": value["live_store_peak"],
        "balance_transitions": value["balance_transitions"],
        "balance_transitions_sha256": value["balance_transitions_sha256"],
        "state_before_sha256": value["state_before_sha256"],
        "reset": value["reset"],
        "host_io_suspended": value["host_io_suspended"],
        "leaf_callback_seen": value["leaf_callback_seen"],
    }


def validate_run(run, bundle, manifest, directory):
    case_id, role, configuration = (run[key] for key in
                                    ("case_id", "process_role", "configuration"))
    name = run_name(case_id, role, configuration)
    require(run["run_id"] == name and run["cell"] == bundle["cell"]
            and run["source_sha"] == bundle["source_sha"]
            and run["manifest_sha256"] == bundle["manifest_sha256"]
            and run["timeout_seconds"] == bundle["timeout_seconds"]
            and run["binary_sha256_before"] ==
            run["binary_sha256_after"] == bundle["binary_sha256"],
            "boundary run source, binary, or identity drifted")
    process = run["process"]
    command = [bundle["binary_path"], "--ignored", "--exact",
               TEST_NAME, "--nocapture"]
    require(process["command"] == run["argv"] == command
            and process["exit_code"] == 0 and process["signal"] is None
            and process["timed_out"] is False
            and process["complete"] is True
            and process["test_harness_passed"] is True
            and process["started_unix_ns"] < process["ended_unix_ns"],
            "boundary child failed, timed out, or used wrong test command")
    depths = None
    if role != DISCOVERY_ROLE:
        frozen = {case["case_id"]: (case["last_success"],
                                     case["first_failure"])
                  for case in manifest["boundary_cases"]}
        if case_id == "deepest_frame_host_call":
            depths = frozen["pulley_plain_paid"]
        else:
            depths = frozen[case_id]
        if bundle["phase"] == "pilot_replay":
            depths = tuple(bundle["discovered_depths"][case_id].values())
            entry = bundle["discovered_depths"][case_id]
            depths = (entry["last_success"], entry["first_failure"])
    require(run["case_env"] == expected_case_env(
        case_id, role, configuration, depths),
        "boundary child has missing, extra, or changed case environment")
    file_evidence(directory, run["raw_log"])
    parsed = parse_worker_log(directory / run["raw_log"]["path"])
    require(all(run[key] == parsed[key] for key in
                ("attempts", "summary", "runtime", "thread_trace", "timings")),
            "boundary parsed run differs from complete raw child transcript")
    summary = parsed["summary"]
    runtime = parsed["runtime"]
    terminal = parsed["terminal"]
    require(set(summary) == SUMMARY_KEYS and set(runtime) == RUNTIME_KEYS
            and set(parsed["thread_trace"]) == TRACE_KEYS
            and summary["case_id"] == runtime["case_id"] == terminal["case_id"] == case_id
            and summary["process_role"] == runtime["process_role"] ==
            terminal["process_role"] == role
            and summary["configuration"] == runtime["configuration"] ==
            terminal["configuration"] == configuration
            and summary["pid"] == runtime["pid"] == terminal["pid"] ==
            process["pid"]
            and summary["attempt_count"] == terminal["attempt_count"] ==
            len(parsed["attempts"])
            and summary["complete"] is terminal["complete"] is True
            and summary["probe_on"] is (role != "probe_off_control")
            and summary["discovery"] is (role == DISCOVERY_ROLE)
            and summary["cache_mode"] == "warm_compiled_cache"
            and runtime["scope"] == "paired_pulley_boundary_worker"
            and runtime["embedded_source_sha"] == bundle["source_sha"]
            and runtime["binary_sha256"] == bundle["binary_sha256"],
            "boundary raw process summary, terminal, or source identity differs")
    require(summary["component_sha256"] ==
            sha256(ROOT / "test-contracts/binaries/stack_probe.wasm.br"),
            "boundary component bytes differ from reviewed fixture")
    for index, attempt in enumerate(parsed["attempts"]):
        require(attempt["case_id"] == case_id
                and attempt["process_role"] == role
                and attempt["configuration"] == configuration
                and attempt["pid"] == process["pid"]
                and attempt["probe_on"] is summary["probe_on"],
                "boundary attempt escaped its child process")
        validate_observation(attempt, summary, manifest, index)
    counts = validate_trace(parsed["thread_trace"], runtime, parsed["attempts"])
    require(len(parsed["timings"]) == len(parsed["attempts"])
            and all(set(timing) == {
                "role", "kind", "sample_index", "setup_ms", "funding_ms",
                "publication_ms", "execution_ms", "postcall_ms",
                "total_sample_ms",
            }
                    and timing["role"] == role
                    and timing["kind"] ==
                    parsed["attempts"][index]["observation"]["kind"]
                    and timing["sample_index"] == index
                    and all(type(timing[key]) is int and timing[key] >= 0
                            for key in ("setup_ms", "funding_ms",
                                        "publication_ms", "execution_ms",
                                        "postcall_ms", "total_sample_ms"))
                    for index, timing in enumerate(parsed["timings"])),
            "boundary per-attempt timing is incomplete")
    if role == DISCOVERY_ROLE:
        require(all(attempt["sample_key"] == "calibration"
                    and attempt["repeat_index"] == index
                    for index, attempt in enumerate(parsed["attempts"])),
                "discovery calibration keys are missing or reordered")
        validate_discovery_sequence(parsed["attempts"], summary)
    elif case_id == "deepest_frame_host_call":
        validate_replay_order(parsed["attempts"], depths, leaf=True)
    else:
        validate_replay_order(parsed["attempts"], depths)
    if role != DISCOVERY_ROLE:
        for sample_key in {attempt["sample_key"] for attempt in parsed["attempts"]}:
            group = [semantic_signature(attempt) for attempt in parsed["attempts"]
                     if attempt["sample_key"] == sample_key]
            require(all(item == group[0] for item in group),
                    "boundary repeated sample semantics changed")
    return [semantic_signature(attempt) for attempt in parsed["attempts"]], counts


def validate_bundle(bundle, directory):
    schema = load_json_strict(SCHEMA)
    error = next(Draft202012Validator(schema).iter_errors(bundle), None)
    require(error is None, f"boundary evidence schema failed: {error}")
    manifest = build_boundary_manifest()
    require(load_json_strict(MANIFEST) == manifest
            and bundle["manifest_sha256"] == sha256(MANIFEST)
            and bundle["qualification_status"] == "missing",
            "boundary manifest or claim status differs from reviewed source")
    control_path = directory / bundle["control_capture"]["path"]
    file_evidence(directory, bundle["control_capture"])
    control, binary = validate_control(
        control_path, bundle["control_capture"]["sha256"],
        build_manifest())
    require(control["source_sha"] == bundle["source_sha"]
            and control["binary_sha256"] == bundle["binary_sha256"]
            and str(binary) == bundle["binary_path"],
            "boundary control source or binary differs from children")
    if bundle["phase"] == "pilot_replay":
        reference = bundle["development_discovery"]
        require(reference is not None,
                "pilot replay lacks its archived production discovery")
        file_evidence(directory, reference)
        development_path = directory / reference["path"]
        development = load_json_strict(development_path)
        require(development["phase"] == "pilot_discovery"
                and development["source_sha"] == bundle["source_sha"]
                and development["binary_sha256"] == bundle["binary_sha256"]
                and development["manifest_sha256"] == bundle["manifest_sha256"]
                and development["discovered_depths"] ==
                bundle["discovered_depths"],
                "pilot replay depths or source differ from archived discovery")
        validate_bundle(development, development_path.parent)
    else:
        require(bundle["development_discovery"] is None,
                "only pilot replay may carry development discovery")
    cases = {case["case_id"] for case in manifest["boundary_cases"]}
    if bundle["phase"] == "final":
        require(manifest["claim_status"] == "candidate_only"
                and bundle["discovered_depths"] == {},
                "final boundary capture lacks reviewed frozen depths")
        expected = {(case_id, role, configuration)
                    for case_id in (*sorted(cases), "deepest_frame_host_call")
                    for role in FINAL_ROLES for configuration in CONFIGURATIONS}
    elif bundle["phase"] == "discovery":
        require(bundle["cell"] == DISCOVERY_CELL
                and set(bundle["discovered_depths"]) == cases,
                "full discovery lacks all eight production cases")
        expected = {(case_id, DISCOVERY_ROLE, "production")
                    for case_id in cases}
    else:
        require(bundle["cell"] == DISCOVERY_CELL
                and set(bundle["discovered_depths"]) ==
                {"pulley_plain_paid", "pulley_wide_paid"},
                "pilot lacks the two paid shape depths")
        if bundle["phase"] == "pilot_discovery":
            expected = {(case_id, DISCOVERY_ROLE, "production")
                        for case_id in bundle["discovered_depths"]}
        else:
            require(bundle["phase"] == "pilot_replay",
                    "unknown boundary capture phase")
            expected = {(case_id, role, configuration)
                        for case_id in bundle["discovered_depths"]
                        for role in FINAL_ROLES for configuration in CONFIGURATIONS}
    runs = bundle["runs"]
    require(set(runs) == {run_name(*key) for key in expected},
            "boundary process registry has missing or extra children")
    process_ids = [(run["process"]["pid"],
                    run["process"]["started_unix_ns"]) for run in runs.values()]
    guard_process = control["guard_control"]["process"]
    process_ids.append((guard_process["pid"],
                        guard_process["started_unix_ns"]))
    require(len(process_ids) == len(set(process_ids)),
            "boundary process PID/start identity is duplicated")
    logs = [run["raw_log"]["path"] for run in runs.values()]
    require(len(logs) == len(set(logs))
            and set(logs) == {path.name for path in directory.glob("*.log")},
            "boundary raw process logs are missing, extra, or duplicated")
    signatures = {}
    compiles = {}
    for key in sorted(expected):
        name = run_name(*key)
        signatures[key], compiles[key] = validate_run(
            runs[name], bundle, manifest, directory)
    if bundle["phase"] in ("discovery", "pilot_discovery"):
        require(all(bundle["discovered_depths"][case_id] == {
            "last_success": runs[run_name(case_id, DISCOVERY_ROLE,
                                          "production")]["summary"]["last_success"],
            "first_failure": runs[run_name(case_id, DISCOVERY_ROLE,
                                           "production")]["summary"]["first_failure"],
        } for case_id in bundle["discovered_depths"]),
                "discovered depths differ from raw production children")
    else:
        for case_id in (sorted(cases) if bundle["phase"] == "final"
                        else sorted(bundle["discovered_depths"])):
            for configuration in CONFIGURATIONS:
                on = signatures[case_id, "target_observed", configuration]
                off = signatures[case_id, "probe_off_control", configuration]
                require(on == off,
                        "boundary probe-on/off semantic parity differs")
            require(signatures[case_id, "target_observed", "reduced"] ==
                    signatures[case_id, "target_observed", "production"],
                    "boundary reduced/production semantics differ")
            for role in FINAL_ROLES:
                reduced = [thread["usable_bytes"] for thread in
                           runs[run_name(case_id, role, "reduced")]
                           ["runtime"]["thread_observations"]
                           if thread["thread_category"] == "tokio_worker"]
                production = [thread["usable_bytes"] for thread in
                              runs[run_name(case_id, role, "production")]
                              ["runtime"]["thread_observations"]
                              if thread["thread_category"] == "tokio_worker"]
                require(reduced and production
                        and min(production) >= 2 * max(reduced),
                        "boundary usable worker-capacity ratio is below two")
        if bundle["phase"] == "final":
            for configuration in CONFIGURATIONS:
                require(signatures[
                    "deepest_frame_host_call", "target_observed", configuration]
                    == signatures[
                    "deepest_frame_host_call", "probe_off_control", configuration],
                    "leaf host probe-on/off semantics differ")
    all_cases = {case["id"] for case in build_manifest()["cases"]
                 if case["family"] != "distinct_contract_chain"}
    bound = cases | {"deepest_frame_host_call"} if bundle["phase"] == "final" else set()
    require(bundle["remaining_case_bindings"] == sorted(all_cases - bound),
            "boundary capture claimed unbound cases")
    return {"signatures": signatures, "compiler_counts": compiles}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    bundle = load_json_strict(args.capture)
    result = validate_bundle(bundle, args.capture.parent)
    print(json.dumps({"status": "validated", "phase": bundle["phase"],
                      "runs": len(bundle["runs"]),
                      "compiler_counts": {
                          "/".join(key): value
                          for key, value in sorted(result["compiler_counts"].items())
                      }}, sort_keys=True))


if __name__ == "__main__":
    main()
