#!/usr/bin/env python3
"""Fail closed on incomplete S2 paired resource evidence."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

from resource_manifest import CELLS, MANIFEST, OBSERVATION_FIELDS, ROOT, THREAD_CATEGORIES, build_manifest

SCHEMA = Path(__file__).with_name("resource-evidence-schema-v1.json")


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def no_nonfinite_constants(value):
    raise ValueError(f"non-finite JSON constant: {value}")


def load_json_strict(path):
    return json.loads(path.read_text(), object_pairs_hook=no_duplicate_keys,
                      parse_constant=no_nonfinite_constants)


def read_process_events(path, process, expected_case_count):
    lines = path.read_text().splitlines()
    require(lines and all(line.strip() for line in lines),
            "process transcript is empty or contains incomplete lines")
    events = [json.loads(line, object_pairs_hook=no_duplicate_keys,
                         parse_constant=no_nonfinite_constants) for line in lines]
    terminal = events.pop()
    require(terminal == {"kind": "terminal", "pid": process["pid"],
                         "case_count": expected_case_count, "attempt_count": len(events),
                         "complete": True, "test_harness_passed": True},
            "process transcript terminal status differs from process record")
    attempts = {}
    for event in events:
        require(set(event) == {"kind", "case_id", "sample_key", "repeat_index",
                               "observation", "worker_attempt"}
                and event["kind"] == "attempt", "unknown process transcript event")
        key = (event["case_id"], event["sample_key"], event["repeat_index"])
        require(key not in attempts, f"duplicate process transcript attempt: {key}")
        attempts[key] = event
    return attempts


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_evidence(directory, entry):
    require(set(entry) == {"path", "sha256"}, "raw log identity is incomplete")
    relative = Path(entry["path"])
    require(not relative.is_absolute() and ".." not in relative.parts, "raw log escapes evidence directory")
    path = directory / relative
    require(path.is_file(), f"missing raw log {relative}")
    require(sha256(path) == entry["sha256"], f"raw log hash mismatch: {relative}")


def thread_capacities(runtime, mode):
    require(runtime["flavor"] == "multi_thread", f"{mode}: runtime is not multithreaded")
    require(type(runtime["worker_count"]) is int and runtime["worker_count"] >= 2,
            f"{mode}: invalid worker count")
    if mode == "reduced":
        require(runtime["worker_requested_bytes"] == 1_048_576,
                "reduced workers did not request 1 MiB")
    observations = runtime["thread_observations"]
    require(isinstance(observations, list), f"{mode}: missing thread observations")
    by_category = {category: [] for category in THREAD_CATEGORIES}
    for thread in observations:
        require(set(thread) == {"thread_category", "thread_id", "requested_bytes",
                                "mapped_bytes", "guard_bytes", "usable_bytes",
                                "mapped_start", "mapped_end", "usable_start", "usable_end",
                                "measurement_api", "guard_treatment"},
                f"{mode}: thread capacity record is incomplete")
        category = thread["thread_category"]
        require(category in by_category, f"{mode}: unknown thread category")
        require(type(thread["mapped_bytes"]) is int and thread["mapped_bytes"] > 0,
                f"{mode}: invalid mapped stack")
        require(type(thread["guard_bytes"]) is int and thread["guard_bytes"] >= 0,
                f"{mode}: invalid guard")
        require(type(thread["usable_bytes"]) is int and
                0 < thread["usable_bytes"] <= thread["mapped_bytes"],
                f"{mode}: usable stack capacity is unverified")
        require(all(type(thread[key]) is int and thread[key] >= 0 for key in
                    ("mapped_start", "mapped_end", "usable_start", "usable_end"))
                and thread["mapped_end"] - thread["mapped_start"] == thread["mapped_bytes"]
                and thread["usable_end"] - thread["usable_start"] == thread["usable_bytes"]
                and thread["mapped_start"] <= thread["usable_start"]
                and thread["usable_end"] <= thread["mapped_end"],
                f"{mode}: actual usable worker range is unverified")
        require(isinstance(thread["measurement_api"], str) and thread["measurement_api"],
                f"{mode}: missing stack measurement API")
        require(isinstance(thread["guard_treatment"], str) and
                thread["guard_treatment"] not in {"", "unknown"},
                f"{mode}: unresolved thread guard treatment")
        by_category[category].append(thread)
    require(len({item["thread_id"] for item in by_category["tokio_worker"]})
            >= runtime["worker_count"], f"{mode}: not all workers measured")
    require(len({item["thread_id"] for item in observations}) == len(observations),
            f"{mode}: duplicate thread capacity record")
    require(all(item["requested_bytes"] == runtime["worker_requested_bytes"]
                for item in by_category["tokio_worker"]),
            f"{mode}: worker request differs from runtime settings")
    require(by_category["blocking_pool"] and runtime["blocking_pool_observed"],
            f"{mode}: blocking pool not observed")
    require(by_category["block_on_caller"] and runtime["block_on_caller_observed"],
            f"{mode}: block_on caller not observed")
    return by_category


def engine_capacity(engine, manifest, mode):
    expected = manifest["configurations"][mode]
    require(engine["wasmtime_revision"] == manifest["wasmtime_revision"],
            f"{mode}: wrong Wasmtime revision")
    require(engine["target"] == "pulley64-unknown-unknown-elf", f"{mode}: wrong engine target")
    require(engine["pulley_stack_bytes"] == expected["pulley_stack_bytes"],
            f"{mode}: logical Pulley capacity changed")
    require(engine["fiber_requested_bytes"] == expected["fiber_requested_bytes"],
            f"{mode}: native fiber request changed")
    require(engine["allocator"] == "on_demand_unix" and engine["sanitizer_mode"] == "none",
            f"{mode}: unsupported fiber allocation path")
    page = engine["page_size_bytes"]
    require(type(page) is int and page > 0 and page & (page - 1) == 0,
            f"{mode}: invalid host page size")
    requested = expected["fiber_requested_bytes"]
    rounded = (requested + page - 1) // page * page
    require(engine["fiber_effective_writable_bytes"] == rounded,
            f"{mode}: fiber writable capacity is not the pinned allocator's rounded size")
    require(engine["guard_bytes"] == page, f"{mode}: guard page changed")


def check_cases(configuration, manifest, mode, directory, transcript):
    expected = {item["id"]: item for item in manifest["cases"]}
    actual = configuration["cases"]
    require(isinstance(actual, list) and len(actual) == len(expected),
            f"{mode}: incomplete case set")
    seen = set()
    signatures = {}
    raw_paths = {entry["path"] for entry in configuration["raw_logs"]}
    worker_ids = {thread["thread_id"] for thread in
                  configuration["runtime"]["thread_observations"]
                  if thread["thread_category"] == "tokio_worker"}
    blocking_ids = {thread["thread_id"] for thread in
                    configuration["runtime"]["thread_observations"]
                    if thread["thread_category"] == "blocking_pool"}
    for case in actual:
        case_id = case["id"]
        require(case_id in expected and case_id not in seen,
                f"{mode}: duplicate or unknown case {case_id}")
        seen.add(case_id)
        require(case["parameters"] == expected[case_id]["parameters"],
                f"{mode}: case parameters drifted: {case_id}")
        require(case["raw_log"]["path"] in raw_paths,
                f"{mode}: case log is absent from raw log manifest: {case_id}")
        require(case["raw_log"] == configuration["process_log"],
                f"{mode}: case is not bound to complete child transcript: {case_id}")
        execution = case["worker_execution"]
        require(execution["whole_operation_spawned"] is True
                and execution["source_sha256"] == manifest["worker_runner"]["sha256"],
                f"{mode}: whole-operation worker boundary is unverified: {case_id}")
        repeats = expected[case_id]["parameters"].get("repeats", 2)
        expected_attempts = {(key, index) for key in expected[case_id]["sample_keys"]
                             for index in range(repeats)}
        seen_attempts = set()
        for attempt in execution["attempts"]:
            key = (attempt["sample_key"], attempt["repeat_index"])
            require(key in expected_attempts and key not in seen_attempts,
                    f"{mode}: duplicate or unknown worker attempt: {case_id}/{key}")
            seen_attempts.add(key)
            phase_threads = attempt["phase_threads"]
            require(set(phase_threads) == {"preparation", "operation", "conversion", "teardown"}
                    and all(isinstance(ids, list) and ids and set(ids) <= worker_ids
                            for ids in phase_threads.values()),
                    f"{mode}: operation phase escaped measured workers: {case_id}/{key}")
            require(set(attempt["blocking_thread_ids"]) <= blocking_ids
                    and (bool(attempt["blocking_thread_ids"]) ==
                         (expected[case_id]["family"] == "blocking_decode")),
                    f"{mode}: blocking-pool execution is unverified: {case_id}/{key}")
            event = transcript.get((case_id, key[0], key[1]))
            require(event is not None and event["worker_attempt"] == attempt,
                    f"{mode}: worker attempt differs from raw process transcript: {case_id}/{key}")
        require(seen_attempts == expected_attempts,
                f"{mode}: missing worker attempts: {case_id}")
        observations = case["observations"]
        require(isinstance(observations, list) and len(observations) >= 2,
                f"{mode}: case lacks repeated observations: {case_id}")
        by_sample = {}
        for observation in observations:
            require(set(observation) == set(OBSERVATION_FIELDS),
                    f"{mode}: incomplete observation: {case_id}")
            require(observation["case_id"] == case_id,
                    f"{mode}: observation case mismatch: {case_id}")
            sample_key = observation["sample_key"]
            require(isinstance(sample_key, str) and sample_key,
                    f"{mode}: missing sample key: {case_id}")
            by_sample.setdefault(sample_key, []).append(observation)
            require(observation["outcome"] in {
                "ok", "deterministic_error", "nondeterministic_error", "trap",
                "invocation_limit", "stack_overflow", "out_of_fuel",
            }, f"{mode}: unknown outcome: {case_id}/{sample_key}")
            expected_outcome = expected[case_id]["expected_outcomes"].get(sample_key)
            require(observation["outcome"] == expected_outcome,
                    f"{mode}: wrong expected outcome: {case_id}/{sample_key}")
            require(observation["error_class"] in {None, "deterministic", "nondeterministic"},
                    f"{mode}: invalid error class: {case_id}/{sample_key}")
            require(observation["error_class"] ==
                    (None if expected_outcome == "ok" else "deterministic"),
                    f"{mode}: wrong error classification: {case_id}/{sample_key}")
            require(observation["trap"] is None or isinstance(observation["trap"], str),
                    f"{mode}: invalid trap: {case_id}/{sample_key}")
            require((observation["trap"] is not None) ==
                    (expected_outcome in {"trap", "stack_overflow", "out_of_fuel"}),
                    f"{mode}: trap evidence differs from expected outcome: {case_id}/{sample_key}")
            require(observation["value"] is None or isinstance(observation["value"], str),
                    f"{mode}: invalid value: {case_id}/{sample_key}")
            require(set(observation["fuel"]) == {"user", "system", "deposit"} and
                    all(type(value) is int and value >= 0 for value in
                        observation["fuel"].values()),
                    f"{mode}: invalid fuel: {case_id}/{sample_key}")
            receipts = observation["receipts"]
            require(isinstance(receipts, list),
                    f"{mode}: invalid receipts: {case_id}/{sample_key}")
            for receipt in receipts:
                require(set(receipt) == {"contract_id", "status", "gas", "value"} and
                        type(receipt["contract_id"]) is int and receipt["contract_id"] >= 0 and
                        isinstance(receipt["status"], str) and
                        type(receipt["gas"]) is int and receipt["gas"] >= 0 and
                        (receipt["value"] is None or isinstance(receipt["value"], str)),
                        f"{mode}: invalid receipt: {case_id}/{sample_key}")
            state = observation["state"]
            require(set(state) == {"before_sha256", "after_sha256", "marker", "balances_sha256"}
                    and all(re.fullmatch(r"[0-9a-f]{64}", state[key]) for key in
                            ("before_sha256", "after_sha256", "balances_sha256")) and
                    (state["marker"] is None or isinstance(state["marker"], str)),
                    f"{mode}: invalid state evidence: {case_id}/{sample_key}")
            require(type(observation["rollback"]) is bool and
                    all(type(observation[key]) is bool for key in
                        ("fresh_store", "suspended", "reused")),
                    f"{mode}: invalid lifecycle flags: {case_id}/{sample_key}")
            for field in ("live_stores", "reservations"):
                counts = observation[field]
                require(set(counts) == {"before", "during", "after"} and
                        all(type(value) is int and value >= 0 for value in counts.values()),
                        f"{mode}: invalid {field}: {case_id}/{sample_key}")
            cleanup = observation["resource_cleanup"]
            require(set(cleanup) == {
                "table_before", "table_after", "savepoint_restored", "stack_empty",
                "invocation_table_released",
            } and type(cleanup["table_before"]) is int and
                    type(cleanup["table_after"]) is int and
                    cleanup["table_before"] >= 0 and cleanup["table_after"] >= 0 and
                    type(cleanup["savepoint_restored"]) is bool and
                    type(cleanup["stack_empty"]) is bool and
                    (cleanup["invocation_table_released"] is None or
                     type(cleanup["invocation_table_released"]) is bool),
                    f"{mode}: invalid cleanup: {case_id}/{sample_key}")
            if expected[case_id]["family"] not in {"cold_compile", "blocking_decode"}:
                require(observation["fresh_store"] is True,
                        f"{mode}: case did not use a fresh invocation Store: {case_id}")
            require(observation["live_stores"]["after"] == 0
                    and observation["reservations"]["after"] == 0,
                    f"{mode}: retained Store or reservation: {case_id}")
            require(observation["resource_cleanup"]["stack_empty"] is True
                    and observation["resource_cleanup"]["savepoint_restored"] is True,
                    f"{mode}: incomplete cleanup: {case_id}")
            if expected_outcome != "ok":
                require(observation["rollback"] is True
                        and observation["state"]["before_sha256"] ==
                        observation["state"]["after_sha256"],
                        f"{mode}: failed case did not roll back application state: {case_id}")
            if expected[case_id]["family"] == "pulley_boundary":
                require(type(observation["observed_depth"]) is int
                        and observation["observed_depth"] > 0,
                        f"{mode}: missing Pulley boundary depth: {case_id}")
            elif case_id == "deepest_frame_host_call":
                require(type(observation["observed_depth"]) is int
                        and observation["observed_depth"] > 0,
                        f"{mode}: missing host-call leaf depth")
            else:
                require(observation["observed_depth"] is None,
                        f"{mode}: unexpected depth measurement: {case_id}")
            if expected[case_id]["family"] == "distinct_contract_chain":
                requested = expected[case_id]["parameters"]["simultaneous_stores"]
                peak = min(requested, 64)
                require(observation["live_stores"]["during"] == peak
                        and observation["reservations"]["during"] == peak,
                        f"{mode}: chain did not reach the required Store count: {case_id}")
            if case_id == "pending_host_io":
                require(observation["suspended"] is True
                        and observation["reused"] is (sample_key == "resumed"),
                        f"{mode}: pending I/O suspension or reuse was not observed")
            if case_id == "explicit_resource_drop":
                require(observation["resource_cleanup"]["table_after"] ==
                        observation["resource_cleanup"]["table_before"]
                        and observation["reused"] is (sample_key == "success_after_trap"),
                        f"{mode}: resource table or post-trap reuse is wrong")
        require(set(by_sample) == set(expected[case_id]["sample_keys"]),
                f"{mode}: missing or extra sample keys: {case_id}")
        for sample_key, group in by_sample.items():
            require(len(group) == repeats and all(item == group[0] for item in group),
                    f"{mode}: unstable or missing repeats: {case_id}/{sample_key}")
            for index, observation in enumerate(group):
                event = transcript.get((case_id, sample_key, index))
                require(event is not None and event["observation"] == observation,
                        f"{mode}: observation differs from raw process transcript: "
                        f"{case_id}/{sample_key}/{index}")
        file_evidence(directory, case["raw_log"])
        signatures[case_id] = {key: group[0] for key, group in sorted(by_sample.items())}
    require(seen == set(expected), f"{mode}: missing mandatory cases")
    require(len(transcript) == sum(len(item["sample_keys"]) *
                                   item["parameters"].get("repeats", 2)
                                   for item in expected.values()),
            f"{mode}: raw process transcript is incomplete or contains extra attempts")
    for case_id, item in expected.items():
        if item["family"] != "pulley_boundary":
            continue
        depths = signatures[case_id]
        require(depths["first_failure"]["observed_depth"] ==
                depths["last_success"]["observed_depth"] + 1,
                f"{mode}: nonadjacent Pulley boundary: {case_id}")
    parent = expected["deepest_frame_host_call"]["parameters"]["depth_from_case"]
    require(signatures["deepest_frame_host_call"]["target"]["observed_depth"] ==
            signatures[parent]["last_success"]["observed_depth"],
            f"{mode}: host operation did not run at the deepest successful Pulley frame")
    return signatures


def check_memory_profiles(profiles, manifest, plan, directory):
    expected = {profile["id"]: profile for profile in manifest["memory_profiles"]}
    require(isinstance(profiles, list) and len(profiles) == len(expected),
            "production memory profiles are incomplete")
    seen = set()
    for profile in profiles:
        profile_id = profile["id"]
        require(profile_id in expected and profile_id not in seen,
                f"duplicate or unknown memory profile: {profile_id}")
        seen.add(profile_id)
        reference = expected[profile_id]
        planned = plan["memory_profiles"][profile_id]
        require(profile["workload_plan_sha256"] == manifest["workload_plan"]["sha256"],
                f"{profile_id}: memory allowance/occupancy plan is not frozen")
        for field in ("guest_memory_occupancy_bytes", "cache_state",
                      "per_root_allowance_bytes", "per_node_allowance_bytes",
                      "shared_overhead_allowance_bytes",
                      "mapped_reservation_allowance_bytes",
                      "reference_cpus", "reference_memory_bytes"):
            require(profile[field] == planned[field],
                    f"{profile_id}: {field} differs from frozen workload plan")
        require(profile["production_capacity_only"] is True
                and profile["uninstrumented"] is True,
                f"{profile_id}: memory run used reduced/instrumented capacity")
        for key in ("view_roots", "reactor_roots"):
            require(profile[key] == reference[key], f"{profile_id}: root overlap changed")
        if "reference_cpus" in reference:
            require(profile["reference_cpus"] == reference["reference_cpus"]
                    and profile["reference_memory_bytes"] == reference["reference_memory_bytes"]
                    and profile["actual_cpus"] == reference["reference_cpus"]
                    and profile["actual_memory_bytes"] == reference["reference_memory_bytes"],
                    f"{profile_id}: reference profile changed")
        if profile_id == "suspended_64":
            require(profile["peak"]["live_stores"] == 64
                    and profile["peak"]["reservations"] == 64,
                    "64-Store suspended profile did not observe 64 live owners")
        for phase in ("baseline", "peak"):
            for field in ("mapped_reservation", "resident", "committed_or_private",
                          "node_accounted"):
                metric = profile[phase][field]
                require(type(metric["value_bytes"]) is int and metric["value_bytes"] >= 0,
                        f"{profile_id}: invalid {field} bytes")
                require(metric["platform_field"] and metric["definition"],
                        f"{profile_id}: missing {field} OS definition")
        peak = profile["peak"]
        baseline = profile["baseline"]
        require(peak["active_view_roots"] == reference["view_roots"]
                and peak["active_reactor_roots"] == reference["reactor_roots"]
                and peak["live_stores"] == peak["reservations"]
                and peak["fibers"] >= peak["live_stores"],
                f"{profile_id}: root/Store/fiber occupancy differs from frozen scenario")
        roots = peak["active_view_roots"] + peak["active_reactor_roots"]
        private_growth = max(0, peak["committed_or_private"]["value_bytes"] -
                             baseline["committed_or_private"]["value_bytes"])
        require(private_growth <= roots * profile["per_root_allowance_bytes"] +
                profile["shared_overhead_allowance_bytes"],
                f"{profile_id}: private/committed growth exceeds frozen allowance")
        require(peak["mapped_reservation"]["value_bytes"] <=
                profile["mapped_reservation_allowance_bytes"]
                and peak["node_accounted"]["value_bytes"] <=
                profile["per_node_allowance_bytes"],
                f"{profile_id}: mapped or node-accounted memory exceeds frozen allowance")
        file_evidence(directory, profile["raw_os_log"])


def validate(report, directory):
    manifest = build_manifest()
    require(MANIFEST.is_file() and load_json_strict(MANIFEST) == manifest,
            "resource manifest changed or source hashes drifted")
    require(all(item["paired_worker_status"] == "ready" for item in manifest["cases"]),
            "manifest still contains mandatory cases without paired worker bindings")
    schema = load_json_strict(SCHEMA)
    Draft202012Validator.check_schema(schema)
    errors = Draft202012Validator(schema).iter_errors(report)
    first_error = next(errors, None)
    require(first_error is None,
            f"resource evidence violates schema at {list(first_error.path) if first_error else []}: "
            f"{first_error.message if first_error else ''}")
    required = {
        "schema_version", "manifest_sha256", "cell", "source_sha", "lockfile_sha256",
        "binary_sha256", "compiler", "build_closure", "target", "host",
        "configurations", "memory_profiles",
    }
    require(set(report) == required, "evidence header is incomplete or has unknown fields")
    require(report["schema_version"] == 1, "unknown evidence schema")
    require(report["manifest_sha256"] == sha256(MANIFEST), "wrong manifest hash")
    require(report["cell"] in CELLS, "unknown target/profile cell")
    require(re.fullmatch(r"[0-9a-f]{40}", report["source_sha"]) is not None,
            "invalid source commit")
    for field in ("lockfile_sha256", "binary_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", report[field]) is not None,
                f"invalid {field}")
    require(report["compiler"]["rustc_verbose"]
            and report["compiler"]["stack_probing_configuration"],
            "compiler or stack probing identity is missing")
    closure = report["build_closure"]
    require(set(closure) == {"profile", "target_triple", "cargo_features", "rustflags",
                             "wasmtime_features", "wasmtime_feature_logs",
                             "cargo_metadata_sha256", "compile_env_sha256",
                             "build_log_sha256", "build_log", "cargo_metadata_log",
                             "compile_env_log"}
            and closure["profile"] == report["cell"].split("/")[1]
            and closure["target_triple"] == report["target"]
            and isinstance(closure["cargo_features"], list)
            and closure["cargo_features"] == sorted(set(closure["cargo_features"]))
            and all(isinstance(flag, str) for flag in closure["rustflags"])
            and all(re.fullmatch(r"[0-9a-f]{64}", closure[field]) for field in
                    ("cargo_metadata_sha256", "build_log_sha256", "compile_env_sha256")),
            "build feature/flag closure is incomplete")
    file_evidence(directory, closure["build_log"])
    require(closure["build_log"]["sha256"] == closure["build_log_sha256"],
            "build log identity differs from build closure")
    for name in ("cargo_metadata", "compile_env"):
        file_evidence(directory, closure[f"{name}_log"])
        require(closure[f"{name}_log"]["sha256"] == closure[f"{name}_sha256"],
                f"{name} identity differs from build closure")
    require(closure["wasmtime_features"] == manifest["wasmtime_features"],
            "resolved Wasmtime feature closure differs from production qualification")
    for graph, feature_log in closure["wasmtime_feature_logs"].items():
        file_evidence(directory, feature_log)
        require((directory / feature_log["path"]).read_text() ==
                ",".join(manifest["wasmtime_features"][graph]) + "\n",
                f"{graph}: resolved Wasmtime feature log differs from reported closure")
    identity = {
        "Linux-X64": ("linux", "x86_64", "x86_64-unknown-linux-gnu"),
        "Linux-ARM64": ("linux", "aarch64", "aarch64-unknown-linux-gnu"),
        "macOS-ARM64": ("macos", "aarch64", "aarch64-apple-darwin"),
    }
    os_name, architecture, target_triple = identity[report["cell"].split("/")[0]]
    require((report["host"]["os"], report["host"]["architecture"], report["target"]) ==
            (os_name, architecture, target_triple),
            "cell label differs from actual host/target identity")
    require(manifest["workload_plan"]["status"] == "ready"
            and manifest["worker_runner"]["status"] == "ready",
            "frozen workload plan or worker runner is missing")
    plan_path = ROOT / manifest["workload_plan"]["path"]
    runner_path = ROOT / manifest["worker_runner"]["path"]
    require(plan_path.is_file() and sha256(plan_path) == manifest["workload_plan"]["sha256"]
            and runner_path.is_file()
            and sha256(runner_path) == manifest["worker_runner"]["sha256"],
            "frozen workload plan or worker runner source changed")
    plan = load_json_strict(plan_path)
    require(set(plan["memory_profiles"]) == {
        profile["id"] for profile in manifest["memory_profiles"]
    }, "frozen workload plan omits a memory profile")
    require(report["host"]["cpu_count"] > 0 and report["host"]["memory_bytes"] > 0
            and report["host"]["storage"] and report["host"]["resource_enforcement"],
            "actual host identity is incomplete")
    runs = report["configurations"]
    require(set(runs) == {"production", "reduced"}, "missing paired configuration")
    signatures = {}
    workers = {}
    processes = {}
    for mode in ("production", "reduced"):
        configuration = runs[mode]
        process = configuration["process"]
        require(set(process) == {"pid", "command", "started_unix_ns", "ended_unix_ns",
                                 "exit_code", "signal", "timed_out", "complete",
                                 "test_harness_passed"} and
                type(process["pid"]) is int and process["pid"] > 0 and
                isinstance(process["command"], list) and process["command"] and
                all(isinstance(arg, str) for arg in process["command"]) and
                type(process["started_unix_ns"]) is int and
                type(process["ended_unix_ns"]) is int and
                0 < process["started_unix_ns"] < process["ended_unix_ns"] and
                process["exit_code"] == 0 and process["signal"] is None and
                process["timed_out"] is False and process["complete"] is True and
                process["test_harness_passed"] is True,
                f"{mode}: process failed or transcript incomplete")
        processes[mode] = process
        engine_capacity(configuration["engine"], manifest, mode)
        require(configuration["runtime"]["worker_count"] == manifest["runtime"]["worker_count"],
                f"{mode}: worker count differs from frozen runtime settings")
        workers[mode] = thread_capacities(configuration["runtime"], mode)["tokio_worker"]
        for log in configuration["raw_logs"]:
            file_evidence(directory, log)
        require(configuration["process_log"] in configuration["raw_logs"],
                f"{mode}: process transcript is not in raw log manifest")
        transcript = read_process_events(directory / configuration["process_log"]["path"],
                                         process, len(manifest["cases"]))
        require(configuration["source_artifact_sha256"] == {
            name: identity["sha256"] for name, identity in manifest["artifacts"].items()
        }, f"{mode}: fixture source hash mismatch")
        signatures[mode] = check_cases(configuration, manifest, mode, directory, transcript)
    production_min = min(item["usable_bytes"] for item in workers["production"])
    reduced_max = max(item["usable_bytes"] for item in workers["reduced"])
    require(production_min >= 2 * reduced_max,
            "actual worker usable-capacity ratio is below two")
    require((processes["production"]["pid"], processes["production"]["started_unix_ns"])
            != (processes["reduced"]["pid"], processes["reduced"]["started_unix_ns"]),
            "paired configurations ran in one child process")
    require(signatures["production"] == signatures["reduced"],
            "paired execution observations differ")
    check_memory_profiles(report["memory_profiles"], manifest, plan, directory)
    return signatures["production"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    validate(load_json_strict(args.report), args.report.parent)
    print(f"resource cell validated; six-cell aggregation still required: {args.report}")


if __name__ == "__main__":
    main()
