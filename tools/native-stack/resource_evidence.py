#!/usr/bin/env python3
"""Fail closed on incomplete S2 paired resource evidence."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from resource_manifest import CELLS, MANIFEST, OBSERVATION_FIELDS, THREAD_CATEGORIES, build_manifest


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
        category = thread["thread_category"]
        require(category in by_category, f"{mode}: unknown thread category")
        require(type(thread["mapped_bytes"]) is int and thread["mapped_bytes"] > 0,
                f"{mode}: invalid mapped stack")
        require(type(thread["guard_bytes"]) is int and thread["guard_bytes"] >= 0,
                f"{mode}: invalid guard")
        require(type(thread["usable_bytes"]) is int and
                0 < thread["usable_bytes"] <= thread["mapped_bytes"],
                f"{mode}: usable stack capacity is unverified")
        require(isinstance(thread["measurement_api"], str) and thread["measurement_api"],
                f"{mode}: missing stack measurement API")
        require(isinstance(thread["guard_treatment"], str) and
                thread["guard_treatment"] not in {"", "unknown"},
                f"{mode}: unresolved thread guard treatment")
        by_category[category].append(thread)
    require(len({item["thread_id"] for item in by_category["tokio_worker"]})
            >= runtime["worker_count"], f"{mode}: not all workers measured")
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


def check_cases(configuration, manifest, mode, directory):
    expected = {item["id"]: item for item in manifest["cases"]}
    actual = configuration["cases"]
    require(isinstance(actual, list) and len(actual) == len(expected),
            f"{mode}: incomplete case set")
    seen = set()
    signatures = {}
    raw_paths = {entry["path"] for entry in configuration["raw_logs"]}
    for case in actual:
        case_id = case["id"]
        require(case_id in expected and case_id not in seen,
                f"{mode}: duplicate or unknown case {case_id}")
        seen.add(case_id)
        require(case["parameters"] == expected[case_id]["parameters"],
                f"{mode}: case parameters drifted: {case_id}")
        require(case["raw_log"]["path"] in raw_paths,
                f"{mode}: case log is absent from raw log manifest: {case_id}")
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
            require(observation["error_class"] in {None, "deterministic", "nondeterministic"},
                    f"{mode}: invalid error class: {case_id}/{sample_key}")
            require(observation["trap"] is None or isinstance(observation["trap"], str),
                    f"{mode}: invalid trap: {case_id}/{sample_key}")
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
            require(observation["fresh_store"] is True,
                    f"{mode}: case did not use a fresh invocation Store: {case_id}")
            require(observation["live_stores"]["after"] == 0
                    and observation["reservations"]["after"] == 0,
                    f"{mode}: retained Store or reservation: {case_id}")
            require(observation["resource_cleanup"]["stack_empty"] is True
                    and observation["resource_cleanup"]["savepoint_restored"] is True,
                    f"{mode}: incomplete cleanup: {case_id}")
        require(set(by_sample) == set(expected[case_id]["sample_keys"]),
                f"{mode}: missing or extra sample keys: {case_id}")
        repeats = expected[case_id]["parameters"].get("repeats", 2)
        for sample_key, group in by_sample.items():
            require(len(group) == repeats and all(item == group[0] for item in group),
                    f"{mode}: unstable or missing repeats: {case_id}/{sample_key}")
        file_evidence(directory, case["raw_log"])
        signatures[case_id] = {key: group[0] for key, group in sorted(by_sample.items())}
    require(seen == set(expected), f"{mode}: missing mandatory cases")
    return signatures


def check_memory_profiles(profiles, manifest, directory):
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
        require(profile["production_capacity_only"] is True
                and profile["uninstrumented"] is True,
                f"{profile_id}: memory run used reduced/instrumented capacity")
        for key in ("view_roots", "reactor_roots"):
            require(profile[key] == reference[key], f"{profile_id}: root overlap changed")
        if "reference_cpus" in reference:
            require(profile["reference_cpus"] == reference["reference_cpus"]
                    and profile["reference_memory_bytes"] == reference["reference_memory_bytes"],
                    f"{profile_id}: reference profile changed")
        if profile_id == "suspended_64":
            require(profile["peak"]["live_stores"] == 64
                    and profile["peak"]["reservations"] == 64,
                    "64-Store suspended profile did not observe 64 live owners")
        for phase in ("baseline", "peak"):
            for field in ("mapped_reservation", "resident", "committed_or_private"):
                metric = profile[phase][field]
                require(type(metric["value_bytes"]) is int and metric["value_bytes"] >= 0,
                        f"{profile_id}: invalid {field} bytes")
                require(metric["platform_field"] and metric["definition"],
                        f"{profile_id}: missing {field} OS definition")
        file_evidence(directory, profile["raw_os_log"])


def validate(report, directory):
    manifest = build_manifest()
    require(MANIFEST.is_file() and json.loads(MANIFEST.read_text()) == manifest,
            "resource manifest changed or source hashes drifted")
    require(all(item["paired_worker_status"] == "ready" for item in manifest["cases"]),
            "manifest still contains mandatory cases without paired worker bindings")
    required = {
        "schema_version", "manifest_sha256", "cell", "source_sha", "lockfile_sha256",
        "binary_sha256", "compiler", "target", "host", "configurations", "memory_profiles",
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
        workers[mode] = thread_capacities(configuration["runtime"], mode)["tokio_worker"]
        for log in configuration["raw_logs"]:
            file_evidence(directory, log)
        require(configuration["source_artifact_sha256"] == {
            name: identity["sha256"] for name, identity in manifest["artifacts"].items()
        }, f"{mode}: fixture source hash mismatch")
        signatures[mode] = check_cases(configuration, manifest, mode, directory)
    production_min = min(item["usable_bytes"] for item in workers["production"])
    reduced_max = max(item["usable_bytes"] for item in workers["reduced"])
    require(production_min >= 2 * reduced_max,
            "actual worker usable-capacity ratio is below two")
    require(processes["production"]["pid"] != processes["reduced"]["pid"],
            "paired configurations ran in one child process")
    require(signatures["production"] == signatures["reduced"],
            "paired execution observations differ")
    check_memory_profiles(report["memory_profiles"], manifest, directory)
    return signatures["production"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    validate(json.loads(args.report.read_text()), args.report.parent)
    print(f"resource cell validated; six-cell aggregation still required: {args.report}")


if __name__ == "__main__":
    main()
