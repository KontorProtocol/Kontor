import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import resource_evidence
import resource_manifest


ZERO = "0" * 64
ONE = "1" * 64
GIB = 1024**3


def raw_log(directory, name, text):
    path = directory / name
    path.write_text(text)
    return {"path": name, "sha256": resource_evidence.sha256(path)}


def thread(category, name, size, requested, pid):
    index = {"worker-1": 1, "worker-2": 2, "blocking": 3, "caller": 4}[name]
    base = index * 4_194_304
    return {
        "thread_category": category, "thread_id": name, "requested_bytes": requested,
        "process_id": pid, "os_thread_id": pid * 10 + index,
        "identity_api": "linux_gettid", "page_size_bytes": 4096,
        "mapped_bytes": size, "guard_bytes": 4096, "usable_bytes": size - 4096,
        "guard_start": base, "guard_end": base + 4096,
        "guard_verification": "linux_maps_prot_none",
        "mapped_start": base, "mapped_end": base + size,
        "usable_start": base + 4096, "usable_end": base + size,
        "measurement_api": "synthetic pthread observation",
        "guard_treatment": "guard excluded from usable interval",
        "guard_verified": True,
    }


def observation(definition, sample):
    outcome = definition["expected_outcomes"][sample]
    case_id = definition["id"]
    during = min(definition["parameters"].get("simultaneous_stores", 1), 64)
    if definition["family"] == "pulley_boundary":
        depth = 10 if sample == "last_success" else 11
    elif case_id == "deepest_frame_host_call":
        depth = 10
    else:
        depth = None
    return {
        "case_id": case_id, "sample_key": sample, "outcome": outcome,
        "error_class": None if outcome == "ok" else "deterministic",
        "trap": definition["expected_traps"][sample], "value": None,
        "fuel": {"user": 0, "system": 0, "deposit": 0}, "receipts": [],
        "state": {"before_sha256": ZERO, "after_sha256": ZERO,
                  "marker": None, "balances_sha256": ZERO},
        "rollback": outcome != "ok",
        "live_stores": {"before": 0, "during": during, "after": 0},
        "reservations": {"before": 0, "during": during, "after": 0},
        "resource_cleanup": {"table_before": 0, "table_after": 0,
                             "savepoint_restored": True, "stack_empty": True,
                             "invocation_table_released": True},
        "fresh_store": definition["family"] not in {"cold_compile", "blocking_decode"},
        "suspended": case_id == "pending_host_io",
        "reused": (case_id == "pending_host_io" and sample == "resumed") or
                  (case_id == "explicit_resource_drop" and sample == "success_after_trap"),
        "observed_depth": depth,
    }


def configuration(directory, manifest, mode, pid):
    size = 2_097_152 if mode == "production" else 1_048_576
    requested = size
    runtime = {
        "flavor": "multi_thread", "worker_count": 2,
        "worker_requested_bytes": requested,
        "thread_observations": [
            thread("tokio_worker", "worker-1", size, requested, pid),
            thread("tokio_worker", "worker-2", size, requested, pid),
            thread("blocking_pool", "blocking", 2_097_152, None, pid),
            thread("block_on_caller", "caller", 2_097_152, None, pid),
        ],
        "blocking_pool_observed": True, "block_on_caller_observed": True,
    }
    process = {"pid": pid, "command": ["indexer-test", mode],
               "started_unix_ns": pid * 1000, "ended_unix_ns": pid * 1000 + 1,
               "exit_code": 0, "signal": None, "timed_out": False,
               "complete": True, "test_harness_passed": True}
    cases = []
    events = []
    for definition in manifest["cases"]:
        case_id = definition["id"]
        observations = []
        attempts = []
        for sample in definition["sample_keys"]:
            for index in range(definition["parameters"].get("repeats", 2)):
                observed = observation(definition, sample)
                attempt = {
                    "sample_key": sample, "repeat_index": index,
                    "phase_threads": {phase: ["worker-1"] for phase in
                                      ("preparation", "operation", "conversion", "teardown")},
                    "blocking_thread_ids": ["blocking"] if
                        definition["family"] == "blocking_decode" else [],
                    "cache_state": "cold" if definition["family"] == "cold_compile"
                        else "warm",
                }
                observations.append(observed)
                attempts.append(attempt)
                events.append({"kind": "attempt", "case_id": case_id,
                               "sample_key": sample, "repeat_index": index,
                               "observation": observed, "worker_attempt": attempt})
        cases.append({"id": case_id, "parameters": definition["parameters"],
                      "observations": observations,
                      "worker_execution": {"whole_operation_spawned": True,
                                           "source_sha256": manifest["worker_runner"]["sha256"],
                                           "attempts": attempts}})
    events.append({"kind": "terminal", "pid": pid, "case_count": len(cases),
                   "attempt_count": len(events), "complete": True,
                   "test_harness_passed": True})
    transcript = raw_log(directory, f"{mode}.jsonl",
                         "".join(json.dumps(event) + "\n" for event in events))
    for case in cases:
        case["raw_log"] = transcript
    return {
        "process": process, "process_log": transcript,
        "engine": {"wasmtime_revision": manifest["wasmtime_revision"],
                   "target": "pulley64-unknown-unknown-elf",
                   "pulley_stack_bytes": 524288, "fiber_requested_bytes": size,
                   "fiber_effective_writable_bytes": size,
                   "page_size_bytes": 4096, "guard_bytes": 4096,
                   "allocator": "on_demand_unix", "sanitizer_mode": "none"},
        "runtime": runtime, "cases": cases, "raw_logs": [transcript],
        "source_artifact_sha256": {name: item["sha256"] for name, item in
                                   manifest["artifacts"].items()},
    }


def metric(value, field):
    return {"value_bytes": value, "platform_field": field,
            "definition": "synthetic control value, not an OS measurement"}


def memory_profile(directory, definition, plan_hash):
    profile_id = definition["id"]
    reference_cpus = definition.get("reference_cpus")
    reference_memory = definition.get("reference_memory_bytes")
    stores = 64 if profile_id == "suspended_64" else 9
    def snapshot(peak):
        return {
            "active_view_roots": definition["view_roots"] if peak else 0,
            "active_reactor_roots": definition["reactor_roots"] if peak else 0,
            "live_stores": stores if peak else 0,
            "reservations": stores if peak else 0, "fibers": stores if peak else 0,
            "mapped_reservation": metric(128 * 1024**2 if peak else 0, "maps"),
            "resident": metric(128 * 1024**2 if peak else 0, "rss"),
            "committed_or_private": metric(64 * 1024**2 if peak else 0, "private"),
            "node_accounted": metric(128 * 1024**2 if peak else 0, "node"),
        }
    return {
        "id": profile_id, "production_capacity_only": True, "uninstrumented": True,
        "reference_cpus": reference_cpus, "reference_memory_bytes": reference_memory,
        "actual_cpus": 16, "actual_memory_bytes": 32 * GIB,
        "enforced_cpus": reference_cpus, "enforced_memory_bytes": reference_memory,
        "cpu_enforcement_field": "cpu.max", "memory_enforcement_field": "memory.max",
        "guest_memory_occupancy_bytes": 0, "cache_state": "cold",
        "per_root_allowance_bytes": GIB, "shared_overhead_allowance_bytes": GIB,
        "mapped_reservation_allowance_bytes": GIB,
        "per_node_allowance_bytes": 9 * GIB,
        "workload_plan_sha256": plan_hash,
        "view_roots": definition["view_roots"],
        "reactor_roots": definition["reactor_roots"],
        "baseline": snapshot(False), "peak": snapshot(True),
        "raw_os_log": raw_log(directory, f"{profile_id}.txt", "synthetic memory control\n"),
    }


def synthetic_report(directory):
    manifest = copy.deepcopy(resource_manifest.build_manifest())
    for case in manifest["cases"]:
        case["paired_worker_status"] = "ready"
        if case["family"] == "native_core":
            case["parameters"]["exact_budget_status"] = "frozen"
        if case["family"] == "cold_compile":
            case["parameters"]["fixture_admission_status"] = "verified"
            for key in ("fixture_function_size_bytes", "fixture_control_depth",
                        "fixture_br_table_entries"):
                if key in case["parameters"]:
                    case["parameters"][key] = 1000
    manifest["publication_constraints"]["near_boundary_accepted_fixture"] = "verified"
    manifest["publication_constraints"]["serialized_transaction_and_wit_admission"] = "verified"
    runner = directory / "runner.rs"
    runner.write_text("synthetic source, not a qualification runner\n")
    manifest["worker_runner"] = {"status": "ready", "path": runner.name,
                                 "sha256": resource_evidence.sha256(runner)}
    plan = {"memory_profiles": {definition["id"]: {
        "reference_cpus": definition.get("reference_cpus"),
        "reference_memory_bytes": definition.get("reference_memory_bytes"),
        "guest_memory_occupancy_bytes": 0, "cache_state": "cold",
        "per_root_allowance_bytes": GIB, "shared_overhead_allowance_bytes": GIB,
        "mapped_reservation_allowance_bytes": GIB,
        "per_node_allowance_bytes": 9 * GIB,
    } for definition in manifest["memory_profiles"]}}
    plan_path = directory / "plan.json"
    plan_path.write_text(json.dumps(plan))
    manifest["workload_plan"] = {"status": "ready", "path": plan_path.name,
                                 "sha256": resource_evidence.sha256(plan_path)}
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    policy = manifest["build_policy"]
    compile_env = raw_log(directory, "compile-env.json", json.dumps(policy["compile_env"]))
    metadata = raw_log(directory, "cargo-metadata.json", "{}")
    build_log = raw_log(directory, "cargo.jsonl", "synthetic build control\n")
    feature_logs = {graph: raw_log(directory, f"{graph}-features.txt",
                                   ",".join(features) + "\n") for graph, features in
                    manifest["wasmtime_features"].items()}
    report = {
        "schema_version": 1, "manifest_sha256": resource_evidence.sha256(manifest_path),
        "cell": "Linux-X64/dev", "source_sha": "1" * 40,
        "lockfile_sha256": ONE, "binary_sha256": ONE,
        "compiler": {"rustc_verbose": "rustc 1.99.1 (synthetic)\nhost: x86_64-unknown-linux-gnu",
                     "stack_probing_configuration": policy["stack_probing_configuration"]},
        "build_closure": {"profile": "dev", "target_triple": "x86_64-unknown-linux-gnu",
                          "cargo_features": [], "rustflags": [],
                          "wasmtime_features": manifest["wasmtime_features"],
                          "wasmtime_feature_logs": feature_logs,
                          "cargo_metadata_sha256": metadata["sha256"],
                          "compile_env_sha256": compile_env["sha256"],
                          "build_log_sha256": build_log["sha256"],
                          "build_log": build_log, "cargo_metadata_log": metadata,
                          "compile_env_log": compile_env},
        "target": "x86_64-unknown-linux-gnu",
        "host": {"os": "linux", "architecture": "x86_64", "cpu_count": 16,
                 "memory_bytes": 32 * GIB, "storage": "synthetic",
                 "resource_enforcement": "synthetic cgroup"},
        "configurations": {mode: configuration(directory, manifest, mode, pid)
                           for mode, pid in (("production", 101), ("reduced", 102))},
        "memory_profiles": [memory_profile(directory, definition,
                                           manifest["workload_plan"]["sha256"])
                            for definition in manifest["memory_profiles"]],
    }
    return manifest, manifest_path, report


class ResourceReportControls(unittest.TestCase):
    def test_complete_synthetic_report_and_downstream_mutations(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, manifest_path, report = synthetic_report(directory)
            with patch.object(resource_evidence, "ROOT", directory), patch.object(
                resource_evidence, "MANIFEST", manifest_path
            ), patch.object(resource_evidence, "build_manifest", return_value=manifest):
                signatures = resource_evidence.validate(report, directory)
                self.assertEqual(set(signatures), {case["id"] for case in manifest["cases"]})

                bad = copy.deepcopy(report)
                bad["build_closure"]["rustflags"] = ["-Ctarget-feature=+avx2"]
                with self.assertRaisesRegex(ValueError, "build feature/flag closure"):
                    resource_evidence.validate(bad, directory)

                bad = copy.deepcopy(report)
                bad["host"]["architecture"] = "aarch64"
                with self.assertRaisesRegex(ValueError, "cell label differs"):
                    resource_evidence.validate(bad, directory)

                bad = copy.deepcopy(report)
                bad["configurations"]["reduced"]["runtime"]["thread_observations"][0][
                    "guard_verified"] = False
                with self.assertRaisesRegex(ValueError, "violates schema"):
                    resource_evidence.validate(bad, directory)

                bad = copy.deepcopy(report)
                bad["configurations"]["reduced"]["runtime"]["thread_observations"][0][
                    "page_size_bytes"] = 16_384
                with self.assertRaisesRegex(ValueError, "thread identity or page size"):
                    resource_evidence.validate(bad, directory)

                bad = copy.deepcopy(report)
                bad["configurations"]["reduced"]["runtime"]["thread_observations"][0][
                    "process_id"] = 101
                with self.assertRaisesRegex(ValueError, "thread identity or page size"):
                    resource_evidence.validate(bad, directory)

                bad = copy.deepcopy(report)
                bad["configurations"]["reduced"]["runtime"]["thread_observations"][0][
                    "guard_end"] += 4096
                with self.assertRaisesRegex(ValueError, "thread guard interval"):
                    resource_evidence.validate(bad, directory)

                bad = copy.deepcopy(report)
                bad["memory_profiles"][1]["enforced_cpus"] = 1
                with self.assertRaisesRegex(ValueError, "reference resource enforcement"):
                    resource_evidence.validate(bad, directory)

                bad = copy.deepcopy(report)
                changed = next(case for case in bad["configurations"]["production"]["cases"]
                               if case["id"] == "large_frame_paid")
                for observed in changed["observations"]:
                    observed["value"] = "tampered"
                with self.assertRaisesRegex(ValueError, "differs from raw process transcript"):
                    resource_evidence.validate(bad, directory)

                bad = copy.deepcopy(report)
                production = bad["configurations"]["production"]
                path = directory / production["process_log"]["path"]
                lines = path.read_text().splitlines()
                duplicate = json.loads(lines[0])
                terminal = json.loads(lines[-1])
                terminal["attempt_count"] += 1
                lines.insert(-1, json.dumps(duplicate))
                lines[-1] = json.dumps(terminal)
                path.write_text("\n".join(lines) + "\n")
                digest = resource_evidence.sha256(path)
                production["process_log"]["sha256"] = digest
                production["raw_logs"][0]["sha256"] = digest
                for case in production["cases"]:
                    case["raw_log"]["sha256"] = digest
                with self.assertRaisesRegex(ValueError, "duplicate process transcript attempt"):
                    resource_evidence.validate(bad, directory)


if __name__ == "__main__":
    unittest.main()
