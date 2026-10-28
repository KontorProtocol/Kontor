import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import resource_evidence
import resource_manifest


ZERO = "0" * 64
GIB = 1024**3


def raw_log(directory, name, text):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
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
    state = {"before_sha256": ZERO, "after_sha256": ZERO,
             "marker": None, "balances_sha256": ZERO}
    if definition["family"] == "distinct_contract_chain":
        state["balance_transitions"] = {
            key: "0" for key in resource_evidence.BALANCE_TRANSITION_FIELDS}
    return {
        "case_id": case_id, "sample_key": sample, "outcome": outcome,
        "error_class": None if outcome == "ok" else "deterministic",
        "trap": definition["expected_traps"][sample], "value": None,
        "fuel": {"user": 0, "system": 0, "deposit": 0}, "receipts": [],
        "state": state,
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


def configuration(directory, manifest, mode, pid, binary_path, binary_sha256,
                  source_sha):
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
    process = {"pid": pid, "command": [binary_path, "--ignored", "--exact",
                                       manifest["worker_runner"]["test_name"], "--nocapture"],
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
                   "test_harness_passed": True,
                   "executable_path": binary_path,
                   "executable_sha256": binary_sha256,
                   "embedded_source_sha": source_sha})
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


def guard_control(directory, manifest, binary_path, binary_sha256, source_sha):
    parent_pid = 103
    lines = ["running 1 test"]
    for mode, pid, tid in (("reduced", 104, 204), ("production", 105, 205)):
        target = {
            "mode": mode, "process_id": pid, "os_thread_id": tid,
            "page_size_bytes": 4096, "guard_start": pid * 4_194_304,
            "guard_end": pid * 4_194_304 + 4096,
            "guard_verification": "guard protected below pthread stack range",
            "address": pid * 4_194_304 + 2048,
        }
        child = {
            "mode": mode, "signal": 6, "target": target,
            "child_binary": binary_path,
            "child_stdout": "running 1 test\nKONTOR_RESOURCE_GUARD_TARGET=" +
                            json.dumps(target) + "\n",
            "child_stderr": f"thread 'tokio-rt-worker' ({tid}) has overflowed its stack\n"
                            "fatal runtime error: stack overflow, aborting\n",
        }
        lines.append("KONTOR_RESOURCE_GUARD_CONTROL=" + json.dumps(child))
    lines.append("KONTOR_RESOURCE_GUARD_TERMINAL=" + json.dumps({
        "pid": parent_pid, "binary_path": binary_path,
        "binary_sha256": binary_sha256, "embedded_source_sha": source_sha,
        "modes": ["reduced", "production"], "complete": True,
    }))
    lines.append("test runtime::call::tests::native_stack_resource::linux_worker_guard_fault_control ... ok")
    lines.append("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 690 filtered out; finished in 0.14s")
    return {
        "process": {"pid": parent_pid,
                    "command": [binary_path, "--exact",
                                manifest["guard_control_runner"]["test_name"],
                                "--ignored", "--nocapture"],
                    "started_unix_ns": 103_000, "ended_unix_ns": 103_001,
                    "exit_code": 0, "signal": None, "timed_out": False,
                    "complete": True, "test_harness_passed": True},
        "raw_log": raw_log(directory, "guard-control.txt", "\n".join(lines) + "\n"),
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
    manifest["attestation_status"] = {name: "ready" for name in
                                      manifest["attestation_status"]}
    runner = directory / "runner.rs"
    runner.write_text("synthetic source, not a qualification runner\n")
    manifest["worker_runner"] = {"status": "ready", "path": runner.name,
                                 "test_name": manifest["worker_runner"]["test_name"],
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
    source_logs = {}
    for source_path in manifest["fiber_source_proof"]["source_files"]:
        entry = raw_log(directory, f"wasmtime-source/{source_path}",
                        f"synthetic pinned source: {source_path}\n")
        manifest["fiber_source_proof"]["source_files"][source_path] = entry["sha256"]
        source_logs[source_path] = entry
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    policy = manifest["build_policy"]
    compile_env = raw_log(directory, "compile-env.json", json.dumps(policy["compile_env"]))
    target = "x86_64-unknown-linux-gnu"
    workspace = directory / "core"
    target_dir = directory / "target"
    binary_path = str(target_dir / target / "debug/deps/indexer-synthetic")
    binary_artifact = raw_log(directory, "indexer-synthetic", "synthetic executable bytes\n")
    rustc_verbose = "rustc 1.99.1 (synthetic)\nhost: x86_64-unknown-linux-gnu\n"
    rustc_log = raw_log(directory, "rustc-vv.txt", rustc_verbose)
    source_sha = "1" * 40
    git_head_log = raw_log(directory, "git-head.txt", source_sha + "\n")
    git_status_log = raw_log(directory, "git-status.txt", "")
    indexer_id = f"path+file://{workspace}/indexer#0.2.0"
    source_prefix = ("git+https://github.com/wilfreddenton/wasmtime?rev="
                     f"{manifest['wasmtime_revision']}")
    wasmtime_id = f"{source_prefix}#51.0.0-kontor.2"
    fiber_id = f"{source_prefix}#wasmtime-internal-fiber@51.0.0-kontor.2"
    checkout = directory / "wasmtime-checkout"
    metadata_json = {
        "version": 1, "workspace_root": str(workspace),
        "target_directory": str(target_dir),
        "packages": [
            {"name": "indexer", "id": indexer_id,
             "manifest_path": str(workspace / "indexer/Cargo.toml"),
             "targets": [{"name": "indexer", "kind": ["lib"]}],
             "dependencies": [{"name": "wasmtime", "source": source_prefix}]},
            {"name": "wasmtime", "id": wasmtime_id, "version": "51.0.0-kontor.2",
             "source": f"{source_prefix}#{manifest['wasmtime_revision']}",
             "manifest_path": str(checkout / "crates/wasmtime/Cargo.toml"),
             "dependencies": [{"name": "wasmtime-internal-fiber",
                               "source": f"{source_prefix}#{manifest['wasmtime_revision']}",
                               "req": "=51.0.0-kontor.2"}]},
            {"name": "wasmtime-internal-fiber", "id": fiber_id,
             "version": "51.0.0-kontor.2",
             "source": f"{source_prefix}#{manifest['wasmtime_revision']}",
             "manifest_path": str(checkout / "crates/fiber/Cargo.toml"),
             "targets": [{"name": "wasmtime_internal_fiber", "kind": ["lib"],
                          "src_path": str(checkout / "crates/fiber/src/lib.rs")}]},
        ],
        "resolve": {"nodes": [
            {"id": indexer_id, "deps": [{"name": "wasmtime", "pkg": wasmtime_id}]},
            {"id": wasmtime_id,
             "deps": [{"name": "wasmtime_fiber", "pkg": fiber_id}]},
            {"id": fiber_id, "deps": [], "features": ["std"]},
        ]},
    }
    metadata = raw_log(directory, "cargo-metadata.json", json.dumps(metadata_json))
    build_messages = [
        {"reason": "compiler-artifact", "package_id": indexer_id,
         "target": {"name": "indexer", "kind": ["lib"]},
         "profile": {"test": True, "opt_level": "0", "debug_assertions": True},
         "features": [], "executable": binary_path},
        {"reason": "compiler-artifact", "package_id": wasmtime_id,
         "target": {"name": "wasmtime", "kind": ["lib"]},
         "features": manifest["wasmtime_features"]["qualification"]},
        {"reason": "compiler-artifact", "package_id": fiber_id,
         "target": {"name": "wasmtime_internal_fiber", "kind": ["lib"]},
         "features": ["std"]},
        {"reason": "build-finished", "success": True},
    ]
    build_log = raw_log(directory, "cargo.jsonl",
                        "".join(json.dumps(message) + "\n" for message in build_messages))
    feature_logs = {graph: raw_log(directory, f"{graph}-features.txt",
                                   ",".join(features) + "\n") for graph, features in
                    manifest["wasmtime_features"].items()}
    report = {
        "schema_version": 1, "manifest_sha256": resource_evidence.sha256(manifest_path),
        "cell": "Linux-X64/dev", "source_sha": source_sha,
        "lockfile_sha256": manifest["artifacts"]["core_lockfile"]["sha256"],
        "binary_path": binary_path, "binary_sha256": binary_artifact["sha256"],
        "compiler": {"rustc_verbose": rustc_verbose,
                     "stack_probing_configuration": policy["stack_probing_configuration"]},
        "build_closure": {"profile": "dev", "target_triple": target,
                          "cargo_features": [], "rustflags": [],
                          "cargo_cwd": str(directory),
                          "cargo_command": ["cargo", "test", "--locked", "--manifest-path",
                                            "core/Cargo.toml", "-p", "indexer", "--lib",
                                            "--no-run", "--message-format=json", "-j2",
                                            "--target", target],
                          "wasmtime_features": manifest["wasmtime_features"],
                          "wasmtime_feature_logs": feature_logs,
                          "wasmtime_source_files": source_logs,
                          "cargo_metadata_sha256": metadata["sha256"],
                          "compile_env_sha256": compile_env["sha256"],
                          "build_log_sha256": build_log["sha256"],
                          "build_log": build_log, "cargo_metadata_log": metadata,
                          "compile_env_log": compile_env, "rustc_log": rustc_log,
                          "binary_artifact": binary_artifact,
                          "git_head_log": git_head_log,
                          "git_status_log": git_status_log},
        "target": target,
        "host": {"os": "linux", "architecture": "x86_64", "cpu_count": 16,
                 "memory_bytes": 32 * GIB, "storage": "synthetic",
                 "resource_enforcement": "synthetic cgroup"},
        "configurations": {mode: configuration(directory, manifest, mode, pid,
                                                binary_path, binary_artifact["sha256"],
                                                source_sha)
                           for mode, pid in (("production", 101), ("reduced", 102))},
        "memory_profiles": [memory_profile(directory, definition,
                                           manifest["workload_plan"]["sha256"])
                            for definition in manifest["memory_profiles"]],
    }
    report["guard_control"] = guard_control(
        directory, manifest, binary_path, binary_artifact["sha256"], source_sha)
    return manifest, manifest_path, report


class ResourceReportControls(unittest.TestCase):
    def test_guard_control_transcript_mutations(self):
        for mutation, expected in (
                ("missing_child", "lacks exact two children and terminal"),
                ("duplicate_mode", "mode is missing or duplicated"),
                ("misattributed_tid", "raw output does not corroborate its fault"),
                ("wrong_terminal_source", "terminal differs from source or binary closure"),
                ("failed_parent", "process failed or transcript is incomplete")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                manifest, manifest_path, report = synthetic_report(directory)
                control = report["guard_control"]
                path = directory / control["raw_log"]["path"]
                lines = path.read_text().splitlines()
                if mutation == "missing_child":
                    lines.pop(2)
                elif mutation == "duplicate_mode":
                    lines[2] = lines[1]
                elif mutation == "misattributed_tid":
                    child = json.loads(lines[2].split("=", 1)[1])
                    child["target"]["os_thread_id"] = 999
                    child["child_stdout"] = (
                        "running 1 test\nKONTOR_RESOURCE_GUARD_TARGET=" +
                        json.dumps(child["target"]) + "\n")
                    lines[2] = "KONTOR_RESOURCE_GUARD_CONTROL=" + json.dumps(child)
                elif mutation == "wrong_terminal_source":
                    terminal = json.loads(lines[3].split("=", 1)[1])
                    terminal["embedded_source_sha"] = "0" * 40
                    lines[3] = "KONTOR_RESOURCE_GUARD_TERMINAL=" + json.dumps(terminal)
                else:
                    control["process"]["exit_code"] = 1
                if mutation != "failed_parent":
                    path.write_text("\n".join(lines) + "\n")
                    control["raw_log"]["sha256"] = resource_evidence.sha256(path)
                with patch.object(resource_evidence, "ROOT", directory), patch.object(
                    resource_evidence, "MANIFEST", manifest_path
                ), patch.object(resource_evidence, "build_manifest", return_value=manifest):
                    with self.assertRaisesRegex(ValueError, expected):
                        resource_evidence.validate(report, directory)

    def test_build_artifact_and_child_identity_mutations(self):
        for mutation in ("metadata", "resolved_fork", "indexer_package", "artifact_path",
                         "compiled_features", "profile", "failed_build",
                         "cargo_target", "rustc_log", "process_command",
                         "binary_bytes", "binary_sha", "git_head", "dirty_tree",
                         "claimed_source_sha",
                         "child_executable_hash", "child_source_sha",
                         "fiber_source_bytes", "fiber_source_claim",
                         "wrong_fiber_source", "wrong_fiber_dependency_source",
                         "wrong_fiber_edge", "wrong_fiber_artifact"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                manifest, manifest_path, report = synthetic_report(directory)
                closure = report["build_closure"]
                expected = {
                    "metadata": "Cargo metadata is incomplete",
                    "resolved_fork": "does not resolve indexer to the pinned Wasmtime fork",
                    "indexer_package": "unique indexer, Wasmtime, or fiber artifacts",
                    "artifact_path": "Cargo artifact path, profile, or compiled features",
                    "compiled_features": "Cargo artifact path, profile, or compiled features",
                    "profile": "Cargo artifact path, profile, or compiled features",
                    "failed_build": "Cargo JSON build did not complete",
                    "cargo_target": "Cargo build command differs",
                    "rustc_log": "rustc identity differs from raw compiler log",
                    "process_command": "child process command differs",
                    "binary_bytes": "raw log hash mismatch",
                    "binary_sha": "executed binary path or captured artifact hash",
                    "git_head": "source checkout revision is stale or dirty",
                    "dirty_tree": "source checkout revision is stale or dirty",
                    "claimed_source_sha": "terminal status differs",
                    "child_executable_hash": "terminal status differs",
                    "child_source_sha": "terminal status differs",
                    "fiber_source_bytes": "raw log hash mismatch",
                    "fiber_source_claim": "fiber allocator source differs from pinned fork",
                    "wrong_fiber_source": "package identity differs from frozen build",
                    "wrong_fiber_dependency_source": "package identity differs from frozen build",
                    "wrong_fiber_edge": "does not resolve Wasmtime to the pinned fiber crate",
                    "wrong_fiber_artifact": "unique indexer, Wasmtime, or fiber artifacts",
                }[mutation]
                if mutation == "metadata":
                    path = directory / closure["cargo_metadata_log"]["path"]
                    path.write_text("{}")
                    digest = resource_evidence.sha256(path)
                    closure["cargo_metadata_log"]["sha256"] = digest
                    closure["cargo_metadata_sha256"] = digest
                elif mutation in {"wrong_fiber_source", "wrong_fiber_dependency_source",
                                  "wrong_fiber_edge"}:
                    path = directory / closure["cargo_metadata_log"]["path"]
                    metadata = json.loads(path.read_text())
                    if mutation == "wrong_fiber_source":
                        metadata["packages"][2]["source"] = "git+https://example.com/fiber#other"
                    elif mutation == "wrong_fiber_dependency_source":
                        metadata["packages"][1]["dependencies"][0]["source"] = (
                            metadata["packages"][2]["source"].split("#")[0])
                    else:
                        metadata["resolve"]["nodes"][1]["deps"][0]["pkg"] += "-other"
                    path.write_text(json.dumps(metadata))
                    digest = resource_evidence.sha256(path)
                    closure["cargo_metadata_log"]["sha256"] = digest
                    closure["cargo_metadata_sha256"] = digest
                elif mutation == "resolved_fork":
                    path = directory / closure["cargo_metadata_log"]["path"]
                    metadata = json.loads(path.read_text())
                    metadata["resolve"]["nodes"][0]["deps"][0]["pkg"] += "-other"
                    path.write_text(json.dumps(metadata))
                    digest = resource_evidence.sha256(path)
                    closure["cargo_metadata_log"]["sha256"] = digest
                    closure["cargo_metadata_sha256"] = digest
                elif mutation in {"indexer_package", "artifact_path", "compiled_features",
                                  "profile", "failed_build", "wrong_fiber_artifact"}:
                    path = directory / closure["build_log"]["path"]
                    entries = [json.loads(line) for line in path.read_text().splitlines()]
                    if mutation == "indexer_package":
                        entries[0]["package_id"] += "-other"
                    elif mutation == "artifact_path":
                        entries[0]["executable"] += "-other"
                    elif mutation == "compiled_features":
                        entries[1]["features"].append("profiling")
                    elif mutation == "wrong_fiber_artifact":
                        entries[2]["package_id"] += "-other"
                    elif mutation == "profile":
                        entries[0]["profile"]["opt_level"] = "3"
                    else:
                        entries[-1]["success"] = False
                    path.write_text("".join(json.dumps(entry) + "\n" for entry in entries))
                    digest = resource_evidence.sha256(path)
                    closure["build_log"]["sha256"] = digest
                    closure["build_log_sha256"] = digest
                elif mutation == "cargo_target":
                    closure["cargo_command"][-1] = "aarch64-unknown-linux-gnu"
                elif mutation == "rustc_log":
                    path = directory / closure["rustc_log"]["path"]
                    path.write_text("rustc 1.99.1 (other)\nhost: x86_64-unknown-linux-gnu\n")
                    closure["rustc_log"]["sha256"] = resource_evidence.sha256(path)
                elif mutation == "process_command":
                    report["configurations"]["production"]["process"]["command"][0] += "-other"
                elif mutation == "binary_bytes":
                    (directory / closure["binary_artifact"]["path"]).write_text("other bytes")
                elif mutation == "binary_sha":
                    report["binary_sha256"] = "0" * 64
                elif mutation in {"fiber_source_bytes", "fiber_source_claim"}:
                    entry = next(iter(closure["wasmtime_source_files"].values()))
                    path = directory / entry["path"]
                    path.write_text("changed source\n")
                    if mutation == "fiber_source_claim":
                        entry["sha256"] = resource_evidence.sha256(path)
                elif mutation in {"git_head", "dirty_tree"}:
                    key = "git_head_log" if mutation == "git_head" else "git_status_log"
                    path = directory / closure[key]["path"]
                    path.write_text("0" * 40 + "\n" if mutation == "git_head"
                                    else " M core/indexer/src/lib.rs\n")
                    closure[key]["sha256"] = resource_evidence.sha256(path)
                elif mutation == "claimed_source_sha":
                    report["source_sha"] = "2" * 40
                    path = directory / closure["git_head_log"]["path"]
                    path.write_text(report["source_sha"] + "\n")
                    closure["git_head_log"]["sha256"] = resource_evidence.sha256(path)
                else:
                    path = directory / report["configurations"]["production"]["process_log"]["path"]
                    events = [json.loads(line) for line in path.read_text().splitlines()]
                    if mutation == "child_executable_hash":
                        events[-1]["executable_sha256"] = "0" * 64
                    else:
                        events[-1]["embedded_source_sha"] = "0" * 40
                    path.write_text("".join(json.dumps(event) + "\n" for event in events))
                    digest = resource_evidence.sha256(path)
                    production = report["configurations"]["production"]
                    production["process_log"]["sha256"] = digest
                    production["raw_logs"][0]["sha256"] = digest
                    for case in production["cases"]:
                        case["raw_log"]["sha256"] = digest
                with patch.object(resource_evidence, "ROOT", directory), patch.object(
                    resource_evidence, "MANIFEST", manifest_path
                ), patch.object(resource_evidence, "build_manifest", return_value=manifest):
                    with self.assertRaisesRegex(ValueError, expected):
                        resource_evidence.validate(report, directory)

    def test_complete_synthetic_report_and_downstream_mutations(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, manifest_path, report = synthetic_report(directory)
            with patch.object(resource_evidence, "ROOT", directory), patch.object(
                resource_evidence, "MANIFEST", manifest_path
            ), patch.object(resource_evidence, "build_manifest", return_value=manifest):
                signatures = resource_evidence.validate(report, directory)
                self.assertEqual(set(signatures), {case["id"] for case in manifest["cases"]})
                chain = next(case for case in report["configurations"]["reduced"]["cases"]
                             if case["id"] == "chain_64_paid")
                self.assertEqual(set(chain["observations"][0]["state"]["balance_transitions"]),
                                 resource_evidence.BALANCE_TRANSITION_FIELDS)

                bad = copy.deepcopy(report)
                chain = next(case for case in bad["configurations"]["reduced"]["cases"]
                             if case["id"] == "chain_64_paid")
                chain["observations"][0]["state"]["balance_transitions"]["after"] = "1/2"
                with self.assertRaisesRegex(ValueError, "violates schema"):
                    resource_evidence.validate(bad, directory)

                for mutation, expected_error in (
                    ("missing_key", "violates schema"),
                    ("extra_key", "violates schema"),
                    ("noncanonical", "noncanonical balance transition"),
                    ("numeric", "violates schema"),
                    ("missing_field", "invalid state evidence"),
                ):
                    with self.subTest(balance_transition_mutation=mutation):
                        bad = copy.deepcopy(report)
                        chain = next(case for case in bad["configurations"]["reduced"]["cases"]
                                     if case["id"] == "chain_64_paid")
                        state = chain["observations"][0]["state"]
                        if mutation == "missing_field":
                            del state["balance_transitions"]
                        elif mutation == "missing_key":
                            del state["balance_transitions"]["after"]
                        elif mutation == "extra_key":
                            state["balance_transitions"]["unexpected"] = "0"
                        elif mutation == "noncanonical":
                            state["balance_transitions"]["after"] = "1.20"
                        else:
                            state["balance_transitions"]["after"] = 1
                        with self.assertRaisesRegex(ValueError, expected_error):
                            resource_evidence.validate(bad, directory)

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
