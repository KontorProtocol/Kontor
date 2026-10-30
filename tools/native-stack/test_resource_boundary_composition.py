import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from resource_boundary_evidence import (TEST_NAME, expected_case_env,
                                        run_name, validate_bundle,
                                        validate_final_parity,
                                        validate_reviewed_discovery,
                                        validate_run)
from resource_boundary_manifest import (CONFIGURATIONS, DISCOVERY_ROLE,
                                        FINAL_ROLES, MANIFEST,
                                        build_boundary_manifest)
from resource_evidence import sha256
from resource_manifest import ROOT, build_manifest
from resource_suite_registry import build_registry
from test_resource_report import guard_control


SOURCE_SHA = "1" * 40


def capacity(category, number, base, pid, configuration):
    guard = 4096 if category == "tokio_worker" else 0
    mapped = (1048576 if configuration == "reduced"
              and category == "tokio_worker" else 2097152)
    start = base + guard
    return {
        "thread_category": category,
        "thread_id": f"ThreadId({number})",
        "process_id": pid,
        "os_thread_id": number,
        "identity_api": "linux_gettid",
        "page_size_bytes": 4096,
        "requested_bytes": (1048576 if configuration == "reduced"
                            and category == "tokio_worker" else None),
        "mapped_bytes": mapped,
        "guard_bytes": guard,
        "guard_start": base if guard else 0,
        "guard_end": start if guard else 0,
        "guard_verification": ("linux_maps_prot_none" if guard
                               else "pthread_reports_none"),
        "usable_bytes": mapped,
        "mapped_start": start,
        "mapped_end": start + mapped,
        "usable_start": start,
        "usable_end": start + mapped,
        "measurement_api": "pthread_getattr_np",
        "guard_treatment": "separate_protected_page",
        "guard_verified": True,
    }


def teardown_events(mode):
    events = []
    identifier = 0
    for role, count in (("nested_chain", 1), ("post_observation", 5),
                        ("rollback_observation", 4),
                        ("target_native_auxiliary", 2 if mode == "paid" else 0)):
        for _ in range(count):
            for kind in ("reserved", "store_created", "table_destroyed",
                         "lease_released"):
                events.append({
                    "id": identifier, "role": role, "kind": kind,
                    "table_alive": False if kind == "table_destroyed" else None,
                })
            identifier += 1
    return events


def observation(case_id, index, depth, component_sha, mutations=None,
                role=DISCOVERY_ROLE, configuration="production"):
    leaf = case_id == "deepest_frame_host_call"
    wide = "_wide_" in case_id
    mode = "paid" if leaf else case_id.rsplit("_", 1)[1]
    outcome = "ok" if depth < 2 else "stack_overflow"
    phase = ("not_applicable" if not leaf else
             "after_host_release" if outcome == "ok" or depth == 2
             else "before_import")
    charged = mode == "paid"
    balances = {
        "before": "100", "after": "99" if charged else "100",
        "restored": "100", "burned_before": "0",
        "burned_after": "1" if charged else "0",
        "supply_before": "100", "supply_after": "99" if charged else "100",
        "floor_before": "3E-9",
        "floor_after": "0" if mode == "core" and outcome == "ok"
        else "3E-9",
        "floor_restored": "3E-9",
    }
    live_deposit_gas = {
        "before": 3,
        "after": 0 if mode == "core" and outcome == "ok" else 3,
        "restored": 3,
    }
    result = {
        "role": role, "sample_index": index,
        "sample_id": f"{role}:{case_id}:{index:04}",
        "cache_mode": "warm_compiled_cache", "call_hook_installed": False,
        "fixture_contracts": 1,
        "kind": "paid_leaf_host" if leaf else (
            f"{mode}_wide" if wide else f"{mode}_recurse"),
        "depth": depth, "outcome": outcome,
        "error": None if outcome == "ok" else "typed Pulley stack overflow",
        "value": str((496 if wide else 1) * depth) if outcome == "ok" else None,
        "receipt": None if mode in ("view", "system") else {
            "status": "Ok" if outcome == "ok" else "Trap", "gas": 1,
        },
        "last_depth": (depth if mode in ("paid", "core")
                       and outcome == "ok" else 0),
        "child_markers": [], "rolled_back": outcome != "ok",
        "fuel": {"user": 100 if charged else 0,
                 "system": 0 if charged else 100, "deposit": 0},
        "gas_limit": 100000, "paid_fuel_limit": 100000000,
        "view_gas_limit": 100000, "view_fuel_limit": 100000000,
        "system_fuel_ceiling": 9223372036854775807,
        "gas_to_fuel_multiplier": 1000, "max_wasm_stack": 524288,
        "async_stack_size": 1048576 if configuration == "reduced" else 2097152,
        "engine_target": "pulley64-unknown-unknown-elf",
        "component_sha256": component_sha,
        "target_os": "linux", "target_arch": "aarch64",
        "teardown_events": (teardown_events(mode)
                            if role != "probe_off_control" else None),
        "teardown_probe_on": role != "probe_off_control",
        "error_class": None if outcome == "ok" else "deterministic",
        "typed_trap": None if outcome == "ok" else "StackOverflow",
        "host_io_suspended": phase == "after_host_release",
        "leaf_callback_seen": phase == "after_host_release",
        "host_import_phase": phase,
        "live_store_peak": 1, "state_before_sha256": "b" * 64,
        "balance_transitions": balances,
        "live_deposit_gas": live_deposit_gas,
        "reset": {
            "pre": {"live_invocations": 0, "stack_empty": True,
                    "savepoint_intact": True, "resource_count": 0,
                    "baseline_resource_count": 0,
                    "failure_rolled_back": True if outcome != "ok" else None},
            "post": {"persistent_digest_sha256": "b" * 64,
                     "baseline_digest_sha256": "b" * 64,
                     "digest_matches": True, "live_invocations": 0,
                     "stack_empty": True, "savepoint_restored": True,
                     "resource_count": 0, "balances_restored": True,
                     "floor_restored": True, "supply_restored": True},
        },
    }
    if mutations is not None:
        mutations(case_id, index, result)
    result["balance_transitions_sha256"] = hashlib.sha256(
        json.dumps(result["balance_transitions"], sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    result["live_deposit_gas_sha256"] = hashlib.sha256(
        json.dumps(result["live_deposit_gas"], sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    return result


def calibration_depths():
    depths = [0, 1024]
    first_failure = 1024
    while first_failure > 2:
        first_failure //= 2
        depths.append(first_failure)
    depths.append(1)
    return depths


def trace_event(name, number=1, category="tokio_worker"):
    return {"name": name, "thread_id": f"ThreadId({number})",
            "os_thread_id": number, "category": category}


def make_run(directory, case_id, pid, binary_path, binary_sha,
             manifest_sha, component_sha, mutations=None,
             source_sha=SOURCE_SHA, trace_mutation=None,
             role=DISCOVERY_ROLE, configuration="production"):
    name = run_name(case_id, role, configuration)
    if role == DISCOVERY_ROLE:
        samples = [("calibration", depth, index)
                   for index, depth in enumerate(calibration_depths())]
    elif case_id == "deepest_frame_host_call":
        samples = [("last_success", 1, 0), ("first_failure", 2, 0),
                   ("last_success", 1, 1), ("first_failure", 2, 1)]
    else:
        samples = [("last_success", 1, 0),
                   ("first_failure", 2, 0),
                   ("first_failure", 2, 1),
                   ("last_success", 1, 1),
                   ("last_success", 1, 2),
                   ("first_failure", 2, 2)]
    attempts = []
    timings = []
    events = [trace_event("fixture_preparation_entry"),
              trace_event("publication_entry"),
              trace_event("compiler_entry"), trace_event("compiler_exit"),
              trace_event("blocking_decode_entry", 3, "blocking_pool"),
              trace_event("blocking_decode_exit", 3, "blocking_pool"),
              trace_event("publication_exit"),
              trace_event("fixture_preparation_exit")]
    for index, (sample_key, depth, repeat_index) in enumerate(samples):
        observed = observation(case_id, index, depth, component_sha,
                               mutations, role, configuration)
        attempts.append({
            "case_id": case_id, "process_role": role,
            "configuration": configuration,
            "probe_on": role != "probe_off_control", "pid": pid,
            "sample_key": sample_key, "repeat_index": repeat_index,
            "depth": depth, "complete": True, "observation": observed,
        })
        timings.append({
            "role": role, "kind": observed["kind"],
            "sample_index": index, "setup_ms": 1, "funding_ms": 1,
            "publication_ms": 1, "execution_ms": 1, "postcall_ms": 1,
            "total_sample_ms": 1,
        })
        events.extend(trace_event(event) for event in (
            "boundary_attempt_start", "sample_preparation_entry",
            "sample_preparation_exit", "operation_entry",
            "canonical_input_entry", "canonical_input_exit",
        ))
        if observed["outcome"] == "ok":
            events.extend(trace_event(event) for event in
                          ("canonical_output_entry", "canonical_output_exit"))
        events.extend(trace_event(event) for event in (
            "operation_exit", "postcall_observation_entry",
            "postcall_observation_exit", "teardown_entry", "teardown_exit",
            "boundary_attempt_end",
        ))
    runtime = {
        "scope": "paired_pulley_boundary_worker",
        "configuration": configuration,
        "case_id": case_id, "process_role": role, "pid": pid,
        "flavor": "multi_thread", "worker_count": 2,
        "worker_requested_bytes": 1048576 if configuration == "reduced" else None,
        "thread_observations": [
            capacity("tokio_worker", 1, 0x1000000, pid, configuration),
            capacity("tokio_worker", 2, 0x2000000, pid, configuration),
            capacity("blocking_pool", 3, 0x3000000, pid, configuration),
            capacity("block_on_caller", 4, 0x4000000, pid, configuration),
        ],
        "blocking_pool_observed": True, "block_on_caller_observed": True,
        "embedded_source_sha": source_sha, "binary_sha256": binary_sha,
    }
    trace = {"scope": runtime["scope"], "configuration": configuration,
             "case_id": case_id, "process_role": role,
             "events": events}
    if trace_mutation is not None:
        trace_mutation(case_id, trace["events"])
    summary = {
        "case_id": case_id, "process_role": role,
        "configuration": configuration,
        "probe_on": role != "probe_off_control", "pid": pid,
        "discovery": role == DISCOVERY_ROLE,
        "last_success": 1, "first_failure": 2,
        "attempt_count": len(attempts), "component_sha256": component_sha,
        "engine_target": "pulley64-unknown-unknown-elf",
        "max_wasm_stack": 524288,
        "async_stack_size": 1048576 if configuration == "reduced" else 2097152,
        "cache_mode": "warm_compiled_cache", "complete": True,
    }
    terminal = {"case_id": case_id, "process_role": role,
                "configuration": configuration, "pid": pid,
                "attempt_count": len(attempts), "complete": True}
    lines = ["running 1 test"]
    for timing, attempt in zip(timings, attempts, strict=True):
        lines.extend(("KONTOR_STACK_TIMING:" + json.dumps(timing),
                      "BOUNDARY_PROBE_ATTEMPT:" + json.dumps(attempt)))
    lines.extend(("BOUNDARY_WORKER_RUNTIME=" + json.dumps(runtime),
                  "BOUNDARY_WORKER_TRACE=" + json.dumps(trace),
                  "BOUNDARY_PROBE_SUMMARY:" + json.dumps(summary),
                  "BOUNDARY_PROBE_TERMINAL:" + json.dumps(terminal),
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                  "1 filtered out; finished in 0.01s"))
    log = directory / f"{name}.log"
    log.write_text("\n".join(lines) + "\n")
    command = [binary_path, "--ignored", "--exact", TEST_NAME, "--nocapture"]
    return {
        "run_id": name, "case_id": case_id, "process_role": role,
        "configuration": configuration, "cell": "Linux-ARM64/dev",
        "argv": command, "case_env": expected_case_env(
            case_id, role, configuration,
            None if role == DISCOVERY_ROLE else (1, 2)),
        "process": {"pid": pid, "command": command,
                    "started_unix_ns": pid * 1000,
                    "ended_unix_ns": pid * 1000 + 1,
                    "exit_code": 0, "signal": None, "timed_out": False,
                    "complete": True, "test_harness_passed": True},
        "raw_log": {"path": log.name, "sha256": sha256(log)},
        "binary_sha256_before": binary_sha,
        "binary_sha256_after": binary_sha,
        "source_sha": source_sha,
        "manifest_sha256": manifest_sha,
        "timeout_seconds": 600,
        "summary": summary, "runtime": runtime, "thread_trace": trace,
        "attempts": attempts, "timings": timings,
    }


class BoundaryCompositionTests(unittest.TestCase):
    def test_leaf_replay_phase_stable_within_and_across_raw_children(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            case_id = "deepest_frame_host_call"
            binary_path = str(directory / "indexer-test")
            binary_sha = "b" * 64
            manifest_sha = sha256(MANIFEST)
            component_sha = sha256(ROOT / "test-contracts/binaries/stack_probe.wasm.br")
            bundle = {
                "phase": "pilot_replay", "cell": "Linux-ARM64/dev",
                "source_sha": SOURCE_SHA, "binary_path": binary_path,
                "binary_sha256": binary_sha, "manifest_sha256": manifest_sha,
                "timeout_seconds": 600,
                "discovered_depths": {case_id: {"last_success": 1,
                                                "first_failure": 2}},
            }
            manifest = build_boundary_manifest()
            signatures = {}
            runs = {}
            for configuration in CONFIGURATIONS:
                for role in FINAL_ROLES:
                    run = make_run(directory, case_id, len(runs) + 300,
                                   binary_path, binary_sha, manifest_sha,
                                   component_sha, role=role,
                                   configuration=configuration)
                    signatures[case_id, role, configuration], _ = validate_run(
                        run, bundle, manifest, directory)
                    runs[run_name(case_id, role, configuration)] = run
            validate_final_parity(signatures, runs, [case_id])

            def change_phase(case, index, value):
                if case == case_id and index == 3:
                    value.update(host_import_phase="before_import",
                                 host_io_suspended=False,
                                 leaf_callback_seen=False)

            run = make_run(directory, case_id, 400, binary_path,
                           binary_sha, manifest_sha, component_sha,
                           change_phase, role="target_observed",
                           configuration="production")
            with self.assertRaises(ValueError):
                validate_run(run, bundle, manifest, directory)

            def change_both_failures(case, index, value):
                if case == case_id and index in (1, 3):
                    value.update(host_import_phase="before_import",
                                 host_io_suspended=False,
                                 leaf_callback_seen=False)

            run = make_run(directory, case_id, 401, binary_path,
                           binary_sha, manifest_sha, component_sha,
                           change_both_failures, role="target_observed",
                           configuration="production")
            changed, _ = validate_run(run, bundle, manifest, directory)
            signatures[case_id, "target_observed", "production"] = changed
            with self.assertRaises(ValueError):
                validate_final_parity(signatures, runs, [case_id])

    def test_historical_archive_binds_all_nine_raw_runs_and_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "source"
            root.mkdir()

            def git(*args):
                return subprocess.run(["git", "-C", str(root), *args],
                                      check=True, capture_output=True,
                                      text=True).stdout.strip()

            def commit(message):
                git("add", ".")
                git("-c", "user.name=Test", "-c",
                    "user.email=test@example.invalid", "commit", "-qm", message)
                return git("rev-parse", "HEAD")

            git("init", "-q")
            source_dir = root / "tools/native-stack"
            source_dir.mkdir(parents=True)
            old_manifest = build_boundary_manifest()
            manifest_path = source_dir / "resource-boundary-manifest-v1.json"
            manifest_path.write_text(json.dumps(old_manifest, indent=2,
                                                sort_keys=True) + "\n")
            old_manifest_sha = sha256(manifest_path)
            old_v1_path = source_dir / "resource-manifest-v1.json"
            old_v1 = build_manifest()
            old_v1["build_policy"].pop("fastnum_generated")
            old_v1["build_policy"].pop("fastnum_build_script_sha256")
            old_v1["build_policy"].pop("native_environment_keys")
            old_v1_path.write_text(json.dumps(old_v1, indent=2,
                                              sort_keys=True) + "\n")
            depths_path = source_dir / "resource-boundary-depths-v1.json"
            depths_path.write_text('{"cases":"pending"}\n')
            old_registry = build_registry()
            registry_path = source_dir / "resource-suite-registry-v1.json"
            registry_path.write_text(json.dumps(old_registry, indent=2,
                                                sort_keys=True) + "\n")

            def frozen_registry(boundary_path):
                result = copy.deepcopy(old_registry)
                boundary_sha = sha256(boundary_path)
                result["parent_manifests"]["boundary"] = boundary_sha
                result["groups"]["pulley_boundary"][
                    "manifest_sha256"] = boundary_sha
                result["remaining_gates"]["boundary_discovery"] = "candidate_only"
                return result
            fixture = root / "test-contracts/binaries/stack_probe.wasm.br"
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes((ROOT / "test-contracts/binaries/stack_probe.wasm.br")
                                .read_bytes())
            runtime = root / "core/indexer/src/runtime/mod.rs"
            runtime.parent.mkdir(parents=True)
            runtime.write_text("stable frame source\n")
            indexer_manifest = root / "core/indexer/Cargo.toml"
            indexer_manifest.write_text("[package]\nname = 'indexer'\n")
            discovery_sha = commit("discovery source")

            evidence = base / "evidence"
            evidence.mkdir()
            binary = evidence / "discovery-indexer-test"
            binary.write_bytes(b"historical selected test artifact")
            binary_sha = sha256(binary)
            archived_workspace = Path("/remote/arm-build/core")
            original_binary = str(archived_workspace / "target/indexer-test")
            component_sha = sha256(fixture)
            cases = [case["case_id"] for case in old_manifest["boundary_cases"]]
            cases.append(old_manifest["leaf_case"]["case_id"])
            runs = {
                run_name(case_id, DISCOVERY_ROLE, "production"):
                make_run(evidence, case_id, 200 + index,
                         original_binary, binary_sha, old_manifest_sha,
                         component_sha, source_sha=discovery_sha)
                for index, case_id in enumerate(cases)
            }
            control_dir = evidence / "control"
            control_dir.mkdir()

            def control_file(name, content):
                path = control_dir / name
                path.write_text(content)
                return {"path": name, "sha256": sha256(path)}

            profile = {"test": True, "opt_level": "0",
                       "debug_assertions": True, "overflow_checks": True}
            artifact = {
                "reason": "compiler-artifact", "package_id": "indexer-package",
                "target": {"name": "indexer", "kind": ["lib"]},
                "profile": profile, "executable": original_binary,
                "features": ["testing"],
            }
            artifacts = control_file("cargo-artifacts.jsonl",
                                     json.dumps(artifact) + "\n" +
                                     json.dumps({"reason": "build-finished",
                                                 "success": True}) + "\n")
            metadata = control_file("cargo-metadata.json", json.dumps({
                "workspace_root": str(archived_workspace),
                "target_directory": str(archived_workspace / "target"),
                "packages": [{"name": "indexer", "id": "indexer-package",
                              "manifest_path": str(archived_workspace /
                                                   "indexer/Cargo.toml")}],
            }) + "\n")
            build_log = control_file("cargo-build.log", "compiler stderr\n")
            v1_manifest = old_v1
            build_attestation = control_file(
                "resource-build-attestation.json", json.dumps({
                    "schema_version": 1,
                    "source_sha": discovery_sha,
                    "manifest_sha256": sha256(old_v1_path),
                    "lockfile_sha256": v1_manifest["artifacts"]["core_lockfile"]["sha256"],
                    "profile": "dev",
                    "rustc_verbose": "rustc 1.99.1 (test)\nhost: aarch64-unknown-linux-gnu\n",
                    "compile_env": v1_manifest["build_policy"]["compile_env"],
                    "cargo_command": ["cargo", "test", "-p", "indexer", "--lib",
                                      "--locked", "-j2", "--no-run",
                                      "--message-format=json"],
                    "cargo_cwd": str(archived_workspace),
                    "cargo_artifacts_sha256": artifacts["sha256"],
                    "cargo_metadata_sha256": metadata["sha256"],
                    "cargo_build_log_sha256": build_log["sha256"],
                    "binary_path": original_binary,
                    "binary_sha256": binary_sha,
                    "indexer_artifact_features": ["testing"],
                    "cargo_home": "/remote/arm-build/cargo-home",
                    "cargo_config_candidates": [
                        "/remote/arm-build/core/.cargo/config.toml",
                        "/remote/arm-build/cargo-home/config.toml",
                    ],
                }) + "\n")
            guard = guard_control(control_dir, build_manifest(),
                                  original_binary, binary_sha, discovery_sha)
            fiber = control_file("fiber.txt", "pinned fiber source\n")
            fiber_sources = {"crates/fiber/src/lib.rs": fiber["sha256"]}
            control = {
                "manifest_sha256": sha256(old_v1_path),
                "source_sha": discovery_sha,
                "binary_path": original_binary,
                "binary_sha256": binary_sha,
                "cargo_artifact": artifact,
                "cargo_artifacts": artifacts,
                "cargo_metadata": metadata,
                "build_attestation": build_attestation,
                "build_log": build_log,
                "guard_control": guard,
                "wasmtime_source_files": {
                    "crates/fiber/src/lib.rs": fiber,
                },
            }
            control_path = control_dir / "resource-control-capture.json"
            control_path.write_text(json.dumps(control) + "\n")
            archive = {
                "schema_version": 1, "phase": "discovery",
                "qualification_status": "missing", "cell": "Linux-ARM64/dev",
                "manifest_sha256": old_manifest_sha,
                "source_sha": discovery_sha,
                "binary_path": original_binary,
                "binary_sha256": binary_sha, "timeout_seconds": 600,
                "control_capture": {"path": "control/" + control_path.name,
                                    "sha256": sha256(control_path)},
                "development_discovery": None, "reviewed_discovery": None,
                "discovery_binary": {"path": binary.name,
                                     "sha256": binary_sha},
                "runs": runs,
                "discovered_depths": {case_id: {
                    "last_success": 1, "first_failure": 2,
                } for case_id in cases},
                "remaining_case_bindings": sorted(
                    case["id"] for case in build_manifest()["cases"]
                    if case["family"] != "distinct_contract_chain"),
            }
            archive_path = evidence / "resource-boundary-capture.json"
            archive_path.write_text(json.dumps(archive) + "\n")
            final_manifest = copy.deepcopy(old_manifest)
            final_manifest["claim_status"] = "candidate_only"
            final_manifest["reviewed_discovery_sha256"] = sha256(archive_path)
            for case in final_manifest["boundary_cases"]:
                case.update(last_success=1, first_failure=2)
            final_manifest["leaf_case"].update(last_success=1,
                                               first_failure=2)
            manifest_path.write_text(json.dumps(final_manifest, indent=2,
                                                sort_keys=True) + "\n")
            depths_path.write_text('{"cases":"frozen"}\n')
            final_registry = frozen_registry(manifest_path)
            registry_path.write_text(json.dumps(final_registry, indent=2,
                                                sort_keys=True) + "\n")
            final_sha = commit("freeze reviewed depths")
            with patch("resource_boundary_evidence.ROOT", root), patch(
                    "resource_boundary_evidence.FIBER_SOURCE_FILES",
                    fiber_sources), patch(
                    "resource_boundary_evidence.MANIFEST", manifest_path), patch(
                    "resource_boundary_evidence.REGISTRY_MANIFEST",
                    registry_path), patch(
                    "resource_boundary_evidence.build_registry",
                    return_value=final_registry):
                validate_reviewed_discovery(archive_path, sha256(archive_path),
                                            final_manifest, final_sha)
                final_dir = base / "final"
                final_dir.mkdir()
                shutil.copytree(evidence, final_dir / "reviewed_discovery")
                final_binary = final_dir / "final-indexer-test"
                final_binary.write_bytes(b"final selected test artifact")
                final_binary_sha = sha256(final_binary)
                final_control_path = final_dir / "control.json"
                final_control_path.write_text("{}\n")
                final_manifest_sha = sha256(manifest_path)
                final_runs = {}
                for index, (case_id, configuration, role) in enumerate(
                    (case_id, configuration, role)
                    for case_id in cases
                    for configuration in ("reduced", "production")
                    for role in ("target_observed", "probe_off_control")
                ):
                    name = run_name(case_id, role, configuration)
                    final_runs[name] = make_run(
                        final_dir, case_id, 300 + index, str(final_binary),
                        final_binary_sha, final_manifest_sha, component_sha,
                        source_sha=final_sha, role=role,
                        configuration=configuration)
                final_bundle = {
                    "schema_version": 1, "phase": "final",
                    "qualification_status": "missing", "cell": "Linux-ARM64/dev",
                    "manifest_sha256": final_manifest_sha,
                    "source_sha": final_sha,
                    "binary_path": str(final_binary),
                    "binary_sha256": final_binary_sha,
                    "timeout_seconds": 600,
                    "control_capture": {"path": final_control_path.name,
                                        "sha256": sha256(final_control_path)},
                    "development_discovery": None,
                    "reviewed_discovery": {
                        "path": "reviewed_discovery/" + archive_path.name,
                        "sha256": sha256(archive_path),
                    },
                    "discovery_binary": None,
                    "runs": final_runs,
                    "discovered_depths": {},
                    "remaining_case_bindings": sorted(
                        case["id"] for case in build_manifest()["cases"]
                        if case["family"] != "distinct_contract_chain"
                        and case["id"] not in cases),
                }
                final_control = {
                    "source_sha": final_sha,
                    "binary_sha256": final_binary_sha,
                    "cargo_artifact": {"profile": {
                        "test": True, "opt_level": "0",
                        "debug_assertions": True,
                    }},
                    "guard_control": {"process": {
                        "pid": 999, "started_unix_ns": 999000,
                    }},
                }
                with patch("resource_boundary_evidence.MANIFEST",
                           manifest_path), patch(
                               "resource_boundary_evidence.build_boundary_manifest",
                               return_value=final_manifest), patch(
                               "resource_boundary_evidence.validate_control",
                               return_value=(final_control, final_binary)), patch(
                               "resource_boundary_evidence.platform.machine",
                               return_value="aarch64"):
                    self.assertEqual(len(validate_bundle(final_bundle, final_dir)
                                         ["signatures"]), 36)
                    wrong_hash_bundle = copy.deepcopy(final_bundle)
                    wrong_hash_bundle["reviewed_discovery"]["sha256"] = "0" * 64
                    with self.assertRaises(ValueError):
                        validate_bundle(wrong_hash_bundle, final_dir)
                    wrong_path_bundle = copy.deepcopy(final_bundle)
                    wrong_path_bundle["reviewed_discovery"]["path"] = \
                        "reviewed_discovery/absent.json"
                    with self.assertRaises(ValueError):
                        validate_bundle(wrong_path_bundle, final_dir)
                    wrong_pair_manifest = copy.deepcopy(final_manifest)
                    wrong_pair_manifest["leaf_case"].update(
                        last_success=2, first_failure=3)
                    wrong_pair_path = base / "wrong-final-manifest.json"
                    wrong_pair_path.write_text(json.dumps(wrong_pair_manifest) + "\n")
                    wrong_pair_registry = frozen_registry(wrong_pair_path)
                    wrong_pair_registry_path = base / "wrong-final-registry.json"
                    wrong_pair_registry_path.write_text(
                        json.dumps(wrong_pair_registry) + "\n")
                    wrong_pair_bundle = copy.deepcopy(final_bundle)
                    wrong_pair_bundle["manifest_sha256"] = sha256(wrong_pair_path)
                    with patch("resource_boundary_evidence.MANIFEST",
                               wrong_pair_path), patch(
                                   "resource_boundary_evidence.build_boundary_manifest",
                                   return_value=wrong_pair_manifest), patch(
                                   "resource_boundary_evidence.REGISTRY_MANIFEST",
                                   wrong_pair_registry_path), patch(
                                   "resource_boundary_evidence.build_registry",
                                   return_value=wrong_pair_registry):
                        with self.assertRaisesRegex(ValueError,
                                                    "frozen depths differ"):
                            validate_bundle(wrong_pair_bundle, final_dir)
                    copied_archive = (final_dir / "reviewed_discovery" /
                                      archive_path.name)
                    copied_control = (final_dir / "reviewed_discovery/control" /
                                      control_path.name)
                    copied_metadata = (final_dir / "reviewed_discovery/control" /
                                       metadata["path"])
                    relocated_metadata = json.loads(copied_metadata.read_text())
                    relocated_metadata["workspace_root"] = "/remote/other/core"
                    copied_metadata.write_text(json.dumps(relocated_metadata) + "\n")
                    relocated_control = json.loads(copied_control.read_text())
                    relocated_control["cargo_metadata"]["sha256"] = \
                        sha256(copied_metadata)
                    copied_control.write_text(json.dumps(relocated_control) + "\n")
                    relocated_archive = json.loads(copied_archive.read_text())
                    relocated_archive["control_capture"]["sha256"] = \
                        sha256(copied_control)
                    copied_archive.write_text(json.dumps(relocated_archive) + "\n")
                    relocated_manifest = copy.deepcopy(final_manifest)
                    relocated_manifest["reviewed_discovery_sha256"] = \
                        sha256(copied_archive)
                    relocated_manifest_path = base / "relocated-final-manifest.json"
                    relocated_manifest_path.write_text(
                        json.dumps(relocated_manifest) + "\n")
                    relocated_registry = frozen_registry(relocated_manifest_path)
                    relocated_registry_path = base / "relocated-final-registry.json"
                    relocated_registry_path.write_text(
                        json.dumps(relocated_registry) + "\n")
                    relocated_bundle = copy.deepcopy(final_bundle)
                    relocated_bundle["manifest_sha256"] = \
                        sha256(relocated_manifest_path)
                    relocated_bundle["reviewed_discovery"]["sha256"] = \
                        sha256(copied_archive)
                    with patch("resource_boundary_evidence.MANIFEST",
                               relocated_manifest_path), patch(
                                   "resource_boundary_evidence.build_boundary_manifest",
                                   return_value=relocated_manifest), patch(
                                   "resource_boundary_evidence.REGISTRY_MANIFEST",
                                   relocated_registry_path), patch(
                                   "resource_boundary_evidence.build_registry",
                                   return_value=relocated_registry):
                        with self.assertRaisesRegex(ValueError,
                                                    "Cargo workspace or artifact paths disagree"):
                            validate_bundle(relocated_bundle, final_dir)
                wrong_pair = copy.deepcopy(final_manifest)
                wrong_pair["leaf_case"]["last_success"] = 2
                with self.assertRaises(ValueError):
                    validate_reviewed_discovery(archive_path,
                                                sha256(archive_path),
                                                wrong_pair, final_sha)
                binary.write_bytes(b"tampered artifact")
                with self.assertRaises(ValueError):
                    validate_reviewed_discovery(archive_path,
                                                sha256(archive_path),
                                                final_manifest, final_sha)
                binary.write_bytes(b"historical selected test artifact")
                metadata_path = control_dir / metadata["path"]
                valid_metadata = metadata_path.read_text()
                for field, wrong_path in (
                    ("manifest_path", str(archived_workspace /
                                          "other/Cargo.toml")),
                    ("target_directory", "/remote/other-target"),
                ):
                    with self.subTest(archive_path_field=field):
                        wrong_metadata = json.loads(valid_metadata)
                        if field == "manifest_path":
                            wrong_metadata["packages"][0][field] = wrong_path
                        else:
                            wrong_metadata[field] = wrong_path
                        metadata_path.write_text(json.dumps(wrong_metadata) + "\n")
                        bad_control = copy.deepcopy(control)
                        bad_control["cargo_metadata"]["sha256"] = sha256(metadata_path)
                        control_path.write_text(json.dumps(bad_control) + "\n")
                        archive["control_capture"]["sha256"] = sha256(control_path)
                        archive_path.write_text(json.dumps(archive) + "\n")
                        bad_manifest = copy.deepcopy(final_manifest)
                        bad_manifest["reviewed_discovery_sha256"] = sha256(archive_path)
                        with self.assertRaises(ValueError):
                            validate_reviewed_discovery(archive_path,
                                                        sha256(archive_path),
                                                        bad_manifest, final_sha)
                metadata_path.write_text(valid_metadata)
                bad_control = copy.deepcopy(control)
                bad_control["cargo_artifact"]["profile"]["opt_level"] = "3"
                control_path.write_text(json.dumps(bad_control) + "\n")
                archive["control_capture"]["sha256"] = sha256(control_path)
                archive_path.write_text(json.dumps(archive) + "\n")
                bad_manifest = copy.deepcopy(final_manifest)
                bad_manifest["reviewed_discovery_sha256"] = sha256(archive_path)
                with self.assertRaises(ValueError):
                    validate_reviewed_discovery(archive_path,
                                                sha256(archive_path),
                                                bad_manifest, final_sha)

    def test_all_nine_discovery_runs_validate_from_raw_transcripts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = build_boundary_manifest()
            manifest_sha = sha256(MANIFEST)
            component_sha = sha256(ROOT / "test-contracts/binaries/stack_probe.wasm.br")
            bundle = {"phase": "discovery", "cell": "Linux-ARM64/dev",
                      "source_sha": SOURCE_SHA,
                      "manifest_sha256": manifest_sha,
                      "binary_path": "/tmp/synthetic-indexer-test",
                      "binary_sha256": "a" * 64,
                      "timeout_seconds": 600}
            cases = [case["case_id"] for case in manifest["boundary_cases"]]
            cases.append(manifest["leaf_case"]["case_id"])
            for index, case_id in enumerate(cases):
                run = make_run(directory, case_id, 100 + index,
                               bundle["binary_path"], bundle["binary_sha256"],
                               manifest_sha, component_sha)
                signatures, counts = validate_run(run, bundle, manifest, directory)
                self.assertEqual(len(signatures), len(calibration_depths()))
                self.assertEqual(counts["compiler_entry"], 1)

    def test_core_deposit_mutants_rejected_after_repairing_all_evidence_hashes(self):
        manifest = build_boundary_manifest()
        manifest_sha = sha256(MANIFEST)
        component_sha = sha256(ROOT / "test-contracts/binaries/stack_probe.wasm.br")
        case_id = "pulley_plain_core"
        mutations = ((0, 3), (1, 1), (1, 2), (2, 0))
        for depth, altered_gas in mutations:
            with self.subTest(depth=depth, gas=altered_gas), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)

                def alter_core_deposit(case, index, value):
                    if case == case_id and value["depth"] == depth:
                        value["live_deposit_gas"]["after"] = altered_gas
                        value["balance_transitions"]["floor_after"] = (
                            f"{altered_gas}E-9")

                bundle = {"phase": "discovery", "cell": "Linux-ARM64/dev",
                          "source_sha": SOURCE_SHA,
                          "manifest_sha256": manifest_sha,
                          "binary_path": "/tmp/synthetic-indexer-test",
                          "binary_sha256": "a" * 64,
                          "timeout_seconds": 600}
                # make_run rebuilds both observation digests and the raw log hash.
                run = make_run(directory, case_id, 100,
                               bundle["binary_path"], bundle["binary_sha256"],
                               manifest_sha, component_sha, alter_core_deposit)
                message = ("Core storage collateral changed outside a successful owner transfer"
                           if depth == 2 else
                           "successful Core fixture write retained depositor gas")
                with self.assertRaisesRegex(
                        ValueError, message):
                    validate_run(run, bundle, manifest, directory)

    def test_full_pilot_discovery_composition_and_semantic_mutants(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest_sha = sha256(MANIFEST)
            component_sha = sha256(ROOT / "test-contracts/binaries/stack_probe.wasm.br")
            binary = directory / "discovery-indexer-test"
            binary.write_bytes(b"synthetic indexer test artifact")
            binary_sha = sha256(binary)
            original_binary_path = str(directory / "indexer-test")
            control_path = directory / "control.json"
            control_path.write_text("{}\n")
            cases = ("pulley_plain_paid", "pulley_wide_paid",
                     "deepest_frame_host_call")

            def bundle_with(mutations=None, trace_mutation=None):
                runs = {
                    run_name(case_id, DISCOVERY_ROLE, "production"):
                    make_run(directory, case_id, 100 + index,
                             original_binary_path, binary_sha, manifest_sha,
                             component_sha, mutations,
                             trace_mutation=trace_mutation)
                    for index, case_id in enumerate(cases)
                }
                remaining = sorted(case["id"] for case in build_manifest()["cases"]
                                   if case["family"] != "distinct_contract_chain")
                return {
                    "schema_version": 1, "phase": "pilot_discovery",
                    "qualification_status": "missing", "cell": "Linux-ARM64/dev",
                    "manifest_sha256": manifest_sha,
                    "source_sha": SOURCE_SHA,
                    "binary_path": original_binary_path,
                    "binary_sha256": binary_sha, "timeout_seconds": 600,
                    "control_capture": {"path": control_path.name,
                                        "sha256": sha256(control_path)},
                    "development_discovery": None,
                    "reviewed_discovery": None,
                    "discovery_binary": {"path": binary.name,
                                         "sha256": binary_sha},
                    "runs": runs,
                    "discovered_depths": {case_id: {
                        "last_success": 1, "first_failure": 2,
                    } for case_id in cases},
                    "remaining_case_bindings": remaining,
                }

            control = {
                "source_sha": SOURCE_SHA,
                "binary_sha256": binary_sha,
                "cargo_artifact": {"profile": {
                    "test": True, "opt_level": "0",
                    "debug_assertions": True,
                }},
                "guard_control": {"process": {
                    "pid": 999, "started_unix_ns": 999000,
                }},
            }
            with patch("resource_boundary_evidence.validate_control",
                       return_value=(control, Path(original_binary_path))), patch(
                           "resource_boundary_evidence.platform.machine",
                           return_value="aarch64"):
                self.assertEqual(len(validate_bundle(bundle_with(), directory)
                                     ["signatures"]), 3)
                for name, mutation in (
                    ("arch", lambda case, index, value:
                     value.update(target_arch="x86_64") if
                     case == "pulley_plain_paid" and index == 0 else None),
                    ("leaf", lambda case, index, value:
                     value.update(host_io_suspended=False) if
                     case == "deepest_frame_host_call" and index == 0 else None),
                    ("leaf failure phase", lambda case, index, value:
                     value.update(host_import_phase="not_applicable") if
                     case == "deepest_frame_host_call" and value["depth"] == 2 else None),
                    ("leaf failure suspension", lambda case, index, value:
                     value.update(host_io_suspended=False) if
                     case == "deepest_frame_host_call" and value["depth"] == 2 else None),
                    ("accounting", lambda case, index, value:
                     value["balance_transitions"].update(burned_after="0") if
                     case == "pulley_plain_paid" and index == 0 else None),
                    ("floor", lambda case, index, value:
                     value["balance_transitions"].update(floor_after="2") if
                     case == "pulley_plain_paid" and index == 0 else None),
                    ("live gas", lambda case, index, value:
                     value["live_deposit_gas"].update(after=4) if
                     case == "pulley_plain_paid" and index == 0 else None),
                    ("restored live gas", lambda case, index, value:
                     value["live_deposit_gas"].update(restored=4) if
                     case == "pulley_plain_paid" and index == 0 else None),
                ):
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        validate_bundle(bundle_with(mutation), directory)
                def move_target_conversion(case_id, events):
                    if case_id != "pulley_plain_paid":
                        return
                    start = next(index for index, event in enumerate(events)
                                 if event["name"] == "boundary_attempt_start")
                    end = next(index for index, event in enumerate(events[start:],
                                                                    start)
                               if event["name"] == "boundary_attempt_end")
                    selected = [event for event in events[start:end]
                                if event["name"].startswith("canonical_")]
                    events[start:end] = [event for event in events[start:end]
                                         if not event["name"].startswith("canonical_")]
                    postcall = next(index for index, event in enumerate(events)
                                    if event["name"] ==
                                    "postcall_observation_entry")
                    events[postcall + 1:postcall + 1] = selected

                with self.assertRaises(ValueError):
                    validate_bundle(bundle_with(trace_mutation=
                                                move_target_conversion), directory)
                wrong_profile = bundle_with()
                control["cargo_artifact"]["profile"]["opt_level"] = "3"
                with self.assertRaises(ValueError):
                    validate_bundle(wrong_profile, directory)


if __name__ == "__main__":
    unittest.main()
