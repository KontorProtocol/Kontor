"""Trace attribution controls for the paired resource diagnostic."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from capture_resource_diagnostic import PHASE_NAMES, parse_worker_log, validate_control
from resource_evidence import sha256
from resource_manifest import MANIFEST, build_manifest


class ResourceDiagnosticTraceTests(unittest.TestCase):
    def test_archive_control_uses_captured_host_and_binary_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            def entry(name, content):
                path = root / name
                path.write_text(content)
                return {"path": name, "sha256": sha256(path)}

            artifacts = entry("cargo-artifacts.jsonl", "artifact\n")
            metadata = entry("cargo-metadata.json", json.dumps({
                "workspace_root": "/origin/core"}) + "\n")
            attestation = entry("resource-build-attestation.json", "attestation\n")
            build_log = entry("cargo-build.log", "build\n")
            fastnum = entry("fastnum-build.rs", "source\n")
            guard = entry("guard-control.log", "\n".join(
                "KONTOR_RESOURCE_GUARD_CONTROL=" + json.dumps({
                    "target": {"page_size_bytes": 4096}}) for _ in range(2)) + "\n")
            origin = Path("/origin/target/debug/deps/indexer-test")
            archived = root / origin.name
            archived.write_bytes(b"archived-indexer-test")
            cargo_artifact = {"executable": str(origin)}
            control = {
                "manifest_sha256": sha256(MANIFEST),
                "source_sha": "a" * 40,
                "binary_path": str(origin),
                "binary_sha256": sha256(archived),
                "cargo_artifact": cargo_artifact,
                "cargo_artifacts": artifacts,
                "cargo_metadata": metadata,
                "build_attestation": attestation,
                "build_log": build_log,
                "fastnum_files": {"build_script": fastnum},
                "guard_control": {"process": {}, "raw_log": guard},
                "wasmtime_source_files": {},
            }
            path = root / "resource-control-capture.json"
            path.write_text(json.dumps(control))
            with (patch("capture_resource_diagnostic.FIBER_SOURCE_FILES", {}),
                  patch("capture_resource_diagnostic.subprocess.run",
                        side_effect=[SimpleNamespace(stdout="a" * 40),
                                     SimpleNamespace(stdout="")]),
                  patch("capture_resource_diagnostic.selected_binary",
                        return_value=(origin, cargo_artifact)),
                  patch("capture_resource_diagnostic.validate_build_attestation",
                        return_value=({"fastnum_build_script": fastnum,
                                       "fastnum_generated": {},
                                       "rustc_verbose": "rustc 1.99.1\nhost: aarch64-apple-darwin\n"},
                                      root / build_log["path"])),
                  patch("capture_resource_diagnostic.check_guard_control") as check_guard):
                observed, binary = validate_control(
                    path, sha256(path), build_manifest(), archive_binary=archived,
                    expected_cell="macOS-ARM64/dev")
            self.assertEqual(observed, control)
            self.assertEqual(binary, origin)
            report_view = check_guard.call_args.args[0]
            self.assertEqual(report_view["host"]["os"], "macos")
            self.assertEqual(report_view["configurations"]["reduced"]
                             ["engine"]["page_size_bytes"], 4096)
            archived.write_bytes(b"changed-indexer-test")
            with (patch("capture_resource_diagnostic.FIBER_SOURCE_FILES", {}),
                  patch("capture_resource_diagnostic.subprocess.run",
                        side_effect=[SimpleNamespace(stdout="a" * 40),
                                     SimpleNamespace(stdout="")]),
                  patch("capture_resource_diagnostic.selected_binary",
                        return_value=(origin, cargo_artifact))):
                with self.assertRaisesRegex(ValueError, "binary differs"):
                    validate_control(path, sha256(path), build_manifest(),
                                     archive_binary=archived,
                                     expected_cell="macOS-ARM64/dev")

    def test_worker_trace_requires_measured_kernel_identity_and_phase_order(self):
        pid = 104
        mode = "reduced"
        runtime = {
            "scope": "diagnostic_only", "mode": mode, "pid": pid,
            "flavor": "multi_thread", "worker_count": 2,
            "worker_requested_bytes": 1_048_576,
            "thread_observations": [],
            "blocking_pool_observed": True, "block_on_caller_observed": True,
        }
        events = [{"name": name, "rust_thread_id": "ThreadId(1)",
                   "category": "tokio_worker", "os_thread_id": 201}
                  for name in PHASE_NAMES]
        events[1:1] = [
            {"name": "compiler_entry", "rust_thread_id": "ThreadId(1)",
             "category": "tokio_worker", "os_thread_id": 201},
            {"name": "compiler_exit", "rust_thread_id": "ThreadId(1)",
             "category": "tokio_worker", "os_thread_id": 201},
            {"name": "blocking_decode_entry", "rust_thread_id": "ThreadId(3)",
             "category": "blocking_pool", "os_thread_id": 203},
            {"name": "blocking_decode_exit", "rust_thread_id": "ThreadId(3)",
             "category": "blocking_pool", "os_thread_id": 203},
        ]
        trace = {"scope": "diagnostic_only", "mode": mode,
                 "compiler_internal_threads": "unobserved", "events": events}
        capacities = {
            "tokio_worker": [{"thread_id": "ThreadId(1)", "os_thread_id": 201},
                             {"thread_id": "ThreadId(2)", "os_thread_id": 202}],
            "blocking_pool": [{"thread_id": "ThreadId(3)", "os_thread_id": 203}],
        }

        def log_file(directory, observed_trace):
            path = Path(directory) / "worker.log"
            path.write_text("\n".join((
                "running 1 test",
                "KONTOR_RESOURCE_THREAD_TRACE=" + json.dumps(observed_trace),
                "KONTOR_RESOURCE_RUNTIME=" + json.dumps(runtime),
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 689 filtered out; finished in 1.00s",
            )) + "\n")
            return path

        with tempfile.TemporaryDirectory() as directory, patch(
                "capture_resource_diagnostic.thread_capacities", return_value=capacities):
            path = log_file(directory, trace)
            observed_runtime, observed_trace, uncovered = parse_worker_log(path, mode, pid, "linux")
            self.assertEqual(observed_runtime, runtime)
            self.assertEqual(observed_trace, trace)
            self.assertEqual(uncovered, [])

            unmeasured_blocking = copy.deepcopy(trace)
            for event in unmeasured_blocking["events"]:
                if event["category"] == "blocking_pool":
                    event["os_thread_id"] = 204
            self.assertEqual(parse_worker_log(
                log_file(directory, unmeasured_blocking), mode, pid,
            )[2], [204])

            wrong_thread = copy.deepcopy(trace)
            wrong_thread["events"][0]["os_thread_id"] = 999
            with self.assertRaisesRegex(ValueError, "worker differs"):
                parse_worker_log(log_file(directory, wrong_thread), mode, pid)

            wrong_order = copy.deepcopy(trace)
            wrong_order["events"][0], wrong_order["events"][5] = (
                wrong_order["events"][5], wrong_order["events"][0]
            )
            with self.assertRaisesRegex(ValueError, "out of order"):
                parse_worker_log(log_file(directory, wrong_order), mode, pid)


if __name__ == "__main__":
    unittest.main()
