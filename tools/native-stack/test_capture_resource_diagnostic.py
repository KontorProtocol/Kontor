"""Trace attribution controls for the paired resource diagnostic."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from capture_resource_diagnostic import PHASE_NAMES, parse_worker_log


class ResourceDiagnosticTraceTests(unittest.TestCase):
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
            observed_runtime, observed_trace, uncovered = parse_worker_log(path, mode, pid)
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
