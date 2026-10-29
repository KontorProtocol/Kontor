import tempfile
import unittest
from pathlib import Path

from resource_pending_evidence import expected_case_env, parse_worker_log


class PendingHostEvidenceTests(unittest.TestCase):
    def test_child_transcript_requires_distinct_ordered_phases(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "child.log"
            lines = [
                "running 1 test",
                "PENDING_HOST_IO_ATTEMPT:{}",
                "KONTOR_STACK_TIMING:{}",
                "PENDING_HOST_IO_ATTEMPT:{}",
                "PENDING_HOST_IO_ATTEMPT:{}",
                "KONTOR_STACK_TIMING:{}",
                "PENDING_HOST_IO_ATTEMPT:{}",
                "PENDING_HOST_IO_SUMMARY:{}",
                "FINITE_STACK_RUNTIME={}",
                "FINITE_STACK_TRACE={}",
                "FINITE_STACK_TERMINAL={}",
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 719 filtered out; finished in 0.14s",
            ]
            path.write_text("\n".join(lines) + "\n")
            self.assertEqual(len(parse_worker_log(path)["attempts"]), 4)
            lines[10], lines[11] = lines[11], lines[10]
            path.write_text("\n".join(lines) + "\n")
            with self.assertRaisesRegex(ValueError, "out of order"):
                parse_worker_log(path)
            lines[10], lines[11] = lines[11], lines[10]
            lines[1] = 'PENDING_HOST_IO_ATTEMPT:{"sample_key": "suspended", "sample_key": "resumed"}'
            path.write_text("\n".join(lines) + "\n")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                parse_worker_log(path)

    def test_case_environment_is_exact(self):
        self.assertEqual(expected_case_env("target_observed", "production"), {
            "KONTOR_FINITE_STACK_CASE": "pending_host_io",
            "KONTOR_FINITE_STACK_ROLE": "target_observed",
            "KONTOR_RESOURCE_MODE": "production",
            "KONTOR_RESOURCE_TEARDOWN_PROBE": "on",
        })
        with self.assertRaisesRegex(ValueError, "unknown pending host I/O run"):
            expected_case_env("target_observed", "unmeasured")


if __name__ == "__main__":
    unittest.main()
