import json
import tempfile
import unittest
from pathlib import Path

from resource_finite_evidence import expected_case_env, parse_worker_log


class FiniteStackEvidenceTests(unittest.TestCase):
    def test_child_transcript_requires_ordered_terminal_and_one_harness_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "child.log"
            lines = [
                "running 1 test",
                "KONTOR_STACK_TIMING:{}",
                "FINITE_STACK_ATTEMPT:{}",
                "FINITE_STACK_SUMMARY:{}",
                "FINITE_STACK_RUNTIME={}",
                "FINITE_STACK_TRACE={}",
                "FINITE_STACK_TERMINAL={}",
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 690 filtered out; finished in 0.14s",
            ]
            path.write_text("\n".join(lines) + "\n")
            self.assertEqual(parse_worker_log(path)["attempts"], [{}])
            lines[6], lines[7] = lines[7], lines[6]
            path.write_text("\n".join(lines) + "\n")
            with self.assertRaisesRegex(ValueError, "out of order"):
                parse_worker_log(path)
            lines[6], lines[7] = lines[7], lines[6]
            lines.insert(2, "FINITE_STACK_ATTEMPT:" + json.dumps({"extra": True}))
            path.write_text("\n".join(lines) + "\n")
            with self.assertRaisesRegex(ValueError, "timings are missing"):
                parse_worker_log(path)

    def test_case_environment_is_exact(self):
        self.assertEqual(expected_case_env("large_frame_paid", "target_observed", "reduced"), {
            "KONTOR_FINITE_STACK_CASE": "large_frame_paid",
            "KONTOR_FINITE_STACK_ROLE": "target_observed",
            "KONTOR_RESOURCE_MODE": "reduced",
            "KONTOR_RESOURCE_TEARDOWN_PROBE": "on",
        })
        with self.assertRaisesRegex(ValueError, "unknown finite-stack run"):
            expected_case_env("cold_publish_br_table", "target_observed", "reduced")


if __name__ == "__main__":
    unittest.main()
