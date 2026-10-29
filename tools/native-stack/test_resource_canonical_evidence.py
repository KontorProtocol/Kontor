import tempfile
import unittest
from pathlib import Path

from resource_canonical_evidence import expected_case_env, parse_worker_log


class CanonicalEvidenceTests(unittest.TestCase):
    def test_case_environment_uses_canonical_worker(self):
        self.assertEqual(expected_case_env("canonical_realloc", "target_observed",
                                           "production"), {
            "KONTOR_FINITE_STACK_CASE": "canonical_realloc",
            "KONTOR_FINITE_STACK_ROLE": "target_observed",
            "KONTOR_RESOURCE_MODE": "production",
            "KONTOR_RESOURCE_TEARDOWN_PROBE": "on",
        })

    def test_transcript_requires_all_case_attempts_in_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "child.log"
            lines = ["running 1 test"]
            for _ in range(4):
                lines.extend(("KONTOR_STACK_TIMING:{}", "CANONICAL_STACK_ATTEMPT:{}"))
            lines.extend((
                'CANONICAL_STACK_SUMMARY:{"case_id":"canonical_lift_lower"}',
                "FINITE_STACK_RUNTIME={}",
                "FINITE_STACK_TRACE={}",
                "FINITE_STACK_TERMINAL={}",
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 720 filtered out; finished in 0.14s",
            ))
            path.write_text("\n".join(lines) + "\n")
            self.assertEqual(len(parse_worker_log(path)["attempts"]), 4)
            lines[3], lines[4] = lines[4], lines[3]
            path.write_text("\n".join(lines) + "\n")
            with self.assertRaisesRegex(ValueError, "out of order"):
                parse_worker_log(path)


if __name__ == "__main__":
    unittest.main()
