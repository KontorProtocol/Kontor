import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from resource_pending_evidence import (HOST_IMPORT, expected_case_env,
                                       parse_worker_log, validate_control_parity,
                                       validate_phase_attempts)


class PendingHostEvidenceTests(unittest.TestCase):
    def test_child_transcript_requires_distinct_ordered_phases(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "child.log"
            lines = [
                "running 1 test",
                "PENDING_HOST_IO_ATTEMPT:{}",
                "KONTOR_STACK_TIMING:{}",
                "PENDING_HOST_IO_ATTEMPT:{}",
                "KONTOR_STACK_TIMING:{}",
                "PENDING_HOST_IO_CONTROL:{}",
                "PENDING_HOST_IO_ATTEMPT:{}",
                "KONTOR_STACK_TIMING:{}",
                "PENDING_HOST_IO_ATTEMPT:{}",
                "KONTOR_STACK_TIMING:{}",
                "PENDING_HOST_IO_CONTROL:{}",
                "PENDING_HOST_IO_SUMMARY:{}",
                "FINITE_STACK_RUNTIME={}",
                "FINITE_STACK_TRACE={}",
                "FINITE_STACK_TERMINAL={}",
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 719 filtered out; finished in 0.14s",
            ]
            path.write_text("\n".join(lines) + "\n")
            self.assertEqual(len(parse_worker_log(path)["attempts"]), 4)
            lines[14], lines[15] = lines[15], lines[14]
            path.write_text("\n".join(lines) + "\n")
            with self.assertRaisesRegex(ValueError, "out of order"):
                parse_worker_log(path)
            lines[14], lines[15] = lines[15], lines[14]
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

    def test_pending_poll_proof_rejects_missing_and_reused_counts(self):
        attempts = []
        for index, (sample_key, repeat_index) in enumerate((
                ("suspended", 0), ("resumed", 0),
                ("suspended", 1), ("resumed", 1))):
            attempts.append({
                "case_id": "pending_host_io",
                "configuration": "reduced",
                "process_role": "target_observed",
                "sample_key": sample_key,
                "repeat_index": repeat_index,
                "pid": 123,
                "host_import": HOST_IMPORT,
                "host_entered": True,
                "host_poll_pending_count": repeat_index + 1,
                "guest_task_pending": sample_key == "suspended",
                "other_task_progressed": True,
                "observation": None if sample_key == "suspended" else {},
            })
        validate_phase_attempts(attempts, "target_observed", "reduced", 123)
        missing = deepcopy(attempts)
        del missing[2]["host_poll_pending_count"]
        with self.assertRaisesRegex(ValueError, "phase markers differ"):
            validate_phase_attempts(missing, "target_observed", "reduced", 123)
        reused = deepcopy(attempts)
        reused[2]["host_poll_pending_count"] = 1
        reused[3]["host_poll_pending_count"] = 1
        with self.assertRaisesRegex(ValueError, "phase markers differ"):
            validate_phase_attempts(reused, "target_observed", "reduced", 123)

    def test_unshadowed_control_rejects_fuel_and_value_mutants(self):
        resumed = {"sample_key": "resumed", "repeat_index": 0,
                   "value": "[1,2]", "fuel": {"system": 100, "user": 0}}
        control = {**resumed, "sample_key": "unshadowed_control"}
        validate_control_parity(resumed, control)
        for key, changed in (("value", "[2,1]"),
                             ("fuel", {"system": 101, "user": 0})):
            mutant = {**control, key: changed}
            with self.assertRaisesRegex(ValueError, "host semantics differ"):
                validate_control_parity(resumed, mutant)


if __name__ == "__main__":
    unittest.main()
