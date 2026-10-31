import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_compare import transcript
from test_sweep import reentry


SPEC = importlib.util.spec_from_file_location("native_stack_qualify", Path(__file__).with_name("qualify.py"))
qualify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualify)


class QualifyTests(unittest.TestCase):
    def test_source_identity_rejects_dirty_worktree(self):
        with patch.object(qualify.subprocess, "check_output", side_effect=["a" * 40 + "\n", " M tools/native-stack/qualify.py\n"]):
            with self.assertRaisesRegex(ValueError, "worktree is dirty"):
                qualify.source_identity()

    def test_owned_control_requires_derived_boundary_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            completed = subprocess.CompletedProcess([], 0, "test result: ok. 1 passed\n", "")
            with patch.object(qualify.subprocess, "run", return_value=completed):
                with self.assertRaisesRegex(ValueError, "missing or duplicate evidence"):
                    qualify.run_owned_control(Path("binary"), "paid_reenter", [63, 64], output, 600)
            self.assertTrue((output / "paid_reenter-owned.log").is_file())

    def test_worker_and_control_use_distinct_processes_and_preserve_logs(self):
        worker, ws = reentry()
        control, cs = reentry("control")
        owned = [
            {"kind": "paid_reenter", "depth": sample["depth"], "outcome": sample["outcome"]}
            for sample in control
        ]
        owned_summary = {"kind": "paid_reenter", "depths": [63, 64], "outcomes": [sample["outcome"] for sample in owned], "owned": True}
        owned_raw = "".join("KONTOR_OWNED_STACK_REPORT:" + json.dumps(sample) + "\n" for sample in owned)
        owned_raw += "KONTOR_OWNED_STACK_SUMMARY:" + json.dumps(owned_summary) + "\n"
        outputs = [subprocess.CompletedProcess([], 0, transcript(samples, summary), "") for samples, summary in ((worker, ws), (control, cs))]
        outputs.append(subprocess.CompletedProcess([], 0, owned_raw, ""))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with patch.object(qualify.subprocess, "run", side_effect=outputs) as run:
                result = qualify.qualify_case(Path("binary"), "paid_reenter", output, 600, 64, 1024)
            self.assertEqual(run.call_count, 3)
            worker_env, control_env, owned_env = [call.kwargs["env"] for call in run.call_args_list]
            self.assertEqual(worker_env["KONTOR_STACK_MODE"], "worker")
            self.assertNotIn("KONTOR_STACK_CONTROL_DEPTHS", worker_env)
            self.assertEqual(control_env["KONTOR_STACK_MODE"], "control")
            self.assertEqual(control_env["KONTOR_STACK_CONTROL_DEPTHS"], "63,64")
            self.assertEqual(owned_env["KONTOR_OWNED_DEPTHS"], "63,64")
            self.assertIn(qualify.OWNED_TEST_NAME, run.call_args_list[2].args[0])
            self.assertTrue((output / result["worker_log"]).is_file())
            self.assertTrue((output / result["control_log"]).is_file())
            self.assertTrue((output / result["owned_log"]).is_file())
            names = [sample["log"] for sample in result["observations"] + result["control_observations"]]
            self.assertEqual(len(names), len(set(names)))
            self.assertTrue(all((output / name).is_file() for name in names))

    def test_failed_worker_is_not_retried_and_control_is_not_started(self):
        samples, summary = reentry()
        for code in (-6, 1):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                completed = subprocess.CompletedProcess([], code, transcript(samples, summary), "failure")
                with patch.object(qualify.subprocess, "run", return_value=completed) as run:
                    with self.assertRaisesRegex(ValueError, "process exited"):
                        qualify.qualify_case(Path("binary"), "paid_reenter", output, 600, 64, 1024)
                self.assertEqual(run.call_count, 1)
                self.assertTrue((output / "paid_reenter-worker.log").read_text().endswith("failure"))

    def test_timeout_preserves_partial_transcript_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            error = subprocess.TimeoutExpired("binary", 600, output=b"partial", stderr=b"diagnostic")
            with patch.object(qualify.subprocess, "run", side_effect=error) as run:
                with self.assertRaisesRegex(ValueError, "timed out"):
                    qualify.qualify_case(Path("binary"), "paid_reenter", output, 600, 64, 1024)
            self.assertEqual(run.call_count, 1)
            self.assertEqual((output / "paid_reenter-worker.log").read_bytes(), b"partialdiagnostic")

    def test_single_recursion_case_does_not_require_reentry(self):
        result = {
            "kind": "paid_recurse",
            "boundary": "first_failure",
            "last_success": 3,
            "first_failure": 4,
            "first_failure_outcome": "stack_overflow",
        }
        self.assertTrue(qualify.acceptable_results([result]))

    def test_selected_reentry_still_requires_exact_boundary(self):
        result = {
            "kind": "paid_reenter",
            "boundary": "first_failure",
            "last_success": 62,
            "first_failure": 63,
            "first_failure_outcome": "invocation_limit",
        }
        self.assertFalse(qualify.acceptable_results([result]))
        result["last_success"] = 63
        result["first_failure"] = 64
        self.assertTrue(qualify.acceptable_results([result]))

    def test_resolved_features_preserve_raw_cargo_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "features.txt"
            with patch.object(qualify.subprocess, "check_output", return_value="pulley,async\n") as run:
                self.assertEqual(
                    qualify.resolved_features("aarch64-unknown-linux-gnu", "no-dev", path),
                    ["async", "pulley"],
                )
            self.assertEqual(path.read_text(), "pulley,async\n")
            self.assertIn("--target", run.call_args.args[0])
            with patch.object(qualify.subprocess, "check_output", return_value="pulley,pulley\n"):
                with self.assertRaises(ValueError):
                    qualify.resolved_features("aarch64-unknown-linux-gnu", "no-dev", path)


if __name__ == "__main__":
    unittest.main()
