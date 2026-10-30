import tempfile
import unittest
from pathlib import Path

from run_workload_profile import check_ancestors, check_result, limits


class ProfileChecks(unittest.TestCase):
    def test_requires_actual_cpu_memory_and_swap_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = {"cpu.max": "200000 100000", "memory.max": "12884901888",
                      "memory.swap.max": "0"}
            for name, value in values.items():
                (root / name).write_text(value)
            self.assertEqual(limits(root, 2, 12 * 1024**3)["memory.swap.max"], 0)
            for name, bad in (("cpu.max", "max 100000"),
                              ("cpu.max", "100000 100000"),
                              ("memory.max", "max"), ("memory.swap.max", "max")):
                with self.subTest(name=name, value=bad):
                    (root / name).write_text(bad)
                    with self.assertRaises(ValueError):
                        limits(root, 2, 12 * 1024**3)
                    (root / name).write_text(values[name])

    def test_rejects_host_slice_with_less_than_requested_resources(self):
        check_ancestors({"parent": {"cpu.max": "max 100000", "memory.max": "max"}},
                        8, 16 * 1024**3)
        check_ancestors({"parent": {"cpu.max": "800000 100000",
                                     "memory.max": str(16 * 1024**3)}},
                        8, 16 * 1024**3)
        for values in ({"cpu.max": "200000 100000"},
                       {"memory.max": str(12 * 1024**3)}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                check_ancestors({"parent": values}, 8, 16 * 1024**3)

    def test_zero_selected_ignored_or_failed_tests_cannot_pass(self):
        passed = "running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored;"
        check_result(passed, {"oom": 0}, {"oom": 0, "oom_kill": 0})
        for log in (passed.replace("running 1", "running 0"),
                    passed.replace("1 passed", "0 passed"),
                    passed.replace("0 ignored", "1 ignored"),
                    passed.replace("0 failed", "1 failed")):
            with self.subTest(log=log), self.assertRaises(ValueError):
                check_result(log, {}, {})
        with self.assertRaisesRegex(ValueError, "out-of-memory"):
            check_result(passed, {"oom_kill": 0}, {"oom_kill": 1})


if __name__ == "__main__":
    unittest.main()
