import copy
import json
import tempfile
import unittest
from pathlib import Path

from run_workload_profile import check_ancestors, check_result, limits, trial_measurements


class ProfileChecks(unittest.TestCase):
    def test_trial_records_reject_missing_reset_wrong_owner_and_memory_pressure(self):
        enforced = {"cpu.max": "200000 100000", "memory.max": 12 * 1024**3,
                    "memory.swap.max": 0}
        sample = {"swap_current_bytes": 0, "memory_current_bytes": 1024,
                  "process_rss_bytes": 512, "memory_events": {
                      "high": 0, "max": 0, "oom": 0, "oom_kill": 0, "oom_group_kill": 0}}
        trials = [{"restore": name, "schema_version": 1, "pid": 100,
                   "cgroup": "/test", "peak_reset": "same_open_file_description",
                   "limits": {key: str(value) for key, value in enforced.items()},
                   "elapsed_ns": 1, "peak_bytes": 2048,
                   "before": copy.deepcopy(sample), "after": copy.deepcopy(sample)}
                  for name in ("timed-one.db", "timed-two.db")]

        def check(records):
            log = "\n".join("workload_trial_memory=" + json.dumps(item) for item in records)
            return trial_measurements(log, 100, Path("/test"), enforced)

        self.assertEqual(check(trials), trials)
        for records in ([], trials[:1], trials[::-1], trials + trials):
            with self.subTest(records=len(records)), self.assertRaises(ValueError):
                check(records)
        for key, value in (("pid", 101), ("cgroup", "/other"),
                           ("peak_reset", "reopened"), ("peak_bytes", 1023)):
            changed = copy.deepcopy(trials)
            changed[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                check(changed)
        for key in sample["memory_events"]:
            changed = copy.deepcopy(trials)
            changed[1]["after"]["memory_events"][key] = 1
            with self.subTest(counter=key), self.assertRaises(ValueError):
                check(changed)
        changed = copy.deepcopy(trials)
        changed[1]["before"]["swap_current_bytes"] = 1
        with self.assertRaises(ValueError):
            check(changed)

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
