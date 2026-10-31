"""Check bounded range oracles and reject changed rows and Store state."""

import copy
import unittest

from resource_sqlite_ranges_evidence import (COMPONENT_SHA256, SAMPLES,
                                             expected_rows, validate_observation)


def teardown_events():
    return [
        {"id": identity, "role": "nested_chain", "kind": kind,
         "table_alive": False if kind == "table_destroyed" else None}
        for identity in (0, 1)
        for kind in ("reserved", "store_created", "table_destroyed",
                     "lease_released")
    ]


def attempt(sample, role="target_observed"):
    lower, upper, size, ascending, descending = expected_rows(sample)
    return {"case_id": "sqlite_ranges", "configuration": "production",
            "process_role": role, "sample_key": sample,
            "repeat_index": 0, "pid": 7,
            "observation": {
                "sample_key": sample, "outcome": "ok",
                "lower": lower, "upper": upper, "page_size": size,
                "row_count": 1_024, "ascending": ascending,
                "descending": descending, "address": "arith:1:0",
                "ascending_value_type": "integer",
                "descending_value_type": "decimal",
                "bound_semantics": "included_lower_excluded_upper",
                "component_sha256": COMPONENT_SHA256,
                "publication_path": "Runtime::publish/native_provenance",
                "execution_path": "Runtime::execute/Runtime::invoke",
                "system_fuel": 2_500, "user_fuel": 0, "deposit_fuel": 0,
                "state_before_sha256": "c" * 64,
                "state_after_sha256": "c" * 64,
                "receipts_before": 1, "receipts_after": 1,
                "resources_before": 0, "resources_after": 0,
                "stack_empty": True, "savepoint_empty": True,
                "live_invocations": 0,
                "teardown_probe_on": role == "target_observed",
                "teardown_events": teardown_events()
                if role == "target_observed" else None,
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": 524_288,
                "async_stack_size": 2_097_152,
            }}


class SqliteRangesEvidenceTests(unittest.TestCase):
    def validate(self, item):
        return validate_observation(item, item["sample_key"], 0,
                                    item["process_role"], "production", 7)

    def test_accepts_every_declared_window_and_page(self):
        self.assertEqual(len(SAMPLES), 12)
        for sample in SAMPLES:
            with self.subTest(sample=sample):
                self.validate(attempt(sample))

    def test_empty_singleton_and_large_window_edges(self):
        self.assertEqual(expected_rows("page_7_range_0"),
                         (512, 512, 7, [], []))
        self.assertEqual(expected_rows("page_7_range_1"),
                         (511, 512, 7, ["511:1511"], ["511:511.5"]))
        lower, upper, size, ascending, descending = expected_rows(
            "page_100_range_1024")
        self.assertEqual((lower, upper, size), (0, 1024, 100))
        self.assertEqual((ascending[0], ascending[-1]),
                         ("0:1000", "99:1099"))
        self.assertEqual((descending[0], descending[-1]),
                         ("1023:1023.5", "924:924.5"))

    def test_rejects_equal_length_skip_duplicate_and_changed_value(self):
        for direction in ("ascending", "descending"):
            for change in ("duplicate", "skip", "value"):
                with self.subTest(direction=direction, change=change):
                    item = attempt("page_7_range_256")
                    rows = item["observation"][direction]
                    if change == "duplicate":
                        rows[1] = rows[0]
                    elif change == "skip":
                        rows.pop(1)
                        rows.append(rows[-1])
                    else:
                        rows[0] += "0"
                    with self.assertRaises(ValueError):
                        self.validate(item)

    def test_rejects_bounds_state_and_store_defects(self):
        baseline = attempt("page_100_range_1024")
        for key, replacement in (("lower", 1), ("upper", 1023),
                                 ("page_size", 7),
                                 ("component_sha256", "d" * 64),
                                 ("ascending_value_type", "decimal"),
                                 ("state_after_sha256", "d" * 64),
                                 ("live_invocations", 1)):
            with self.subTest(key=key):
                item = copy.deepcopy(baseline)
                item["observation"][key] = replacement
                with self.assertRaises(ValueError):
                    self.validate(item)
        item = copy.deepcopy(baseline)
        item["observation"]["teardown_events"].pop()
        with self.assertRaises(ValueError):
            self.validate(item)

    def test_probe_off_has_no_teardown_events(self):
        self.validate(attempt("page_7_range_256", "probe_off_control"))


if __name__ == "__main__":
    unittest.main()
