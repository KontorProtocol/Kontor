"""Reject missing large values, cursor shifts, and false paid rollback claims."""

import copy
import unittest

from resource_sqlite_large_values_evidence import (COMPONENT_SHA256, SAMPLES,
                                                   expected_page,
                                                   validate_observation)


EVENTS = [
    {"id": 0, "role": "nested_chain", "kind": kind,
     "table_alive": False if kind == "table_destroyed" else None}
    for kind in ("reserved", "store_created", "table_destroyed", "lease_released")
]


def paid_rejection():
    return {"outcome": "deterministic_error",
            "error": "storage deposit exceeds the op's gas budget",
            "key": "k999", "row_absent": True,
            "state_before_sha256": "a" * 64,
            "state_after_sha256": "b" * 64,
            "receipts_before": 10, "receipts_after": 11}


def attempt(sample, role="target_observed"):
    rows, cursor, continuation, page_size, value_bytes = expected_page(sample)
    return {"case_id": "sqlite_large_values", "configuration": "production",
            "process_role": role, "sample_key": sample,
            "repeat_index": 0, "pid": 7,
            "observation": {
                "sample_key": sample, "outcome": "ok",
                "page_size": page_size, "value_bytes": value_bytes,
                "row_count": 101, "items": rows, "cursor": cursor,
                "next": continuation, "large_key": "k050",
                "setup_provenance": "paid" if value_bytes == 16_384
                else "core_after_paid_rejection",
                "paid_rejection": paid_rejection() if value_bytes == 1_048_576
                else None,
                "address": "counter:1:0",
                "component_sha256": COMPONENT_SHA256,
                "publication_path": "Runtime::publish/native_provenance",
                "execution_path": "Runtime::execute/Runtime::invoke",
                "system_fuel": 2_500, "user_fuel": 0, "deposit_fuel": 0,
                "state_before_sha256": "c" * 64,
                "state_after_sha256": "c" * 64,
                "receipts_before": 12, "receipts_after": 12,
                "resources_before": 0, "resources_after": 0,
                "stack_empty": True, "savepoint_empty": True,
                "live_invocations": 0,
                "teardown_probe_on": role == "target_observed",
                "teardown_events": copy.deepcopy(EVENTS)
                if role == "target_observed" else None,
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": 524_288,
                "async_stack_size": 2_097_152,
            }}


class SqliteLargeValuesEvidenceTests(unittest.TestCase):
    def validate(self, item):
        return validate_observation(item, item["sample_key"], 0,
                                    item["process_role"], "production", 7)

    def test_accepts_all_declared_pages_and_both_setup_provenances(self):
        self.assertEqual(len(SAMPLES), 6)
        for sample in SAMPLES:
            with self.subTest(sample=sample):
                self.validate(attempt(sample))

    def test_large_row_and_cursor_position_are_frozen(self):
        for value_bytes in (16_384, 1_048_576):
            for page_size, cursor, next_key in ((1, "k049", "k050"),
                                                (7, "k046", "k053"),
                                                (100, None, "k099")):
                with self.subTest(value_bytes=value_bytes, page_size=page_size):
                    rows, actual_cursor, actual_next, _, _ = expected_page(
                        f"value_{value_bytes}_page_{page_size}")
                    self.assertEqual((actual_cursor, actual_next),
                                     (cursor, next_key))
                    self.assertEqual([row for row in rows if row["key"] == "k050"]
                                     [0]["value_bytes"], value_bytes)

    def test_rejects_changed_value_missing_row_and_cursor(self):
        baseline = attempt("value_1048576_page_7")
        for change in ("hash", "length", "duplicate", "skip", "cursor", "next"):
            with self.subTest(change=change):
                item = copy.deepcopy(baseline)
                observed = item["observation"]
                rows = observed["items"]
                if change == "hash":
                    rows[3]["value_sha256"] = "0" * 64
                elif change == "length":
                    rows[3]["value_bytes"] = 16_384
                elif change == "duplicate":
                    rows[1] = copy.deepcopy(rows[0])
                elif change == "skip":
                    rows.pop(1)
                    rows.append(copy.deepcopy(rows[-1]))
                elif change == "cursor":
                    observed["cursor"] = "k045"
                else:
                    observed["next"] = "k054"
                with self.assertRaises(ValueError):
                    self.validate(item)

    def test_rejects_false_paid_cap_and_state_claims(self):
        baseline = attempt("value_1048576_page_1")
        for key, replacement in (("row_absent", False),
                                 ("outcome", "ok"),
                                 ("error", "out of fuel"),
                                 ("receipts_after", 9)):
            with self.subTest(key=key):
                item = copy.deepcopy(baseline)
                item["observation"]["paid_rejection"][key] = replacement
                with self.assertRaises(ValueError):
                    self.validate(item)
        item = copy.deepcopy(baseline)
        item["observation"]["state_after_sha256"] = "d" * 64
        with self.assertRaises(ValueError):
            self.validate(item)

    def test_rejects_store_leak_and_probe_off_events(self):
        item = attempt("value_16384_page_100")
        item["observation"]["teardown_events"].pop()
        with self.assertRaises(ValueError):
            self.validate(item)
        self.validate(attempt("value_16384_page_100", "probe_off_control"))


if __name__ == "__main__":
    unittest.main()
