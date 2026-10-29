"""Check frozen native page expectations and reject plausible cursor defects."""

import copy
import unittest

from resource_sqlite_pagination_evidence import (SAMPLES, expected_page,
                                                 validate_observation)


EVENTS = [
    {"id": 0, "role": "nested_chain", "kind": kind, "table_alive": alive}
    for kind, alive in (("reserved", None), ("store_created", None),
                        ("table_destroyed", False), ("lease_released", None))
]


def attempt(sample, role="target_observed"):
    page, cursor, size = expected_page(sample)
    source = sample.split("_", 1)[0]
    return {"case_id": "sqlite_pagination", "configuration": "production",
            "process_role": role, "sample_key": sample,
            "repeat_index": 0, "pid": 7,
            "observation": {
                "sample_key": sample, "outcome": "ok", "page": copy.deepcopy(page),
                "cursor": cursor, "page_size": size, "row_count": 1_024,
                "address": f"{source}:0:0",
                "execution_path": "Runtime::execute_api/Runtime::invoke",
                "system_fuel": 2_500, "user_fuel": 0, "deposit_fuel": 0,
                "state_before_sha256": "c" * 64,
                "state_after_sha256": "c" * 64,
                "receipts_before": 1, "receipts_after": 1,
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


class SqlitePaginationEvidenceTests(unittest.TestCase):
    def validate(self, item):
        return validate_observation(item, item["sample_key"], 0,
                                    item["process_role"], "production", 7)

    def test_accepts_all_declared_pages(self):
        self.assertEqual(len(SAMPLES), 18)
        for sample in SAMPLES:
            with self.subTest(sample=sample):
                self.validate(attempt(sample))

    def test_frozen_middle_and_final_boundaries(self):
        page, cursor, size = expected_page("token_7_middle")
        self.assertEqual(cursor, "10511")
        self.assertEqual(page["items"][0]["acc"], "10512")
        self.assertEqual(page["next"], "10518")
        self.assertEqual(size, 7)
        page, cursor, _ = expected_page("nft_100_final")
        self.assertEqual(cursor, "nft-0973")
        self.assertEqual(page["items"][0]["nft_id"], "nft-0974")
        self.assertEqual(page["items"][-1]["nft_id"], "nft-1023")
        self.assertIsNone(page["next"])

    def test_rejects_equal_length_missing_duplicate_and_shifted_rows(self):
        for sample in ("token_7_middle", "nft_100_final"):
            baseline = attempt(sample)
            for change in ("duplicate", "skip", "mutate_value"):
                with self.subTest(sample=sample, change=change):
                    item = copy.deepcopy(baseline)
                    rows = item["observation"]["page"]["items"]
                    if change == "duplicate":
                        rows[1] = copy.deepcopy(rows[0])
                    elif change == "skip":
                        rows.pop(1)
                        rows.append(copy.deepcopy(rows[-1]))
                    elif sample.startswith("token"):
                        rows[0]["amt"] = "2"
                    else:
                        rows[0]["agreement_id"] = "file-0000"
                    with self.assertRaises(ValueError):
                        self.validate(item)

    def test_rejects_continuation_cursor_and_store_defects(self):
        baseline = attempt("token_7_middle")
        for path, replacement in (("cursor", "10509"),
                                  ("page_size", 1),
                                  ("state_after_sha256", "d" * 64),
                                  ("live_invocations", 1)):
            with self.subTest(path=path):
                item = copy.deepcopy(baseline)
                item["observation"][path] = replacement
                with self.assertRaises(ValueError):
                    self.validate(item)
        item = copy.deepcopy(baseline)
        item["observation"]["page"]["next"] = "10519"
        with self.assertRaises(ValueError):
            self.validate(item)
        item = copy.deepcopy(baseline)
        item["observation"]["teardown_events"].pop()
        with self.assertRaises(ValueError):
            self.validate(item)


if __name__ == "__main__":
    unittest.main()
