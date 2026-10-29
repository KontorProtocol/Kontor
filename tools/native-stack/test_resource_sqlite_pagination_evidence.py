"""Check frozen native page expectations and reject plausible cursor defects."""

import copy
import unittest
from unittest.mock import patch

from resource_sqlite_pagination_evidence import (SAMPLES, expected_page,
                                                 validate_observation,
                                                 validate_trace)


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
        token_final, _, _ = expected_page("token_100_final")
        self.assertEqual(token_final["items"][-1],
                         {"acc": "7", "amt": "1000000000"})
        self.assertEqual(page["items"][-1]["owner"], "7")

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

    def test_accepts_output_scope_migration_between_measured_workers(self):
        def event(name, worker=1, category="tokio_worker"):
            return {"name": name, "thread_id": worker,
                    "os_thread_id": worker + 10, "category": category}

        events = [event("fixture_preparation_entry"),
                  event("compiler_entry"), event("compiler_exit"),
                  event("blocking_decode_entry", 3, "blocking_pool"),
                  event("blocking_decode_exit", 3, "blocking_pool"),
                  event("fixture_preparation_exit")]
        attempts = [{"sample_key": sample} for sample in SAMPLES
                    for _ in range(2)]
        for index, _ in enumerate(attempts):
            if index == 18:
                events.extend((event("fixture_preparation_entry"),
                               event("fixture_preparation_exit")))
            events.extend((event("finite_stack_attempt_start"),
                           event("canonical_input_entry"),
                           event("canonical_input_exit"),
                           event("canonical_output_entry"),
                           event("canonical_output_exit", 2),
                           event("finite_stack_attempt_end", 2)))
        identity = {"scope": "paired_finite_stack_worker",
                    "configuration": "production", "case_id": "sqlite_pagination",
                    "process_role": "target_observed"}
        runtime = {**identity, "pid": 7, "embedded_source_sha": "a" * 64,
                   "binary_sha256": "b" * 64,
                   "thread_observations": [{"page_size_bytes": 4096}]}
        trace = {**identity, "events": events}
        threads = {"tokio_worker": [{"thread_id": 1, "os_thread_id": 11},
                                    {"thread_id": 2, "os_thread_id": 12}],
                   "blocking_pool": [{"thread_id": 3, "os_thread_id": 13}]}
        with patch("resource_sqlite_pagination_evidence.thread_capacities",
                   return_value=threads):
            validate_trace(trace, runtime, attempts, "linux")
            bad = copy.deepcopy(trace)
            bad["events"].pop(-2)
            with self.assertRaises(ValueError):
                validate_trace(bad, runtime, attempts, "linux")
            crossing = copy.deepcopy(trace)
            crossing_events = crossing["events"]
            first_exit = next(index for index, item in enumerate(crossing_events)
                              if item["name"] == "canonical_output_exit")
            moved = crossing_events.pop(first_exit)
            second_entry = [index for index, item in enumerate(crossing_events)
                            if item["name"] == "canonical_output_entry"][1]
            crossing_events.insert(second_entry + 1, moved)
            with self.assertRaises(ValueError):
                validate_trace(crossing, runtime, attempts, "linux")
            overlap = copy.deepcopy(trace)
            overlap_events = overlap["events"]
            input_exit = next(index for index, item in enumerate(overlap_events)
                              if item["name"] == "canonical_input_exit")
            output_entry = next(index for index, item in enumerate(overlap_events)
                                if item["name"] == "canonical_output_entry")
            overlap_events[input_exit], overlap_events[output_entry] = (
                overlap_events[output_entry], overlap_events[input_exit])
            with self.assertRaises(ValueError):
                validate_trace(overlap, runtime, attempts, "linux")
            reversed_output = copy.deepcopy(trace)
            reverse_events = reversed_output["events"]
            output_entry = next(index for index, item in enumerate(reverse_events)
                                if item["name"] == "canonical_output_entry")
            output_exit = next(index for index, item in enumerate(reverse_events)
                               if item["name"] == "canonical_output_exit")
            reverse_events[output_entry], reverse_events[output_exit] = (
                reverse_events[output_exit], reverse_events[output_entry])
            with self.assertRaises(ValueError):
                validate_trace(reversed_output, runtime, attempts, "linux")


if __name__ == "__main__":
    unittest.main()
