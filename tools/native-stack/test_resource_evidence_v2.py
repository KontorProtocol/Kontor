"""Exercise v2 process identity and per-Store teardown rejection paths."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from resource_evidence_v2 import (expected_case_env, historical_semantics,
                                  marker_positions, validate_process_record,
                                  validate_teardown)
from resource_manifest_v2 import MANIFEST, SCHEMA, build_manifest_v2


def store_events(count, role="nested_chain", depth_gate=False):
    events = []
    for identifier in range(count):
        events.extend([
            {"id": identifier, "role": role, "kind": "reserved", "table_alive": None},
            {"id": identifier, "role": role, "kind": "store_created", "table_alive": None},
        ])
    if depth_gate:
        events.append({"id": None, "role": "nested_chain",
                       "kind": "depth_gate_rejected", "table_alive": None})
    for identifier in reversed(range(count)):
        events.extend([
            {"id": identifier, "role": role, "kind": "table_destroyed",
             "table_alive": False},
            {"id": identifier, "role": role, "kind": "lease_released",
             "table_alive": None},
        ])
    return events


def process_run():
    case_id = "chain_64_paid"
    role = "target_observed"
    configuration = "reduced"
    argv = ["/tmp/chain-test", "--ignored", "--exact",
            "runtime::call::tests::native_stack_resource::chain_worker_case",
            "--nocapture"]
    return {
        "run_id": f"{case_id}_{role}_{configuration}", "case_id": case_id,
        "process_role": role, "configuration": configuration,
        "process_attempt_index": 0, "argv": argv,
        "case_env": expected_case_env(case_id, role, configuration),
        "binary_sha256_before": "a" * 64, "binary_sha256_after": "a" * 64,
        "process": {"pid": 10, "command": argv, "started_unix_ns": 100,
                    "ended_unix_ns": 200, "exit_code": 0, "signal": None,
                    "timed_out": False, "complete": True,
                    "test_harness_passed": True},
    }


class EvidenceV2Tests(unittest.TestCase):
    def test_manifest_has_all_role_and_trial_bindings(self):
        manifest = build_manifest_v2()
        self.assertEqual(json.loads(MANIFEST.read_text()), manifest)
        self.assertEqual(len(manifest["case_roles"]), 30)
        self.assertEqual(len(manifest["remaining_case_ids"]), 29)
        self.assertEqual(manifest["auxiliary_count_status"], "pilot_pending")
        self.assertEqual(sum(len(item["trials"]) for item in manifest["case_roles"]), 90)
        self.assertTrue(all(item["nested_chain_created"] in (33, 63, 64)
                            for item in manifest["case_roles"]))

    def test_teardown_closes_per_id_even_when_nested(self):
        result = validate_teardown(store_events(64, depth_gate=True), 64, 1)
        self.assertEqual(result["created"]["nested_chain"], 64)
        self.assertEqual(result["alive_after_teardown_count"], 0)

    def test_teardown_rejects_retained_missing_reordered_and_unknown(self):
        base = store_events(2)
        invalid = []
        retained = copy.deepcopy(base)
        retained[4]["table_alive"] = True
        invalid.append(retained)
        invalid.append(base[:-1])
        duplicate = copy.deepcopy(base)
        duplicate.append(copy.deepcopy(base[-1]))
        invalid.append(duplicate)
        reordered = copy.deepcopy(base)
        reordered[4], reordered[5] = reordered[5], reordered[4]
        invalid.append(reordered)
        unassigned = copy.deepcopy(base)
        unassigned[0]["role"] = "unassigned"
        invalid.append(unassigned)
        no_store = copy.deepcopy(base)
        no_store[1]["kind"] = "lease_released"
        invalid.append(no_store)
        failed_initialization = copy.deepcopy(base)
        failed_initialization.insert(2, {"id": 0, "role": "nested_chain",
                                         "kind": "store_initialization_failed",
                                         "table_alive": None})
        invalid.append(failed_initialization)
        for events in invalid:
            with self.subTest(events=events):
                with self.assertRaises(ValueError):
                    validate_teardown(events, 2, 0)

    def test_process_rejects_failure_drift_and_unexpected_env(self):
        base = process_run()
        validate_process_record(base)
        mutations = (
            ("process", "timed_out", True),
            ("process", "signal", 9),
            ("process", "exit_code", 1),
            ("process", "started_unix_ns", 300),
            ("binary_sha256_after", None, "b" * 64),
            ("process_attempt_index", None, 1),
        )
        for outer, inner, value in mutations:
            changed = copy.deepcopy(base)
            if inner is None:
                changed[outer] = value
            else:
                changed[outer][inner] = value
            with self.subTest(field=(outer, inner)):
                with self.assertRaises(ValueError):
                    validate_process_record(changed)
        changed = copy.deepcopy(base)
        changed["case_env"]["KONTOR_CHAIN_DEPTH"] = "100"
        with self.assertRaisesRegex(ValueError, "environment"):
            validate_process_record(changed)

    def test_marker_order_and_duplicates(self):
        report = {"mode": "paid", "stores": 64,
                  "trials": [{"sample_key": "target", "repeat_index": i}
                             for i in range(3)]}
        lines = ["CHAIN_PROBE_REPORT:{}", "CHAIN_PROBE_COMPLETE mode=paid stores=64",
                 "KONTOR_CHAIN_WORKER_RUNTIME={}", "KONTOR_CHAIN_WORKER_TRACE={}",
                 "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 1.0s"]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "child.log"
            path.write_text("\n".join(lines))
            self.assertEqual(marker_positions(path, report)["trial_keys"][1]["repeat_index"], 1)
            for bad in (lines + [lines[0]], [lines[1], lines[0], *lines[2:]]):
                path.write_text("\n".join(bad))
                with self.assertRaises(ValueError):
                    marker_positions(path, report)

    def test_schema_rejects_unknown_nested_fields_and_v1(self):
        schema = json.loads(SCHEMA.read_text())
        Draft202012Validator.check_schema(schema)
        self.assertFalse(Draft202012Validator(schema).is_valid({"schema_version": 1}))
        validator = Draft202012Validator({"$ref": "#/$defs/v2_teardown_event",
                                          "$defs": schema["$defs"]})
        event = store_events(1)[0]
        self.assertTrue(validator.is_valid(event))
        self.assertFalse(validator.is_valid({**event, "unexpected": True}))

    def test_historical_comparison_excludes_only_provenance_sensitive_full_db(self):
        observation = {"state": {"before_sha256": "a", "after_sha256": "a",
                                 "balances_sha256": "x", "marker": "m"},
                       "resource_cleanup": {"invocation_table_released": True},
                       "fuel": {"user": 1}}
        changed = copy.deepcopy(observation)
        changed["state"].update(before_sha256="b", after_sha256="b")
        self.assertEqual(historical_semantics([observation]),
                         historical_semantics([changed]))
        changed["fuel"]["user"] = 2
        self.assertNotEqual(historical_semantics([observation]),
                            historical_semantics([changed]))


if __name__ == "__main__":
    unittest.main()
