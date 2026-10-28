"""Reject chain evidence that does not prove the 64-Store boundary."""

import copy
import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from capture_resource_chain import (measured_trace, observation_from_trial,
                                    verify_final_closure)
from resource_manifest import ROOT


class ChainObservationTests(unittest.TestCase):
    def test_conversion_evidence_must_occur_inside_target_operation(self):
        names = (
            "chain_attempt_start", "chain_preparation_entry", "chain_preparation_exit",
            "chain_operation_entry", "chain_guest_task_entry",
            "canonical_input_entry", "canonical_input_exit",
            "canonical_output_entry", "canonical_output_exit",
            "chain_guest_task_exit", "chain_operation_exit",
            "chain_postcall_entry", "canonical_input_entry", "canonical_input_exit",
            "chain_postcall_exit", "chain_teardown_entry",
            "canonical_input_entry", "canonical_input_exit",
            "chain_teardown_exit",
            "chain_attempt_end",
        )
        events = [{"name": name, "thread_id": "worker-1", "os_thread_id": 201,
                   "category": "tokio_worker"}
                  for _ in range(3) for name in names]
        trace = {"scope": "paired_chain_target", "mode": "reduced",
                 "stores": 64, "events": events}
        runtime = {"scope": "paired_chain_target", "mode": "reduced", "stores": 64,
                   "pid": 100, "flavor": "multi_thread", "worker_count": 2,
                   "worker_requested_bytes": 1_048_576,
                   "thread_observations": [], "blocking_pool_observed": True,
                   "block_on_caller_observed": True}
        categories = {"tokio_worker": [
            {"thread_id": "worker-1", "os_thread_id": 201},
            {"thread_id": "worker-2", "os_thread_id": 202},
        ], "blocking_pool": [{"thread_id": "blocking", "os_thread_id": 203}]}
        with patch("capture_resource_chain.thread_capacities", return_value=categories):
            self.assertEqual(len(measured_trace(trace, runtime, "reduced", 64, 100)), 3)
            outside_only = copy.deepcopy(trace)
            outside_only["events"] = [event for index, event in
                                      enumerate(outside_only["events"])
                                      if index % len(names) not in (5, 6, 7, 8)]
            with self.assertRaisesRegex(ValueError, "canonical conversion"):
                measured_trace(outside_only, runtime, "reduced", 64, 100)
            escaped = copy.deepcopy(trace)
            escaped["events"][1:1] = [
                {"name": name, "thread_id": "worker-1", "os_thread_id": 201,
                 "category": "tokio_worker"}
                for name in ("canonical_input_entry", "canonical_input_exit")
            ]
            with self.assertRaisesRegex(ValueError, "conversion escaped named worker phases"):
                measured_trace(escaped, runtime, "reduced", 64, 100)

    def test_final_closure_rejects_source_and_manifest_drift(self):
        control = {"source_sha": "1" * 40, "manifest_sha256": "0" * 64}
        fake_git = [SimpleNamespace(stdout="2" * 40), SimpleNamespace(stdout="")]
        with patch("capture_resource_chain.subprocess.run", side_effect=fake_git):
            with self.assertRaisesRegex(ValueError, "source revision changed"):
                verify_final_closure(control, Path("unused"), Path("unused"),
                                     Path("unused"), "0" * 64)
        fake_git = [SimpleNamespace(stdout="1" * 40), SimpleNamespace(stdout="")]
        with patch("capture_resource_chain.subprocess.run", side_effect=fake_git):
            with self.assertRaisesRegex(ValueError, "resource manifest changed"):
                verify_final_closure(control, Path("unused"), Path("unused"),
                                     Path("unused"), "0" * 64)

    def test_peak_and_rollback_must_be_observed(self):
        balances = {"actor": "100", "burner": "0", "floor": "0", "supply": "1000"}
        digest = hashlib.sha256(json.dumps(
            balances, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        state = "1" * 64
        trial = {
            "sample_key": "target", "outcome": "invocation_limit",
            "live_stores_before": 0, "live_stores_after": 0,
            "live_store_peak": 64, "rolled_back": True,
            "savepoint_restored": True, "stack_empty": True,
            "rollback_clean": True, "resource_count": 0,
            "baseline_resource_count": 0, "state_before_sha256": state,
            "state_after_sha256": state, "balances_snapshot": balances,
            "balances_sha256": digest,
            "receipt": {"contract_id": 70, "status": "Other", "gas": 1, "value": None},
            "receipt_count": 1, "value": None,
            "storage_state": "[0, 0, 0, 0]", "host_io_suspended": False,
            "leaf_callback_seen": False,
            "fuel": {"user": 1, "system": 0, "deposit": 0},
        }
        schema = json.loads((ROOT / "tools/native-stack/resource-evidence-schema-v1.json").read_text())
        observed = observation_from_trial(trial, "chain_65_paid", "invocation_limit", schema)
        self.assertEqual(observed["live_stores"]["during"], 64)
        self.assertEqual(observed["reservations"]["during"], 64)
        self.assertIsNone(observed["resource_cleanup"]["invocation_table_released"])
        for key, value in (("live_store_peak", 63),
                           ("state_after_sha256", "2" * 64),
                           ("rollback_clean", False)):
            changed = copy.deepcopy(trial)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                observation_from_trial(changed, "chain_65_paid", "invocation_limit", schema)


if __name__ == "__main__":
    unittest.main()
