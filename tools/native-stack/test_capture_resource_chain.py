"""Reject chain evidence that does not prove the 64-Store boundary."""

import copy
import hashlib
import json
import unittest

from capture_resource_chain import observation_from_trial
from resource_manifest import ROOT


class ChainObservationTests(unittest.TestCase):
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
        for key, value in (("live_store_peak", 63),
                           ("state_after_sha256", "2" * 64),
                           ("rollback_clean", False)):
            changed = copy.deepcopy(trial)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                observation_from_trial(changed, "chain_65_paid", "invocation_limit", schema)


if __name__ == "__main__":
    unittest.main()
