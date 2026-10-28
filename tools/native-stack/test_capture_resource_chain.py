"""Reject incomplete paired chain and measured trap-control evidence."""

import copy
import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from capture_resource_chain import (CHAIN_MODES, CHAIN_STORES, balance_amounts,
                                    check_run_consistency, cross_mode_initial_states,
                                    measured_trace, observation_from_trial,
                                    verify_final_closure)
from resource_manifest import ROOT


def trial_fixture(mode, stores, outcome, sample_key="target"):
    balances = {"actor": "100", "burner": "0", "floor": "5", "supply": "1000"}
    digest = hashlib.sha256(json.dumps(
        balances, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    paid = mode == "paid"
    success = outcome == "ok"
    return {
        "sample_key": sample_key, "outcome": outcome,
        "error_class": None if success else "deterministic",
        "trap": "UnreachableCodeReached" if outcome == "trap" else None,
        "live_stores_before": 0, "live_stores_after": 0,
        "live_store_peak": min(stores, 64), "rolled_back": True,
        "savepoint_restored": True, "stack_empty": True,
        "rollback_clean": True, "resource_count": 0,
        "baseline_resource_count": 0, "state_before_sha256": "1" * 64,
        "state_after_sha256": "1" * 64, "balances_snapshot": balances,
        "balances_sha256": digest,
        "balances": {"before": "100", "after": "90" if paid else "100",
                     "restored": "100", "burned_before": "0",
                     "burned_after": "10" if paid else "0",
                     "supply_before": "1000", "supply_after": "990" if paid else "1000",
                     "floor_before": "5",
                     "floor_after": "4" if mode == "core" and success else "5",
                     "floor_restored": "5"},
        "receipt": None if mode == "view" else {
            "contract_id": 70, "status": "Ok" if success else "Other",
            "gas": 1, "value": "42" if success else None,
        },
        "receipt_count": 0 if mode == "view" else stores if success else 1,
        "value": "42" if success else None,
        "storage_state": "[2, 0, 0, 0]" if success and mode != "view"
                         else "[0, 0, 0, 0]",
        "host_io_suspended": outcome != "invocation_limit",
        "leaf_callback_seen": outcome != "invocation_limit",
        "fuel": {"user": 1 if paid else 0, "system": 0 if paid else 1,
                 "deposit": 0},
    }


def normalized_transitions(trial, case_id):
    return {key: str(value) for key, value in
            balance_amounts(trial["balances"], case_id).items()}


class ChainObservationTests(unittest.TestCase):
    def test_cross_mode_initial_state_requires_specific_fixture_reason(self):
        captured = {
            f"chain_{stores}_{mode}_reduced": {
                "observations": [{"state": {"before_sha256": "a" * 64}}],
            }
            for stores in CHAIN_STORES for mode in CHAIN_MODES
        }
        captured["chain_33_core_reduced"]["observations"][0]["state"]["before_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "cross-mode initial state needs a fixture reason"):
            cross_mode_initial_states(captured, {})
        reason = "Core fixture seeds a separate prestate row."
        summary = cross_mode_initial_states(captured, {(33, "core"): reason})
        self.assertFalse(summary["33"]["comparisons"]["core"]["matches_paid"])
        self.assertEqual(summary["33"]["comparisons"]["core"]["fixture_reason"], reason)
        self.assertTrue(summary["64"]["comparisons"]["view"]["matches_paid"])

    def test_control_requires_same_full_prestate_as_paired_target(self):
        success = {"state": {"before_sha256": "a" * 64}, "fuel": {"user": 10}}
        trap = {"outcome": "trap", "trap": "UnreachableCodeReached"}
        transitions = {"after": "90"}
        captured = {"chain_64_paid_reduced": {
            "observations": [copy.deepcopy(success) for _ in range(3)],
            "balance_transitions": [copy.deepcopy(transitions) for _ in range(3)],
        }}
        control = {"observations": [copy.deepcopy(success), trap, copy.deepcopy(success)],
                   "balance_transitions": [copy.deepcopy(transitions) for _ in range(3)]}
        check_run_consistency(captured, "chain_64_paid", "reduced", True, control)
        changed = copy.deepcopy(control)
        changed["observations"][0]["state"]["before_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "target and control prestate"):
            check_run_consistency(captured, "chain_64_paid", "reduced", True, changed)
        captured["chain_64_paid_trap_control_reduced"] = control
        captured["chain_64_paid_production"] = captured["chain_64_paid_reduced"]
        changed = copy.deepcopy(control)
        changed["observations"][1]["trap"] = None
        with self.assertRaisesRegex(ValueError, "full observations differ"):
            check_run_consistency(captured, "chain_64_paid", "production", True, changed)

    def test_financial_transitions_participate_in_strict_pairing(self):
        schema = json.loads((ROOT / "tools/native-stack/resource-evidence-schema-v1.json").read_text())
        for mode in ("paid", "core"):
            case_id = f"chain_64_{mode}"
            baseline = trial_fixture(mode, 64, "ok")
            changed = copy.deepcopy(baseline)
            if mode == "paid":
                changed["balances"].update(after="80", burned_after="20", supply_after="980")
            else:
                changed["balances"]["floor_after"] = "3"
            first = observation_from_trial(baseline, case_id, "ok", schema)
            second = observation_from_trial(changed, case_id, "ok", schema)
            self.assertEqual(first, second)
            captured = {f"{case_id}_reduced": {
                "observations": [first] * 3,
                "balance_transitions": [normalized_transitions(baseline, case_id)] * 3,
            }}
            detail = {"observations": [second] * 3,
                      "balance_transitions": [normalized_transitions(changed, case_id)] * 3}
            with self.subTest(mode=mode), self.assertRaisesRegex(
                ValueError, "full observations differ",
            ):
                check_run_consistency(captured, case_id, "production", False, detail)

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
        trace = {"scope": "paired_chain_worker", "mode": "reduced",
                 "stores": 64, "chain_mode": "paid", "trap_control": False,
                 "events": events}
        runtime = {"scope": "paired_chain_worker", "mode": "reduced", "stores": 64,
                   "chain_mode": "paid", "trap_control": False,
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
            migrated = copy.deepcopy(trace)
            migrated["events"][6]["thread_id"] = "worker-2"
            migrated["events"][6]["os_thread_id"] = 202
            with self.assertRaisesRegex(ValueError, "unmatched canonical conversion"):
                measured_trace(migrated, runtime, "reduced", 64, 100)
            control = copy.deepcopy(trace)
            control["trap_control"] = True
            control_runtime = {**runtime, "trap_control": True}
            control["events"] = [event for index, event in enumerate(control["events"])
                                 if index // len(names) != 1
                                 or index % len(names) not in (7, 8)]
            self.assertEqual([attempt["sample_key"] for attempt in measured_trace(
                control, control_runtime, "reduced", 64, 100, "paid", True,
                ("target", "trap_control", "target"),
            )], ["target", "trap_control", "target"])

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
        trial = trial_fixture("paid", 65, "invocation_limit")
        schema = json.loads((ROOT / "tools/native-stack/resource-evidence-schema-v1.json").read_text())
        observed = observation_from_trial(trial, "chain_65_paid", "invocation_limit", schema)
        self.assertEqual(observed["live_stores"]["during"], 64)
        self.assertEqual(observed["reservations"]["during"], 64)
        self.assertIsNone(observed["resource_cleanup"]["invocation_table_released"])
        for key, value in (("live_store_peak", 63),
                           ("state_after_sha256", "2" * 64),
                           ("rollback_clean", False),
                           ("trap", "UnreachableCodeReached")):
            changed = copy.deepcopy(trial)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                observation_from_trial(changed, "chain_65_paid", "invocation_limit", schema)

    def test_view_core_and_trap_economics_are_checked(self):
        schema = json.loads((ROOT / "tools/native-stack/resource-evidence-schema-v1.json").read_text())
        for mode in ("view", "core"):
            trial = trial_fixture(mode, 64, "ok")
            observation = observation_from_trial(trial, f"chain_64_{mode}", "ok", schema)
            self.assertEqual(len(observation["receipts"]), 0 if mode == "view" else 1)
            changed = copy.deepcopy(trial)
            changed["balances"]["after"] = "99"
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "balance transition"):
                observation_from_trial(changed, f"chain_64_{mode}", "ok", schema)
        trap = trial_fixture("paid", 64, "trap", "trap_control")
        observation = observation_from_trial(
            trap, "chain_64_paid", "trap", schema, "trap_control",
        )
        self.assertEqual(observation["trap"], "UnreachableCodeReached")
        trap["trap"] = None
        with self.assertRaisesRegex(ValueError, "typed outcome"):
            observation_from_trial(trap, "chain_64_paid", "trap", schema, "trap_control")


if __name__ == "__main__":
    unittest.main()
