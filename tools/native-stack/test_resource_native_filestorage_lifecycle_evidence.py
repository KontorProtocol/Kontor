"""Reject incorrect filestorage lifecycle semantics and incomplete Store teardown."""

import copy
import unittest

from resource_native_filestorage_lifecycle_evidence import (
    validate_observation, validate_operation_phases)


def teardown(roles):
    return [{"id": index, "role": role, "kind": kind,
             "table_alive": False if kind == "table_destroyed" else None}
            for index, role in enumerate(roles)
            for kind in ("reserved", "store_created", "table_destroyed",
                         "lease_released")]


def attempt(sample):
    cleanup = sample == "cleanup"
    count = 3 if cleanup else 32
    files = 40 if cleanup else 32
    agreements = [f"agreement-{index:02d}" for index in range(files)]
    active_before = agreements[32:] if cleanup else agreements
    penalty = 960 if sample == "penalty" else 0
    function = "expire-challenges" if sample == "expiry" else "settle-expired-challenges"
    pairs = ([("token", "burn"), ("staking", "slash")] * 32
             if sample == "penalty" else [])
    pairs.append(("filestorage", function))
    receipts = []
    for index, (contract, receipt_function) in enumerate(pairs):
        value = ("ok({src: signer-id(4), amt: 1})" if contract == "token" else
                 "ok({burned: 1})" if contract == "staking" else
                 "32" if sample == "expiry" else
                 "ok(32)" if sample == "penalty" else "ok(9)")
        receipts.append({
            "contract": contract, "function": receipt_function,
            "status": "Ok", "gas": 100, "size": len(value), "value": value,
            "signer_id": 4 if contract == "token" else 1,
            "payer_signer_id": 1 if contract == "filestorage" else None,
            "height": 2016, "tx_id": None, "input_index": None,
            "op_index": None, "result_index": index})
    roles = (["nested_chain"] * (33 if sample == "penalty" else 1)
             + ["target_native_auxiliary"] * (32 if sample == "penalty" else 0))
    return {"case_id": "native_filestorage_lifecycle",
            "configuration": "production", "process_role": "target_observed",
            "sample_key": sample, "repeat_index": 0, "pid": 7,
            "observation": {
                "sample_key": sample, "outcome": "ok",
                "processed": 9 if cleanup else 32,
                "challenge_count": count, "file_count": files,
                "challenge_ids": [f"challenge-{index}" for index in range(count)],
                "agreements": agreements,
                "requirements": ["1"] * files,
                "active_agreements_before": active_before,
                "active_agreements_after": [] if cleanup else agreements,
                "statuses_before":
                    ["Settled" if cleanup else
                     "Active" if sample == "expiry" else "Expired"] * count,
                "statuses_after":
                    ["Expired" if sample == "expiry" else "Settled"] * count,
                "stake_before": "0" if cleanup else "9000",
                "stake_after": "0" if cleanup else str(9000 - penalty),
                "supply_before": "30000", "supply_after": str(30000 - penalty),
                "penalty_total": str(penalty),
                "reservation_before": "8" if cleanup else "32",
                "reservation_after": "0" if cleanup else "32",
                "pending_before": cleanup, "pending_after": False,
                "obligations_before": True,
                "obligations_after": not cleanup,
                "memberships_before": 8 if cleanup else files,
                "memberships_after": 0 if cleanup else files,
                "system_fuel": 100, "user_fuel": 0, "deposit_fuel": 0,
                "state_before_sha256": "a" * 64,
                "state_after_sha256": "b" * 64,
                "state_restored_sha256": "a" * 64,
                "receipts_before": 10,
                "receipts_after": 10 + len(receipts),
                "measured_receipts": receipts, "receipts_restored": 10,
                "resources_before": 0, "resources_after": 0,
                "stack_empty": True, "savepoint_restored": True,
                "savepoint_empty": True, "live_invocations": 0,
                "teardown_probe_on": True, "teardown_events": teardown(roles),
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": 524_288,
                "async_stack_size": 2_097_152}}


class FilestorageLifecycleEvidenceTests(unittest.TestCase):
    def validate(self, item):
        return validate_observation(item, item["sample_key"], 0,
                                    "target_observed", "production", 7)

    def test_accepts_all_three_frozen_samples(self):
        for sample in ("expiry", "penalty", "cleanup"):
            with self.subTest(sample=sample):
                self.validate(attempt(sample))

    def test_rejects_budget_and_transition_drift(self):
        for sample, key, value in (
            ("expiry", "processed", 31),
            ("expiry", "statuses_after", ["Active"] * 32),
            ("penalty", "processed", 33),
            ("penalty", "stake_after", "9000"),
            ("penalty", "supply_after", "30000"),
            ("penalty", "penalty_total", "0"),
            ("cleanup", "processed", 8),
            ("cleanup", "memberships_after", 1),
            ("cleanup", "pending_after", True),
            ("cleanup", "obligations_after", True),
            ("cleanup", "reservation_after", "1"),
        ):
            with self.subTest(sample=sample, key=key):
                item = attempt(sample)
                item["observation"][key] = value
                with self.assertRaises(ValueError):
                    self.validate(item)

    def test_collateral_uses_each_active_agreement_requirement(self):
        for sample in ("expiry", "cleanup"):
            with self.subTest(sample=sample):
                item = attempt(sample)
                item["observation"]["requirements"] = [
                    str(index + 1) for index in range(item["observation"]["file_count"])]
                active = set(item["observation"]["active_agreements_before"])
                item["observation"]["reservation_before"] = str(sum(
                    index + 1 for index, agreement in
                    enumerate(item["observation"]["agreements"])
                    if agreement in active))
                if sample == "expiry":
                    item["observation"]["reservation_after"] = (
                        item["observation"]["reservation_before"])
                self.validate(item)
                item["observation"]["reservation_before"] = "8"
                with self.assertRaises(ValueError):
                    self.validate(item)

    def test_rejects_receipt_rollback_and_store_drift(self):
        baseline = attempt("expiry")
        for key, value in (
            ("receipts_after", 12),
            ("state_restored_sha256", "c" * 64),
            ("resources_after", 1),
            ("live_invocations", 1),
            ("savepoint_restored", False),
            ("teardown_events", teardown(["nested_chain"] * 2)),
        ):
            with self.subTest(key=key):
                item = copy.deepcopy(baseline)
                item["observation"][key] = value
                with self.assertRaises(ValueError):
                    self.validate(item)
        item = copy.deepcopy(baseline)
        item["observation"]["measured_receipts"][0]["function"] = "wrong"
        with self.assertRaises(ValueError):
            self.validate(item)

    def test_penalty_receipt_graph_is_exact(self):
        baseline = attempt("penalty")
        self.validate(baseline)
        for change in ("missing_burn", "reversed_pair", "wrong_signer",
                       "wrong_payer", "wrong_root_value"):
            with self.subTest(change=change):
                item = copy.deepcopy(baseline)
                receipts = item["observation"]["measured_receipts"]
                if change == "missing_burn":
                    receipts.pop(0)
                    item["observation"]["receipts_after"] -= 1
                elif change == "reversed_pair":
                    receipts[0], receipts[1] = receipts[1], receipts[0]
                elif change == "wrong_signer":
                    receipts[0]["signer_id"] = 1
                elif change == "wrong_payer":
                    receipts[1]["payer_signer_id"] = 1
                else:
                    receipts[-1]["value"] = "ok(31)"
                with self.assertRaises(ValueError):
                    self.validate(item)

    def test_rejects_missing_or_reordered_canonical_phases(self):
        def event(name):
            return {"name": name, "thread_id": "w1", "os_thread_id": 1}
        valid = [event(name) for name in (
            "operation_entry", "canonical_input_entry",
            "canonical_input_exit", "canonical_output_entry",
            "canonical_output_exit", "operation_exit")]
        validate_operation_phases(valid, 1)
        for invalid in (
            valid[:3] + valid[4:],
            valid[:2] + valid[3:],
            [valid[0], valid[3], valid[1], valid[2], valid[4], valid[5]],
        ):
            with self.assertRaises(ValueError):
                validate_operation_phases(invalid, 1)


if __name__ == "__main__":
    unittest.main()
