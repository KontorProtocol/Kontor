"""Reject wrong native reward accounting, holders, and rollback claims."""

import copy
import unittest
from decimal import Decimal

from resource_native_staking_rewards_evidence import (expected_emission,
                                                      expected_storage_budget, q,
                                                      validate_observation,
                                                      validate_operation_phases)


KEYS = (
    ("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 1),
    ("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", 2),
    ("e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", 4),
    ("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", 3),
)


def events(count):
    return [{"id": index, "role": "nested_chain" if index == 0
             else "target_native_auxiliary", "kind": kind,
             "table_alive": False if kind == "table_destroyed" else None}
            for index in range(count)
            for kind in ("reserved", "store_created", "table_destroyed",
                         "lease_released")]


def attempt(population):
    emission = expected_emission(Decimal(population * 1000), population > 0)
    credited = Decimal(0)
    accounts = []
    metadata_before = []
    metadata_after = []
    ordered_keys = sorted(KEYS[:population], key=lambda item: str(6 + item[1]))
    for index, (source_key, key_index) in enumerate(ordered_keys):
        holder = str(6 + key_index)
        remaining = emission - credited
        share = remaining if index + 1 == population else min(
            q(emission / population), remaining)
        accounts.append({"holder": holder,
                         "source_x_only_pubkey": source_key,
                         "ed25519_pubkey": bytes([key_index] * 32).hex(),
                         "stake_before": "1000",
                         "stake_after": str(Decimal(1000) + share)})
        metadata = {"holder": holder,
                    "ed25519_pubkey": bytes([key_index] * 32).hex(),
                    "status": "Active", "activation_height": 0,
                    "deactivation_height": 0, "withdrawal_height": None}
        metadata_before.append({**metadata, "validator_stake": "1000",
                                "bonded_stake": "1000"})
        metadata_after.append({**metadata,
                               "validator_stake": str(Decimal(1000) + share),
                               "bonded_stake": str(Decimal(1000) + share)})
        credited += share
    receipts = []
    expected_receipts = ([('staking', 'distribute-ordering-reward')]
                         if population == 0 else
                         [('token', 'transfer-ordering-reward'),
                          ('staking', 'distribute-ordering-reward')])
    for index, (contract, function) in enumerate(expected_receipts):
        receipts.append({"contract": contract, "function": function,
                         "status": "Ok", "gas": 100 + index,
                         "size": 2, "value": "ok", "signer_id": 1,
                         "payer_signer_id": 1 if contract == "staking" else None,
                         "height": 1,
                         "tx_id": None, "input_index": None,
                         "op_index": None, "result_index": index})
    storage_budget = str(expected_storage_budget(Decimal(population * 1000)))
    return {"case_id": "native_staking_rewards", "configuration": "production",
            "process_role": "target_observed",
            "sample_key": f"population_{population}", "repeat_index": 0, "pid": 7,
            "observation": {
                "sample_key": f"population_{population}", "outcome": "ok",
                "population": population, "eligible": population > 0,
                "amount": str(emission), "paid": str(emission),
                "credited": str(emission), "accounts": accounts,
                "validator_metadata_before": metadata_before,
                "validator_metadata_after": metadata_after,
                "supply_pre_mint": str(population * 1000),
                "supply_before": str(Decimal(population * 1000) + emission),
                "supply_after": str(Decimal(population * 1000) + emission),
                "storage_emission_budget_before": storage_budget,
                "storage_emission_budget_after": storage_budget,
                "escrow_before": str(population * 1000),
                "escrow_after": str(Decimal(population * 1000) + emission),
                "pool_before": str(emission), "pool_after": "0",
                "total_stake_before": str(population * 1000),
                "total_stake_after": str(Decimal(population * 1000) + emission),
                "last_reward_height": 1,
                "system_fuel": 10000, "user_fuel": 0, "deposit_fuel": 0,
                "state_before_sha256": "a" * 64,
                "state_after_sha256": "b" * 64,
                "state_restored_sha256": "a" * 64,
                "receipts_before": 10, "receipts_after": 11 if population == 0 else 12,
                "measured_receipts": receipts,
                "receipts_restored": 10,
                "resources_before": 0, "resources_after": 0,
                "stack_empty": True, "savepoint_restored": True,
                "savepoint_empty": True, "live_invocations": 0,
                "teardown_probe_on": True,
                "teardown_events": events(1 if population == 0 else 2),
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": 524_288, "async_stack_size": 2_097_152}}


class NativeStakingRewardsEvidenceTests(unittest.TestCase):
    def validate(self, item):
        return validate_observation(item, item["sample_key"], 0,
                                    "target_observed", "production", 7)

    def test_accepts_zero_and_four_validator_rewards(self):
        self.validate(attempt(0))
        self.validate(attempt(4))

    def test_rejects_receipt_state_and_supply_drift(self):
        baseline = attempt(4)
        for key, replacement in (("receipts_after", 11),
                                 ("receipts_after", 13),
                                 ("receipts_restored", 12),
                                 ("state_restored_sha256", "c" * 64),
                                 ("state_after_sha256", "a" * 64),
                                 ("supply_after", "4000"),
                                 ("pool_after", "0.1"),
                                 ("total_stake_after", "4000"),
                                 ("paid", "0")):
            with self.subTest(key=key, replacement=replacement):
                item = copy.deepcopy(baseline)
                item["observation"][key] = replacement
                with self.assertRaises(ValueError):
                    self.validate(item)

    def test_rejects_holder_order_metadata_and_rounding(self):
        baseline = attempt(4)
        for change in ("order", "metadata", "source_key", "holder_id",
                       "share", "last_share"):
            with self.subTest(change=change):
                item = copy.deepcopy(baseline)
                accounts = item["observation"]["accounts"]
                if change == "order":
                    accounts[0], accounts[1] = accounts[1], accounts[0]
                elif change == "metadata":
                    accounts[0]["ed25519_pubkey"] = "ff" * 32
                elif change == "source_key":
                    accounts[0]["source_x_only_pubkey"] = "ff" * 32
                elif change == "holder_id":
                    accounts[0]["holder"] = "999"
                elif change == "share":
                    accounts[0]["stake_after"] = "1000"
                else:
                    accounts[-1]["stake_after"] = "1000"
                with self.assertRaises(ValueError):
                    self.validate(item)

    def test_rejects_validator_transitions_and_storage_budget_drift(self):
        baseline = attempt(4)
        for key, replacement in (("status", "PendingExit"),
                                 ("activation_height", 1),
                                 ("deactivation_height", 1),
                                 ("withdrawal_height", 1),
                                 ("holder", "ff" * 32),
                                 ("bonded_stake", "999")):
            with self.subTest(key=key):
                item = copy.deepcopy(baseline)
                item["observation"]["validator_metadata_after"][0][key] = replacement
                with self.assertRaises(ValueError):
                    self.validate(item)
        for key in ("storage_emission_budget_before",
                    "storage_emission_budget_after"):
            with self.subTest(key=key):
                item = copy.deepcopy(baseline)
                item["observation"][key] = "0"
                with self.assertRaises(ValueError):
                    self.validate(item)
        item = copy.deepcopy(baseline)
        item["observation"]["validator_metadata_after"].pop()
        with self.assertRaises(ValueError):
            self.validate(item)

    def test_rejects_measured_receipt_content_and_order_drift(self):
        baseline = attempt(4)
        for key, replacement in (("contract", "staking"),
                                 ("function", "hold"),
                                 ("status", "ContractErr"),
                                 ("gas", 0),
                                 ("size", 1),
                                 ("value", ""),
                                 ("signer_id", 2),
                                 ("payer_signer_id", 1),
                                 ("height", 2),
                                 ("tx_id", 1),
                                 ("result_index", 1)):
            with self.subTest(key=key):
                item = copy.deepcopy(baseline)
                item["observation"]["measured_receipts"][0][key] = replacement
                with self.assertRaises(ValueError):
                    self.validate(item)
        item = copy.deepcopy(baseline)
        item["observation"]["measured_receipts"].pop()
        with self.assertRaises(ValueError):
            self.validate(item)
        for payer in (None, True, 1.0, 2):
            zero = attempt(0)
            zero["observation"]["measured_receipts"][0]["payer_signer_id"] = payer
            with self.subTest(payer=payer), self.assertRaises(ValueError):
                self.validate(zero)
        zero = attempt(0)
        del zero["observation"]["measured_receipts"][0]["payer_signer_id"]
        with self.assertRaises(ValueError):
            self.validate(zero)

    def test_zero_branch_and_store_lifecycle_are_distinct(self):
        item = attempt(0)
        item["observation"]["receipts_after"] = 12
        with self.assertRaises(ValueError):
            self.validate(item)

    def test_operation_canonical_phases_reject_missing_reversed_and_cross_attempt(self):
        def event(name, thread="w1"):
            return {"name": name, "thread_id": thread,
                    "os_thread_id": 1 if thread == "w1" else 2}

        first = [event("operation_entry"), event("canonical_input_entry"),
                 event("canonical_input_exit"), event("canonical_output_entry"),
                 event("canonical_output_exit", "w2"), event("operation_exit")]
        validate_operation_phases(first, 1)
        for changed in (
            first[:4] + first[5:],
            first[:2] + first[3:],
            [first[0], first[3], first[1], first[2], first[4], first[5]],
            first[:4] + [first[5]],
            [first[0], event("canonical_input_entry", "w2"),
             first[2], first[3], first[4], first[5]],
        ):
            with self.subTest(changed=[item["name"] for item in changed]):
                with self.assertRaises(ValueError):
                    validate_operation_phases(changed, 1)
        second = [event("operation_entry"), event("canonical_output_exit"),
                  event("operation_exit")]
        with self.assertRaises(ValueError):
            validate_operation_phases(second, 1)
        cycle = first[1:-1]
        two_cycles = [first[0], *cycle, *cycle, first[-1]]
        three_cycles = [first[0], *cycle, *cycle, *cycle, first[-1]]
        validate_operation_phases(two_cycles, 2)
        for changed, expected in ((first, 2), (two_cycles, 1)):
            with self.subTest(actual=len(changed), expected=expected):
                with self.assertRaises(ValueError):
                    validate_operation_phases(changed, expected)
        for relocated_repeat in (first, three_cycles):
            with self.assertRaises(ValueError):
                validate_operation_phases(relocated_repeat, 2)
        item = attempt(0)
        item["observation"]["teardown_events"] = events(2)
        with self.assertRaises(ValueError):
            self.validate(item)
        item = attempt(4)
        item["observation"]["teardown_events"].pop()
        with self.assertRaises(ValueError):
            self.validate(item)


if __name__ == "__main__":
    unittest.main()
