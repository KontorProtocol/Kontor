"""Reject wrong native reward accounting, holders, and rollback claims."""

import copy
import unittest
from decimal import Decimal

from resource_native_staking_rewards_evidence import (expected_emission, q,
                                                      validate_observation)


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
    for index, (holder, key_index) in enumerate(KEYS[:population]):
        remaining = emission - credited
        share = remaining if index + 1 == population else min(
            q(emission / population), remaining)
        accounts.append({"holder": holder,
                         "ed25519_pubkey": bytes([key_index] * 32).hex(),
                         "stake_before": "1000",
                         "stake_after": str(Decimal(1000) + share)})
        credited += share
    return {"case_id": "native_staking_rewards", "configuration": "production",
            "process_role": "target_observed",
            "sample_key": f"population_{population}", "repeat_index": 0, "pid": 7,
            "observation": {
                "sample_key": f"population_{population}", "outcome": "ok",
                "population": population, "eligible": population > 0,
                "amount": str(emission), "paid": str(emission),
                "credited": str(emission), "accounts": accounts,
                "supply_pre_mint": str(population * 1000),
                "supply_before": str(Decimal(population * 1000) + emission),
                "supply_after": str(Decimal(population * 1000) + emission),
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
        for change in ("order", "metadata", "share", "last_share"):
            with self.subTest(change=change):
                item = copy.deepcopy(baseline)
                accounts = item["observation"]["accounts"]
                if change == "order":
                    accounts[0], accounts[1] = accounts[1], accounts[0]
                elif change == "metadata":
                    accounts[0]["ed25519_pubkey"] = "ff" * 32
                elif change == "share":
                    accounts[0]["stake_after"] = "1000"
                else:
                    accounts[-1]["stake_after"] = "1000"
                with self.assertRaises(ValueError):
                    self.validate(item)

    def test_zero_branch_and_store_lifecycle_are_distinct(self):
        item = attempt(0)
        item["observation"]["receipts_after"] = 12
        with self.assertRaises(ValueError):
            self.validate(item)
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
