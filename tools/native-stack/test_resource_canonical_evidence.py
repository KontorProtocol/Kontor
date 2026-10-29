import hashlib
import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from resource_canonical_evidence import (expected_case_env, parse_worker_log,
                                         validate_paid_accounting,
                                         validate_post_return_delta)


def paid_balances(gas):
    fee = Decimal(gas) / Decimal(10**9)
    after = Decimal(100) - fee
    balances = {
        "before": "100", "after": str(after), "restored": "100",
        "burned_before": "0", "burned_after": str(fee),
        "supply_before": "100", "supply_after": str(after),
        "floor_before": "0", "floor_after": "0", "floor_restored": "0",
    }
    encoded = json.dumps(balances, sort_keys=True, separators=(",", ":")).encode()
    return balances, hashlib.sha256(encoded).hexdigest()


class CanonicalEvidenceTests(unittest.TestCase):
    def test_paid_fee_rejects_repaired_digest_undercharging(self):
        fuel = {"user": 115476, "system": 517797, "deposit": 0}
        receipt = {"status": "Trap", "gas": 116}
        balances, digest = paid_balances(116)
        self.assertEqual(validate_paid_accounting(
            fuel, receipt, balances, digest, 100000, 1000),
            Decimal("0.000000116"))
        undercharged, repaired_digest = paid_balances(1)
        with self.assertRaisesRegex(ValueError, "receipt gas differs"):
            validate_paid_accounting(
                fuel, {"status": "Trap", "gas": 1}, undercharged,
                repaired_digest, 100000, 1000)
        with self.assertRaisesRegex(ValueError, "priced gas"):
            validate_paid_accounting(
                fuel, receipt, undercharged, repaired_digest, 100000, 1000)
        with self.assertRaisesRegex(ValueError, "deposit fuel"):
            validate_paid_accounting(
                {**fuel, "deposit": 1}, receipt, balances, digest, 100000, 1000)

    def test_heavy_post_return_requires_higher_gas_and_fee(self):
        light = {"fuel": {"user": 788}, "receipt": {"gas": 1},
                 "execution_fee": "1E-9"}
        heavy = {"fuel": {"user": 115476}, "receipt": {"gas": 116},
                 "execution_fee": "1.16E-7"}
        validate_post_return_delta(light, heavy)
        for changed in ({"receipt": {"gas": 1}},
                        {"execution_fee": "1E-9"}):
            with self.assertRaisesRegex(ValueError, "work or fee"):
                validate_post_return_delta(light, {**heavy, **changed})

    def test_case_environment_uses_canonical_worker(self):
        self.assertEqual(expected_case_env("canonical_realloc", "target_observed",
                                           "production"), {
            "KONTOR_FINITE_STACK_CASE": "canonical_realloc",
            "KONTOR_FINITE_STACK_ROLE": "target_observed",
            "KONTOR_RESOURCE_MODE": "production",
            "KONTOR_RESOURCE_TEARDOWN_PROBE": "on",
        })

    def test_transcript_requires_all_case_attempts_in_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "child.log"
            lines = ["running 1 test"]
            for _ in range(4):
                lines.extend(("KONTOR_STACK_TIMING:{}", "CANONICAL_STACK_ATTEMPT:{}"))
            lines.extend((
                'CANONICAL_STACK_SUMMARY:{"case_id":"canonical_lift_lower"}',
                "FINITE_STACK_RUNTIME={}",
                "FINITE_STACK_TRACE={}",
                "FINITE_STACK_TERMINAL={}",
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 720 filtered out; finished in 0.14s",
            ))
            path.write_text("\n".join(lines) + "\n")
            self.assertEqual(len(parse_worker_log(path)["attempts"]), 4)
            lines[3], lines[4] = lines[4], lines[3]
            path.write_text("\n".join(lines) + "\n")
            with self.assertRaisesRegex(ValueError, "out of order"):
                parse_worker_log(path)


if __name__ == "__main__":
    unittest.main()
