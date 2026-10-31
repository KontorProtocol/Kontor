import json
import unittest
from copy import deepcopy

from sweep import parse_transcript, validate_pair
from test_compare import add_sweep_fields, observation, transcript


def reentry(role="worker"):
    depths = [62, 63, 64, 64, 63, 62, 62, 63, 64] if role == "worker" else [63, 64]
    samples = [observation("paid_reenter", depth, "invocation_limit" if depth == 64 else "ok", "linux", "aarch64", "") for depth in depths]
    summary = add_sweep_fields(samples, "paid_reenter", role, {
        "last_success": 63, "first_failure": 64, "first_failure_outcome": "invocation_limit",
    })
    return samples, summary


class SweepTests(unittest.TestCase):
    def test_complete_worker_and_fresh_control(self):
        worker, ws = reentry()
        control, cs = reentry("control")
        for samples, summary in ((worker, ws), (control, cs)):
            parsed, actual = parse_transcript(transcript(samples, summary), "paid_reenter", summary["role"])
            self.assertEqual(actual, summary)
            self.assertEqual(len(parsed), len(samples))
        validate_pair(worker, ws, control, cs)

    def test_reset_failure_cannot_be_hidden_by_a_successful_summary(self):
        mutations = [
            ("pre", "live_invocations", 1), ("pre", "stack_empty", False),
            ("pre", "savepoint_intact", False), ("pre", "resource_count", 1),
            ("pre", "failure_rolled_back", False),
            ("post", "live_invocations", 1), ("post", "stack_empty", False),
            ("post", "savepoint_restored", False), ("post", "resource_count", 1),
            ("post", "balances_restored", False), ("post", "floor_restored", False),
            ("post", "supply_restored", False), ("post", "digest_matches", False),
            ("post", "persistent_digest_sha256", "2" * 64),
        ]
        for stage, field, value in mutations:
            with self.subTest(stage=stage, field=field):
                samples, summary = reentry()
                samples[2]["reset"][stage][field] = value
                with self.assertRaises(ValueError):
                    parse_transcript(transcript(samples, summary), "paid_reenter", "worker")

    def test_missing_duplicate_reordered_or_wrong_role_samples_fail(self):
        for mutation in ("missing", "duplicate", "reordered", "role", "fixture", "index"):
            with self.subTest(mutation=mutation):
                samples, summary = reentry()
                if mutation == "missing":
                    samples.pop()
                elif mutation == "duplicate":
                    samples[1] = deepcopy(samples[0])
                elif mutation == "reordered":
                    samples[0], samples[1] = samples[1], samples[0]
                elif mutation == "role":
                    samples[0]["role"] = "control"
                elif mutation == "fixture":
                    samples[0]["fixture_contracts"] = 64
                else:
                    samples[0]["sample_index"] = False
                with self.assertRaises(ValueError):
                    parse_transcript(transcript(samples, summary), "paid_reenter", "worker")

    def test_incomplete_duplicate_or_failed_terminal_transcript_fails(self):
        samples, summary = reentry()
        raw = transcript(samples, summary)
        bad = [
            raw.split("KONTOR_STACK_SWEEP_SUMMARY:")[0],
            raw.split("test result:")[0],
            raw.replace("test result: ok.", "test result: FAILED."),
            raw + "KONTOR_STACK_SWEEP_SUMMARY:" + json.dumps(summary) + "\n",
            raw + "KONTOR_STACK_REPORT:" + json.dumps(samples[0]) + "\n",
        ]
        for index, value in enumerate(bad):
            with self.subTest(index=index), self.assertRaises(ValueError):
                parse_transcript(value, "paid_reenter", "worker")

    def test_fresh_control_disagreement_fails(self):
        worker, ws = reentry()
        control, cs = reentry("control")
        control[0]["fuel"]["user"] += 1
        with self.assertRaisesRegex(ValueError, "execution differs"):
            validate_pair(worker, ws, control, cs)
        control, cs = reentry("control")
        cs["baseline_digest_sha256"] = "2" * 64
        with self.assertRaisesRegex(ValueError, "baseline_digest"):
            validate_pair(worker, ws, control, cs)

    def test_forward_only_repeats_fail_even_with_valid_id_order(self):
        samples, summary = reentry()
        samples.sort(key=lambda sample: sample["depth"])
        summary = add_sweep_fields(samples, "paid_reenter", "worker", summary["boundaries"])
        with self.assertRaisesRegex(ValueError, "order"):
            parse_transcript(transcript(samples, summary), "paid_reenter", "worker")

    def test_embedded_record_prefix_is_not_a_record(self):
        samples, summary = reentry()
        raw = transcript(samples, summary)
        parse_transcript("diagnostic: KONTOR_STACK_REPORT:not JSON\n" + raw, "paid_reenter", "worker")
        with self.assertRaises(ValueError):
            parse_transcript(raw.replace("KONTOR_STACK_REPORT:", "diagnostic: KONTOR_STACK_REPORT:", 1), "paid_reenter", "worker")

    def test_installed_or_unreported_test_hook_is_rejected(self):
        for value in (True, None):
            with self.subTest(value=value):
                samples, summary = reentry()
                samples[0]["call_hook_installed"] = value
                with self.assertRaisesRegex(ValueError, "test-only call hook"):
                    parse_transcript(transcript(samples, summary), "paid_reenter", "worker")
