import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from resource_boundary_evidence import (parse_worker_log,
                                        normalized_boundary_amount,
                                        postcard_u64_length,
                                        semantic_signature,
                                        validate_balance_transitions,
                                        validate_live_deposit_gas,
                                        validate_cell_identity,
                                        validate_discovery_sequence,
                                        validate_final_parity,
                                        validate_frozen_discovery_pairs,
                                        validate_replay_order, validate_trace,
                                        validate_source_freeze, run_name)
from resource_boundary_manifest import SCHEMA
from resource_boundary_manifest import DISCOVERY_ROLE
from resource_evidence import load_json_strict
from resource_evidence_v2 import validate_teardown


def attempt(depth, outcome, sample_key="calibration", repeat_index=0):
    return {
        "depth": depth,
        "sample_key": sample_key,
        "repeat_index": repeat_index,
        "observation": {"outcome": outcome},
    }


class BoundaryEvidenceTests(unittest.TestCase):
    def test_real_paid_balance_rows_with_constructed_live_gas(self):
        # Raw balances and digests: .build-cache/native-stack-5bdf-pilot/discovery/
        # pulley_plain_paid_discovery_production_observed_production.log and
        # pulley_wide_paid_discovery_production_observed_production.log, plus
        # .build-cache/native-stack-ad48-leaf-diagnostic/leaf-discovery.log.
        # Live gas is constructed because those captures did not measure it.
        def digest(values):
            return hashlib.sha256(json.dumps(values, sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()

        cases = (
            ("plain", "99.999999918", "8.2E-8", "3E-9", "ok", 0,
             "556d5f5ec796f7fd45ec05cf0ea0fe6317f6ec301913f248ef101c96f5103438"),
            ("plain positive", "99.99999989", "1.1E-7", "4E-9", "ok", 1024,
             "704ab99e81eb4f568a8f579414767f9a6d18ad0ad8c582e1f783abc5b53f7b93"),
            ("plain 2048", "99.999999862", "1.38E-7", "4E-9", "ok", 2048,
             "47e89a7a2e4c51455edf697f1fba20fda199624b405870adc2308e20a35b10bb"),
            ("plain 4096", "99.999999807", "1.93E-7", "4E-9", "ok", 4096,
             "8a77c03b6921d0572e586581819e66fcad54a2ec3083373e8091f83dedd8aec0"),
            ("plain 6144", "99.999999752", "2.48E-7", "4E-9", "ok", 6144,
             "bae3bf5797f1f5ac499412466b3300b6ad36611bce9d316f19fc5f2d47be37f9"),
            ("plain 7168", "99.999999724", "2.76E-7", "4E-9", "ok", 7168,
             "e5237c627df0034d7b9ec00e6d9035e9a3c07aaa0f999a0ee5db40a363009795"),
            ("plain 7680", "99.99999971", "2.9E-7", "4E-9", "ok", 7680,
             "9b4f90e586e70ea83d9dc449948e70ac1f3a79ae9ce830614f8ab45853db78e3"),
            ("plain 7936", "99.999999703", "2.97E-7", "4E-9", "ok", 7936,
             "275b498646721f0a88d5c68dd3c5af79c5714fdefd46718d066109ddc38d87f8"),
            ("plain 8064", "99.9999997", "3E-7", "4E-9", "ok", 8064,
             "4e21d47fd04c6da686ef53e5dd08d1d8d96523b43f5859ee83c2c5e878bb3cd4"),
            ("plain 8128", "99.999999698", "3.02E-7", "4E-9", "ok", 8128,
             "5447b1ab0104ef8b6322044a0e8d309c611f7ebeb3140c33a62ea3bd67327948"),
            ("plain 8160", "99.999999697", "3.03E-7", "4E-9", "ok", 8160,
             "e3bc0358d25b7732ab52339770fc43d5cb29fe3307f64734b2edd6442c1f3379"),
            ("plain 8176", "99.999999697", "3.03E-7", "4E-9", "ok", 8176,
             "e3bc0358d25b7732ab52339770fc43d5cb29fe3307f64734b2edd6442c1f3379"),
            ("plain 8184", "99.999999697", "3.03E-7", "4E-9", "ok", 8184,
             "e3bc0358d25b7732ab52339770fc43d5cb29fe3307f64734b2edd6442c1f3379"),
            ("plain 8186", "99.999999697", "3.03E-7", "4E-9", "ok", 8186,
             "e3bc0358d25b7732ab52339770fc43d5cb29fe3307f64734b2edd6442c1f3379"),
            ("plain boundary", "99.999999796", "2.04E-7", "3E-9",
             "stack_overflow", 8187,
             "c99b442c70084f675cde58aa001d60c23ea53b300fe63740dd3c3ec106e4b33d"),
            ("wide", "99.999999913", "8.7E-8", "3E-9", "ok", 0,
             "1e543949caae9e9b5bbc20e614fc33a0cc6cfce82a540c081dc2a8d61928693d"),
            ("wide positive", "99.999999468", "5.32E-7", "4E-9", "ok", 1024,
             "cfba02a67ec7fa86f1c5ca2d4458c6dba14e4176b8ef145d0d3eeb2b8523fb06"),
            ("wide 1536", "99.999999246", "7.54E-7", "4E-9", "ok", 1536,
             "69dda129b1dfc5b27ab6741a8fce49edb870c1c6a74f466411b8f5bb13edae90"),
            ("wide 1664", "99.999999191", "8.09E-7", "4E-9", "ok", 1664,
             "8d41a5cc517156e8906ada9cd77c5e0552ececa1a0f4c4823bde8359dee32593"),
            ("wide 1696", "99.999999177", "8.23E-7", "4E-9", "ok", 1696,
             "0a3457bdd22ab32d07614435acea994d2f3d0ff2004497d5661b9ae12d94c2d3"),
            ("wide 1712", "99.99999917", "8.3E-7", "4E-9", "ok", 1712,
             "85d38447ca661251bee82b2be9e8a54b89213c755b57c5749edc211e2385e778"),
            ("wide 1720", "99.999999166", "8.34E-7", "4E-9", "ok", 1720,
             "53fd1fca69fa11727b63759a56f64f96221570dfd06ff2791c41a05a9d5dcc68"),
            ("wide 1722", "99.999999165", "8.35E-7", "4E-9", "ok", 1722,
             "85a03c940d27ff5992e08ad8e4f39a7b9119413a02d1ac9fb75cc5e0a861342d"),
            ("wide boundary", "99.99999918", "8.2E-7", "3E-9",
             "stack_overflow", 1723,
             "8b839883fa317bdeda79aea320a437e782acb4913be25f58b44a97042290e71c"),
            ("leaf positive", "99.999999889", "1.11E-7", "4E-9", "ok", 1024,
             "5384c163e6485e998efa2a989ff0786c10090c7e09ece47ea8d947fddd7aa58b"),
            ("leaf 2048", "99.999999862", "1.38E-7", "4E-9", "ok", 2048,
             "47e89a7a2e4c51455edf697f1fba20fda199624b405870adc2308e20a35b10bb"),
            ("leaf 4096", "99.999999806", "1.94E-7", "4E-9", "ok", 4096,
             "19bb3913854139e41551207f28be5b4e85dd28b5b7c5567b434f7fb39ae09e11"),
            ("leaf 6144", "99.999999751", "2.49E-7", "4E-9", "ok", 6144,
             "23576a243a267986fbaef859343fd873c9f8d001107ce30cee7f42ebbaea1b43"),
            ("leaf 7168", "99.999999723", "2.77E-7", "4E-9", "ok", 7168,
             "a431c47fa577ed2dfc16f996791f5caee7df0d6bcfc149ae347771827f459ed6"),
            ("leaf 7680", "99.99999971", "2.9E-7", "4E-9", "ok", 7680,
             "9b4f90e586e70ea83d9dc449948e70ac1f3a79ae9ce830614f8ab45853db78e3"),
            ("leaf 7936", "99.999999703", "2.97E-7", "4E-9", "ok", 7936,
             "275b498646721f0a88d5c68dd3c5af79c5714fdefd46718d066109ddc38d87f8"),
            ("leaf 8064", "99.999999699", "3.01E-7", "4E-9", "ok", 8064,
             "01407f1ea77c3b3e64f5b18f3e5af5a4f381ca728a280ba2750b0d81399da648"),
            ("leaf 8128", "99.999999698", "3.02E-7", "4E-9", "ok", 8128,
             "5447b1ab0104ef8b6322044a0e8d309c611f7ebeb3140c33a62ea3bd67327948"),
            ("leaf 8160", "99.999999697", "3.03E-7", "4E-9", "ok", 8160,
             "e3bc0358d25b7732ab52339770fc43d5cb29fe3307f64734b2edd6442c1f3379"),
            ("leaf 8176", "99.999999696", "3.04E-7", "4E-9", "ok", 8176,
             "235a8e8fb4f066f1cbfc0961e66e57115f989f88fb47520b58125bc5c5b3925f"),
            ("leaf", "99.999999796", "2.04E-7", "3E-9", "stack_overflow", 8184,
             "c99b442c70084f675cde58aa001d60c23ea53b300fe63740dd3c3ec106e4b33d"),
        )
        for name, after, burned_after, floor_after, outcome, depth, raw_digest in cases:
            with self.subTest(case=name):
                balances = {
                    "before": "99.999999959", "after": after,
                    "restored": "99.999999959",
                    "burned_before": "4.1E-8", "burned_after": burned_after,
                    "supply_before": "99.999999959", "supply_after": after,
                    "floor_before": "3E-9", "floor_after": floor_after,
                    "floor_restored": "3E-9",
                }
                self.assertEqual(digest(balances), raw_digest)
                normalized = validate_balance_transitions(
                    balances, "paid", outcome, depth, raw_digest)
                constructed_live_gas = {
                    "before": 3,
                    "after": 4 if outcome == "ok" and depth >= 128 else 3,
                    "restored": 3,
                }
                validate_live_deposit_gas(
                    constructed_live_gas, digest(constructed_live_gas),
                    balances, "paid", outcome, depth)
                self.assertEqual(normalized["floor_before"], "0.000000003")
                self.assertEqual(normalized["burned_after"],
                                 normalized_boundary_amount(burned_after))
                fixed = {key: normalized_boundary_amount(value)
                         for key, value in balances.items()}
                sample = {"sample_key": "first_failure", "depth": depth,
                          "observation": {
                              "outcome": outcome, "error_class": "deterministic",
                              "typed_trap": "StackOverflow", "value": None,
                              "receipt": {"status": "Trap", "gas": 167},
                              "last_depth": 0, "rolled_back": True,
                              "fuel": {"user": 1, "system": 1, "deposit": 1},
                              "live_store_peak": 1,
                              "balance_transitions": balances,
                              "balance_transitions_sha256": digest(balances),
                              "live_deposit_gas": constructed_live_gas,
                              "live_deposit_gas_sha256": digest(constructed_live_gas),
                              "state_before_sha256": "a" * 64, "reset": {},
                              "host_io_suspended": True,
                              "leaf_callback_seen": True,
                              "host_import_phase": "after_host_release",
                          }}
                fixed_sample = copy.deepcopy(sample)
                fixed_sample["observation"]["balance_transitions"] = fixed
                fixed_sample["observation"]["balance_transitions_sha256"] = digest(fixed)
                self.assertEqual(semantic_signature(sample),
                                 semantic_signature(fixed_sample))
                with self.assertRaises(ValueError):
                    validate_balance_transitions(balances, "paid", outcome,
                                                 depth, digest(fixed))

    def test_constructed_live_deposit_pricing_and_rollback_mutations(self):
        def digest(value):
            return hashlib.sha256(json.dumps(value, sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()

        balances = {
            "floor_before": "3E-9", "floor_after": "4E-9",
            "floor_restored": "3E-9",
        }
        gas = {"before": 3, "after": 4, "restored": 3}
        validate_live_deposit_gas(gas, digest(gas), balances,
                                  "paid", "ok", 1024)
        for altered_balances, altered_gas, outcome in (
            ({**balances, "floor_after": "5E-9"}, gas, "ok"),
            (balances, {**gas, "after": 5}, "ok"),
            ({**balances, "floor_after": "3E-9"},
             {**gas, "after": 3}, "ok"),
            (balances, gas, "stack_overflow"),
            ({**balances, "floor_restored": "4E-9"}, gas, "ok"),
        ):
            with self.subTest(outcome=outcome, balances=altered_balances,
                              gas=altered_gas), self.assertRaises(ValueError):
                validate_live_deposit_gas(
                    altered_gas, digest(altered_gas), altered_balances,
                    "paid", outcome, 1024)
        with self.assertRaises(ValueError):
            validate_live_deposit_gas(gas, "0" * 64, balances,
                                      "paid", "ok", 1024)
        with self.assertRaises(ValueError):
            validate_live_deposit_gas({**gas, "after": True},
                                      digest({**gas, "after": True}), balances,
                                      "paid", "ok", 1024)

        trapped_balances = {**balances, "floor_after": "3E-9"}
        trapped_gas = {**gas, "after": 3}
        validate_live_deposit_gas(trapped_gas, digest(trapped_gas),
                                  trapped_balances, "paid",
                                  "stack_overflow", 1024)
        # The real trapped call recorded deposit fuel, but its live row rolled back.
        with self.assertRaises(ValueError):
            validate_live_deposit_gas(gas, digest(gas), balances,
                                      "paid", "stack_overflow", 1024)

    def test_constructed_postcard_threshold_gas(self):
        def digest(value):
            return hashlib.sha256(json.dumps(value, sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()

        for depth, encoded_size in ((0, 1), (127, 1), (128, 2),
                                    (16383, 2), (16384, 3)):
            with self.subTest(depth=depth):
                self.assertEqual(postcard_u64_length(depth), encoded_size)
                after = 2 + encoded_size
                balances = {
                    "floor_before": "3E-9",
                    "floor_after": f"{after}E-9",
                    "floor_restored": "3E-9",
                }
                gas = {"before": 3, "after": after, "restored": 3}
                validate_live_deposit_gas(gas, digest(gas), balances,
                                          "paid", "ok", depth)
        for depth in (-1, 2**32):
            with self.assertRaises(ValueError):
                postcard_u64_length(depth)

    def test_boundary_decimal_domain_rejects_malformed_and_subgrid_values(self):
        for value in ("0", "0.00", "0E-18", "0e+16", "1.0E-7", "1e+16"):
            with self.subTest(valid=value):
                normalized_boundary_amount(value)
        for value in ("1e-7", "1E+7", "01", "1E-019", "1,0", "NaN",
                      "Infinity", " 1", "+1E-7", "-0", "1E-19",
                      "1e+129", "9" * 129, str(2**256)):
            with self.subTest(invalid=value), self.assertRaises(ValueError):
                normalized_boundary_amount(value)

    def test_reviewed_nine_pairs_include_independent_leaf(self):
        case_ids = [f"pulley_{shape}_{mode}"
                    for shape in ("plain", "wide")
                    for mode in ("paid", "view", "system", "core")]
        leaf = "deepest_frame_host_call"
        manifest = {
            "boundary_cases": [
                {"case_id": case_id, "last_success": 100 + index,
                 "first_failure": 101 + index}
                for index, case_id in enumerate(case_ids)
            ],
            "leaf_case": {"case_id": leaf, "last_success": 90,
                          "first_failure": 91},
        }
        archive = {"discovered_depths": {}, "runs": {}}
        for case in [*manifest["boundary_cases"], manifest["leaf_case"]]:
            case_id = case["case_id"]
            pair = {key: case[key] for key in
                    ("last_success", "first_failure")}
            archive["discovered_depths"][case_id] = pair
            archive["runs"][run_name(case_id, DISCOVERY_ROLE,
                                      "production")] = {"summary": pair}
        validate_frozen_discovery_pairs(archive, manifest)
        wrong_leaf = copy.deepcopy(archive)
        wrong_leaf["discovered_depths"][leaf]["last_success"] = 100
        with self.assertRaises(ValueError):
            validate_frozen_discovery_pairs(wrong_leaf, manifest)
        wrong_boundary = copy.deepcopy(archive)
        wrong_boundary["runs"][run_name(case_ids[0], DISCOVERY_ROLE,
                                         "production")]["summary"]["first_failure"] += 1
        with self.assertRaises(ValueError):
            validate_frozen_discovery_pairs(wrong_boundary, manifest)

    def test_reviewed_source_freeze_accepts_only_metadata_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.run(["git", "-C", str(root), *args],
                                      check=True, capture_output=True,
                                      text=True).stdout.strip()

            git("init", "-q")
            native = root / "tools/native-stack"
            native.mkdir(parents=True)
            manifest = native / "resource-boundary-manifest-v1.json"
            depths = native / "resource-boundary-depths-v1.json"
            runtime = root / "core/indexer/src/runtime/mod.rs"
            runtime.parent.mkdir(parents=True)
            manifest.write_text('{"claim_status":"pending_discovery"}\n')
            depths.write_text('{"cases":null}\n')
            runtime.write_text("stable runtime frame\n")
            git("add", ".")
            git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "commit", "-qm", "discovery source")
            discovery_sha = git("rev-parse", "HEAD")
            manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
            manifest.write_text('{"claim_status":"candidate_only"}\n')
            depths.write_text('{"cases":"frozen"}\n')
            git("add", ".")
            git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "commit", "-qm", "freeze depths")
            final_sha = git("rev-parse", "HEAD")
            with patch("resource_boundary_evidence.ROOT", root):
                self.assertEqual(validate_source_freeze(
                    discovery_sha, final_sha, manifest_sha),
                    {"claim_status": "pending_discovery"})
                with self.assertRaises(ValueError):
                    validate_source_freeze(discovery_sha, final_sha,
                                           "0" * 64)
                runtime.write_text("changed runtime frame\n")
                git("add", ".")
                git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                    "commit", "-qm", "change runtime frame")
                with self.assertRaises(ValueError):
                    validate_source_freeze(discovery_sha, git("rev-parse", "HEAD"),
                                           manifest_sha)

    def test_balance_conservation_rejects_false_paid_and_nonpaid_charges(self):
        balances = {
            "before": "100", "after": "90", "restored": "100",
            "burned_before": "0", "burned_after": "10",
            "supply_before": "100", "supply_after": "90",
            "floor_before": "0", "floor_after": "0", "floor_restored": "0",
        }

        def digest(value):
            return hashlib.sha256(json.dumps(value, sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()

        validate_balance_transitions(balances, "paid", "ok", 100,
                                     digest(balances))
        false_burn = {**balances, "burned_after": "1"}
        false_supply = {**balances, "supply_after": "99"}
        rounded_mismatch = {
            **balances,
            "after": "98.9999999999999999999999999999",
            "burned_after": "1.0000000000000000000000000002",
            "supply_after": "98.9999999999999999999999999997",
        }
        noncanonical = {**balances, "burned_after": "1.0"}
        for altered in (false_burn, false_supply, rounded_mismatch,
                        noncanonical):
            with self.assertRaises(ValueError):
                validate_balance_transitions(altered, "paid", "ok", 100,
                                             digest(altered))
        with self.assertRaises(ValueError):
            validate_balance_transitions(balances, "view", "ok", 100,
                                         digest(balances))
        no_charge = {**balances, "after": "100", "burned_after": "0",
                     "supply_after": "100"}
        for mode in ("view", "system", "core"):
            validate_balance_transitions(no_charge, mode, "ok", 0,
                                         digest(no_charge))
        changed_floor = {**no_charge, "floor_before": "2",
                         "floor_after": "1", "floor_restored": "2"}
        validate_balance_transitions(changed_floor, "core", "ok", 100,
                                     digest(changed_floor))
        for mode in ("view", "system"):
            with self.assertRaises(ValueError):
                validate_balance_transitions(changed_floor, mode, "ok", 100,
                                             digest(changed_floor))
        with self.assertRaises(ValueError):
            validate_balance_transitions(changed_floor, "core",
                                         "stack_overflow", 100,
                                         digest(changed_floor))
        unchanged_floor = {**changed_floor, "floor_after": "2"}
        with self.assertRaises(ValueError):
            validate_balance_transitions(unchanged_floor, "core", "ok", 100,
                                         digest(unchanged_floor))

    def test_cell_rejects_wrong_architecture_or_build_profile(self):
        artifact = {"profile": {
            "test": True, "opt_level": "0",
            "debug_assertions": True,
        }}
        with patch("resource_boundary_evidence.platform.machine",
                   return_value="aarch64"):
            self.assertEqual(validate_cell_identity(
                "Linux-ARM64/dev", artifact), "aarch64")
            with self.assertRaises(ValueError):
                validate_cell_identity("Linux-X64/dev", artifact)
            with self.assertRaises(ValueError):
                validate_cell_identity("Linux-ARM64/release", artifact)
        release = {"profile": {
            "test": True, "opt_level": "3",
            "debug_assertions": False,
        }}
        with patch("resource_boundary_evidence.platform.machine",
                   return_value="aarch64"):
            self.assertEqual(validate_cell_identity(
                "Linux-ARM64/release", release), "aarch64")

    def test_leaf_requires_cross_configuration_semantics_and_capacity(self):
        case_id = "deepest_frame_host_call"
        signatures = {}
        runs = {}
        for configuration, usable in (("reduced", 1_000_000),
                                      ("production", 2_000_000)):
            for role in ("target_observed", "probe_off_control"):
                signatures[case_id, role, configuration] = [{
                    "sample_key": "target",
                    "depth": 100,
                    "fuel": {"user": 100, "system": 0, "deposit": 0},
                    "receipt": {"status": "Ok", "gas": 10},
                    "host_import_phase": "after_host_release",
                }]
                runs[run_name(case_id, role, configuration)] = {
                    "runtime": {"thread_observations": [
                        {"thread_category": "tokio_worker",
                         "usable_bytes": usable},
                        {"thread_category": "tokio_worker",
                         "usable_bytes": usable},
                    ]}
                }
        validate_final_parity(signatures, runs, [case_id])
        different_semantics = copy.deepcopy(signatures)
        for role in ("target_observed", "probe_off_control"):
            different_semantics[case_id, role, "reduced"][0]["fuel"]["user"] += 1
        with self.assertRaises(ValueError):
            validate_final_parity(different_semantics, runs, [case_id])
        different_phase = copy.deepcopy(signatures)
        different_phase[case_id, "target_observed", "reduced"][0][
            "host_import_phase"] = "before_import"
        with self.assertRaises(ValueError):
            validate_final_parity(different_phase, runs, [case_id])
        insufficient_capacity = copy.deepcopy(runs)
        for role in ("target_observed", "probe_off_control"):
            key = run_name(case_id, role, "production")
            for thread in insufficient_capacity[key]["runtime"]["thread_observations"]:
                thread["usable_bytes"] = 1_999_999
        with self.assertRaises(ValueError):
            validate_final_parity(signatures, insufficient_capacity, [case_id])

    def test_trace_binds_phase_and_compiler_to_measured_threads(self):
        def thread(category, number, base, requested):
            guard = 4096 if category == "tokio_worker" else 0
            mapped = 2_097_152
            mapped_start = base + guard
            return {
                "thread_category": category,
                "thread_id": f"ThreadId({number})",
                "process_id": 123,
                "os_thread_id": number,
                "identity_api": "linux_gettid",
                "page_size_bytes": 4096,
                "requested_bytes": requested,
                "mapped_bytes": mapped,
                "guard_bytes": guard,
                "guard_start": base if guard else 0,
                "guard_end": base + guard if guard else 0,
                "guard_verification": ("linux_maps_prot_none" if guard
                                       else "pthread_reports_none"),
                "usable_bytes": mapped,
                "mapped_start": mapped_start,
                "mapped_end": mapped_start + mapped,
                "usable_start": mapped_start,
                "usable_end": mapped_start + mapped,
                "measurement_api": "pthread_getattr_np",
                "guard_treatment": "separate_protected_page",
                "guard_verified": True,
            }
        runtime = {
            "scope": "paired_pulley_boundary_worker",
            "configuration": "production",
            "case_id": "pulley_plain_paid",
            "process_role": "target_observed",
            "pid": 123,
            "flavor": "multi_thread",
            "worker_count": 2,
            "worker_requested_bytes": None,
            "thread_observations": [
                thread("tokio_worker", 1, 0x1000000, None),
                thread("tokio_worker", 2, 0x2000000, None),
                thread("blocking_pool", 3, 0x3000000, None),
                thread("block_on_caller", 4, 0x4000000, None),
            ],
            "blocking_pool_observed": True,
            "block_on_caller_observed": True,
            "embedded_source_sha": "0" * 40,
            "binary_sha256": "0" * 64,
        }
        def event(name, number=1, category="tokio_worker"):
            return {
                "name": name,
                "thread_id": f"ThreadId({number})",
                "os_thread_id": number,
                "category": category,
            }
        events = [
            event("fixture_preparation_entry"),
            event("publication_entry"),
            event("compiler_entry"), event("compiler_exit"),
            event("blocking_decode_entry", 3, "blocking_pool"),
            event("blocking_decode_exit", 3, "blocking_pool"),
            event("publication_exit"),
            event("fixture_preparation_exit"),
            event("boundary_attempt_start"),
            event("sample_preparation_entry"),
            event("sample_preparation_exit"),
            event("operation_entry"),
            event("canonical_input_entry"), event("canonical_input_exit"),
            event("canonical_output_entry"), event("canonical_output_exit"),
            event("operation_exit"),
            event("postcall_observation_entry"),
            event("postcall_observation_exit"),
            event("teardown_entry"), event("teardown_exit"),
            event("boundary_attempt_end"),
        ]
        trace = {
            "scope": runtime["scope"],
            "configuration": runtime["configuration"],
            "case_id": runtime["case_id"],
            "process_role": runtime["process_role"],
            "events": events,
        }
        observed = [{"observation": {"outcome": "ok"}}]
        self.assertEqual(validate_trace(trace, runtime, observed)["compiler_entry"], 1)
        wrong_worker = copy.deepcopy(trace)
        wrong_worker["events"][11]["thread_id"] = "ThreadId(3)"
        wrong_worker["events"][11]["os_thread_id"] = 3
        with self.assertRaises(ValueError):
            validate_trace(wrong_worker, runtime, observed)
        missing_phase = copy.deepcopy(trace)
        missing_phase["events"] = [item for item in events
                                   if item["name"] != "teardown_exit"]
        with self.assertRaises(ValueError):
            validate_trace(missing_phase, runtime, observed)
        moved_conversion = copy.deepcopy(trace)
        conversions = [item for item in moved_conversion["events"]
                       if item["name"].startswith("canonical_")]
        moved_conversion["events"] = [item for item in moved_conversion["events"]
                                      if not item["name"].startswith("canonical_")]
        postcall = next(index for index, item in
                        enumerate(moved_conversion["events"])
                        if item["name"] == "postcall_observation_entry")
        moved_conversion["events"][postcall + 1:postcall + 1] = conversions
        with self.assertRaises(ValueError):
            validate_trace(moved_conversion, runtime, observed)

    def test_discovery_reconstructs_exact_adaptive_search(self):
        threshold = 1723
        attempts = [attempt(0, "ok")]
        depth = 1024
        last = 0
        while True:
            outcome = "ok" if depth < threshold else "stack_overflow"
            attempts.append(attempt(depth, outcome))
            if outcome != "ok":
                first = depth
                break
            last = depth
            depth *= 2
        while first - last > 1:
            middle = last + (first - last) // 2
            outcome = "ok" if middle < threshold else "stack_overflow"
            attempts.append(attempt(middle, outcome))
            if outcome == "ok":
                last = middle
            else:
                first = middle
        summary = {"last_success": last, "first_failure": first}
        validate_discovery_sequence(attempts, summary)
        for mutated in (
            attempts[:-1],
            [*attempts[:2], attempt(1777, "ok"), *attempts[3:]],
            [*attempts[:2], attempt(attempts[2]["depth"], "out_of_fuel"),
             *attempts[3:]],
        ):
            with self.assertRaises(ValueError):
                validate_discovery_sequence(mutated, summary)
        with self.assertRaises(ValueError):
            validate_discovery_sequence(attempts, {
                "last_success": last - 1, "first_failure": first,
            })

    def test_replay_rejects_reordered_duplicate_and_wrong_trap(self):
        depths = (1722, 1723)
        valid = [
            attempt(1722, "ok", "last_success", 0),
            attempt(1723, "stack_overflow", "first_failure", 0),
            attempt(1723, "stack_overflow", "first_failure", 1),
            attempt(1722, "ok", "last_success", 1),
            attempt(1722, "ok", "last_success", 2),
            attempt(1723, "stack_overflow", "first_failure", 2),
        ]
        validate_replay_order(valid, depths)
        wrong_order = copy.deepcopy(valid)
        wrong_order[1], wrong_order[2] = wrong_order[2], wrong_order[1]
        wrong_trap = copy.deepcopy(valid)
        wrong_trap[1]["observation"]["outcome"] = "out_of_fuel"
        for mutated in (valid[:-1], wrong_order, wrong_trap):
            with self.assertRaises(ValueError):
                validate_replay_order(mutated, depths)
        leaf = [
            attempt(1722, "ok", "last_success", 0),
            attempt(1723, "stack_overflow", "first_failure", 0),
            attempt(1722, "ok", "last_success", 1),
            attempt(1723, "stack_overflow", "first_failure", 1),
        ]
        validate_replay_order(leaf, depths, leaf=True)
        leaf[1]["depth"] = 1722
        with self.assertRaises(ValueError):
            validate_replay_order(leaf, depths, leaf=True)

    def test_teardown_requires_table_before_lease_and_no_retention(self):
        events = [
            {"id": 0, "role": "nested_chain", "kind": "reserved",
             "table_alive": None},
            {"id": 0, "role": "nested_chain", "kind": "store_created",
             "table_alive": None},
            {"id": 0, "role": "nested_chain", "kind": "table_destroyed",
             "table_alive": False},
            {"id": 0, "role": "nested_chain", "kind": "lease_released",
             "table_alive": None},
        ]
        self.assertEqual(validate_teardown(events, 1, 0)["created"]["nested_chain"], 1)
        retained = copy.deepcopy(events)
        retained[2]["table_alive"] = True
        reordered = [*events[:2], events[3], events[2]]
        missing = events[:-1]
        for mutated in (retained, reordered, missing):
            with self.assertRaises(ValueError):
                validate_teardown(mutated, 1, 0)

    def test_raw_transcript_rejects_duplicate_terminal(self):
        markers = [
            'running 1 test',
            'KONTOR_STACK_TIMING:{"total_sample_ms":1}',
            'BOUNDARY_PROBE_ATTEMPT:{"depth":1}',
            'BOUNDARY_WORKER_RUNTIME={"pid":1}',
            'BOUNDARY_WORKER_TRACE={"events":[]}',
            'BOUNDARY_PROBE_SUMMARY:{"attempt_count":1}',
            'BOUNDARY_PROBE_TERMINAL:{"complete":true}',
            'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s',
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "child.log"
            path.write_text("\n".join(markers) + "\n")
            self.assertEqual(len(parse_worker_log(path)["attempts"]), 1)
            path.write_text("\n".join(markers[:7] + [markers[6]] +
                                      markers[7:]) + "\n")
            with self.assertRaises(ValueError):
                parse_worker_log(path)

    def test_schema_rejects_unknown_top_level_field(self):
        schema = load_json_strict(SCHEMA)
        self.assertTrue(Draft202012Validator.check_schema(schema) is None)
        minimal = {
            "schema_version": 1, "phase": "pilot_discovery",
            "qualification_status": "missing", "cell": "Linux-ARM64/dev",
            "manifest_sha256": "0" * 64, "source_sha": "0" * 40,
            "binary_path": "/tmp/indexer-test", "binary_sha256": "0" * 64,
            "timeout_seconds": 600,
            "control_capture": {"path": "control.json", "sha256": "0" * 64},
            "development_discovery": None,
            "reviewed_discovery": None,
            "discovery_binary": {"path": "indexer-test", "sha256": "0" * 64},
            "runs": {"x": {}}, "discovered_depths": {},
            "remaining_case_bindings": [],
        }
        baseline_errors = list(Draft202012Validator(schema).iter_errors(minimal))
        changed = {**minimal, "unexpected": True}
        errors = list(Draft202012Validator(schema).iter_errors(changed))
        self.assertGreater(len(errors), len(baseline_errors))


if __name__ == "__main__":
    unittest.main()
