"""Synthetic document tests. No Bitcoin, runtime, or qualification evidence."""

from copy import deepcopy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from workload_fixture import FixtureError
from workload_manifest import check_reports, export_verified, load_frozen_documents
from workload_schema import money, validate_manifest


def hash_value(number):
    return f"{number:064x}"


def file_reference(name):
    return {"path": name, "sha256": hash_value(99)}


def amount(value):
    scaled = value * 10**18
    assert scaled.denominator == 1
    whole, fraction = divmod(scaled.numerator, 10**18)
    tail = f"{fraction:018d}".rstrip("0")
    return f"{whole}.{tail}" if tail else str(whole)


def documents():
    operations = [
        {"txid": hash_value(3), "tx_index": 2, "input_index": 0, "op_index": index,
         "contract": "smokeb_2_1" if index == 1 else "smokea_2_0",
         "expression": expression, "gas_limit": 100000}
        for index, expression in enumerate((
            "write-result-payload(1)", "scan-compound(false)", "write-result-payload(2)",
        ))
    ]
    manifest = {
        "schema_version": 1, "kind": "smoke", "case_id": "paid-success-failure-success-v1",
        "funding_seed_hex": "01" * 64,
        "source": {"kontor_commit": "a" * 40, "rustc_verbose": "synthetic", "target": "synthetic",
                   "profile": "dev", "features": [], "core_lockfile": file_reference("Cargo.lock"),
                   "wasmtime_revision": "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7",
                   "engine": "pulley", "pulley_stack_bytes": 524288, "native_fiber_bytes": 2097152},
        "artifacts": [
            {"id": name, "compressed": file_reference(f"{name}.wasm.br"), "raw_sha256": hash_value(8),
             "addresses": ["smokea_2_0", "smokeb_2_1"] if name == "error_test" else [f"{name}_0_0"]}
            for name in ("error_test", "filestorage", "nft", "staking", "system", "token")
        ],
        "snapshot": {"database": file_reference("snapshot.db"), "schema_sha256": hash_value(9),
                     "anchor_height": 9, "anchor_hash": hash_value(9), "checkpoint": "before",
                     "prune_watermark": 0, "reset_report": file_reference("before.json")},
        "input": {"raw_block": file_reference("block.bin"), "height": 10, "block_hash": hash_value(10),
                  "previous_hash": hash_value(9), "raw_txids": [hash_value(n) for n in (1, 2, 3)],
                  "kontor_txids": [hash_value(3)], "kontor_input_count": 1, "operation_count": 3,
                  "payer_x_only_pubkey": hash_value(20), "operations": operations,
                  "bitcoin_validation": {"network": "regtest", "bitcoind_version": "synthetic",
                                         "accepted_block_hash": hash_value(10), "record": file_reference("bitcoin.json")}},
        "execution": {"executor": "RuntimeExecutor", "component_cache": "cold", "network": "regtest",
                      "starting_block_height": 1,
                      "prune_enabled": True, "retain_blocks": 6, "gas_to_fuel_multiplier": 1000,
                      "execution_price": "0.000000001", "storage_gas_per_byte": 1,
                      "lifecycle_parameters": file_reference("lifecycle.json"),
                      "independent_resets": 2, "timing_claim": "none"},
        "expected_report": file_reference("after.json"), "numeric_check": file_reference("numeric.json"),
        "decision": {"consensus_height": 10, "certificate_hex": "", "value_kind": "block",
                     "block_height": 10, "block_hash": hash_value(10), "certified_txs": None},
    }
    before = {
        "schema_version": 1, "height": 9, "block_hash": hash_value(9), "checkpoint": "before",
        "prune_watermark": 0, "receipts": [], "usage": [],
        "accounts": {name: {"balance": "0", "floor": "0"}
                     for name in ("payer", "burner", "core", "ordering_pool", "storage_pool", "total_supply")},
        "contract_views": {name: {"address": address, "storage_state": [0, 0, 0, 0]}
                           for name, address in (("A", "smokea_2_0"), ("B", "smokeb_2_1"))},
        "state_versions": [{"contract": "history_1_0", "path_hex": "01", "height": height,
                            "value_hex": f"{height:02x}", "deleted": False,
                            "depositor": None, "deposited_gas": None} for height in (1, 3)],
        "table_counts": [{"table": "contract_state", "rows": 2}],
    }
    before["accounts"]["payer"]["balance"] = "1"
    before["accounts"]["total_supply"]["balance"] = "1"
    after = deepcopy(before)
    after.update(height=10, block_hash=hash_value(10), checkpoint="after", prune_watermark=4)
    after["state_versions"].pop(0)
    after["table_counts"][0]["rows"] = 1
    after["contract_views"]["A"]["storage_state"] = [1, 0, 0, 1]
    numeric = {"schema_version": 1, "snapshot_sha256": hash_value(99), "raw_block_sha256": hash_value(99),
               "source_commit": "a" * 40, "operations": []}
    payer, burner, floor = Fraction(1), Fraction(0), Fraction(0)
    for index, operation in enumerate(operations):
        fee, next_floor = Fraction(8, 10**9), Fraction(2, 10**9)
        status = "Other" if index == 1 else "Ok"
        value = ('"é\\n"', None, '"é\\né\\n"')[index]
        evidence = {key: operation[key] for key in operation if key != "gas_limit"}
        evidence.update(
            status=status, value=value, gas=10, user_fuel=8000, system_fuel=1000,
            deposit_fuel=2000, reserved_deposit_gas=2,
            payer_before=amount(payer), payer_after=amount(payer - fee),
            burner_before=amount(burner), burner_after=amount(burner + fee),
            floor_before=amount(floor), floor_after=amount(next_floor), execution_fee=amount(fee),
            error_message="row scan requires direct scalar leaves" if index == 1 else None,
            storage_state=[0, 0, 0, 0] if index == 1 else [1, 0, 0, 1],
        )
        numeric["operations"].append(evidence)
        after["receipts"].append({
            "id": index + 1, "height": 10, "tx_index": 0, "input_index": 0, "op_index": index,
            "result_index": 0, "func": operation["expression"].split("(")[0], "gas": 10,
            "status": status, "value": value, "contract": operation["contract"],
            "txid": operation["txid"], "signer_id": 10, "payer_signer_id": 10,
        })
        payer, burner, floor = payer - fee, burner + fee, next_floor
    after["accounts"]["payer"] = {"balance": amount(payer), "floor": amount(floor)}
    after["accounts"]["burner"]["balance"] = amount(burner)
    after["usage"] = [
        {"height": 10, "tx_index": 2, "txid": hash_value(3), "kind": "transaction",
         "user_fuel": 24000, "system_fuel": 3000, "deposit_fuel": 6000},
        {"height": 10, "tx_index": None, "txid": None, "kind": "block",
         "user_fuel": 0, "system_fuel": 5000, "deposit_fuel": 0},
    ]
    return manifest, before, after, numeric


class WorkloadDocumentTests(unittest.TestCase):
    def check(self, values):
        manifest, before, after, numeric = values
        validate_manifest(manifest)
        check_reports(manifest, before, after, numeric)

    def test_consistent_synthetic_documents(self):
        self.check(documents())

    def test_predecessor_retention_has_explicit_versioned_metadata(self):
        data = documents()
        data[0]["schema_version"] = 2
        data[0]["execution"]["effective_retain_blocks"] = 7
        data[2]["prune_watermark"] = 3
        self.check(data)
        for version, retention, watermark in [(1, 7, 3), (2, 6, 4), (2, 7, 4), (2, True, 3)]:
            altered = deepcopy(data)
            altered[0]["schema_version"] = version
            altered[0]["execution"]["effective_retain_blocks"] = retention
            altered[2]["prune_watermark"] = watermark
            with self.subTest(version=version, retention=retention, watermark=watermark):
                with self.assertRaises(FixtureError):
                    self.check(altered)
        # Legacy archives keep their original watermark, without relabeling it.
        self.check(documents())

    def test_identity_and_scope_mutations_are_rejected(self):
        changes = [
            (0, ("schema_version",), 2), (0, ("schema_version",), True),
            (0, ("execution", "network"), "mainnet"),
            (0, ("input", "operations", 2, "op_index"), 0),
            (0, ("input", "operations", 1, "tx_index"), 0),
            (0, ("input", "previous_hash"), hash_value(77)),
            (0, ("decision", "block_hash"), hash_value(77)),
            (2, ("receipts", 0, "height"), 9),
            (2, ("usage", 0, "tx_index"), None),
            (3, ("source_commit",), "b" * 40),
            (3, ("operations", 0, "gas"), True),
            (0, ("execution", "starting_block_height"), 0),
            (0, ("execution", "starting_block_height"), 10),
            (2, ("receipts", 1, "result_index"), 1),
        ]
        self.reject_mutations(changes)

    def reject_mutations(self, changes):
        for document, path, value in changes:
            data = documents()
            target = data[document]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path, value=value), self.assertRaises(FixtureError):
                self.check(data)

    def test_accounting_and_rollback_mutations_are_rejected(self):
        self.reject_mutations([
            (3, ("operations", 1, "deposit_fuel"), 2001),
            (3, ("operations", 1, "reserved_deposit_gas"), 1),
            (3, ("operations", 1, "payer_after"), "1"),
            (3, ("operations", 1, "burner_after"), "0"),
            (3, ("operations", 1, "floor_after"), "0"),
            (3, ("operations", 1, "storage_state"), [1, 0, 1, 0]),
            (3, ("operations", 1, "error_message"), "unrelated failure"),
            (2, ("contract_views", "B", "storage_state"), [1, 0, 1, 0]),
            (2, ("prune_watermark",), 0),
            (2, ("usage", 0, "system_fuel"), 3001),
        ])

    def test_equal_wrong_outcomes_do_not_pass(self):
        data = documents()
        data[2]["receipts"][0]["status"] = "Other"
        data[3]["operations"][0]["status"] = "Other"
        with self.assertRaisesRegex(FixtureError, "unexpected smoke operation outcome"):
            self.check(data)

    def test_equal_wrong_values_do_not_pass(self):
        data = documents()
        data[2]["receipts"][0]["value"] = '"wrong"'
        data[3]["operations"][0]["value"] = '"wrong"'
        with self.assertRaisesRegex(FixtureError, "unexpected smoke return value"):
            self.check(data)

    def test_gas_must_reconcile_with_fuel_even_when_both_reports_change(self):
        data = documents()
        data[2]["usage"][0]["user_fuel"] = 0
        for operation in data[3]["operations"]:
            operation["user_fuel"] = 0
        with self.assertRaisesRegex(FixtureError, "gas differs from measured gross user fuel"):
            self.check(data)

    def test_extra_paid_receipts_cannot_be_filtered_out(self):
        data = documents()
        extra = deepcopy(data[2]["receipts"][-1])
        extra.update(id=4, op_index=3)
        data[2]["receipts"].append(extra)
        with self.assertRaisesRegex(FixtureError, "paid roots missing, duplicated or reordered"):
            self.check(data)

    def test_core_lifecycle_receipts_can_have_payer_metadata(self):
        data = documents()
        core = deepcopy(data[2]["receipts"][-1])
        core.update(id=4, txid=None, tx_index=None, input_index=None, op_index=None,
                    signer_id=1, payer_signer_id=1, contract="token_0_0", func="mint-emission")
        data[2]["receipts"].append(core)
        self.check(data)

    def test_raw_index_and_persisted_ordinal_are_distinct(self):
        data = documents()
        self.assertEqual(data[0]["input"]["operations"][0]["tx_index"], 2)
        self.assertEqual(data[2]["receipts"][0]["tx_index"], 0)
        self.check(data)
        data[2]["receipts"][0]["tx_index"] = 2
        with self.assertRaisesRegex(FixtureError, "persisted receipt transaction position differs"):
            self.check(data)

    def test_missing_or_extra_nested_fields_do_not_pass(self):
        data = documents()
        data[3]["operations"][0]["ignored"] = "extra"
        with self.assertRaises(FixtureError):
            self.check(data)
        data = documents()
        del data[2]["receipts"][0]["payer_signer_id"]
        with self.assertRaises(FixtureError):
            self.check(data)

    def test_pruning_requires_removed_and_retained_versions(self):
        for mutate in ("nothing_removed", "no_successor", "changed_successor"):
            data = documents()
            if mutate == "nothing_removed":
                data[2]["state_versions"] = deepcopy(data[1]["state_versions"])
            elif mutate == "no_successor":
                data[2]["state_versions"] = []
            else:
                data[2]["state_versions"][0]["value_hex"] = "ff"
            with self.subTest(mutate=mutate), self.assertRaises(FixtureError):
                self.check(data)

    def test_pruning_rejects_only_unfinalized_successor(self):
        data = documents()
        data[1]["state_versions"][1]["height"] = 5
        data[2]["state_versions"][0]["height"] = 5
        with self.assertRaisesRegex(FixtureError, "finalized superseding version"):
            self.check(data)

    def test_pruning_rejects_removal_above_watermark(self):
        data = documents()
        data[1]["state_versions"][0]["height"] = 5
        data[1]["state_versions"][1]["height"] = 6
        data[2]["state_versions"][0]["height"] = 6
        with self.assertRaisesRegex(FixtureError, "inside retention window"):
            self.check(data)

    def test_decimal_comparison_is_exact_and_bounded(self):
        self.assertEqual(money("0.000000000000000001", "money"), Fraction(1, 10**18))
        for value in ("-1", "01", "1.0", "1e-9", "0.0000000000000000001", str(2**256), "NaN", 0.1):
            with self.subTest(value=value), self.assertRaises(FixtureError):
                money(value, "money")

    def test_loading_binds_reports_to_the_same_frozen_files(self):
        manifest, before, after, numeric = documents()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def write(reference, data):
                (root / reference["path"]).write_bytes(data)
                reference["sha256"] = hashlib.sha256(data).hexdigest()

            for reference in (
                manifest["snapshot"]["database"], manifest["input"]["raw_block"],
                manifest["source"]["core_lockfile"],
                manifest["input"]["bitcoin_validation"]["record"],
                manifest["execution"]["lifecycle_parameters"],
                *(item["compressed"] for item in manifest["artifacts"]),
            ):
                write(reference, b"synthetic file identity only")
            numeric["snapshot_sha256"] = manifest["snapshot"]["database"]["sha256"]
            numeric["raw_block_sha256"] = manifest["input"]["raw_block"]["sha256"]
            write(manifest["input"]["bitcoin_validation"]["record"], b'{"network":"regtest"}')
            write(manifest["execution"]["lifecycle_parameters"], b'{"network":"regtest"}')
            for reference, value in (
                (manifest["snapshot"]["reset_report"], before),
                (manifest["expected_report"], after),
                (manifest["numeric_check"], numeric),
            ):
                write(reference, json.dumps(value).encode())
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest))
            _, loaded_before, loaded_after, loaded_numeric = load_frozen_documents(path)
            self.assertEqual((loaded_before, loaded_after, loaded_numeric), (before, after, numeric))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            exported = export_verified(path, digest)
            self.assertEqual(exported["manifest_sha256"], digest)
            self.assertEqual(exported["numeric"], numeric)
            self.assertEqual(exported["bitcoin"], {"network": "regtest"})
            with self.assertRaisesRegex(FixtureError, "pinned SHA-256"):
                export_verified(path, "0" * 64)
            (root / manifest["numeric_check"]["path"]).write_text("{}")
            with self.assertRaisesRegex(FixtureError, "SHA-256 mismatch"):
                load_frozen_documents(path)


if __name__ == "__main__":
    unittest.main()
