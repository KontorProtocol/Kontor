"""Validate frozen smoke documents, before the Rust replay validates live inputs.

This is not an acceptance runner. Bitcoin decoding, artifact decompression,
runtime/source checks, SQLite reset checks and actual replay remain mandatory.
"""

from fractions import Fraction
import argparse
import json
import sys

from workload_fixture import FixtureReader
from workload_schema import (NUMERIC_CHECK, effective_retention, require,
                             validate_manifest, validate_report)


IDENTITY_FIELDS = ("txid", "input_index", "op_index", "contract")
STATUSES = ("Ok", "Other", "Ok")
STATES = ([1, 0, 0, 1], [0, 0, 0, 0], [1, 0, 0, 1])
VALUES = ('"é\\n"', None, '"é\\né\\n"')


def operation_identity(operation):
    return tuple(operation[key] for key in IDENTITY_FIELDS)


def check_numeric(manifest, report, numeric):
    NUMERIC_CHECK(numeric, "numeric_check")
    require(numeric["snapshot_sha256"] == manifest["snapshot"]["database"]["sha256"], "numeric check used a different snapshot")
    require(numeric["raw_block_sha256"] == manifest["input"]["raw_block"]["sha256"], "numeric check used a different block")
    require(numeric["source_commit"] == manifest["source"]["kontor_commit"], "numeric check used a different source")
    identities = [operation_identity(item) for item in manifest["input"]["operations"]]
    txid = manifest["input"]["kontor_txids"][0]
    require(all(item["txid"] in (None, txid) for item in report["receipts"]), "receipt belongs to an unplanned transaction")
    # Core lifecycle calls can carry payer metadata despite bypassing user
    # settlement. Their null transaction identity distinguishes them here.
    receipts = [item for item in report["receipts"] if item["txid"] == txid]
    require([operation_identity(item) for item in receipts] == identities, "paid roots missing, duplicated or reordered")
    signer = receipts[0]["signer_id"]
    require(all(item["payer_signer_id"] == item["signer_id"] == signer for item in receipts), "smoke roots are not paid by the same direct signer")
    multiplier = manifest["execution"]["gas_to_fuel_multiplier"]
    price = Fraction(manifest["execution"]["execution_price"])
    for index, (expected, actual, receipt) in enumerate(zip(manifest["input"]["operations"], numeric["operations"], receipts)):
        require(operation_identity(actual) == identities[index] and actual["expression"] == expected["expression"], "numeric operation identity differs")
        require(actual["tx_index"] == expected["tx_index"], "numeric raw transaction position differs")
        # ResultRow joins the persisted filtered transaction ordinal. Guest
        # context uses the original Bitcoin index, which includes coinbase.
        require(receipt["tx_index"] == manifest["input"]["kontor_txids"].index(expected["txid"]), "persisted receipt transaction position differs")
        require(actual["status"] == receipt["status"] == STATUSES[index], "unexpected smoke operation outcome")
        require(actual["value"] == receipt["value"] == VALUES[index], "unexpected smoke return value")
        require(receipt["func"] == expected["expression"].split("(")[0], "receipt function differs")
        require(receipt["result_index"] == 0, "smoke root result index differs")
        require(actual["gas"] == receipt["gas"] <= expected["gas_limit"], "gas differs or exceeds limit")
        require(actual["gas"] > 0, "paid operation has no gas charge")
        gross_user_fuel = actual["user_fuel"] + actual["deposit_fuel"]
        require(actual["gas"] == max(1, (gross_user_fuel + multiplier - 1) // multiplier), "gas differs from measured gross user fuel")
        require(actual["storage_state"] == STATES[index], "diagnostic committed state or rollback differs")
        require(actual["deposit_fuel"] % multiplier == 0, "fractional deposit reservation")
        reserved = actual["deposit_fuel"] // multiplier
        require(actual["reserved_deposit_gas"] == reserved <= actual["gas"], "invalid deposit reservation")
        fee = (actual["gas"] - reserved) * price
        require(Fraction(actual["execution_fee"]) == fee, "fee differs from source pricing formula")
        require(Fraction(actual["payer_before"]) - Fraction(actual["payer_after"]) == fee, "payer debit differs from fee")
        require(Fraction(actual["burner_after"]) - Fraction(actual["burner_before"]) == fee, "burner credit differs from fee")
        require(Fraction(actual["payer_after"]) >= Fraction(actual["floor_after"]), "diagnostic payer below floor")
        if index:
            previous = numeric["operations"][index - 1]
            for account in ("payer", "burner", "floor"):
                require(actual[f"{account}_before"] == previous[f"{account}_after"], "numeric check did not preserve prior operation effects")
        if index == 1:
            require(actual["value"] is None and isinstance(actual["error_message"], str)
                    and "row scan requires direct scalar leaves" in actual["error_message"], "wrong deterministic failure")
            require(reserved > 0 and actual["floor_before"] == actual["floor_after"], "failed writes did not consume and release reservations")
        else:
            require(actual["value"] is not None and actual["error_message"] is None, "successful operation lacks its result")
    require(numeric["operations"][0]["value"] != numeric["operations"][2]["value"], "distinct successful calls must have distinct results")
    usage = [item for item in report["usage"] if item["kind"] == "transaction"]
    require(len(usage) == 1 and usage[0]["txid"] == manifest["input"]["kontor_txids"][0], "missing reveal usage")
    require(usage[0]["tx_index"] == manifest["input"]["operations"][0]["tx_index"], "usage transaction position differs")
    for field in ("user_fuel", "system_fuel", "deposit_fuel"):
        require(sum(item[field] for item in numeric["operations"]) == usage[0][field], f"diagnostic {field} differs from transaction usage")


def check_reports(manifest, before, after, numeric):
    validate_report(before)
    validate_report(after)
    snapshot, block = manifest["snapshot"], manifest["input"]
    require((before["height"], before["block_hash"], before["checkpoint"], before["prune_watermark"])
            == (snapshot["anchor_height"], snapshot["anchor_hash"], snapshot["checkpoint"], snapshot["prune_watermark"]), "reset report differs from snapshot anchor")
    require(after["height"] == block["height"] and after["block_hash"] == block["block_hash"], "result report describes a different block")
    require(after["prune_watermark"] == block["height"] - effective_retention(manifest), "pruning did not reach expected watermark")
    require([item["table"] for item in before["table_counts"]] == [item["table"] for item in after["table_counts"]], "persistent schema table set changed")
    for name, index in (("A", 0), ("B", 1)):
        address = block["operations"][index]["contract"]
        require(before["contract_views"][name]["address"] == after["contract_views"][name]["address"] == address, "contract view identity differs")
        require(before["contract_views"][name]["storage_state"] == [0, 0, 0, 0], "smoke contract pre-state is not initialized empty")
        require(after["contract_views"][name]["storage_state"] == STATES[index], "smoke final contract state differs")
    require(len([item for item in after["usage"] if item["kind"] == "block"]) == 1, "missing block lifecycle usage")
    check_numeric(manifest, after, numeric)
    first, last = numeric["operations"][0], numeric["operations"][-1]
    for account in ("payer", "burner"):
        require(before["accounts"][account]["balance"] == first[f"{account}_before"], "numeric account pre-state differs")
        require(after["accounts"][account]["balance"] == last[f"{account}_after"], "numeric account post-state differs")
    require(before["accounts"]["payer"]["floor"] == first["floor_before"]
            and after["accounts"]["payer"]["floor"] == last["floor_after"], "numeric collateral differs from block state")
    before_rows = {(item["contract"], item["path_hex"], item["height"]): item for item in before["state_versions"]}
    after_rows = {(item["contract"], item["path_hex"], item["height"]): item for item in after["state_versions"]}
    removed = before_rows.keys() - after_rows.keys()
    require(bool(removed), "smoke lacks useful pruning")
    for key in removed:
        require(key[2] <= after["prune_watermark"], "removed state inside retention window")
        successors = [row for row_key, row in before_rows.items()
                      if row_key[:2] == key[:2] and key[2] < row_key[2] <= after["prune_watermark"]]
        require(bool(successors), "pruning fixture lacks a finalized superseding version")
        latest = max(successors, key=lambda item: item["height"])
        latest_key = (latest["contract"], latest["path_hex"], latest["height"])
        require(not latest["deleted"] and after_rows.get(latest_key) == latest, "pruning lost the retained live successor")


def _file_references(value, where="manifest"):
    if isinstance(value, dict):
        if set(value) == {"path", "sha256"}:
            yield where, value
        else:
            for key, child in value.items():
                yield from _file_references(child, f"{where}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _file_references(child, f"{where}[{index}]")


def load_frozen_documents(manifest_path):
    reader = FixtureReader(manifest_path)
    manifest = validate_manifest(reader.manifest)
    for where, reference in _file_references(manifest):
        reader.verify_reference(reference, where)
    before = reader.read_document(manifest["snapshot"]["reset_report"], "reset_report")
    after = reader.read_document(manifest["expected_report"], "expected_report")
    numeric = reader.read_document(manifest["numeric_check"], "numeric_check")
    check_reports(manifest, before, after, numeric)
    return reader, before, after, numeric


def export_verified(manifest_path, expected_sha256):
    reader, before, after, numeric = load_frozen_documents(manifest_path)
    require(reader.manifest_sha256 == expected_sha256, "manifest differs from pinned SHA-256")
    manifest = reader.manifest
    return {
        "python_version": sys.version,
        "manifest_sha256": reader.manifest_sha256,
        "manifest": manifest,
        "before": before,
        "after": after,
        "numeric": numeric,
        "bitcoin": reader.read_document(manifest["input"]["bitcoin_validation"]["record"], "bitcoin record"),
        "lifecycle": reader.read_document(manifest["execution"]["lifecycle_parameters"], "lifecycle parameters"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export verified documents for the Rust replay harness")
    parser.add_argument("manifest")
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(export_verified(args.manifest, args.sha256), ensure_ascii=False))
