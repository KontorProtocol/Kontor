"""Assemble a review candidate from an actual development-smoke capture.

This does not approve or refreeze an existing workload. The Rust frozen replay
must still pass at the captured source revision before the candidate is usable.
"""

import argparse
import hashlib
import json
from pathlib import Path
import tomllib

from workload_fixture import parse_document
from workload_manifest import load_frozen_documents
from workload_schema import require


def assemble(directory):
    root = Path(directory).resolve(strict=True)

    def read(name):
        return parse_document((root / name).read_bytes(), name)

    def reference(name):
        return {"path": name, "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest()}

    candidate, source = read("candidate.json"), read("source.json")
    before, after = read("before-report.json"), read("trial-one.db-report.json")
    require(after == read("trial-two.db-report.json"), "candidate replay reports differ")
    require(read("trial-one.db-projection.json") == read("trial-two.db-projection.json"),
            "candidate replay database projections differ")
    require(candidate["replays"] == 2 and candidate["frozen_acceptance"] is False,
            "expected an unapproved two-replay development candidate")
    require(source["git_status_log"] == "" and source["git_head_log"].strip()
            == source["embedded_source_commit"] == candidate["source_commit"], "candidate source differs")
    lockfile = reference("Cargo.lock")
    require(lockfile["sha256"] == source["core_lockfile_sha256"], "candidate lockfile differs")
    packages = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    wasmtime = [package for package in packages if package["name"] == "wasmtime"]
    require(len(wasmtime) == 1, "expected one Wasmtime package")
    revision = wasmtime[0]["source"].rsplit("#", 1)[-1]
    bitcoin = read("bitcoin-validation.json")
    raw_block = reference("block.bin")
    snapshot = reference("snapshot.db")
    require(raw_block["sha256"] == candidate["raw_block_sha256"]
            and snapshot["sha256"] == candidate["snapshot_sha256"], "candidate input identity differs")
    txid = candidate["raw_txids"][2]
    operations = [
        {"txid": txid, "tx_index": 2, "input_index": 0, "op_index": index,
         "contract": candidate["contracts"][int(index == 1)], "expression": expression, "gas_limit": 100_000}
        for index, expression in enumerate(("write-result-payload(1)", "scan-compound(false)", "write-result-payload(2)"))
    ]
    manifest = {
        "schema_version": 1, "kind": "smoke", "case_id": "paid-success-failure-success-v1",
        "funding_seed_hex": candidate["funding_seed_hex"],
        "source": {
            "kontor_commit": candidate["source_commit"],
            **{key: source[key] for key in ("rustc_verbose", "target", "profile", "features")},
            "core_lockfile": lockfile, "wasmtime_revision": revision, "engine": "pulley",
            "pulley_stack_bytes": 524288, "native_fiber_bytes": 2097152,
        },
        "artifacts": read("artifacts.json"),
        "snapshot": {
            "database": snapshot, "schema_sha256": candidate["schema_sha256"],
            "anchor_height": candidate["anchor_height"], "anchor_hash": candidate["anchor_hash"],
            "checkpoint": before["checkpoint"], "prune_watermark": before["prune_watermark"],
            "reset_report": reference("before-report.json"),
        },
        "input": {
            "raw_block": raw_block, "height": candidate["block_height"],
            "block_hash": candidate["block_hash"], "previous_hash": candidate["anchor_hash"],
            "raw_txids": candidate["raw_txids"], "kontor_txids": [txid],
            "kontor_input_count": 1, "operation_count": 3,
            "payer_x_only_pubkey": candidate["payer_x_only_pubkey"], "operations": operations,
            "bitcoin_validation": {
                "network": bitcoin["network"], "bitcoind_version": bitcoin["bitcoind_version"],
                "accepted_block_hash": bitcoin["accepted_block_hash"], "record": reference("bitcoin-validation.json"),
            },
        },
        "execution": {
            "executor": "RuntimeExecutor", "component_cache": "cold", "network": "regtest",
            "prune_enabled": True, "retain_blocks": 6, "starting_block_height": candidate["starting_block_height"],
            "gas_to_fuel_multiplier": 1000, "execution_price": "0.000000001", "storage_gas_per_byte": 1,
            "lifecycle_parameters": reference("lifecycle-parameters.json"), "independent_resets": 2, "timing_claim": "none",
        },
        "expected_report": reference("trial-one.db-report.json"), "numeric_check": reference("numeric-check.json"),
        "decision": {
            "consensus_height": candidate["next_consensus_height"], "certificate_hex": "", "value_kind": "block",
            "block_height": candidate["block_height"], "block_hash": candidate["block_hash"], "certified_txs": None,
        },
    }
    output = root / "candidate-manifest.json"
    # Never replace a reviewed manifest when new observations differ.
    with output.open("xb") as destination:
        destination.write(json.dumps(manifest, ensure_ascii=False, indent=2).encode() + b"\n")
    try:
        reader, *_ = load_frozen_documents(output)
    except BaseException:
        output.unlink()
        raise
    return {"manifest": str(output), "sha256": reader.manifest_sha256, "frozen_acceptance": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate_directory")
    print(json.dumps(assemble(parser.parse_args().candidate_directory)))
