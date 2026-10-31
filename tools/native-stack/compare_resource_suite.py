#!/usr/bin/env python3
"""Validate archived S2 child evidence and compare semantics across six cells."""

import argparse
import hashlib
import importlib
import json
from pathlib import Path

from resource_evidence import load_json_strict, require, sha256
from resource_manifest import CELLS, ROOT
from resource_suite_closure import validate_index
from resource_suite_registry import MANIFEST as REGISTRY_MANIFEST


def canonical(value):
    if isinstance(value, dict):
        pairs = [(canonical(key), canonical(item)) for key, item in value.items()]
        return {"dict": sorted(pairs, key=lambda pair: json.dumps(pair[0], sort_keys=True))}
    if isinstance(value, tuple):
        return {"tuple": [canonical(item) for item in value]}
    if isinstance(value, list):
        return {"list": [canonical(item) for item in value]}
    require(value is None or type(value) in {str, int, float, bool},
            "validator returned a non-serializable semantic signature")
    return value


def signature_sha256(signature):
    encoded = json.dumps(canonical(signature), sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def validator_for(group):
    source = ROOT / group["validator"]["path"]
    require(sha256(source) == group["validator"]["sha256"],
            "suite validator source differs from registry")
    module = importlib.import_module(source.stem)
    require(Path(module.__file__).resolve() == source.resolve(),
            "suite validator module loaded from a different source")
    return module.validate_bundle


def compare_suite(index, root):
    validate_index(index, root)
    registry = load_json_strict(REGISTRY_MANIFEST)
    signatures = {}
    for cell in CELLS:
        record = index["cells"][cell]
        binary_archive = root / record["binary"]["path"]
        cell_signatures = {}
        for group_id, group in registry["groups"].items():
            path = root / record["groups"][group_id]["path"]
            bundle = load_json_strict(path)
            validate_bundle = validator_for(group)
            cell_signatures[group_id] = validate_bundle(
                bundle, path.parent, archive_binary=binary_archive)
        signatures[cell] = cell_signatures
    reference = signatures[CELLS[0]]
    for cell in CELLS[1:]:
        for group_id in registry["groups"]:
            require(signatures[cell][group_id] == reference[group_id],
                    f"{cell}/{group_id}: deterministic execution semantics differ")
    return {
        "status": "case_semantics_equal",
        "qualification_status": "missing",
        "source_sha": index["source_sha"],
        "index_canonical_sha256": signature_sha256(index),
        "cells": len(CELLS),
        "case_count": registry["case_count"],
        "group_signature_sha256": {
            group_id: signature_sha256(reference[group_id])
            for group_id in registry["groups"]},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    index = load_json_strict(args.index)
    result = compare_suite(index, root)
    with args.output.open("x") as destination:
        json.dump(result, destination, indent=2, sort_keys=True)
        destination.write("\n")
    print(json.dumps({"status": result["status"],
                      "source_sha": result["source_sha"]}, sort_keys=True))


if __name__ == "__main__":
    main()
