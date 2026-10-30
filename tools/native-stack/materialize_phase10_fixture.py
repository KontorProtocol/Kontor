#!/usr/bin/env python3
"""Expand and verify the pinned historical phase10 chain capture."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path

from resource_evidence import load_json_strict, require, sha256
from resource_evidence_v2 import HISTORICAL_BUNDLE_SHA256
from resource_manifest_v2 import MANIFEST, build_manifest_v2


FIXTURE = Path(__file__).with_name("fixtures") / "phase10-resource-chain-capture.json.gz"
RAW_SIZE = 14_018_873


def materialize(destination):
    manifest = build_manifest_v2()
    require(load_json_strict(MANIFEST) == manifest,
            "historical fixture manifest differs from source")
    require(sha256(FIXTURE) == manifest["sources"]["historical_phase10_gzip"]["sha256"],
            "compressed historical phase10 fixture differs")
    require(not destination.exists(), "historical output already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    with gzip.open(FIXTURE, "rb") as source, destination.open("xb") as output:
        while chunk := source.read(1 << 20):
            size += len(chunk)
            require(size <= RAW_SIZE, "historical phase10 fixture expands beyond pin")
            digest.update(chunk)
            output.write(chunk)
    require(size == RAW_SIZE and digest.hexdigest() == HISTORICAL_BUNDLE_SHA256,
            "historical phase10 fixture differs from raw pin")
    return {"path": str(destination), "size": size, "sha256": digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(materialize(args.output), sort_keys=True))


if __name__ == "__main__":
    main()
