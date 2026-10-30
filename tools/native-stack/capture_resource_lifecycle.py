#!/usr/bin/env python3
"""Capture published guest resource lifecycle cases on measured worker stacks."""

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from capture_resource_finite import capture
from resource_evidence import sha256
from resource_lifecycle_evidence import (CASES, expected_case_env, run_name,
                                         validate_bundle)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--control-capture", type=Path, required=True)
    parser.add_argument("--control-sha256", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args()
    path = capture(
        args.cell, args.control_capture, args.control_sha256,
        args.evidence_dir, args.timeout_seconds, case_ids=CASES,
        make_run_name=run_name, make_case_env=expected_case_env,
        validate=validate_bundle, output_prefix="resource-lifecycle")
    print(json.dumps({"capture_path": str(path), "sha256": sha256(path)},
                     sort_keys=True))


if __name__ == "__main__":
    main()
