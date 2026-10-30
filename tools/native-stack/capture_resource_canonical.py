#!/usr/bin/env python3
"""Capture published canonical ABI calls on both measured worker configurations."""

import argparse
import json
from pathlib import Path

from capture_resource_finite import capture
from resource_canonical_evidence import (CASES, expected_case_env, parse_worker_log,
                                         run_name, validate_bundle)
from resource_evidence import sha256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--control-capture", type=Path, required=True)
    parser.add_argument("--control-sha256", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    args = parser.parse_args()
    path = capture(
        args.cell, args.control_capture, args.control_sha256,
        args.evidence_dir, args.timeout_seconds,
        case_ids=CASES,
        make_run_name=run_name,
        make_case_env=expected_case_env,
        parse_log=parse_worker_log, validate=validate_bundle,
        output_prefix="canonical-stack",
    )
    print(json.dumps({"capture_path": str(path), "sha256": sha256(path)},
                     sort_keys=True))


if __name__ == "__main__":
    main()
