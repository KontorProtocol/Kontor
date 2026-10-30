#!/usr/bin/env python3
"""Capture bounded pending host I/O children on both measured worker stacks."""

import argparse
import json
from pathlib import Path

from capture_resource_finite import capture
from resource_evidence import sha256
from resource_pending_evidence import (CASE_ID, expected_case_env,
                                       parse_worker_log, run_name, validate_bundle)


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
        args.evidence_dir, args.timeout_seconds,
        case_ids=(CASE_ID,),
        make_run_name=lambda case_id, role, configuration: run_name(role, configuration),
        make_case_env=lambda case_id, role, configuration:
            expected_case_env(role, configuration),
        parse_log=parse_worker_log, validate=validate_bundle,
        output_prefix="pending-host-io",
    )
    print(json.dumps({"capture_path": str(path), "sha256": sha256(path)},
                     sort_keys=True))


if __name__ == "__main__":
    main()
