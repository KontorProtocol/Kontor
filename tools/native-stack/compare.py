#!/usr/bin/env python3
"""Compare native stack qualification results across hosts and profiles."""

import argparse
import json
import sys
from pathlib import Path


def observation_signature(observation):
    return {
        key: observation.get(key)
        for key in (
            "depth",
            "outcome",
            "value",
            "receipt",
            "last_depth",
            "child_markers",
            "rolled_back",
            "fuel",
        )
    }


def signature(case):
    boundary = {
        key: case.get(key)
        for key in ("boundary", "last_success", "first_failure", "first_failure_outcome")
    }
    boundary["observations"] = [
        observation_signature(observation)
        for observation in case.get("observations", [case])
    ]
    return boundary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected", type=int, default=6)
    args = parser.parse_args()
    paths = sorted(args.directory.glob("*/qualification.json"))
    reports = {path.parent.name: json.loads(path.read_text()) for path in paths}
    cases = {
        variant: {case["kind"]: signature(case) for case in report["cases"]}
        for variant, report in reports.items()
    }
    signatures = list(cases.values())
    consistent = bool(signatures) and all(item == signatures[0] for item in signatures)
    components = {
        observation["component_sha256"]
        for report in reports.values()
        for case in report["cases"]
        for observation in case.get("observations", [case])
        if "component_sha256" in observation
    }
    settings = {
        variant: sorted(
            {
                (observation["max_wasm_stack"], observation["async_stack_size"])
                for case in report["cases"]
                for observation in case.get("observations", [case])
                if "max_wasm_stack" in observation
            }
        )
        for variant, report in reports.items()
    }
    same_settings = len({tuple(values) for values in settings.values()}) == 1
    result = {
        "expected_reports": args.expected,
        "actual_reports": len(reports),
        "same_component": len(components) == 1,
        "same_measurements": consistent,
        "same_effective_stack_settings": same_settings,
        "components": sorted(components),
        "settings": settings,
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return int(
        len(reports) != args.expected
        or len(components) != 1
        or not consistent
        or not same_settings
    )


if __name__ == "__main__":
    sys.exit(main())
