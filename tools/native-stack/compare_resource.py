#!/usr/bin/env python3
"""Require complete six-cell S2 resource evidence with equal execution results."""

import argparse
from pathlib import Path

from resource_evidence import load_json_strict, require, validate
from resource_manifest import CELLS


def compare(paths):
    require(len(paths) == len(CELLS), "six resource reports are required")
    reports = {}
    signatures = {}
    for path in paths:
        report = load_json_strict(path)
        cell = report["cell"]
        require(cell in CELLS and cell not in reports,
                f"duplicate or unknown resource cell: {cell}")
        signatures[cell] = validate(report, path.parent)
        reports[cell] = report
    require(set(reports) == set(CELLS), "resource matrix has a missing cell")
    first = reports[CELLS[0]]
    for cell in CELLS[1:]:
        report = reports[cell]
        for field in ("manifest_sha256", "source_sha", "lockfile_sha256"):
            require(report[field] == first[field], f"{cell}: {field} differs across nodes")
        require(signatures[cell] == signatures[CELLS[0]],
                f"{cell}: deterministic execution observations differ")
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path)
    args = parser.parse_args()
    compare(args.reports)
    print("six-cell resource evidence validated; phase review and merge gates remain separate")


if __name__ == "__main__":
    main()
